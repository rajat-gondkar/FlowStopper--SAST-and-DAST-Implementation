"""Flask route extractor (Owner: A, P1-A2) — the primary framework, handled most thoroughly.

Recognises `@app.route` / `@bp.route`, the verb shortcuts (`@app.get/post/...`), `add_url_rule`,
`MethodView` classes registered via `as_view`, blueprint `url_prefix` (set either in `Blueprint(...)`
or at `register_blueprint(..., url_prefix=...)`), nested blueprints, and the `create_app` factory
pattern (app / blueprints as function locals). Parse only; nothing is imported or executed (R7).
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Optional

from FlowStopper.models import ParamLocation, Route
from FlowStopper.sast.index import FunctionInfo, ModuleInfo, ProjectIndex, iter_block
from FlowStopper.sast.routes.common import (
    AUTH_DECORATORS,
    HTTP_VERBS,
    build_route,
    resolve_class,
)
from FlowStopper.sast.routes.resolver import (
    const_str,
    first_str_arg,
    join_paths,
    keyword,
    str_sequence,
)

FLASK_APP = "flask.Flask"
FLASK_BLUEPRINT = "flask.Blueprint"


@dataclass
class _Obj:
    kind: str  # "app" | "blueprint"
    key: str
    module: str
    url_prefix: str = ""  # blueprint's own prefix (from Blueprint(..., url_prefix=))
    scope: Optional[str] = None  # enclosing function qualname when the object is a local


@dataclass
class _RouteDef:
    obj: str  # object key the route is registered on
    rule: str
    methods: list[str]
    handler: FunctionInfo


@dataclass
class _Registration:
    parent: str
    child: str
    url_prefix: Optional[str]  # explicit register-time prefix, or None


def extract(index: ProjectIndex) -> list[Route]:
    return _FlaskExtractor(index).run()


class _FlaskExtractor:
    def __init__(self, index: ProjectIndex) -> None:
        self.ix = index
        self.objects: dict[str, _Obj] = {}
        self.local_objs: dict[tuple[str, str], str] = {}  # (func qualname, local name) -> object key
        self.registrations: list[_Registration] = []
        self._mount_cache: dict[str, list[str]] = {}

    # ------------------------------------------------------------------ driver
    def run(self) -> list[Route]:
        self._discover_objects()
        if not self.objects:
            return []
        self._discover_registrations()
        defs = self._decorator_routes() + self._add_url_rule_routes()
        routes: list[Route] = []
        seen: set[str] = set()
        for d in defs:
            obj = self.objects[d.obj]
            mounts = [""] if obj.kind == "app" else self._mounts(d.obj)
            for mount in mounts:
                path = join_paths(mount, d.rule)
                for method in d.methods:
                    route = build_route(self.ix, method, path, d.handler, self._flask_params, self._auth)
                    if route.id not in seen:
                        seen.add(route.id)
                        routes.append(route)
        return routes

    # ------------------------------------------------------------------ objects
    def _discover_objects(self) -> None:
        for var in self.ix.variables.values():
            ctor = self.ix.call_target(var.value, var.module)
            if ctor == FLASK_APP:
                self.objects[var.qualname] = _Obj("app", var.qualname, var.module)
            elif ctor == FLASK_BLUEPRINT and isinstance(var.value, ast.Call):
                self.objects[var.qualname] = _Obj(
                    "blueprint", var.qualname, var.module, url_prefix=const_str(keyword(var.value, "url_prefix")) or ""
                )
        for fn in self.ix.functions.values():
            for name, call in self._local_constructor_calls(fn):
                ctor = self.ix.resolve_expr(call.func, fn.module, fn)
                if ctor not in (FLASK_APP, FLASK_BLUEPRINT):
                    continue
                key = f"{fn.qualname}::{name}"
                prefix = const_str(keyword(call, "url_prefix")) or "" if ctor == FLASK_BLUEPRINT else ""
                kind = "app" if ctor == FLASK_APP else "blueprint"
                self.objects[key] = _Obj(kind, key, fn.module, url_prefix=prefix, scope=fn.qualname)
                self.local_objs[(fn.qualname, name)] = key
        self._discover_param_objects()

    def _discover_param_objects(self) -> None:
        """Route-registration functions that receive the app as a parameter (`def init(app): @app.route`).

        The parameter becomes a mountable object with no prefix of its own. Each statically resolvable
        call site that passes a known app or blueprint registers it there; with no such call site (e.g.
        the module is loaded through `importlib`) it is mounted at the root, like an unregistered
        blueprint. Only modules that import Flask qualify, so other frameworks' routers are left alone.
        """
        params: list[tuple[FunctionInfo, str, int]] = []
        for fn in self.ix.functions.values():
            if fn.class_name is not None or not _imports_flask(self.ix.modules[fn.module]):
                continue
            positional = [a.arg for a in (*fn.node.args.posonlyargs, *fn.node.args.args)]
            for name in sorted(self._route_receivers(fn)):
                if name not in fn.params or (fn.qualname, name) in self.local_objs:
                    continue
                key = f"{fn.qualname}::{name}"
                self.objects[key] = _Obj("blueprint", key, fn.module, scope=fn.qualname)
                self.local_objs[(fn.qualname, name)] = key
                params.append((fn, name, positional.index(name) if name in positional else -1))
        if params:
            self._param_call_sites(params)

    def _route_receivers(self, fn: FunctionInfo) -> set[str]:
        """Names used as the receiver of a route decorator on a nested def, or of `add_url_rule`, in `fn`."""
        names: set[str] = set()
        for node in ast.walk(fn.node):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node is not fn.node:
                for dec in node.decorator_list:
                    if isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute):
                        if _decorator_methods(dec) is not None and isinstance(dec.func.value, ast.Name):
                            names.add(dec.func.value.id)
            elif _is_method_call(node, "add_url_rule") and isinstance(node.func.value, ast.Name):
                names.add(node.func.value.id)
        return names

    def _param_call_sites(self, params: list[tuple[FunctionInfo, str, int]]) -> None:
        by_function: dict[str, list[tuple[str, int]]] = {}
        for fn, name, position in params:
            by_function.setdefault(fn.qualname, []).append((name, position))
        for mod in self.ix.modules.values():
            for node in ast.walk(mod.tree):
                if not isinstance(node, ast.Call):
                    continue
                scope = self.ix.function_at(mod.file, node.lineno)
                target = self.ix.resolve_expr(node.func, mod.name, scope)
                for name, position in by_function.get(target or "", []):
                    arg = keyword(node, name)
                    if arg is None and 0 <= position < len(node.args):
                        arg = node.args[position]
                    parent = self._resolve_obj(arg, mod.name, scope) if arg is not None else None
                    if parent is not None:
                        self.registrations.append(_Registration(parent, f"{target}::{name}", None))

    @staticmethod
    def _local_constructor_calls(fn: FunctionInfo):
        for stmt in iter_block(fn.node.body):
            if isinstance(stmt, ast.Assign) and isinstance(stmt.value, ast.Call):
                for target in stmt.targets:
                    if isinstance(target, ast.Name):
                        yield target.id, stmt.value

    def _resolve_obj(self, expr: ast.expr, module: str, scope: Optional[FunctionInfo]) -> Optional[str]:
        if isinstance(expr, ast.Name):
            fn = scope
            while fn is not None:
                key = self.local_objs.get((fn.qualname, expr.id))
                if key is not None:
                    return key
                fn = self.ix.enclosing_function(fn)
        qualname = self.ix.resolve_expr(expr, module, scope)
        return qualname if qualname in self.objects else None

    # ------------------------------------------------------------------ registrations + mounts
    def _discover_registrations(self) -> None:
        for mod in self.ix.modules.values():
            for node in ast.walk(mod.tree):
                if not _is_method_call(node, "register_blueprint") or not node.args:
                    continue
                scope = self.ix.function_at(mod.file, node.lineno)
                parent = self._resolve_obj(node.func.value, mod.name, scope)
                child = self._resolve_obj(node.args[0], mod.name, scope)
                if parent is not None and child is not None:
                    self.registrations.append(_Registration(parent, child, const_str(keyword(node, "url_prefix"))))

    def _mounts(self, key: str, stack: frozenset[str] = frozenset()) -> list[str]:
        if key in self._mount_cache:
            return self._mount_cache[key]
        if key in stack:
            return []  # registration cycle
        obj = self.objects.get(key)
        if obj is None:
            return []
        if obj.kind == "app":
            return [""]
        parents = [r for r in self.registrations if r.child == key]
        if not parents:
            result = [obj.url_prefix]  # defined but never registered: fall back to its own prefix
        else:
            result = []
            for reg in parents:
                effective = reg.url_prefix if reg.url_prefix is not None else obj.url_prefix
                for parent_mount in self._mounts(reg.parent, stack | {key}):
                    result.append(join_paths(parent_mount, effective))
        result = sorted(set(result))
        self._mount_cache[key] = result
        return result

    # ------------------------------------------------------------------ route definitions
    def _decorator_routes(self) -> list[_RouteDef]:
        out: list[_RouteDef] = []
        for fn in self.ix.functions.values():
            scope = self.ix.enclosing_function(fn)
            for dec in fn.node.decorator_list:
                if not isinstance(dec, ast.Call) or not isinstance(dec.func, ast.Attribute):
                    continue
                methods = _decorator_methods(dec)
                if methods is None:
                    continue
                key = self._resolve_obj(dec.func.value, fn.module, scope)
                rule = first_str_arg(dec)
                if key is not None and rule is not None:
                    out.append(_RouteDef(key, rule, methods, fn))
        return out

    def _add_url_rule_routes(self) -> list[_RouteDef]:
        out: list[_RouteDef] = []
        for mod in self.ix.modules.values():
            for node in ast.walk(mod.tree):
                if not _is_method_call(node, "add_url_rule"):
                    continue
                scope = self.ix.function_at(mod.file, node.lineno)
                key = self._resolve_obj(node.func.value, mod.name, scope)
                rule = first_str_arg(node)
                if key is None or rule is None:
                    continue
                view = keyword(node, "view_func") or (node.args[2] if len(node.args) > 2 else None)
                methods = str_sequence(keyword(node, "methods"))
                out += self._view_routes(key, rule, view, methods, mod.name, scope)
        return out

    def _view_routes(
        self,
        key: str,
        rule: str,
        view: Optional[ast.expr],
        methods: Optional[list[str]],
        module: str,
        scope: Optional[FunctionInfo],
    ) -> list[_RouteDef]:
        if view is None:
            return []
        if isinstance(view, ast.Call) and _is_attr(view.func, "as_view"):
            cls = resolve_class(self.ix, view.func.value, module, scope)
            return self._methodview_routes(key, rule, cls, methods)
        fn = self.ix.functions.get(self.ix.resolve_expr(view, module, scope) or "")
        if fn is None:
            return []
        return [_RouteDef(key, rule, [m.upper() for m in (methods or ["GET"])], fn)]

    def _methodview_routes(
        self, key: str, rule: str, cls: Optional[str], methods: Optional[list[str]]
    ) -> list[_RouteDef]:
        if cls is None:
            return []
        wanted = {m.lower() for m in methods} if methods else None
        out: list[_RouteDef] = []
        for verb in HTTP_VERBS:
            if wanted is not None and verb not in wanted:
                continue
            mq = self.ix.find_method(cls, verb)
            if mq is not None:
                out.append(_RouteDef(key, rule, [verb.upper()], self.ix.functions[mq]))
        return out

    # ------------------------------------------------------------------ params + auth
    def _flask_params(self, fn: FunctionInfo) -> list[tuple[str, ParamLocation]]:
        return _RequestScan(self.ix, fn).collect()

    def _auth(self, fn: FunctionInfo) -> bool:
        return any(d.rsplit(".", 1)[-1] in AUTH_DECORATORS for d in fn.decorators)


# --------------------------------------------------------------------------- Flask request scan
_CONTAINER_LOCATION = {
    "args": ParamLocation.QUERY,
    "values": ParamLocation.QUERY,
    "form": ParamLocation.FORM,
    "files": ParamLocation.FORM,
    "headers": ParamLocation.HEADER,
    "cookies": ParamLocation.COOKIE,
}
_GETTERS = frozenset({"get", "getlist", "pop"})
_JSON_CALLS = frozenset({"get_json"})
_JSON_ATTRS = frozenset({"json"})


class _RequestScan:
    """Finds HTTP parameter names read from `flask.request` in a handler body, with their location."""

    def __init__(self, index: ProjectIndex, fn: FunctionInfo) -> None:
        self.ix = index
        self.fn = fn
        self.found: list[tuple[str, ParamLocation]] = []
        self.seen: set[tuple[str, ParamLocation]] = set()

    def collect(self) -> list[tuple[str, ParamLocation]]:
        json_vars = self._json_source_vars()
        for node in ast.walk(self.fn.node):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in _GETTERS:
                self._from_accessor(node.func.value, _arg0(node), json_vars)
            elif isinstance(node, ast.Subscript):
                self._from_accessor(node.value, _slice_str(node.slice), json_vars)
        return self.found

    def _json_source_vars(self) -> set[str]:
        names: set[str] = set()
        for node in ast.walk(self.fn.node):
            if isinstance(node, ast.Assign) and self._is_json(node.value):
                names.update(t.id for t in node.targets if isinstance(t, ast.Name))
        return names

    def _from_accessor(self, base: Optional[ast.expr], name: Optional[str], json_vars: set[str]) -> None:
        if name is None or base is None:
            return
        if isinstance(base, ast.Attribute) and base.attr in _CONTAINER_LOCATION and self._is_request(base.value):
            self._add(name, _CONTAINER_LOCATION[base.attr])
        elif isinstance(base, ast.Name) and base.id in json_vars:
            self._add(name, ParamLocation.JSON)
        elif self._is_json(base):
            self._add(name, ParamLocation.JSON)

    def _is_request(self, expr: ast.expr) -> bool:
        return self.ix.resolve_expr(expr, self.fn.module, self.fn) == "flask.request"

    def _is_json(self, expr: ast.expr) -> bool:
        if isinstance(expr, ast.Call) and _is_attr(expr.func, *_JSON_CALLS) and self._is_request(expr.func.value):
            return True
        return isinstance(expr, ast.Attribute) and expr.attr in _JSON_ATTRS and self._is_request(expr.value)

    def _add(self, name: str, loc: ParamLocation) -> None:
        if (name, loc) not in self.seen:
            self.seen.add((name, loc))
            self.found.append((name, loc))


# --------------------------------------------------------------------------- AST helpers
def _decorator_methods(dec: ast.Call) -> Optional[list[str]]:
    attr = dec.func.attr if isinstance(dec.func, ast.Attribute) else ""
    if attr == "route":
        return [m.upper() for m in (str_sequence(keyword(dec, "methods")) or ["GET"])]
    if attr in HTTP_VERBS:
        return [attr.upper()]
    return None


def _imports_flask(mod: ModuleInfo) -> bool:
    return any(target == "flask" or target.startswith("flask.") for _, target in mod.bindings.values())


def _is_attr(expr: ast.expr, *names: str) -> bool:
    return isinstance(expr, ast.Attribute) and expr.attr in names


def _is_method_call(node: ast.AST, attr: str) -> bool:
    return isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == attr


def _arg0(call: ast.Call) -> Optional[str]:
    return const_str(call.args[0]) if call.args else None


def _slice_str(node: ast.expr) -> Optional[str]:
    return const_str(node)
