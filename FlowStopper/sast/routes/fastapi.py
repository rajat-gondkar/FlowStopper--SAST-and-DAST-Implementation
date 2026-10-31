"""FastAPI route extractor (Owner: A, P1-A2).

Recognises `@app.get/post/...` and `@app.api_route`, `APIRouter(prefix=...)`,
`include_router(router, prefix=...)` (prefixes compose additively, FastAPI semantics), and reads
handler parameters from the function signature: `Query/Path/Body/Form/Header/Cookie` markers,
plain typed params (query by default, path when named in the template), and pydantic model bodies
(expanded to their field names). Parse only (R7).
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from typing import Optional

from FlowStopper.models import ParamLocation, Route
from FlowStopper.sast.index import FunctionInfo, ProjectIndex, iter_block
from FlowStopper.sast.routes.common import HTTP_VERBS, build_route
from FlowStopper.sast.routes.resolver import const_str, first_str_arg, join_paths, keyword, str_sequence

FASTAPI_APP = frozenset({"fastapi.FastAPI", "fastapi.applications.FastAPI"})
FASTAPI_ROUTER = frozenset({"fastapi.APIRouter", "fastapi.routing.APIRouter"})

_MARKER_LOCATION = {
    "Query": ParamLocation.QUERY,
    "Path": ParamLocation.PATH,
    "Body": ParamLocation.JSON,
    "Form": ParamLocation.FORM,
    "Header": ParamLocation.HEADER,
    "Cookie": ParamLocation.COOKIE,
}
_DEPENDS = frozenset({"Depends", "Security"})
_SKIP_ANNOT = frozenset({"Request", "Response", "WebSocket", "BackgroundTasks"})
_ANNOTATED = frozenset({"typing.Annotated", "typing_extensions.Annotated"})
_AUTH_DEP = re.compile(
    r"current[_-]?user|get[_-]?user|authenticat|require[_-]?(auth|login|user)|verify[_-]?(token|jwt)"
    r"|security|oauth|bearer|\blogin\b|\btoken\b|\bjwt\b|credential",
    re.IGNORECASE,
)


@dataclass
class _Obj:
    kind: str  # "app" | "router"
    key: str
    module: str
    prefix: str = ""
    scope: Optional[str] = None


@dataclass
class _Inclusion:
    parent: str
    child: str
    prefix: str


@dataclass
class _RouteDef:
    obj: str
    rule: str
    methods: list[str]
    handler: FunctionInfo


def extract(index: ProjectIndex) -> list[Route]:
    return _FastAPIExtractor(index).run()


class _FastAPIExtractor:
    def __init__(self, index: ProjectIndex) -> None:
        self.ix = index
        self.objects: dict[str, _Obj] = {}
        self.local_objs: dict[tuple[str, str], str] = {}
        self.inclusions: list[_Inclusion] = []
        self._mount_cache: dict[str, list[str]] = {}

    def run(self) -> list[Route]:
        self._discover_objects()
        if not self.objects:
            return []
        self._discover_inclusions()
        routes: list[Route] = []
        seen: set[str] = set()
        for d in self._decorator_routes():
            obj = self.objects[d.obj]
            mounts = [""] if obj.kind == "app" else self._mounts(d.obj)
            for mount in mounts:
                path = join_paths(mount, d.rule)
                for method in d.methods:
                    route = build_route(self.ix, method, path, d.handler, self._signature_params, self._auth)
                    if route.id not in seen:
                        seen.add(route.id)
                        routes.append(route)
        return routes

    # ------------------------------------------------------------------ objects
    def _discover_objects(self) -> None:
        for var in self.ix.variables.values():
            ctor = self.ix.call_target(var.value, var.module)
            kind = _obj_kind(ctor)
            if kind is not None and isinstance(var.value, ast.Call):
                prefix = const_str(keyword(var.value, "prefix")) or "" if kind == "router" else ""
                self.objects[var.qualname] = _Obj(kind, var.qualname, var.module, prefix=prefix)
        for fn in self.ix.functions.values():
            for stmt in iter_block(fn.node.body):
                if not (isinstance(stmt, ast.Assign) and isinstance(stmt.value, ast.Call)):
                    continue
                kind = _obj_kind(self.ix.resolve_expr(stmt.value.func, fn.module, fn))
                if kind is None:
                    continue
                prefix = const_str(keyword(stmt.value, "prefix")) or "" if kind == "router" else ""
                for target in stmt.targets:
                    if isinstance(target, ast.Name):
                        key = f"{fn.qualname}::{target.id}"
                        self.objects[key] = _Obj(kind, key, fn.module, prefix=prefix, scope=fn.qualname)
                        self.local_objs[(fn.qualname, target.id)] = key

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

    # ------------------------------------------------------------------ inclusions + mounts
    def _discover_inclusions(self) -> None:
        for mod in self.ix.modules.values():
            for node in ast.walk(mod.tree):
                if not (isinstance(node, ast.Call) and _is_attr(node.func, "include_router")) or not node.args:
                    continue
                scope = self.ix.function_at(mod.file, node.lineno)
                parent = self._resolve_obj(node.func.value, mod.name, scope)
                child = self._resolve_obj(node.args[0], mod.name, scope)
                if parent is not None and child is not None:
                    self.inclusions.append(_Inclusion(parent, child, const_str(keyword(node, "prefix")) or ""))

    def _mounts(self, key: str, stack: frozenset[str] = frozenset()) -> list[str]:
        if key in self._mount_cache:
            return self._mount_cache[key]
        if key in stack:
            return []
        obj = self.objects.get(key)
        if obj is None:
            return []
        if obj.kind == "app":
            return [""]
        parents = [i for i in self.inclusions if i.child == key]
        if not parents:
            result = [obj.prefix]
        else:
            result = []
            for inc in parents:
                for parent_mount in self._mounts(inc.parent, stack | {key}):
                    result.append(join_paths(parent_mount, inc.prefix, obj.prefix))
        result = sorted(set(result))
        self._mount_cache[key] = result
        return result

    # ------------------------------------------------------------------ routes
    def _decorator_routes(self) -> list[_RouteDef]:
        out: list[_RouteDef] = []
        for fn in self.ix.functions.values():
            scope = self.ix.enclosing_function(fn)
            for dec in fn.node.decorator_list:
                if not isinstance(dec, ast.Call) or not isinstance(dec.func, ast.Attribute):
                    continue
                methods = _decorator_methods(dec)
                key = self._resolve_obj(dec.func.value, fn.module, scope)
                rule = first_str_arg(dec)
                if methods and key is not None and rule is not None:
                    out.append(_RouteDef(key, rule, methods, fn))
        return out

    # ------------------------------------------------------------------ params + auth
    def _signature_params(self, fn: FunctionInfo) -> list[tuple[str, ParamLocation]]:
        out: list[tuple[str, ParamLocation]] = []
        for arg, default in _iter_args(fn):
            params, _ = self._classify(arg.arg, arg.annotation, default, fn)
            out.extend(params)
        return out

    def _auth(self, fn: FunctionInfo) -> bool:
        for _, default in _iter_args(fn):
            if isinstance(default, ast.Call):
                _, is_auth = self._classify("", None, default, fn)
                if is_auth:
                    return True
        return False

    def _classify(
        self, name: str, annotation: Optional[ast.expr], default: Optional[ast.expr], fn: FunctionInfo
    ) -> tuple[list[tuple[str, ParamLocation]], bool]:
        if name in ("self", "cls"):
            return [], False
        anno_type, marker = self._unwrap_annotated(annotation, fn)
        if isinstance(default, ast.Call):
            marker = marker or default
        marker_leaf = _leaf(self.ix.resolve_expr(marker.func, fn.module, fn)) if isinstance(marker, ast.Call) else None
        if marker_leaf in _DEPENDS:
            return [], self._dependency_is_auth(marker, marker_leaf, fn)
        if marker_leaf in _MARKER_LOCATION:
            return [(name, _MARKER_LOCATION[marker_leaf])], False
        model = self.ix.resolve_expr(anno_type, fn.module, fn) if anno_type is not None else None
        if model is not None and self._is_pydantic(model):
            return [(field, ParamLocation.JSON) for field in self._model_fields(model)], False
        if _leaf(model) in _SKIP_ANNOT:
            return [], False
        return [(name, ParamLocation.QUERY)], False

    def _unwrap_annotated(
        self, annotation: Optional[ast.expr], fn: FunctionInfo
    ) -> tuple[Optional[ast.expr], Optional[ast.Call]]:
        if not (isinstance(annotation, ast.Subscript) and isinstance(annotation.slice, ast.Tuple)):
            return annotation, None
        if self.ix.resolve_expr(annotation.value, fn.module, fn) not in _ANNOTATED:
            return annotation, None
        elts = annotation.slice.elts
        marker = next((e for e in elts[1:] if isinstance(e, ast.Call)), None)
        return (elts[0] if elts else None), marker

    def _dependency_is_auth(self, marker: ast.Call, leaf: str, fn: FunctionInfo) -> bool:
        if leaf == "Security":
            return True
        if not marker.args:
            return False
        dep = marker.args[0]
        name = self.ix.resolve_expr(dep, fn.module, fn) or (dep.id if isinstance(dep, ast.Name) else "")
        return bool(_AUTH_DEP.search(name))

    def _is_pydantic(self, qualname: str) -> bool:
        if qualname not in self.ix.classes:
            return False
        return any("BaseModel" in _leaf(base) for base in self.ix.ancestors(qualname))

    def _model_fields(self, qualname: str) -> list[str]:
        out: list[str] = []
        seen: set[str] = set()
        for cls_q in self.ix.mro(qualname):
            cls = self.ix.classes.get(cls_q)
            if cls is None:
                continue
            for stmt in cls.node.body:
                field = _field_name(stmt)
                if (
                    field
                    and not field.startswith("_")
                    and field not in ("model_config", "Config")
                    and field not in seen
                ):
                    seen.add(field)
                    out.append(field)
        return out


# --------------------------------------------------------------------------- helpers
def _obj_kind(ctor: Optional[str]) -> Optional[str]:
    if ctor in FASTAPI_APP:
        return "app"
    if ctor in FASTAPI_ROUTER:
        return "router"
    return None


def _decorator_methods(dec: ast.Call) -> list[str]:
    attr = dec.func.attr if isinstance(dec.func, ast.Attribute) else ""
    if attr in HTTP_VERBS:
        return [attr.upper()]
    if attr == "api_route":
        return [m.upper() for m in (str_sequence(keyword(dec, "methods")) or ["GET"])]
    return []


def _iter_args(fn: FunctionInfo) -> list[tuple[ast.arg, Optional[ast.expr]]]:
    args = fn.node.args
    positional = list(args.posonlyargs) + list(args.args)
    out: list[tuple[ast.arg, Optional[ast.expr]]] = []
    offset = len(positional) - len(args.defaults)
    for i, arg in enumerate(positional):
        out.append((arg, args.defaults[i - offset] if i >= offset else None))
    out.extend(zip(args.kwonlyargs, args.kw_defaults, strict=True))  # equal length by the grammar
    return out


def _field_name(stmt: ast.stmt) -> Optional[str]:
    if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
        return stmt.target.id
    if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
        return stmt.targets[0].id
    return None


def _leaf(qualname: Optional[str]) -> str:
    return qualname.rsplit(".", 1)[-1] if qualname else ""


def _is_attr(expr: ast.expr, name: str) -> bool:
    return isinstance(expr, ast.Attribute) and expr.attr == name
