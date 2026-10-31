"""Django route extractor (Owner: A, P1-A2). Deliberately shallow (spec cut-list).

Walks `urlpatterns` built from `path()` / `re_path()` / `url()`, follows `include()` across project
modules composing prefixes, and resolves function views and class-based views (`as_view()`). Method
detection: function views -> GET; CBVs -> the HTTP verbs they define. `re_path` regexes are reduced
to `<name>` templates (precision such as `[0-9]{4}` is dropped — acceptable at this depth). Parse only (R7).
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Optional

from FlowStopper.models import ParamLocation, Route
from FlowStopper.sast.index import FunctionInfo, ProjectIndex
from FlowStopper.sast.routes.common import HTTP_VERBS, build_route, resolve_class
from FlowStopper.sast.routes.resolver import const_str, join_paths, repath_regex

_ROUTE_CALLS = frozenset({"path", "re_path", "url"})
_REQUEST_SOURCE = {
    "GET": ParamLocation.QUERY,
    "POST": ParamLocation.FORM,
    "COOKIES": ParamLocation.COOKIE,
    "FILES": ParamLocation.FORM,
    "META": ParamLocation.HEADER,
    "headers": ParamLocation.HEADER,
}


@dataclass
class _Pattern:
    template: str  # already a <name> template (regex routes are converted)
    view: Optional[ast.expr]
    include: Optional[ast.expr]
    module: str


def extract(index: ProjectIndex) -> list[Route]:
    return _DjangoExtractor(index).run()


class _DjangoExtractor:
    def __init__(self, index: ProjectIndex) -> None:
        self.ix = index
        self._patterns_by_module = self._collect_urlpatterns()

    def run(self) -> list[Route]:
        if not self._patterns_by_module:
            return []
        included = self._included_modules()
        roots = [m for m in self._patterns_by_module if m not in included]
        routes: list[Route] = []
        seen: set[str] = set()
        for module in sorted(roots):  # an included sub-urlconf is reached only through its includer
            self._walk(module, "", frozenset(), routes, seen)
        return routes

    def _included_modules(self) -> set[str]:
        out: set[str] = set()
        for module, patterns in self._patterns_by_module.items():
            if not isinstance(patterns, (ast.List, ast.Tuple)):
                continue
            for element in patterns.elts:
                pat = self._pattern(element, module)
                if pat is not None and pat.include is not None:
                    target = self._include_target(pat.include, module)
                    if target is not None:
                        out.add(target)
        return out

    def _collect_urlpatterns(self) -> dict[str, ast.expr]:
        out: dict[str, ast.expr] = {}
        for var in self.ix.variables.values():
            if var.name == "urlpatterns" and isinstance(var.value, (ast.List, ast.Tuple)):
                out[var.module] = var.value
        return out

    def _walk(self, module: str, prefix: str, stack: frozenset[str], routes: list[Route], seen: set[str]) -> None:
        if module in stack:
            return
        patterns = self._patterns_by_module.get(module)
        if not isinstance(patterns, (ast.List, ast.Tuple)):
            return
        for element in patterns.elts:
            pat = self._pattern(element, module)
            if pat is None:
                continue
            path = join_paths(prefix, pat.template)
            if pat.include is not None:
                target = self._include_target(pat.include, module)
                if target is not None:
                    self._walk(target, path, stack | {module}, routes, seen)
            elif pat.view is not None:
                for route in self._view_routes(pat.view, path, module):
                    if route.id not in seen:
                        seen.add(route.id)
                        routes.append(route)

    def _pattern(self, element: ast.expr, module: str) -> Optional[_Pattern]:
        if not (isinstance(element, ast.Call) and isinstance(element.func, (ast.Name, ast.Attribute))):
            return None
        leaf = element.func.attr if isinstance(element.func, ast.Attribute) else element.func.id
        if leaf not in _ROUTE_CALLS or not element.args:
            return None
        route_str = const_str(element.args[0]) or ""
        template = repath_regex(route_str)[1] if leaf == "re_path" else "/" + route_str
        second = element.args[1] if len(element.args) > 1 else None
        if isinstance(second, ast.Call) and _call_leaf(second.func) == "include":
            return _Pattern(template, None, second, module)
        return _Pattern(template, second, None, module)

    def _include_target(self, include_call: ast.expr, module: str) -> Optional[str]:
        if not (isinstance(include_call, ast.Call) and include_call.args):
            return None
        arg = include_call.args[0]
        name = const_str(arg)
        if name is not None:  # include("app.urls")
            return name if name in self._patterns_by_module else None
        target = self.ix.resolve_expr(arg, module, None)  # include(other.urls) module reference
        return target if target in self._patterns_by_module else None

    def _view_routes(self, view: ast.expr, path: str, module: str) -> list[Route]:
        cls = _resolve_as_view(self.ix, view, module)
        if cls is not None:
            return self._cbv_routes(cls, path)
        fn = self.ix.functions.get(self.ix.resolve_expr(view, module, None) or "")
        if fn is None:
            return []
        return [self._build("GET", path, fn)]

    def _cbv_routes(self, cls: str, path: str) -> list[Route]:
        out = [
            self._build(verb.upper(), path, self.ix.functions[mq])
            for verb in HTTP_VERBS
            if (mq := self.ix.find_method(cls, verb)) is not None
        ]
        if not out:  # generic CBV with no explicit verb handlers: assume GET
            dispatch = self.ix.find_method(cls, "dispatch")
            fn = self.ix.functions.get(dispatch or "")
            if fn is not None:
                out.append(self._build("GET", path, fn))
        return out

    def _build(self, method: str, path: str, fn: FunctionInfo) -> Route:
        return build_route(self.ix, method, path, fn, self._params, lambda f: False)

    def _params(self, fn: FunctionInfo) -> list[tuple[str, ParamLocation]]:
        request_name = _request_param(fn)
        if request_name is None:
            return []
        found: list[tuple[str, ParamLocation]] = []
        seen: set[tuple[str, ParamLocation]] = set()
        for node in ast.walk(fn.node):
            name, loc = _request_access(node, request_name)
            if name is not None and loc is not None and (name, loc) not in seen:
                seen.add((name, loc))
                found.append((name, loc))
        return found


def _resolve_as_view(index: ProjectIndex, expr: ast.expr, module: str) -> Optional[str]:
    if isinstance(expr, ast.Call) and isinstance(expr.func, ast.Attribute) and expr.func.attr == "as_view":
        return resolve_class(index, expr.func.value, module, None)
    return None


def _request_param(fn: FunctionInfo) -> Optional[str]:
    if fn.is_method:
        return "request" if "request" in fn.params else (fn.params[1] if len(fn.params) > 1 else None)
    return fn.params[0] if fn.params else None


def _request_access(node: ast.AST, request_name: str) -> tuple[Optional[str], Optional[ParamLocation]]:
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in ("get", "getlist"):
        return _source(node.func.value, request_name, const_str(node.args[0]) if node.args else None)
    if isinstance(node, ast.Subscript):
        return _source(node.value, request_name, const_str(node.slice))
    return None, None


def _source(base: ast.expr, request_name: str, key: Optional[str]) -> tuple[Optional[str], Optional[ParamLocation]]:
    if key is None or not (isinstance(base, ast.Attribute) and base.attr in _REQUEST_SOURCE):
        return None, None
    if isinstance(base.value, ast.Name) and base.value.id == request_name:
        return key, _REQUEST_SOURCE[base.attr]
    return None, None


def _call_leaf(expr: ast.expr) -> str:
    if isinstance(expr, ast.Attribute):
        return expr.attr
    if isinstance(expr, ast.Name):
        return expr.id
    return ""
