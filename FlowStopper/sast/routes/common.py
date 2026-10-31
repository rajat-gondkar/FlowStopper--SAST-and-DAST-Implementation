"""Shared helpers for the route extractors (Owner: A, P1-A2)."""

from __future__ import annotations

import ast
from typing import Callable, Optional

from FlowStopper.models import ParamLocation, Route, RouteParam
from FlowStopper.sast.index import FunctionInfo, ProjectIndex
from FlowStopper.sast.routes.resolver import split_params, template_regex

# HTTP verbs, lower-case, in a stable priority order (used for verb decorators and MethodView methods).
HTTP_VERBS: tuple[str, ...] = ("get", "post", "put", "delete", "patch", "head", "options")

# Decorator leaf-names that mark a handler as requiring authentication (framework-agnostic, generic — R6).
AUTH_DECORATORS: frozenset[str] = frozenset(
    {
        "login_required",
        "fresh_login_required",
        "jwt_required",
        "fresh_jwt_required",
        "jwt_optional",
        "token_required",
        "auth_required",
        "authenticated",
        "requires_auth",
        "requires_authorization",
        "requires_login",
        "permission_required",
        "permissions_required",
        "roles_required",
        "role_required",
        "admin_required",
        "staff_member_required",
    }
)

ParamsFn = Callable[[FunctionInfo], "list[tuple[str, ParamLocation]]"]
AuthFn = Callable[[FunctionInfo], bool]


def build_route(
    index: ProjectIndex,
    method: str,
    path: str,
    handler: FunctionInfo,
    params_fn: ParamsFn,
    auth_fn: AuthFn,
) -> Route:
    """Assemble a `Route`: path params (from the template) first, then body/signature params, de-duplicated."""
    params: list[RouteParam] = []
    seen: set[tuple[str, ParamLocation]] = set()
    path_names: set[str] = set()

    def add(name: str, location: ParamLocation, required: bool) -> None:
        if (name, location) not in seen:
            seen.add((name, location))
            params.append(RouteParam(name=name, location=location, required=required))

    for name, _ in split_params(path):
        path_names.add(name)
        add(name, ParamLocation.PATH, True)
    for name, location in params_fn(handler):
        if name not in path_names:
            add(name, location, location is ParamLocation.PATH)

    return Route(
        id=f"{method.upper()} {path}",
        method=method.upper(),
        path_template=path,
        path_regex=template_regex(path),
        handler=handler.qualname,
        file=handler.file,
        line_start=handler.line_start,
        line_end=handler.line_end,
        params=params,
        auth_required=auth_fn(handler),
        reachable_functions=[],
    )


def resolve_class(index: ProjectIndex, expr: ast.expr, module: str, scope: Optional[FunctionInfo]) -> Optional[str]:
    """Qualname of a project class referred to by `expr`, else None."""
    qualname = index.resolve_expr(expr, module, scope)
    return qualname if qualname in index.classes else None
