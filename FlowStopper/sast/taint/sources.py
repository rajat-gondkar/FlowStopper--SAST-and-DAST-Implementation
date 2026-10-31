"""Taint sources: Flask / FastAPI / Django request data (Owner: A, P2-A3).

Two kinds of source, both generic (no app-specific constants, R6):

Request reads
    `request.args/form/values/json/data/cookies/headers/files/view_args` with `.get()`, `[]`,
    `getlist()`, `get_json()`, `to_dict()` (Flask/Werkzeug), the same shapes on Starlette's
    `query_params`/`path_params`, and Django's `request.GET/POST/body/COOKIES/META/FILES`.
    The receiver is recognised either by its resolved name (`flask.request`) or, when it is an
    unresolved `request` parameter (Django and FastAPI handlers take one), by the attribute chain.

Handler signature parameters
    Seeded from `Route.params` (DECISIONS A-14), so Flask path converters, FastAPI
    `Query/Path/Body/Form/Header/Cookie` markers and Django URL kwargs all arrive through P1-A2
    instead of being re-derived here.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Optional

from FlowStopper.models import ParamLocation, Route
from FlowStopper.sast.index import FunctionInfo, ModuleContext, dotted_parts
from FlowStopper.sast.routes.resolver import const_str

FLASK_REQUEST = "flask.request"
REQUEST_NAMES: frozenset[str] = frozenset({"request", "req"})
RECEIVER_NAMES: frozenset[str] = frozenset({"self", "cls"})  # class-based views: `self.request`

# Request container -> where the value came from, for every supported framework.
CONTAINERS: dict[str, ParamLocation] = {
    # Flask / Werkzeug
    "args": ParamLocation.QUERY,
    "values": ParamLocation.QUERY,
    "form": ParamLocation.FORM,
    "files": ParamLocation.FORM,
    "json": ParamLocation.JSON,
    "data": ParamLocation.JSON,
    "cookies": ParamLocation.COOKIE,
    "headers": ParamLocation.HEADER,
    "view_args": ParamLocation.PATH,
    # Starlette / FastAPI Request
    "query_params": ParamLocation.QUERY,
    "path_params": ParamLocation.PATH,
    # Django
    "GET": ParamLocation.QUERY,
    "POST": ParamLocation.FORM,
    "body": ParamLocation.JSON,
    "COOKIES": ParamLocation.COOKIE,
    "META": ParamLocation.HEADER,
    "FILES": ParamLocation.FORM,
}
ITEM_GETTERS: frozenset[str] = frozenset({"get", "getlist", "getall", "pop"})
CONTAINER_CALLS: frozenset[str] = frozenset({"to_dict", "copy", "dict", "lists"})
JSON_CALLS: frozenset[str] = frozenset({"get_json", "json"})
# The requested URL itself (DECISIONS A-44): request data with no parameter name. Redirecting to it is
# the redirect-to-self idiom, so CWE-601 is cleared from the start.
URL_ATTRIBUTES: frozenset[str] = frozenset({"url", "path", "full_path", "base_url"})
URL_CLEARED: frozenset[int] = frozenset({601})


@dataclass(frozen=True)
class SourceRef:
    """One request read. `param_name` is None for a whole container (DECISIONS A-15).

    `cleared` lists CWEs the read can never be dangerous for (the request URL and CWE-601, A-44).
    """

    param_name: Optional[str]
    location_kind: ParamLocation
    is_container: bool = False
    cleared: frozenset[int] = frozenset()


def request_source(expr: ast.expr, ctx: ModuleContext) -> Optional[SourceRef]:
    """The request read `expr` performs, else None. Never imports or evaluates anything (R7)."""
    if isinstance(expr, ast.Call):
        return _call_source(expr, ctx)
    if isinstance(expr, ast.Subscript):
        location = container_location(expr.value, ctx)
        return None if location is None else SourceRef(const_str(expr.slice), location, False)
    if isinstance(expr, ast.Attribute) and expr.attr in URL_ATTRIBUTES and is_request(expr.value, ctx):
        return SourceRef(None, ParamLocation.PATH, False, cleared=URL_CLEARED)
    location = container_location(expr, ctx)
    return None if location is None else SourceRef(None, location, True)


def container_location(expr: ast.expr, ctx: ModuleContext) -> Optional[ParamLocation]:
    """Where a whole request container came from (`request.args`, `request.get_json()`), else None."""
    if isinstance(expr, ast.Call):
        return _call_container(expr, ctx)
    if isinstance(expr, ast.Attribute) and is_request(expr.value, ctx):
        return CONTAINERS.get(expr.attr)
    return None


def is_request(expr: ast.expr, ctx: ModuleContext) -> bool:
    """True when `expr` denotes the framework request object."""
    resolved = ctx.resolve(expr)
    if resolved == FLASK_REQUEST:
        return True
    if resolved is not None and ctx.index.is_project_symbol(resolved):
        return False
    parts = dotted_parts(expr)
    if parts is None:
        return False
    if len(parts) == 1:
        return parts[0] in REQUEST_NAMES
    return len(parts) == 2 and parts[0] in RECEIVER_NAMES and parts[1] in REQUEST_NAMES


def handler_param_sources(fn: FunctionInfo, route: Route) -> dict[str, SourceRef]:
    """Handler signature parameters that carry request data, keyed by parameter name (A-14)."""
    declared = set(fn.params)
    out: dict[str, SourceRef] = {}
    for param in route.params:
        if param.name in declared and param.name not in out:
            out[param.name] = SourceRef(param.name, param.location, False)
    return out


# --------------------------------------------------------------------------- AST helpers
def _call_container(call: ast.Call, ctx: ModuleContext) -> Optional[ParamLocation]:
    func = call.func
    if not isinstance(func, ast.Attribute):
        return None
    if func.attr in JSON_CALLS and is_request(func.value, ctx):
        return ParamLocation.JSON
    if func.attr in CONTAINER_CALLS:
        return container_location(func.value, ctx)
    return None


def _call_source(call: ast.Call, ctx: ModuleContext) -> Optional[SourceRef]:
    location = _call_container(call, ctx)
    if location is not None:
        return SourceRef(None, location, True)
    func = call.func
    if isinstance(func, ast.Attribute) and func.attr in ITEM_GETTERS:
        container = container_location(func.value, ctx)
        if container is not None:
            return SourceRef(const_str(call.args[0]) if call.args else None, container, False)
    return None
