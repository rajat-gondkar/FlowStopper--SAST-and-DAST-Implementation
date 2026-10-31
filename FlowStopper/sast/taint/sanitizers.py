"""Sanitisers and guard patterns per CWE (Owner: A, P2-A3).

Sanitisers neutralise taint **per CWE** (DECISIONS A-07): `html.escape(x)` clears CWE-79 and leaves
89/78/22/601 tainted, `int(x)` clears everything. Matching is by resolved dotted name only, so a
project function called `escape` never silences a flow.

Guards implement the spec's "path-sensitive lite" list. `guard_clearance(test, ctx)` answers *which
names are constrained when `test` is true*; pass `negated=True` for *when `test` is false*, which is
what the engine needs for the `if not guard: return` shape and for the `else` branch (A-11).
Recognition is deliberately unsound in the safe direction: a missed finding is preferred over a
wrong one.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Optional

from FlowStopper.sast.index import ModuleContext, dotted_parts
from FlowStopper.sast.routes.resolver import const_str

ALL_CWES: frozenset[int] = frozenset({22, 78, 79, 89, 601})
SQLI: frozenset[int] = frozenset({89})
CMDI: frozenset[int] = frozenset({78})
XSS: frozenset[int] = frozenset({79})
TRAVERSAL: frozenset[int] = frozenset({22})
REDIRECT: frozenset[int] = frozenset({601})

SANITIZERS: dict[str, frozenset[int]] = {
    # casts: the value is no longer a string at all
    "builtins.int": ALL_CWES,
    "builtins.float": ALL_CWES,
    "builtins.bool": ALL_CWES,
    "uuid.UUID": ALL_CWES,
    # HTML escaping
    "html.escape": XSS,
    "cgi.escape": XSS,
    "markupsafe.escape": XSS,
    "markupsafe.escape_silent": XSS,
    "flask.escape": XSS,
    "jinja2.escape": XSS,
    "jinja2.utils.escape": XSS,
    "django.utils.html.escape": XSS,
    "django.utils.html.conditional_escape": XSS,
    "django.utils.html.strip_tags": XSS,
    "bleach.clean": XSS,
    # shell quoting
    "shlex.quote": CMDI,
    "pipes.quote": CMDI,
    # path containment
    "werkzeug.utils.secure_filename": TRAVERSAL,
    "werkzeug.security.safe_join": TRAVERSAL,
    "werkzeug.utils.safe_join": TRAVERSAL,
    "os.path.basename": TRAVERSAL,
    "flask.send_from_directory": TRAVERSAL,
    "flask.helpers.send_from_directory": TRAVERSAL,
    "django.utils._os.safe_join": TRAVERSAL,
    # URL building
    "flask.url_for": REDIRECT,
    "flask.helpers.url_for": REDIRECT,
    "django.urls.reverse": REDIRECT,
}

# Sanitisers whose result is a response, not a string derived from the argument.
SANITIZER_BARRIERS: frozenset[str] = frozenset({"flask.send_from_directory", "flask.helpers.send_from_directory"})

# Guard call shapes, by attribute leaf name, with the CWEs they clear.
_CHARACTER_CLASS_GUARDS: frozenset[str] = frozenset({"isdigit", "isnumeric", "isdecimal", "isalnum", "isalpha"})
_CONTAINMENT_GUARDS: frozenset[str] = frozenset({"startswith", "is_relative_to", "samefile"})
_REGEX_GUARDS: frozenset[str] = frozenset({"re.fullmatch"})
_SAME_HOST_GUARDS: frozenset[str] = frozenset(
    {
        "django.utils.http.url_has_allowed_host_and_scheme",
        "django.utils.http.is_safe_url",
    }
)
_SAME_HOST_LEAVES: frozenset[str] = frozenset({"url_has_allowed_host_and_scheme", "is_safe_url"})
_NORMALISERS: frozenset[str] = frozenset(
    {"os.path.realpath", "os.path.abspath", "os.path.normpath", "resolve", "realpath", "abspath", "normpath"}
)
_COMMONPATH: frozenset[str] = frozenset({"os.path.commonpath", "os.path.commonprefix"})
_NETLOC_PARTS: frozenset[str] = frozenset({"netloc", "hostname"})


@dataclass(frozen=True)
class Sanitizer:
    """A recognised sanitising call and the CWEs it clears.

    `result_barrier` marks the helpers that return a response rather than a derived string, so the
    tainted value stops there instead of flowing into the caller's response (A-09).
    """

    name: str
    cwes: frozenset[int]
    result_barrier: bool = False


@dataclass(frozen=True)
class GuardMatch:
    """A recognised guard: which names it constrains and for which CWEs."""

    label: str
    cwes: frozenset[int]
    names: frozenset[str]


def sanitizer_at(call: ast.Call, ctx: ModuleContext) -> Optional[Sanitizer]:
    """The sanitiser `call` is, else None."""
    resolved = ctx.resolve(call.func)
    if resolved is None:
        return None
    cwes = SANITIZERS.get(resolved)
    if cwes is None:
        return None
    return Sanitizer(resolved, cwes, result_barrier=resolved in SANITIZER_BARRIERS)


def guard_clearance(test: ast.expr, ctx: ModuleContext, *, negated: bool = False) -> list[GuardMatch]:
    """Guards that hold when `test` is true (or false, with `negated=True`). Any BoolOp operand counts."""
    if isinstance(test, ast.BoolOp):
        out: list[GuardMatch] = []
        for operand in test.values:
            out += guard_clearance(operand, ctx, negated=negated)
        return out
    if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
        return guard_clearance(test.operand, ctx, negated=not negated)
    if isinstance(test, ast.Compare):
        return _compare_guard(test, ctx, negated)
    if isinstance(test, ast.Call) and not negated:
        return _call_guard(test, ctx)
    return []


def is_constant_collection(expr: Optional[ast.expr], ctx: ModuleContext) -> bool:
    """True for a literal collection of constants or a module-level constant assigned exactly once."""
    if expr is None:
        return False
    if isinstance(expr, ast.Constant):
        return isinstance(expr.value, (str, bytes))
    if isinstance(expr, (ast.List, ast.Tuple, ast.Set)):
        return bool(expr.elts) and all(isinstance(e, ast.Constant) for e in expr.elts)
    if isinstance(expr, ast.Dict):
        return bool(expr.keys) and all(isinstance(k, ast.Constant) for k in expr.keys)
    resolved = ctx.resolve(expr)
    variable = ctx.index.variables.get(resolved or "")
    if variable is None or len(variable.history) != 1:
        return False
    return is_constant_collection(variable.value, ctx)


def names_in(expr: Optional[ast.expr]) -> frozenset[str]:
    """Every `ast.Name` id in an expression (the names a guard constrains)."""
    if expr is None:
        return frozenset()
    return frozenset(node.id for node in ast.walk(expr) if isinstance(node, ast.Name))


# --------------------------------------------------------------------------- guard shapes
def _compare_guard(test: ast.Compare, ctx: ModuleContext, negated: bool) -> list[GuardMatch]:
    if len(test.ops) != 1 or len(test.comparators) != 1:
        return []
    op, left, right = test.ops[0], test.left, test.comparators[0]
    if isinstance(op, (ast.In, ast.NotIn)):
        if isinstance(op, ast.In) is negated:  # `x in ALLOWED` is a guard only when it is true
            return []
        if not is_constant_collection(right, ctx):
            return []
        label = "same-host-allow-list" if _is_netloc(left) else "allow-list"
        return [GuardMatch(label, ALL_CWES, names_in(left))]
    if isinstance(op, (ast.Eq, ast.NotEq)):
        if isinstance(op, ast.Eq) is negated:
            return []
        if _is_netloc(left) and const_str(right) == "":
            return [GuardMatch("same-site", REDIRECT, names_in(left))]
        if _resolves_to(left, ctx, _COMMONPATH):
            return [GuardMatch("commonpath", TRAVERSAL, names_in(left))]
        if _resolves_to(right, ctx, _COMMONPATH):
            return [GuardMatch("commonpath", TRAVERSAL, names_in(right))]
    return []


def _call_guard(call: ast.Call, ctx: ModuleContext) -> list[GuardMatch]:
    resolved = ctx.resolve(call.func)
    leaf = call.func.attr if isinstance(call.func, ast.Attribute) else None
    if resolved in _SAME_HOST_GUARDS or _leaf_of(resolved) in _SAME_HOST_LEAVES or leaf in _SAME_HOST_LEAVES:
        names = names_in(call.args[0]) if call.args else frozenset()
        return [GuardMatch("same-host-check", REDIRECT, names or _all_argument_names(call))]
    if resolved in _REGEX_GUARDS and len(call.args) >= 2 and is_constant_collection(call.args[0], ctx):
        return [GuardMatch("regex-fullmatch", ALL_CWES, names_in(call.args[1]))]
    if leaf is None:
        return []
    receiver = call.func.value
    if leaf in _CHARACTER_CLASS_GUARDS:
        return [GuardMatch(f"{leaf}-check", ALL_CWES, names_in(receiver))]
    if leaf in _CONTAINMENT_GUARDS and _is_normalised(receiver, call, ctx):
        return [GuardMatch("path-containment", TRAVERSAL, names_in(receiver))]
    return []


def _is_normalised(receiver: ast.expr, call: ast.Call, ctx: ModuleContext) -> bool:
    """A containment check counts only against a normalised path or a constant base (spec P2-A3)."""
    if _contains_normaliser(receiver, ctx):
        return True
    return bool(call.args) and (is_constant_collection(call.args[0], ctx) or _contains_normaliser(call.args[0], ctx))


def _contains_normaliser(expr: ast.expr, ctx: ModuleContext) -> bool:
    for node in ast.walk(expr):
        if not isinstance(node, ast.Call):
            continue
        resolved = ctx.resolve(node.func)
        leaf = node.func.attr if isinstance(node.func, ast.Attribute) else None
        if resolved in _NORMALISERS or _leaf_of(resolved) in _NORMALISERS or leaf in _NORMALISERS:
            return True
    return False


def _is_netloc(expr: ast.expr) -> bool:
    """`urlparse(x).netloc` / `urlsplit(x).hostname`."""
    if isinstance(expr, ast.Attribute) and expr.attr in _NETLOC_PARTS:
        return True
    parts = dotted_parts(expr)
    return bool(parts) and parts[-1] in _NETLOC_PARTS


def _resolves_to(expr: ast.expr, ctx: ModuleContext, names: frozenset[str]) -> bool:
    if not isinstance(expr, ast.Call):
        return False
    resolved = ctx.resolve(expr.func)
    return resolved in names or _leaf_of(resolved) in {_leaf_of(n) for n in names}


def _all_argument_names(call: ast.Call) -> frozenset[str]:
    out: frozenset[str] = frozenset()
    for node in (*call.args, *(kw.value for kw in call.keywords)):
        out |= names_in(node)
    return out


def _leaf_of(dotted: Optional[str]) -> Optional[str]:
    return dotted.rsplit(".", 1)[-1] if dotted else None
