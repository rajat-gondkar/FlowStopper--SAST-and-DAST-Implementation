"""B-2 noise cut (Owner: A, P4-A2).

suppress_reason values: "sanitized:<name>", "safe:<pattern>", "unreachable" (never for CWE-798).

Reasons (DECISIONS A-47)
    `sanitized:<names>` - every label reaching the sink was cleared for its CWE by a recognised
    sanitiser or guard; `<names>` are the sorted sanitiser/guard names joined with `+`
    (`sanitized:html.escape`, `sanitized:guard:allow-list`). `safe:sql-parameterised` - constant SQL
    text with request data only in the bind parameters. `safe:subprocess-list-no-shell` /
    `safe:subprocess-no-shell` - a subprocess call without a shell. `unreachable` - a function no
    route can reach (A-48), never applied to CWE-798.

The taint engine emits the sanitised/safe reports itself, since it knows the clearance at the sink
(A-49); this module holds the reason strings, the request-hook test (A-46) and the conservative
reachability test. It imports neither the sinks nor the engine (the sinks import it). Parse only:
nothing here imports or executes scanned code (R7).
"""

from __future__ import annotations

import ast
import re
from collections.abc import Iterable
from typing import Optional, Protocol

from FlowStopper.models import Route
from FlowStopper.sast.callgraph import CallGraph, local_types, own_calls
from FlowStopper.sast.index import FunctionInfo, ProjectIndex

SANITIZED_PREFIX = "sanitized:"
SAFE_PREFIX = "safe:"
SAFE_SQL_PARAMETERISED = "safe:sql-parameterised"
SAFE_SUBPROCESS_LIST_NO_SHELL = "safe:subprocess-list-no-shell"
SAFE_SUBPROCESS_NO_SHELL = "safe:subprocess-no-shell"
SAFE_YAML_SAFE_LOADER = "safe:yaml-safe-loader"
UNREACHABLE = "unreachable"
SECRET_CWE = 798  # hard-coded secrets are never suppressed as unreachable

# Decorator leaves that register a function the framework calls around requests (A-46): walked as
# code-only entry points, with no route id of their own.
REQUEST_HOOK_DECORATORS: frozenset[str] = frozenset(
    {
        "errorhandler",
        "app_errorhandler",
        "before_request",
        "before_app_request",
        "after_request",
        "after_app_request",
        "teardown_request",
        "teardown_app_request",
        "before_first_request",
        "exception_handler",
        "middleware",
    }
)

# A string that may name a function: `"run"`, `"pkg.tasks.run"`, `"pkg.wsgi:create_app()"`.
_NAME_PATH = re.compile(r"[\w.:]+(?:\(\))?")
_IDENTIFIER = re.compile(r"[^\W\d]\w*")

# Calls that look a name up at run time (A-52). `_NAME_ARGS` maps a call leaf to the slice of its
# positional arguments that hold names: a non-constant one there (`getattr(mod, "cmd_" + x)`) means
# any function may be reached. `_NAMESPACE_CALLS` hand out a namespace dict (`globals()[...]`), so
# any call counts.
_NAME_ARGS: dict[str, slice] = {
    "getattr": slice(1, 2),
    "attrgetter": slice(0, None),
    "methodcaller": slice(0, 1),
    "eval": slice(0, 1),
    "exec": slice(0, 1),
}
_NAMESPACE_CALLS: frozenset[str] = frozenset({"globals", "locals", "vars", "getmembers"})


class ClearedLabel(Protocol):
    """What `sanitized_reason` reads from a taint label (the engine's `TaintLabel`)."""

    @property
    def cleared(self) -> frozenset[int]: ...

    @property
    def sanitizers(self) -> tuple[str, ...]: ...


def is_request_hook(fn: FunctionInfo) -> bool:
    """True when a decorator registers `fn` as a request hook or error handler (`@app.errorhandler(404)`)."""
    return any(d.rsplit(".", 1)[-1] in REQUEST_HOOK_DECORATORS for d in fn.decorators)


def sanitized_reason(labels: Iterable[ClearedLabel], cwe: int) -> Optional[str]:
    """`sanitized:<names>` for the labels cleared for `cwe`, or None when no sanitiser name explains it."""
    names = sorted({name for label in labels if cwe in label.cleared for name in label.sanitizers})
    return SANITIZED_PREFIX + "+".join(names) if names else None


def unreachable_reason(cwe: int) -> Optional[str]:
    """The reason an unreachable function's finding gets, or None when it must not be suppressed."""
    return None if cwe == SECRET_CWE else UNREACHABLE


def unreachable_functions(index: ProjectIndex, routes: list[Route], graph: CallGraph) -> frozenset[str]:
    """Module-level functions no route handler can reach, by a deliberately conservative test (A-48).

    Empty when the project has no routes. A function is a candidate only when it is module-level,
    not a method, undecorated, not a dunder, and its name never appears anywhere in the project as a
    value reference, a name-like string, the leaf of a call that does not resolve to a project
    function or class, or the leaf of any call the call graph does not see (module or class level,
    lambdas, decorators, defaults). Everything else, plus every route handler, is a root; candidates
    the call graph reaches from a root (no depth cap) are not unreachable. Doubt means reachable, so
    the result is also empty when the project looks a name up at run time (A-52: `getattr` with a
    computed name, `globals()`/`locals()`/`vars()`, `__dict__`, `attrgetter`, `eval`/`exec`).
    """
    if not routes or _has_dynamic_lookup(index):
        return frozenset()
    referenced = _referenced_names(index)
    candidates = {qualname for qualname, fn in index.functions.items() if _is_candidate(fn, referenced)}
    if not candidates:
        return frozenset()
    seen = {qualname for qualname in index.functions if qualname not in candidates}
    seen.update(route.handler for route in routes)
    stack = sorted(seen)
    while stack:
        for callee in graph.get(stack.pop(), ()):
            if callee not in seen:
                seen.add(callee)
                stack.append(callee)
    return frozenset(candidates - seen)


# --------------------------------------------------------------------------- helpers
def _is_candidate(fn: FunctionInfo, referenced: set[str]) -> bool:
    return (
        fn.parent is None
        and not fn.is_method
        and not fn.decorators
        and not (fn.name.startswith("__") and fn.name.endswith("__"))
        and fn.name not in referenced
    )


def _referenced_names(index: ProjectIndex) -> set[str]:
    """Every name the project may reach a function through other than a resolved in-function call."""
    names: set[str] = set()
    graph_calls: set[int] = set()
    for fn in index.functions.values():
        types = local_types(index, fn)
        for call in own_calls(fn.node):
            graph_calls.add(id(call))
            target = index.resolve_call(call, fn.module, fn, types)
            if target not in index.functions and target not in index.classes:
                _add_leaf(names, call.func)
    for module in index.modules.values():
        call_funcs: set[int] = set()
        for node in ast.walk(module.tree):  # breadth-first: a call is seen before its `func`
            if isinstance(node, ast.Call):
                call_funcs.add(id(node.func))
                if id(node) not in graph_calls:
                    _add_leaf(names, node.func)
            elif isinstance(node, ast.Name):
                if isinstance(node.ctx, ast.Load) and id(node) not in call_funcs:
                    names.add(node.id)
            elif isinstance(node, ast.Attribute):
                if isinstance(node.ctx, ast.Load) and id(node) not in call_funcs:
                    names.add(node.attr)
            elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                text = node.value.strip()
                if _NAME_PATH.fullmatch(text):
                    names.update(_IDENTIFIER.findall(text))
    return names


def _has_dynamic_lookup(index: ProjectIndex) -> bool:
    """True when some module may reach a function through a name built at run time (A-52)."""
    for module in index.modules.values():
        callees = {id(node.func) for node in ast.walk(module.tree) if isinstance(node, ast.Call)}
        for node in ast.walk(module.tree):
            if isinstance(node, ast.Attribute) and node.attr == "__dict__":
                return True
            if isinstance(node, ast.Call) and _is_dynamic_lookup(node):
                return True
            # a lookup function passed as a value (`reduce(getattr, parts, mod)`): its arguments are unknown
            if (
                isinstance(node, (ast.Name, ast.Attribute))
                and isinstance(node.ctx, ast.Load)
                and _leaf(node) in _NAME_ARGS
                and id(node) not in callees
            ):
                return True
    return False


def _is_dynamic_lookup(call: ast.Call) -> bool:
    """A namespace call, or a name-lookup call whose name argument is not a string constant."""
    leaf = _leaf(call.func)
    if leaf in _NAMESPACE_CALLS:
        return True
    names = _NAME_ARGS.get(leaf or "")
    if names is None:
        return False
    if any(isinstance(arg, ast.Starred) for arg in call.args):
        return True
    return any(not (isinstance(arg, ast.Constant) and isinstance(arg.value, str)) for arg in call.args[names])


def _leaf(func: ast.expr) -> Optional[str]:
    if isinstance(func, ast.Attribute):
        return func.attr
    if isinstance(func, ast.Name):
        return func.id
    return None


def _add_leaf(names: set[str], func: ast.expr) -> None:
    if isinstance(func, ast.Attribute):
        names.add(func.attr)
    elif isinstance(func, ast.Name):
        names.add(func.id)
