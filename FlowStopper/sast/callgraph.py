"""Static call graph (Owner: A, P1-A3). Route.reachable_functions = BFS depth <= 4, cycle-safe.

Edges connect project functions by name resolution only (via `index.resolve_call`): direct calls,
method calls through `self`/`cls`/`super()`, calls on module-level instances, and calls on locals
whose class is tracked from a `name = SomeClass(...)` assignment. A call to a project class adds an
edge to its `__init__`. Dynamic or unresolved callees are ignored, never guessed (R7 / spec P1-A3).
"""

from __future__ import annotations

import ast
from typing import Optional

from FlowStopper.models import Route
from FlowStopper.sast.config import SastConfig
from FlowStopper.sast.index import FunctionInfo, ProjectIndex, iter_block

CallGraph = dict[str, list[str]]  # function qualname -> sorted callee qualnames (project functions)


def build_call_graph(index: ProjectIndex, config: Optional[SastConfig] = None) -> CallGraph:
    """Resolved call edges between project functions."""
    graph: CallGraph = {}
    for fn in index.functions.values():
        local_types = _local_types(index, fn)
        callees: set[str] = set()
        for call in _own_calls(fn.node):
            target = index.resolve_call(call, fn.module, fn, local_types)
            if target is None:
                continue
            if target in index.functions:
                callees.add(target)
            elif target in index.classes:
                init = index.find_method(target, "__init__")
                if init is not None:
                    callees.add(init)
        graph[fn.qualname] = sorted(callees)
    return graph


def reachable_functions(graph: CallGraph, start: str, max_depth: int) -> list[str]:
    """Project functions reachable from `start` within `max_depth` call hops (start excluded), sorted."""
    seen = {start}
    reached: set[str] = set()
    frontier = [start]
    for _ in range(max(max_depth, 0)):
        nxt: list[str] = []
        for node in frontier:
            for callee in graph.get(node, ()):
                if callee not in seen:
                    seen.add(callee)
                    reached.add(callee)
                    nxt.append(callee)
        if not nxt:
            break
        frontier = nxt
    return sorted(reached)


def annotate_reachable(index: ProjectIndex, routes: list[Route], config: Optional[SastConfig] = None) -> list[Route]:
    """Return copies of `routes` with `reachable_functions` filled from the call graph."""
    config = config or SastConfig()
    graph = build_call_graph(index, config)
    out: list[Route] = []
    for route in routes:
        reach = reachable_functions(graph, route.handler, config.max_call_depth) if route.handler in graph else []
        out.append(route.model_copy(update={"reachable_functions": reach}))
    return out


# --------------------------------------------------------------------------- helpers
def _local_types(index: ProjectIndex, fn: FunctionInfo) -> dict[str, str]:
    """Local variables assigned a project-class instance (`x = Service()` -> {"x": "...Service"})."""
    types: dict[str, str] = {}
    for stmt in iter_block(fn.node.body):
        if isinstance(stmt, ast.Assign) and isinstance(stmt.value, ast.Call):
            cls = index.resolve_expr(stmt.value.func, fn.module, fn)
            if cls in index.classes:
                for target in stmt.targets:
                    if isinstance(target, ast.Name):
                        types[target.id] = cls
    return types


def _own_calls(fn_node: ast.AST) -> list[ast.Call]:
    """Call nodes in a function's own scope (not inside nested defs/classes/lambdas)."""
    calls: list[ast.Call] = []
    body = getattr(fn_node, "body", [])
    for stmt in body:
        _collect_calls(stmt, calls)
    return calls


def _collect_calls(node: ast.AST, calls: list[ast.Call]) -> None:
    for child in ast.iter_child_nodes(node):
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        if isinstance(child, ast.Call):
            calls.append(child)
        _collect_calls(child, calls)
