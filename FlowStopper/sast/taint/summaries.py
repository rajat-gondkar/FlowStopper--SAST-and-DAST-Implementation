"""Interprocedural summaries + fixpoint (Owner: A, P2-A2).

Two phases (DECISIONS A-16):

1. `compute_summaries` walks every project function with *parametric* taint (formal parameter `i` is
   tainted) and records what each parameter reaches: the return value, and every sink - including
   sinks inside callees, so the summary is transitive. Functions are visited in reverse-topological
   order of the call graph and the whole pass repeats until nothing changes, capped at
   `config.fixpoint_max_iterations`; chains never revisit a function, so recursion terminates.
2. `analyse_taint` walks each route handler with a *seeded* environment (request reads and the
   handler's own signature parameters, A-14) and applies callee summaries at call sites. A
   parameter-to-sink hit becomes a finding **at the sink**, with
   `call_chain = [handler, ..., function_with_sink]`.

`source_param` is the earliest-read contributing label (A-12), `entry_routes` the routes whose
handler starts the flow (A-13), and findings that would share a `Finding.id` key are merged
deterministically. Parse only: nothing here imports or executes scanned code (R7).
"""

from __future__ import annotations

import ast
import logging
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field, replace
from typing import Optional

from FlowStopper.models import CodeLocation, ParamLocation, Route, TaintInfo
from FlowStopper.sast.callgraph import CallGraph, build_call_graph, local_types
from FlowStopper.sast.config import SastConfig
from FlowStopper.sast.index import FunctionInfo, ProjectIndex
from FlowStopper.sast.suppress import (
    UNREACHABLE,
    is_request_hook,
    sanitized_reason,
    unreachable_functions,
    unreachable_reason,
)
from FlowStopper.sast.taint.engine import (
    PARAM,
    REQUEST,
    UNTAINTED,
    CallEffect,
    CallSite,
    SinkReport,
    TaintEnv,
    TaintLabel,
    TaintValue,
    param_seed,
    source_value,
    walk_function,
)
from FlowStopper.sast.taint.sources import handler_param_sources
from FlowStopper.sast.templates import TemplateLookup

log = logging.getLogger(__name__)

SinkHit = SinkReport  # a summarised sink: the same record the engine reports

CONFIDENCE_FULL = 0.9  # a handler-rooted chain with a named source parameter
CONFIDENCE_PARTIAL = 0.7  # unknown parameter name, or routes found only by reachability


@dataclass
class TaintStats:
    """Counts the SAST runner copies into `SastResult.stats`; counts only, never timings (FR-6)."""

    functions_analysed: int = 0
    summary_iterations: int = 0
    request_hooks: int = 0
    unreachable_functions: int = 0


@dataclass(frozen=True)
class FunctionSummary:
    """What one project function does with its parameters (P2-A2)."""

    qualname: str
    returned: TaintValue = UNTAINTED
    param_to_sink: tuple[SinkHit, ...] = ()
    request_sinks: tuple[SinkHit, ...] = ()

    @property
    def param_to_return(self) -> frozenset[int]:
        """Formal parameter indices that reach the return value."""
        return frozenset(
            label.param_index for label in self.returned.labels if label.kind == PARAM and label.param_index is not None
        )

    @property
    def returns_constant_string(self) -> bool:
        return self.returned.is_constant_string


@dataclass(frozen=True)
class TaintFinding:
    """One taint finding, ready for the SAST runner to turn into a `Finding` (P2-A6)."""

    cwe: int
    rule_id: str
    title: str
    file: str
    line_start: int
    line_end: int
    function: Optional[str]
    confidence: float
    taint: TaintInfo
    suppressed: bool = False
    suppress_reason: Optional[str] = None
    raw: dict = field(default_factory=dict)


def compute_summaries(
    index: ProjectIndex,
    graph: Optional[CallGraph] = None,
    config: Optional[SastConfig] = None,
    *,
    templates: Optional[TemplateLookup] = None,
    stats: Optional[TaintStats] = None,
) -> dict[str, FunctionSummary]:
    """Parametric summary of every project function, iterated to a fixpoint (P2-A2).

    `stats`, when given, receives how many functions were summarised and how many passes it took.
    """
    cfg = config or SastConfig()
    graph = build_call_graph(index, cfg) if graph is None else graph
    order = _reverse_topological(graph, index.functions)
    summaries: dict[str, FunctionSummary] = {}
    iterations = 0
    converged = False
    for _ in range(max(cfg.fixpoint_max_iterations, 1)):
        iterations += 1
        changed = False
        for qualname in order:
            summary = _summarise(index, index.functions[qualname], summaries, cfg, templates)
            if summaries.get(qualname) != summary:
                summaries[qualname] = summary
                changed = True
        if not changed:
            converged = True
            break
    if not converged:  # summaries may be incomplete: say so instead of silently missing flows (A-41)
        log.warning(
            "taint summaries hit the fixpoint cap (fixpoint_max_iterations=%d) before converging on %d functions",
            cfg.fixpoint_max_iterations,
            len(order),
        )
    if stats is not None:
        stats.functions_analysed = len(summaries)
        stats.summary_iterations = iterations
    return summaries


def analyse_taint(
    index: ProjectIndex,
    routes: list[Route],
    graph: Optional[CallGraph] = None,
    templates: Optional[TemplateLookup] = None,
    config: Optional[SastConfig] = None,
    *,
    stats: Optional[TaintStats] = None,
) -> list[TaintFinding]:
    """Taint findings for every route handler, sorted by (file, line, cwe, rule_id).

    `templates` is the P2-A5 index: with it, a render call's unescaped keyword arguments are CWE-79
    sinks. `stats`, when given, receives the summary-pass counts for `SastResult.stats`.
    """
    cfg = config or SastConfig()
    graph = build_call_graph(index, cfg) if graph is None else graph
    summaries = compute_summaries(index, graph, cfg, templates=templates, stats=stats)
    by_handler: dict[str, list[Route]] = {}
    for route in routes:
        by_handler.setdefault(route.handler, []).append(route)

    findings: list[TaintFinding] = []
    for qualname in sorted(by_handler):
        handler = index.functions.get(qualname)
        if handler is None:
            continue
        ctx = index.context(handler.module, handler, local_types(index, handler))
        result = walk_function(
            ctx,
            handler,
            _handler_env(handler, by_handler[qualname]),
            cfg,
            hook=_SummaryHook(index, summaries, qualname),
            is_handler=True,
            templates=templates,
        )
        for report in result.reports:
            finding = _finding(report, routes)
            if finding is not None:
                findings.append(finding)

    # Request hooks (`@app.errorhandler(404)`, `@app.before_request`, ...): code-only entry points
    # with no route id of their own and no reachability fallback (A-46).
    hooks = sorted(q for q, fn in index.functions.items() if q not in by_handler and is_request_hook(fn))
    for qualname in hooks:
        hook_fn = index.functions[qualname]
        ctx = index.context(hook_fn.module, hook_fn, local_types(index, hook_fn))
        result = walk_function(
            ctx,
            hook_fn,
            {},
            cfg,
            hook=_SummaryHook(index, summaries, qualname),
            is_handler=True,
            templates=templates,
        )
        for report in result.reports:
            finding = _finding(report, routes, fallback=False)
            if finding is not None:
                findings.append(finding)

    # Functions no route can reach: their own sinks, kept as suppressed findings (A-48).
    unreachable = unreachable_functions(index, routes, graph)
    for qualname in sorted(unreachable):
        summary = summaries.get(qualname)
        if summary is None:
            continue
        for hit in (*summary.param_to_sink, *summary.request_sinks):
            if hit.chain == (qualname,) and unreachable_reason(hit.cwe) is not None:
                findings.append(_unreachable_finding(hit, index.functions[qualname]))
    if stats is not None:
        stats.request_hooks = len(hooks)
        stats.unreachable_functions = len(unreachable)
    return _merge(findings)


# --------------------------------------------------------------------------- phase 1
class _SummaryHook:
    """Applies callee summaries at a call site; the engine calls it for project functions."""

    def __init__(self, index: ProjectIndex, summaries: Mapping[str, FunctionSummary], caller: str) -> None:
        self.index = index
        self.summaries = summaries
        self.caller = caller

    def __call__(self, site: CallSite) -> Optional[CallEffect]:
        summary = self.summaries.get(site.callee)
        callee = self.index.functions.get(site.callee)
        if summary is None or callee is None:
            return CallEffect()  # not summarised yet: contributes nothing (monotone growth)
        actuals = _actuals(site, callee)
        return CallEffect(value=self._result(summary, actuals), reports=self._reports(summary, actuals))

    def _result(self, summary: FunctionSummary, actuals: Mapping[int, TaintValue]) -> TaintValue:
        labels: set[TaintLabel] = set()
        built = summary.returned.built
        for label in summary.returned.labels:
            if label.kind != PARAM:
                labels.add(label)
                continue
            actual = actuals.get(label.param_index) if label.param_index is not None else None
            if actual is None:
                continue
            built |= actual.built
            labels.update(actual.carry(label.cleared, label.sanitizers).labels)
        return TaintValue(
            labels=frozenset(labels),
            is_constant_string=summary.returned.is_constant_string,
            built=built,
            html_markup=summary.returned.html_markup,
        )

    def _reports(self, summary: FunctionSummary, actuals: Mapping[int, TaintValue]) -> tuple[SinkReport, ...]:
        out: list[SinkReport] = []
        for hit in summary.param_to_sink:
            if self.caller in hit.chain:
                continue  # recursion: the chain already passes through this function
            live, cleared, built = self._map_labels(hit, actuals)
            chain = (self.caller, *hit.chain)
            if hit.suppressed:  # already suppressed in the callee: keep its reason
                if live or cleared:
                    out.append(replace(hit, labels=live | cleared, built=hit.built | built, chain=chain))
            elif live:
                out.append(replace(hit, labels=live, built=hit.built | built, chain=chain))
            elif cleared:  # every caller label was sanitised for this CWE on the way (A-47)
                reason = sanitized_reason(cleared, hit.cwe)
                if reason is not None:
                    out.append(
                        replace(
                            hit,
                            labels=cleared,
                            built=hit.built | built,
                            chain=chain,
                            suppressed=True,
                            suppress_reason=reason,
                        )
                    )
        for hit in summary.request_sinks:
            if self.caller not in hit.chain:
                out.append(replace(hit, chain=(self.caller, *hit.chain)))
        return tuple(out)

    @staticmethod
    def _map_labels(
        hit: SinkHit, actuals: Mapping[int, TaintValue]
    ) -> tuple[frozenset[TaintLabel], frozenset[TaintLabel], frozenset[str]]:
        """The caller-side labels a parameter-to-sink hit stands for: (live, cleared for its CWE, built kinds)."""
        live: set[TaintLabel] = set()
        cleared: set[TaintLabel] = set()
        built: frozenset[str] = frozenset()
        for label in hit.labels:
            if label.kind != PARAM or label.param_index is None:
                continue
            actual = actuals.get(label.param_index)
            if actual is None:
                continue
            built |= actual.built
            for caller_label in actual.labels:
                carried = caller_label.carry(label.cleared, label.sanitizers)
                (cleared if hit.cwe in carried.cleared else live).add(carried)
        return frozenset(live), frozenset(cleared), built


def _summarise(
    index: ProjectIndex,
    fn: FunctionInfo,
    summaries: Mapping[str, FunctionSummary],
    config: SastConfig,
    templates: Optional[TemplateLookup] = None,
) -> FunctionSummary:
    ctx = index.context(fn.module, fn, local_types(index, fn))
    result = walk_function(
        ctx,
        fn,
        param_seed(fn),
        config,
        hook=_SummaryHook(index, summaries, fn.qualname),
        templates=templates,
    )
    return FunctionSummary(
        qualname=fn.qualname,
        returned=result.returned,
        param_to_sink=_hits(result.reports, PARAM),
        request_sinks=_hits(result.reports, REQUEST),
    )


def _hits(reports: Iterable[SinkReport], kind: str) -> tuple[SinkHit, ...]:
    """Reports restricted to labels of one kind, de-duplicated, shortest chain first."""
    best: dict[tuple, SinkHit] = {}
    for report in reports:
        labels = frozenset(label for label in report.labels if label.kind == kind)
        if not labels:
            continue
        hit = replace(report, labels=labels)
        key = (
            hit.cwe,
            hit.family,
            hit.token,
            hit.file,
            hit.line_start,
            hit.function,
            hit.suppressed,
            tuple(sorted(hit.built)),
            tuple(sorted(_label_key(label) for label in labels)),
        )
        current = best.get(key)
        if current is None or (len(hit.chain), hit.chain) < (len(current.chain), current.chain):
            best[key] = hit
    return tuple(sorted(best.values(), key=_hit_order))


def _reverse_topological(graph: CallGraph, nodes: Mapping[str, FunctionInfo]) -> list[str]:
    """Callees before callers (depth-first postorder, cycle-safe, deterministic)."""
    seen: set[str] = set()
    out: list[str] = []
    for root in sorted(nodes):
        if root in seen:
            continue
        seen.add(root)
        stack = [(root, iter(graph.get(root, ())))]
        while stack:
            node, callees = stack[-1]
            nxt = next(callees, None)
            if nxt is None:
                stack.pop()
                out.append(node)
            elif nxt not in seen and nxt in nodes:
                seen.add(nxt)
                stack.append((nxt, iter(graph.get(nxt, ()))))
    return out


def _actuals(site: CallSite, callee: FunctionInfo) -> dict[int, TaintValue]:
    """Argument values by formal parameter index (the receiver is parameter 0 of a bound method)."""
    params = callee.params
    bound = callee.is_method and not callee.is_staticmethod and isinstance(site.call.func, ast.Attribute)
    offset = 1 if bound else 0
    out: dict[int, TaintValue] = {}
    if offset and params:
        out[0] = site.receiver
    for position, value in enumerate(site.args):
        index = position + offset
        if index < len(params):
            out[index] = value
    for name, value in site.kwargs.items():
        if name in params:
            out[params.index(name)] = value
    return out


# --------------------------------------------------------------------------- phase 2
def _handler_env(handler: FunctionInfo, routes: list[Route]) -> TaintEnv:
    """Seed a handler's signature parameters from its routes' params (A-14)."""
    env: TaintEnv = {}
    for route in sorted(routes, key=lambda r: r.id):
        for name, ref in handler_param_sources(handler, route).items():
            if name not in env:
                env[name] = source_value(ref, handler.file, handler.line_start, handler.qualname)
    return env


def _finding(report: SinkReport, routes: list[Route], *, fallback: bool = True) -> Optional[TaintFinding]:
    """A finding for one handler-walk report.

    `fallback=False` (request hooks, A-46) never borrows route ids by reachability: a helper shared
    with a route must not take that route's id.
    """
    labels = sorted((label for label in report.labels if label.kind == REQUEST), key=lambda lbl: lbl.sort_key)
    if not labels:
        return None
    winner = labels[0]
    origin = report.chain[0] if report.chain else report.function
    entry_routes = sorted({route.id for route in routes if route.handler == origin})
    confidence = CONFIDENCE_FULL
    if not entry_routes and not fallback:
        confidence = CONFIDENCE_PARTIAL
    elif not entry_routes:  # no handler-rooted origin: fall back to reachability (A-13)
        entry_routes = sorted(
            {
                route.id
                for route in routes
                if report.function is not None
                and (report.function in route.reachable_functions or route.handler == report.function)
            }
        )
        confidence = CONFIDENCE_PARTIAL
    if winner.param_name is None:
        confidence = min(confidence, CONFIDENCE_PARTIAL)
    source_params = sorted({label.param_name for label in labels if label.param_name})
    taint = TaintInfo(
        source_param=winner.param_name,
        source_kind=winner.location_kind,
        source_location=CodeLocation(
            file=winner.file,
            line_start=winner.line,
            line_end=winner.line,
            function=winner.function,
        ),
        call_chain=list(report.chain),
        entry_routes=entry_routes,
        sanitizers_seen=list(report.sanitizers_seen),
    )
    return TaintFinding(
        cwe=report.cwe,
        rule_id=report.rule_id,
        title=report.title,
        file=report.file,
        line_start=report.line_start,
        line_end=report.line_end,
        function=report.function,
        confidence=confidence,
        taint=taint,
        suppressed=report.suppressed,
        suppress_reason=report.suppress_reason,
        raw={"source_params": source_params, "built": sorted(report.built), "html_markup": report.html_markup},
    )


def _unreachable_finding(hit: SinkHit, fn: FunctionInfo) -> TaintFinding:
    """A sink inside a function no route reaches: suppressed, code-only (A-48).

    An existing `safe:`/`sanitized:` reason wins over `unreachable`.
    """
    reason = hit.suppress_reason if hit.suppressed and hit.suppress_reason else UNREACHABLE
    requests = sorted((label for label in hit.labels if label.kind == REQUEST), key=lambda lbl: lbl.sort_key)
    winner = requests[0] if requests else None
    params = sorted(
        {
            fn.params[label.param_index]
            for label in hit.labels
            if label.kind == PARAM and label.param_index is not None and label.param_index < len(fn.params)
        }
    )
    source_location = None
    if winner is not None:
        source_location = CodeLocation(
            file=winner.file, line_start=winner.line, line_end=winner.line, function=winner.function
        )
    taint = TaintInfo(
        source_param=winner.param_name if winner is not None else None,
        source_kind=winner.location_kind if winner is not None else None,
        source_location=source_location,
        call_chain=[fn.qualname],
        entry_routes=[],
        sanitizers_seen=list(hit.sanitizers_seen),
    )
    report = replace(hit, suppressed=True, suppress_reason=reason)
    return TaintFinding(
        cwe=hit.cwe,
        rule_id=hit.rule_id,
        title=report.title,
        file=hit.file,
        line_start=hit.line_start,
        line_end=hit.line_end,
        function=hit.function,
        confidence=CONFIDENCE_PARTIAL,
        taint=taint,
        suppressed=True,
        suppress_reason=reason,
        raw={
            "source_params": sorted({label.param_name for label in requests if label.param_name}),
            "built": sorted(hit.built),
            "html_markup": hit.html_markup,
            "function_params": params,
        },
    )


def _merge(findings: Iterable[TaintFinding]) -> list[TaintFinding]:
    """One finding per `Finding.id` key: union the routes and sanitisers, keep the strongest chain.

    A live finding at a sink site `(file, function, line, cwe)` drops every suppressed finding at the
    same site (A-47), so a suppressed duplicate can never stand in for the live one downstream.
    """
    best: dict[tuple, TaintFinding] = {}
    for finding in findings:
        key = (finding.file, finding.function, finding.line_start, finding.cwe, finding.rule_id)
        current = best.get(key)
        best[key] = finding if current is None else _merge_two(current, finding)
    live_sites = {_site(f) for f in best.values() if not f.suppressed}
    kept = [f for f in best.values() if not f.suppressed or _site(f) not in live_sites]
    return sorted(kept, key=lambda f: (f.file, f.line_start, f.cwe, f.rule_id))


def _site(finding: TaintFinding) -> tuple:
    return (finding.file, finding.function, finding.line_start, finding.cwe)


def _merge_two(left: TaintFinding, right: TaintFinding) -> TaintFinding:
    if left.suppressed != right.suppressed:  # never union a live finding with a suppressed one (A-47)
        return right if left.suppressed else left
    primary, other = (left, right) if _rank(left) <= _rank(right) else (right, left)
    taint = primary.taint.model_copy(
        update={
            "entry_routes": sorted(set(left.taint.entry_routes) | set(right.taint.entry_routes)),
            "sanitizers_seen": sorted(set(left.taint.sanitizers_seen) | set(right.taint.sanitizers_seen)),
        }
    )
    raw = dict(primary.raw)
    raw["source_params"] = sorted(set(left.raw.get("source_params", [])) | set(right.raw.get("source_params", [])))
    raw["built"] = sorted(set(left.raw.get("built", [])) | set(right.raw.get("built", [])))
    raw["html_markup"] = bool(left.raw.get("html_markup")) or bool(right.raw.get("html_markup"))
    return replace(
        primary,
        confidence=max(left.confidence, right.confidence),
        taint=taint,
        suppressed=primary.suppressed,
        suppress_reason=primary.suppress_reason,
        raw=raw,
    )


def _rank(finding: TaintFinding) -> tuple:
    """A real finding beats a suppressed one, then higher confidence, then the shortest chain."""
    chain = tuple(finding.taint.call_chain)
    return (finding.suppressed, -finding.confidence, len(chain), chain)


def _hit_order(hit: SinkHit) -> tuple:
    return (hit.file, hit.line_start, hit.cwe, hit.family, hit.token, hit.chain, tuple(sorted(hit.built)))


def _label_key(label: TaintLabel) -> tuple:
    return (
        label.kind,
        label.file,
        label.line,
        label.function or "",
        label.param_name or "",
        _location_value(label.location_kind),
        -1 if label.param_index is None else label.param_index,
        label.is_container,
        tuple(sorted(label.cleared)),
        label.sanitizers,
    )


def _location_value(location: Optional[ParamLocation]) -> str:
    return location.value if location is not None else ""
