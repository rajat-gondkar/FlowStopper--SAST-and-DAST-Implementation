"""Candidate generation with the hard route gate (Owner: B, P2-B6 step 2).

A code finding and a runtime finding can only be linked if they are the same kind of bug *and* the
runtime route actually reaches the code. The route test is a **hard gate**: when it yields 0 the
pair is not a candidate at all, no matter how well the parameter names agree. That is the single
most important rule for keeping wrong links under control - "same CWE and same parameter name" is
otherwise very easy to satisfy by coincidence across a large app.

Strength of the route evidence, strongest first (spec P2-B6):
  1.0  the taint flow *originates* at that route's handler (`route_id in taint.entry_routes`)
  0.9  the sink sits inside the route handler's own line span
  0.8  the sink's function is merely reachable from the handler
  0.0  no relationship -> rejected
"""

from __future__ import annotations

import posixpath
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Optional

from FlowStopper import cwe as cwe_mod
from FlowStopper.correlate.config import CorrelateConfig
from FlowStopper.models import Finding, Route

# Route-evidence kinds, mapped to the LinkReason.kind values in models.py.
CHAIN_ORIGIN = "route_chain_origin"
HANDLER_SPAN = "route_handler_span"
REACHABLE = "route_reachable"


@dataclass(frozen=True)
class Candidate:
    """One possible link, with every component of its score kept for explanation."""

    code: Finding
    runtime: Finding
    route: Optional[Route]
    route_match: float
    route_kind: str
    param_match: float
    method_match: float
    specificity: float


def normalise_param(name: Optional[str]) -> str:
    """Case-insensitive, `[]` stripped, last segment of a dotted JSON path (spec P2-B6)."""
    if not name:
        return ""
    cleaned = name.strip().replace("[]", "")
    if "." in cleaned:
        cleaned = cleaned.rsplit(".", 1)[-1]
    return cleaned.lower()


def _same_file(a: str, b: str) -> bool:
    return posixpath.normpath(a.replace("\\", "/")).lstrip("/") == posixpath.normpath(b.replace("\\", "/")).lstrip("/")


def route_evidence(
    code: Finding, runtime: Finding, route: Optional[Route], config: CorrelateConfig
) -> tuple[float, str]:
    """The hard gate. Returns (route_match, reason kind); (0.0, "") means *not a candidate*."""
    if route is None:
        return 0.0, ""
    taint = code.taint
    if taint and route.id in taint.entry_routes:
        return config.route_chain_origin, CHAIN_ORIGIN
    loc = code.code
    if loc is not None and _same_file(loc.file, route.file) and route.line_start <= loc.line_start <= route.line_end:
        return config.route_handler_span, HANDLER_SPAN
    if loc is not None and loc.function and loc.function in route.reachable_functions:
        return config.route_reachable, REACHABLE
    return 0.0, ""


def param_evidence(code: Finding, runtime: Finding, config: CorrelateConfig) -> float:
    """1.0 equal names, 0.5 when SAST could not name the parameter, 0.0 when both known and different."""
    sast_param = normalise_param(code.taint.source_param if code.taint else None)
    dast_param = normalise_param(runtime.runtime.param if runtime.runtime else None)
    if not sast_param or not dast_param:
        return config.param_unknown
    return 1.0 if sast_param == dast_param else 0.0


def method_evidence(runtime: Finding, route: Optional[Route]) -> float:
    if route is None or runtime.runtime is None:
        return 0.0
    return 1.0 if runtime.runtime.method.upper() == route.method.upper() else 0.0


def specificity_of(code: Finding) -> float:
    """1.0 for a complete flow (a call chain *and* a named source parameter), else 0.5.

    A flow we cannot attribute to a named parameter is weaker evidence: it is exactly the case that
    produces ties between sibling sinks in one handler, so it must not score like a full chain.
    """
    taint = code.taint
    if taint and taint.call_chain and taint.source_param:
        return 1.0
    return 0.5


def generate_candidates(
    code_findings: Sequence[Finding],
    runtime_findings: Sequence[Finding],
    routes: Sequence[Route],
    config: Optional[CorrelateConfig] = None,
) -> list[Candidate]:
    """Every (code, runtime) pair that survives the family check and the route gate."""
    config = config or CorrelateConfig()
    routes_by_id = {r.id: r for r in routes}
    out: list[Candidate] = []
    for runtime in runtime_findings:
        rt = runtime.runtime
        if rt is None or runtime.suppressed:
            continue  # suppressed runtime findings never get linked either (B-15)
        route = routes_by_id.get(rt.route_id) if rt.route_id else None
        for code in code_findings:
            if code.suppressed or code.code is None:
                continue  # suppressed findings never get linked (B-2)
            if not cwe_mod.same_family(code.cwe, runtime.cwe):
                continue
            match, kind = route_evidence(code, runtime, route, config)
            if match <= 0:
                continue  # hard gate
            out.append(
                Candidate(
                    code=code,
                    runtime=runtime,
                    route=route,
                    route_match=match,
                    route_kind=kind,
                    param_match=param_evidence(code, runtime, config),
                    method_match=method_evidence(runtime, route),
                    specificity=specificity_of(code),
                )
            )
    return out
