"""B-3 link explanations: LinkReason list per issue (Owner: B, P4-B3).

Every linked issue must be auditable: a reviewer should be able to read why two findings were
joined, and why two others were *not*. Each reason carries the weight it contributed, and the
weights sum to the issue's `link_score` by construction (see scoring.component_weights).
"""

from __future__ import annotations

from collections.abc import Sequence

from FlowStopper import cwe as cwe_mod
from FlowStopper.correlate.config import CorrelateConfig
from FlowStopper.correlate.matcher import CHAIN_ORIGIN, HANDLER_SPAN, Candidate
from FlowStopper.correlate.scoring import component_weights
from FlowStopper.models import LinkReason


def _specificity_note(cand: Candidate, config: CorrelateConfig) -> str:
    kind = "full taint chain" if cand.specificity >= 1.0 else "partial taint chain"
    return f"({kind}, +{round(config.w_specificity * cand.specificity, 4)} specificity)"


UNKNOWN = "unknown"


def _quoted(name: str | None) -> str:
    """`'name'` for a known name, the bare word `unknown` otherwise (never `'None'` or `?`)."""
    return f"'{name}'" if name else UNKNOWN


def _route_id(cand: Candidate) -> str:
    if cand.route is not None and cand.route.id:
        return cand.route.id
    rt = cand.runtime.runtime
    if rt is not None and rt.route_id:
        return rt.route_id
    return f"{UNKNOWN} route"


def _route_detail(cand: Candidate, config: CorrelateConfig) -> str:
    note = _specificity_note(cand, config)
    route_id = _route_id(cand)
    handler = cand.route.handler if cand.route and cand.route.handler else f"{UNKNOWN} handler"
    if cand.route_kind == CHAIN_ORIGIN:
        return f"taint flow originates at handler {handler} for route {route_id} {note}"
    loc = cand.code.code
    where = f"{loc.file}:{loc.line_start}" if loc else f"{UNKNOWN} location"
    if cand.route_kind == HANDLER_SPAN:
        return f"sink at {where} lies inside the handler span of route {route_id} {note}"
    function = loc.function if loc and loc.function else where
    return f"function {function} is reachable from handler {handler} for route {route_id} {note}"


def _param_detail(cand: Candidate) -> str:
    sast = cand.code.taint.source_param if cand.code.taint else None
    dast = cand.runtime.runtime.param if cand.runtime.runtime else None
    if cand.param_match >= 1.0:
        return f"DAST param {_quoted(dast)} == SAST source param {_quoted(sast)}"
    if not sast or not dast:
        side = "SAST could not name the source parameter" if not sast else "DAST did not name the parameter"
        return f"{side} (DAST used {_quoted(dast)}, SAST source param {_quoted(sast)}); partial credit"
    return f"DAST param {_quoted(dast)} != SAST source param {_quoted(sast)}"


def link_reasons(cand: Candidate, config: CorrelateConfig) -> list[LinkReason]:
    """Reasons for one accepted link, in a fixed order; weights sum to the link score."""
    weights = component_weights(cand, config)
    family = cwe_mod.family_name(cand.code.cwe)
    reasons = [
        LinkReason(
            kind="same_cwe",
            detail=(f"SAST CWE-{cand.code.cwe} and DAST CWE-{cand.runtime.cwe} are in the same family ({family})"),
            weight=0.0,
        ),
        LinkReason(kind=cand.route_kind, detail=_route_detail(cand, config), weight=weights["route"]),
        LinkReason(kind="same_param", detail=_param_detail(cand), weight=weights["param"]),
    ]
    method = cand.runtime.runtime.method if cand.runtime.runtime and cand.runtime.runtime.method else UNKNOWN
    route_method = cand.route.method if cand.route and cand.route.method else UNKNOWN
    detail = (
        f"DAST method {method} == route method {route_method}"
        if weights["method"] > 0
        else f"DAST method {method} != route method {route_method}"
    )
    reasons.append(LinkReason(kind="same_method", detail=detail, weight=weights["method"]))
    return reasons


def auto_verified_reason(
    check_name: str,
    route_id: str | None,
    param: str | None,
    proof: str | None,
    payload: str | None,
) -> LinkReason:
    """The reason attached when auto-verify (P4-B4) confirms a Code-only finding at runtime.

    Weight is 0.0: it records *how* the finding was confirmed, not a link component, so the
    weight-sum == link_score invariant of the other reasons still holds.
    """
    detail = (
        f"auto-verified: DAST check {check_name or UNKNOWN} re-tested route {route_id or f'{UNKNOWN} route'} "
        f"param {_quoted(param)} with payload {repr(payload) if payload else UNKNOWN} and observed {proof or UNKNOWN} proof"
    )
    return LinkReason(kind="auto_verified", detail=detail, weight=0.0)


def ambiguity_reason(
    runtime_key: str,
    param: str | None,
    tied: Sequence[Candidate],
    best: float,
    second: float,
) -> LinkReason:
    """The reason recorded on every issue left unlinked by the ambiguity rule.

    Weight is the forfeited link score, negative, so a reader can see what the conservative choice
    cost: we would rather report two separate issues than assert a link we cannot justify.
    """
    functions = sorted({c.code.code.function or c.code.code.file for c in tied if c.code.code})
    detail = (
        f"not linked: runtime finding {runtime_key} param '{param}' matches {len(tied)} code findings "
        f"in {', '.join(functions)} equally ({best:.2f} vs {second:.2f})"
    )
    if all(not (c.code.taint and c.code.taint.source_param) for c in tied):
        detail += " and the SAST source param is unknown"
    return LinkReason(kind="ambiguity_penalty", detail=detail, weight=-round(best, 2))
