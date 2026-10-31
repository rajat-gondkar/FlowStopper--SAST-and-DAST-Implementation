"""Link score and risk score (Owner: B, P2-B6 steps 3 and 6).

`score = 0.50*route + 0.35*param + 0.10*method + 0.05*specificity` (weights in CorrelateConfig).

The score is assembled from *named components* rather than one expression, because every component
has to be shown to the user as a `LinkReason` with its own weight (B-3). Deriving the total from the
same numbers the explanation prints keeps the two from ever drifting apart, and rounding to 4
decimals keeps float noise out of the stored `link_score`.

Specificity has no reason kind of its own in the frozen contract, so it is folded into the route
reason's weight and called out in that reason's text.
"""

from __future__ import annotations

from collections.abc import Sequence

from FlowStopper.correlate.config import CorrelateConfig
from FlowStopper.correlate.matcher import Candidate
from FlowStopper.models import Finding, Label, Route

ROUNDING = 4


def component_weights(cand: Candidate, config: CorrelateConfig) -> dict[str, float]:
    """Weighted contribution of each component. Keys match the reason kinds built by explain.py."""
    return {
        "route": round(config.w_route * cand.route_match + config.w_specificity * cand.specificity, ROUNDING),
        "param": round(config.w_param * cand.param_match, ROUNDING),
        "method": round(config.w_method * cand.method_match, ROUNDING),
    }


def link_score(cand: Candidate, config: CorrelateConfig) -> float:
    """Total link score: the sum of the component weights (so reasons always add up to it)."""
    return round(sum(component_weights(cand, config).values()), ROUNDING)


def risk_score(
    *,
    cvss: float,
    label: Label,
    runtime_findings: Sequence[Finding],
    route: Route | None,
    config: CorrelateConfig,
) -> float:
    """`clamp(cvss * exploitability_factor, 0, 10)` (spec P2-B6 step 6).

    Factors: authenticated route 0.85; proof is only a response difference 0.9; never observed at
    runtime 0.6; runtime-only with weak confidence 0.9.
    """
    factor = 1.0
    if route is not None and route.auth_required:
        factor *= config.factor_auth

    if label is Label.CODE_ONLY:
        factor *= config.factor_code_only
    else:
        proofs = {f.runtime.proof for f in runtime_findings if f.runtime}
        if proofs == {"differential"}:
            factor *= config.factor_differential_only
        if label is Label.RUNTIME_ONLY and runtime_findings:
            best = max(f.confidence for f in runtime_findings)
            if best < config.low_conf_threshold:
                factor *= config.factor_low_conf_runtime

    return round(min(max(cvss * factor, 0.0), 10.0), 2)
