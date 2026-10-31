"""Correlator configuration (Owner: B, P2-B6). Tuned by the eval harness in P4-B2.

Spec names: LINK_MIN -> link_min, AMBIGUITY_MARGIN -> ambiguity_margin.
"""

from __future__ import annotations

from pydantic import BaseModel


class CorrelateConfig(BaseModel):
    # score = w_route*route_match + w_param*param_match + w_method*method_match + w_specificity*specificity
    w_route: float = 0.50
    w_param: float = 0.35
    w_method: float = 0.10
    w_specificity: float = 0.05
    link_min: float = 0.70
    ambiguity_margin: float = 0.10
    # route_match values (hard gate: 0 -> not a candidate)
    route_chain_origin: float = 1.0
    route_handler_span: float = 0.9
    route_reachable: float = 0.8
    # param_match when the SAST side has no source_param
    param_unknown: float = 0.5
    # risk = clamp(cvss * product(factors), 0, 10), rounded to 2 decimals
    factor_auth: float = 0.85
    factor_differential_only: float = 0.9
    factor_code_only: float = 0.6
    factor_low_conf_runtime: float = 0.9
    low_conf_threshold: float = 0.7  # runtime-only with confidence below this gets factor_low_conf_runtime
