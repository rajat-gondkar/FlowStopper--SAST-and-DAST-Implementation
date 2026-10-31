"""Reflected XSS check, CWE-79 (Owner: B, P1-B4). Payloads: spec Appendix B only (R4).

Sends a unique canary carrying raw `<`/`"`/`'`; reports only when the response is HTML and those raw
characters come back unencoded right after the canary. No JavaScript is ever executed.
"""

from __future__ import annotations

from FlowStopper.dast.checks.base import INJECTABLE, CheckContext, make_finding
from FlowStopper.dast.types import Endpoint, Param
from FlowStopper.models import Finding

CWE = 79


def _classify(body: str, canary: str, default: str) -> str:
    """Name the reflection context for the evidence line."""
    i = body.find(canary)
    before = body[:i].lower()
    if before.rfind("<script") > before.rfind("</script>"):
        return "script"
    return default


async def run(ctx: CheckContext, endpoint: Endpoint, param: Param) -> list[Finding]:
    if param.location not in INJECTABLE:
        return []
    canary = ctx.token()
    probes = [(f"{canary}<\"'>", "html_body"), (f'{canary}"onmouseover=x', "attribute")]
    for payload, context in probes:
        ex = await ctx.send(endpoint, param, payload)
        if "html" not in ex.response_headers.get("content-type", "").lower():
            continue
        marker = payload[len(canary)]  # '<' for the body probe, '"' for the attribute probe
        if canary + marker in ex.body:  # the raw char survived unencoded -> reflected XSS
            label = _classify(ex.body, canary, context)
            evidence = f"Canary {canary} reflected unencoded in the HTML response (context: {label})."
            return [
                make_finding(
                    endpoint,
                    param,
                    ex,
                    cwe_id=CWE,
                    rule_id="dast.xss.reflected",
                    proof="echo",
                    payload=payload,
                    evidence=evidence,
                    confidence=0.9,
                    title=f"Reflected XSS in parameter '{param.name}'",
                )
            ]
    return []
