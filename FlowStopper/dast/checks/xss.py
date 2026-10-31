"""Reflected XSS check, CWE-79 (Owner: B, P1-B4). Payloads: spec Appendix B only (R4).

Sends a unique canary carrying raw `<`/`"`/`'`; reports only when the response is HTML and those raw
characters come back unencoded right after the canary. No JavaScript is ever executed.

A reflection inside a 5xx debug traceback page is a symptom of the verbose-error finding the passive
pass already reports (CWE-209), not a separate injection sink, so it is returned suppressed at lower
confidence (DECISIONS_Dev2 B-15). A clean reflection from a later probe still wins.

`probe_unknown_path` is a host-wide variant: one GET to a random, non-existent path made of the same
Appendix B body canary, to catch an error (404) handler that echoes the request path unescaped. It
has no route and no parameter, so it is reported runtime-only (DECISIONS_Dev2 B-16).
"""

from __future__ import annotations

from urllib.parse import quote

import httpx

from FlowStopper import cwe as cwe_mod
from FlowStopper import ids
from FlowStopper.dast.checks.base import INJECTABLE, CheckContext, make_finding
from FlowStopper.dast.checks.passive import ERROR_MARKERS
from FlowStopper.dast.client import HttpExchange
from FlowStopper.dast.types import Endpoint, Param
from FlowStopper.models import Engine, Finding, RuntimeLocation
from FlowStopper.scope import ScopeError

CWE = 79
TRACEBACK_REASON = "dast:debug-traceback-reflection"
TRACEBACK_CONFIDENCE = 0.5
UNKNOWN_PATH_RULE = "dast.xss.unknown_path"
UNKNOWN_PATH_KEY = "<unknown-path>"  # stable id key for the unknown-path probe (its real path holds the canary)
UNKNOWN_PATH_CONFIDENCE = 0.8


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
    traceback_hit: Finding | None = None
    for payload, context in probes:
        ex = await ctx.send(endpoint, param, payload)
        if "html" not in ex.response_headers.get("content-type", "").lower():
            continue
        marker = payload[len(canary)]  # '<' for the body probe, '"' for the attribute probe
        if canary + marker in ex.body:  # the raw char survived unencoded -> reflected XSS
            label = _classify(ex.body, canary, context)
            evidence = f"Canary {canary} reflected unencoded in the HTML response (context: {label})."
            finding = make_finding(
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
            if ex.status >= 500 and ERROR_MARKERS.search(ex.body):
                if traceback_hit is None:
                    note = (
                        f" Reflected only inside a {ex.status} debug traceback page: a symptom of the"
                        " verbose-error finding (dast.passive.verbose-error, CWE-209), suppressed."
                    )
                    runtime = finding.runtime.model_copy(update={"evidence": evidence + note})
                    traceback_hit = finding.model_copy(
                        update={
                            "confidence": TRACEBACK_CONFIDENCE,
                            "suppressed": True,
                            "suppress_reason": TRACEBACK_REASON,
                            "runtime": runtime,
                        }
                    )
                continue  # a later probe may still show a genuine reflection
            return [finding]
    return [traceback_hit] if traceback_hit is not None else []


async def _unknown_path_exchange(ctx: CheckContext, base: str) -> tuple[str, str, HttpExchange | None, bool]:
    """GET `{base}/{canary<"'>}` (percent-encoded); returns (canary, payload, exchange, raw reflection)."""
    canary = ctx.token()
    payload = f"{canary}<\"'>"
    ctx.sent_payloads.append(payload)  # R4 audit: the Appendix B body canary, nothing else
    try:
        ex = await ctx.client.get(f"{base}/{quote(payload, safe='')}")
    except (ScopeError, httpx.HTTPError):
        return canary, payload, None, False
    html = "html" in ex.response_headers.get("content-type", "").lower()
    return canary, payload, ex, html and canary + "<" in ex.body


async def probe_unknown_path(ctx: CheckContext, base: str) -> list[Finding]:
    """One request to a non-existent path carrying the XSS canary; a hit is re-probed once.

    Sends exactly one request on a miss and two on a hit (the second with a fresh canary, P2-B3
    discipline). The finding has no route and no parameter. A reflection inside a 5xx debug
    traceback is returned suppressed, as in `run` (B-15).
    """
    base = base.rstrip("/")
    canary, payload, ex, hit = await _unknown_path_exchange(ctx, base)
    if ex is None or not hit:
        return []
    second_canary, second_payload, _, again = await _unknown_path_exchange(ctx, base)
    if not again:
        return []

    evidence = f"Canary {canary} in an unknown path reflected unescaped in the error page (status {ex.status})."
    suppressed = ex.status >= 500 and bool(ERROR_MARKERS.search(ex.body))
    if suppressed:
        evidence += (
            f" Reflected only inside a {ex.status} debug traceback page: a symptom of the verbose-error"
            " finding (dast.passive.verbose-error, CWE-209), suppressed."
        )
    rt = RuntimeLocation(
        method="GET",
        url=ex.url,
        path=ex.path,
        route_id=None,
        param=None,
        payload=payload,
        proof="echo",
        request=ex.request_text,
        response_excerpt=ex.response_excerpt,
        evidence=evidence,
        repro_curl=ex.repro_curl,
    )
    finding = Finding(
        # The path holds the per-scan canary, so it must not be in the id (FR-6: same id for any seed).
        id=ids.runtime_finding_id(Engine.DAST, UNKNOWN_PATH_RULE, CWE, "GET", UNKNOWN_PATH_KEY, None),
        engine=Engine.DAST,
        tool="FlowStopper-dast",
        rule_id=UNKNOWN_PATH_RULE,
        cwe=CWE,
        title="Reflected XSS in the error page for an unknown path",
        severity=cwe_mod.get_cwe(CWE).severity,
        confidence=TRACEBACK_CONFIDENCE if suppressed else UNKNOWN_PATH_CONFIDENCE,
        runtime=rt,
        raw={
            "verification": {
                "reproduced": True,
                "second_payload": second_payload,
                "control_applied": False,
                "detail": f"fresh canary {second_canary} also reflected unescaped",
            }
        },
    )
    if suppressed:
        finding = finding.model_copy(update={"suppressed": True, "suppress_reason": TRACEBACK_REASON})
    return [finding]
