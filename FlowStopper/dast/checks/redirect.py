"""Open redirect check, CWE-601 (Owner: B, P2-B1). Never follows the redirect.

Payloads point at `<canary>.invalid` - `.invalid` is an IANA-reserved TLD that can never resolve, so
no third-party host is ever contacted even in principle (R3/R4). A finding needs a 3xx **and** a
`Location` whose host is our canary; the redirect itself is never followed, so the scanner makes no
off-scope request.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from FlowStopper.dast.checks.base import INJECTABLE, CheckContext, make_finding
from FlowStopper.dast.types import Endpoint, Param
from FlowStopper.models import Finding

CWE = 601


def redirect_host(location: str) -> str:
    """Host a browser would navigate to for a `Location` value ("" if same-origin/relative).

    Backslashes are normalised to slashes and a run of leading slashes collapsed to two, so the
    `/\\host` and `///host` bypass forms resolve the way browsers treat them.
    """
    loc = location.strip().replace("\\", "/")
    if loc.startswith("//"):
        loc = "//" + loc.lstrip("/")
    try:
        return (urlsplit(loc).hostname or "").lower()
    except ValueError:
        return ""


async def run(ctx: CheckContext, endpoint: Endpoint, param: Param) -> list[Finding]:
    if param.location not in INJECTABLE:
        return []
    canary_host = f"{ctx.token()}.invalid"
    payloads = [f"//{canary_host}/", f"https://{canary_host}/", f"/\\{canary_host}", f"///{canary_host}"]

    for payload in payloads:
        ex = await ctx.send(endpoint, param, payload)  # follow=False by default: never followed
        if not 300 <= ex.status < 400:
            continue
        location = ex.response_headers.get("location", "")
        if redirect_host(location) == canary_host:
            evidence = (
                f"Open redirect on '{param.name}': payload {payload!r} produced HTTP {ex.status} "
                f"with Location {location!r}, pointing off-site to {canary_host} "
                "(redirect not followed)."
            )
            return [
                make_finding(
                    endpoint,
                    param,
                    ex,
                    cwe_id=CWE,
                    rule_id="dast.redirect.open",
                    proof="redirect",
                    payload=payload,
                    evidence=evidence,
                    confidence=0.9,
                    title=f"Open redirect in parameter '{param.name}'",
                    raw={"location": location, "status": ex.status},
                )
            ]
    return []
