"""Path traversal check, CWE-22 (Owner: B, P2-B1). Payloads: spec Appendix B only (R4).

Read-only probe for one benign, universally present file (`/etc/passwd`); a finding needs the
response to match `root:[x*!]*:0:0:`, either verbatim or after HTML-entity decoding (an app that
echoes the file through an HTML encoder still discloses it). Nothing is written, nothing outside that single path is
requested. The pre-encoded `..%2f` variant is spliced verbatim into the query string or path segment
so the target receives the encoding the payload is actually testing (docs/DECISIONS_Dev2.md B-03, B-11).
"""

from __future__ import annotations

import html
import re
from typing import Optional

from FlowStopper.dast.checks.base import INJECTABLE, CheckContext, make_finding
from FlowStopper.dast.discovery import benign_value
from FlowStopper.dast.types import Endpoint, Param
from FlowStopper.models import Finding, ParamLocation

CWE = 22

# Appendix B proof: the first line of a real /etc/passwd.
PASSWD_RE = re.compile(r"root:[x*!]*:0:0:")


def passwd_match(body: str) -> Optional[re.Match[str]]:
    """The passwd proof in `body`, as sent or with HTML character references decoded."""
    m = PASSWD_RE.search(body)
    if m is None and "&" in body:
        m = PASSWD_RE.search(html.unescape(body))
    return m


# (payload, send-with-raw-query) - Appendix B catalogue, read-only.
PAYLOADS: tuple[tuple[str, bool], ...] = (
    ("../../../../../../etc/passwd", False),
    ("....//....//....//etc/passwd", False),
    ("..%2f..%2f..%2f..%2fetc%2fpasswd", True),
    ("/etc/passwd", False),
)


async def run(ctx: CheckContext, endpoint: Endpoint, param: Param) -> list[Finding]:
    if param.location not in INJECTABLE:
        return []
    _ = param.value or benign_value(param.name)

    # A benign page that already contains the passwd pattern makes attribution impossible.
    baseline = await ctx.baseline(endpoint, param)
    if passwd_match(baseline.sample.body):
        return []

    for payload, raw_query in PAYLOADS:
        # the pre-encoded form can only be sent verbatim in a query string or a path segment; skip it
        # elsewhere (a form/JSON body would re-encode it)
        if raw_query and param.location not in (ParamLocation.QUERY, ParamLocation.PATH):
            continue
        ex = await ctx.send(endpoint, param, payload, raw_query=raw_query)
        m = passwd_match(ex.body)
        if m:
            evidence = (
                f"Path traversal on '{param.name}': payload {payload!r} returned a system password "
                f"file (matched {m.group(0)!r}); the baseline response does not contain it."
            )
            return [
                make_finding(
                    endpoint,
                    param,
                    ex,
                    cwe_id=CWE,
                    rule_id="dast.traversal.file",
                    proof="file",
                    payload=payload,
                    evidence=evidence,
                    confidence=0.9,
                    title=f"Path traversal in parameter '{param.name}'",
                    raw={"matched": m.group(0)},
                )
            ]
    return []
