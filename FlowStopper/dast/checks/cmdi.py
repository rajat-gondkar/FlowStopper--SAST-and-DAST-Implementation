"""Command injection check, CWE-78 (Owner: B, P2-B1). Payloads: spec Appendix B only (R4).

Sends `echo <canary>$((A*B))X` behind each shell separator (`;`, `|`, `&&`, `$(...)`, backticks,
newline) and reports only when the response contains the **evaluated** product `<canary><A*B>X`.
That distinction is the whole point: a plain reflection of the payload can only ever echo back the
unevaluated `$((A*B))` text, so an arithmetic match proves a shell actually ran. The payload runs
`echo` only - nothing destructive, nothing persistent (R4).
"""

from __future__ import annotations

from FlowStopper.dast.checks.base import INJECTABLE, CheckContext, make_finding
from FlowStopper.dast.discovery import benign_value
from FlowStopper.dast.types import Endpoint, Param
from FlowStopper.models import Finding

CWE = 78


async def run(ctx: CheckContext, endpoint: Endpoint, param: Param) -> list[Finding]:
    if param.location not in INJECTABLE:
        return []
    orig = param.value or benign_value(param.name)
    canary = ctx.token()
    a, b = ctx.small_ints()
    expr = f"$(({a}*{b}))"
    command = f"echo {canary}{expr}X"
    marker = f"{canary}{a * b}X"  # the evaluated form we require as proof

    # Appendix B separators. Each keeps the original value intact so the handler still works.
    payloads = [
        f"{orig};{command}",
        f"{orig}|{command}",
        f"{orig}&&{command}",
        f"{orig}$({command})",
        f"{orig}`{command}`",
        f"{orig}\n{command}",
    ]
    for payload in payloads:
        ex = await ctx.send(endpoint, param, payload)
        if marker in ex.body:
            evidence = (
                f"Shell execution proved on '{param.name}': the response contains the evaluated "
                f"marker {marker!r} ({a}*{b}={a * b}); a plain reflection could only echo the "
                f"literal {expr!r}."
            )
            return [
                make_finding(
                    endpoint,
                    param,
                    ex,
                    cwe_id=CWE,
                    rule_id="dast.cmdi.marker",
                    proof="marker",
                    payload=payload,
                    evidence=evidence,
                    confidence=0.9,
                    title=f"OS command injection in parameter '{param.name}'",
                    raw={"marker": marker, "expression": expr},
                )
            ]
    return []
