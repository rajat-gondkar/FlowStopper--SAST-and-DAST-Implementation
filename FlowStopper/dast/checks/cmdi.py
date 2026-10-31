"""Command injection check, CWE-78 (Owner: B, P2-B1; differential mode P4 item 2, B-12).

Payloads: spec Appendix B only (R4).

**Marker mode.** Sends `echo <canary>$((A*B))X` behind each shell separator (`;`, `|`, `&&`, `$(...)`,
backticks, newline) and reports only when the response contains the **evaluated** product
`<canary><A*B>X`. A plain reflection of the payload can only ever echo back the unevaluated
`$((A*B))` text, so an arithmetic match proves a shell actually ran. The payload runs `echo` only -
nothing destructive, nothing persistent (R4).

**Differential mode** (lower confidence). Many sinks (`os.system`, `subprocess.call(..., shell=True)`)
run the shell but never echo its output, so no marker can come back. The *same* payloads still split
along shell semantics: after `;`, `|` or a newline the injected `echo` is the last command, so the
outcome (exit code, status text) becomes the echo's; `$(...)` and backticks only change the
*argument* of the original command, so that command fails or succeeds exactly as with the benign
value. We report only that exact split - separators agree with each other and differ from the
baseline, both substitutions match the baseline, the separator result reproduces and a benign
control matches the baseline - after stripping every reflection of the value from the body. A safe
handler that merely reacts to unusual characters changes for the substitution payloads too, so it
does not fit the pattern. `&&` is ignored: its outcome depends on whether the first command passed.
"""

from __future__ import annotations

import html
import json
from dataclasses import replace
from urllib.parse import quote

from FlowStopper.dast.baseline import Fingerprint
from FlowStopper.dast.checks.base import INJECTABLE, CheckContext, make_finding
from FlowStopper.dast.client import HttpExchange
from FlowStopper.dast.discovery import benign_value
from FlowStopper.dast.types import Endpoint, Param
from FlowStopper.models import Finding

CWE = 78
DIFFERENTIAL_CONFIDENCE = 0.7

# Indices into the payload list built in run().
_SEMICOLON, _PIPE, _AND, _DOLLAR, _BACKTICK, _NEWLINE = range(6)
_SEPARATORS = (_SEMICOLON, _PIPE, _NEWLINE)
_SUBSTITUTIONS = (_DOLLAR, _BACKTICK)


def _reflection_forms(value: str) -> list[str]:
    """The ways a reflected value commonly appears in a body: raw, JSON-escaped, HTML-escaped, URL-quoted."""
    forms = {value, json.dumps(value)[1:-1], html.escape(value), quote(value, safe="")}
    return sorted((f for f in forms if f), key=lambda f: (-len(f), f))


def _stripped_fp(ex: HttpExchange, values: list[str]) -> Fingerprint:
    """Fingerprint of `ex` with every reflection of `values` (in order) removed from the body."""
    body = ex.body
    for value in values:
        for form in _reflection_forms(value):
            body = body.replace(form, "")
    return Fingerprint.of(replace(ex, body=body))


def _fp_raw(fp: Fingerprint) -> dict:
    return {"status": fp.status, "hash": fp.body_hash}


async def _differential(
    ctx: CheckContext,
    endpoint: Endpoint,
    param: Param,
    orig: str,
    payloads: list[str],
    exchanges: list[HttpExchange],
) -> list[Finding]:
    baseline = await ctx.baseline(endpoint, param)
    if baseline.unstable:
        return []
    base_fp = _stripped_fp(baseline.sample, [orig])
    fps = [_stripped_fp(ex, [p, orig]) for p, ex in zip(payloads, exchanges, strict=True)]

    sep_fp = fps[_SEMICOLON]
    if any(fps[i] != sep_fp for i in _SEPARATORS):
        return []
    if sep_fp.status != base_fp.status or sep_fp.body_hash == base_fp.body_hash:
        return []
    if any(fps[i] != base_fp for i in _SUBSTITUTIONS):
        return []

    # Reproduce the separator result, then make sure the benign value still gives the baseline.
    again = await ctx.send(endpoint, param, payloads[_SEMICOLON])
    if _stripped_fp(again, [payloads[_SEMICOLON], orig]) != sep_fp:
        return []
    control = await ctx.send(endpoint, param, orig)
    if _stripped_fp(control, [orig]) != base_fp:
        return []

    evidence = (
        f"Shell semantics on '{param.name}' (no output echoed): the ';', '|' and newline payloads, which "
        f"make the injected echo the last command, all return the same response that differs from the "
        f"baseline, while the '$(...)' and backtick payloads, which only alter the argument, match the "
        f"baseline. The separator result reproduced and a benign control matched the baseline."
    )
    raw = {
        "mode": "differential",
        "baseline": _fp_raw(base_fp),
        "separator": {"payloads": [payloads[i] for i in _SEPARATORS], **_fp_raw(sep_fp)},
        "substitution": {"payloads": [payloads[i] for i in _SUBSTITUTIONS], **_fp_raw(fps[_DOLLAR])},
    }
    return [
        make_finding(
            endpoint,
            param,
            exchanges[_SEMICOLON],
            cwe_id=CWE,
            rule_id="dast.cmdi.differential",
            proof="differential",
            payload=payloads[_SEMICOLON],
            evidence=evidence,
            confidence=DIFFERENTIAL_CONFIDENCE,
            title=f"OS command injection in parameter '{param.name}' (blind, differential)",
            raw=raw,
        )
    ]


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
    # Order matters: the differential mode indexes this list (_SEMICOLON ... _NEWLINE).
    payloads = [
        f"{orig};{command}",
        f"{orig}|{command}",
        f"{orig}&&{command}",
        f"{orig}$({command})",
        f"{orig}`{command}`",
        f"{orig}\n{command}",
    ]
    exchanges: list[HttpExchange] = []
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
        exchanges.append(ex)
    return await _differential(ctx, endpoint, param, orig, payloads, exchanges)
