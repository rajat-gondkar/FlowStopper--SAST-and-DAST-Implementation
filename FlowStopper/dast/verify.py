"""Second-canary + control re-test and per-(cwe, route, param) collapse (Owner: B, P2-B3).

Two independent jobs:

**Verification** - an active hit is only reported if it survives a re-test. We re-run the check,
which mints a *fresh canary* from the per-scan RNG, and require the bug to reproduce; then, where
the proof is not canary-bound, we send a **control** request with the benign value and require the
signal to be *absent*. That kills the two classic false-positive sources: a flaky one-off response,
and a page that always contains the pattern we match on.

Note on controls: for `marker`/`echo`/`file`-by-canary proofs the evidence contains a random token
only we could have introduced, so a benign control cannot exhibit it and the check is recorded as
not-applicable rather than silently "passed". Controls are applied where they genuinely discriminate
(SQL error strings, a password-file body, an off-site redirect).

**Collapse** - several payloads often prove the same bug. Findings are grouped by
`(cwe, route_id or path, param)`, the strongest proof is kept, and the rest are preserved in
`raw["other_payloads"]` so no evidence is lost.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Optional, Protocol

import httpx

from FlowStopper.dast.checks import redirect as redirect_check
from FlowStopper.dast.checks import sqli as sqli_check
from FlowStopper.dast.checks import traversal as traversal_check
from FlowStopper.dast.checks.base import CheckContext
from FlowStopper.dast.client import HttpExchange
from FlowStopper.dast.discovery import benign_value
from FlowStopper.dast.types import Endpoint, Param
from FlowStopper.models import Finding
from FlowStopper.scope import ScopeError

# Higher wins when collapsing: a reproduced marker/file read is stronger evidence than a
# statistical difference between two responses.
PROOF_STRENGTH: dict[str, int] = {
    "marker": 6,
    "file": 6,
    "error": 5,
    "redirect": 5,
    "echo": 4,
    "differential": 3,
    "header": 2,
}


class Check(Protocol):
    """A check module: `run(ctx, endpoint, param) -> list[Finding]`."""

    async def run(self, ctx: CheckContext, endpoint: Endpoint, param: Param) -> list[Finding]: ...


def _redirect_signal(ex: HttpExchange) -> bool:
    if not 300 <= ex.status < 400:
        return False
    host = redirect_check.redirect_host(ex.response_headers.get("location", ""))
    return host.endswith(".invalid")


# Signals that a *benign* value must NOT produce. Rules absent here have canary-bound proofs,
# where a control request cannot discriminate (see module docstring).
CONTROL_SIGNALS: dict[str, Callable[[HttpExchange], bool]] = {
    "dast.sqli.error": lambda ex: bool(sqli_check.SQL_ERRORS.search(ex.body)),
    "dast.sqli.status": lambda ex: ex.status >= 500,
    "dast.traversal.file": lambda ex: bool(traversal_check.PASSWD_RE.search(ex.body)),
    "dast.redirect.open": _redirect_signal,
}

# Rules whose check already sends its own benign control (and re-sends the proving payload) before it
# reports. A generic "benign value must not show the signal" control cannot discriminate a response
# *difference*, so reverify only records that the control happened inside the check (B-12).
SELF_CONTROLLED_RULES: frozenset[str] = frozenset({"dast.cmdi.differential"})


@dataclass
class VerifyOutcome:
    """Why a finding was kept or dropped - surfaced in `raw` and useful when triaging."""

    finding: Finding
    confirmed: bool
    reason: str
    second_payload: Optional[str] = None
    control_applied: bool = False


async def reverify(
    ctx: CheckContext,
    endpoint: Endpoint,
    param: Param,
    finding: Finding,
    check: Check,
) -> VerifyOutcome:
    """Re-test one finding with a fresh canary and (where meaningful) a benign control."""
    try:
        repeat = await check.run(ctx, endpoint, param)
    except (ScopeError, httpx.HTTPError) as exc:
        return VerifyOutcome(finding, False, f"re-test failed: {type(exc).__name__}")

    same = [f for f in repeat if f.cwe == finding.cwe]
    if not same:
        return VerifyOutcome(finding, False, "second canary did not reproduce the finding")
    second = same[0]

    if finding.rule_id in SELF_CONTROLLED_RULES:
        return VerifyOutcome(
            finding,
            True,
            "reproduced with a second canary; benign control checked inside the check",
            second.runtime.payload if second.runtime else None,
            control_applied=True,
        )

    predicate = CONTROL_SIGNALS.get(finding.rule_id)
    if predicate is None:
        return VerifyOutcome(
            finding,
            True,
            "reproduced with a second canary; control not applicable (proof is canary-bound)",
            second.runtime.payload if second.runtime else None,
        )

    control_value = param.value or benign_value(param.name)
    try:
        control = await ctx.send(endpoint, param, control_value)
    except (ScopeError, httpx.HTTPError) as exc:
        return VerifyOutcome(finding, False, f"control request failed: {type(exc).__name__}")
    if predicate(control):
        return VerifyOutcome(
            finding,
            False,
            "control request with a benign value shows the same signal - not caused by our payload",
            control_applied=True,
        )
    return VerifyOutcome(
        finding,
        True,
        "reproduced with a second canary and the benign control is clean",
        second.runtime.payload if second.runtime else None,
        control_applied=True,
    )


def _annotate(outcome: VerifyOutcome) -> Finding:
    raw = dict(outcome.finding.raw)
    raw["verification"] = {
        "reproduced": True,
        "second_payload": outcome.second_payload,
        "control_applied": outcome.control_applied,
        "detail": outcome.reason,
    }
    return outcome.finding.model_copy(update={"raw": raw})


async def verify_findings(
    ctx: CheckContext,
    endpoint: Endpoint,
    param: Param,
    findings: Sequence[Finding],
    check: Check,
) -> tuple[list[Finding], list[VerifyOutcome]]:
    """Verify every finding for one (endpoint, param). Returns (kept findings, all outcomes)."""
    kept: list[Finding] = []
    outcomes: list[VerifyOutcome] = []
    for finding in findings:
        outcome = await reverify(ctx, endpoint, param, finding, check)
        outcomes.append(outcome)
        if outcome.confirmed:
            kept.append(_annotate(outcome))
    return kept, outcomes


# --------------------------------------------------------------------------- collapse
def _group_key(f: Finding) -> tuple[int, str, str]:
    rt = f.runtime
    if rt is None:  # a code finding never reaches here, but keep the key total
        return (f.cwe, "", "")
    return (f.cwe, rt.route_id or rt.path, rt.param or "")


def _rank(f: Finding) -> tuple[int, float, str]:
    proof = f.runtime.proof if f.runtime else "header"
    return (PROOF_STRENGTH.get(proof, 0), f.confidence, f.rule_id)


def collapse(findings: Sequence[Finding]) -> list[Finding]:
    """One finding per (cwe, route_id|path, param): strongest proof wins, others kept in `raw`."""
    groups: dict[tuple[int, str, str], list[Finding]] = {}
    for f in findings:
        groups.setdefault(_group_key(f), []).append(f)

    out: list[Finding] = []
    for key in sorted(groups):
        members = sorted(groups[key], key=_rank, reverse=True)
        best, rest = members[0], members[1:]
        if not rest:
            out.append(best)
            continue
        raw = dict(best.raw)
        payloads = sorted({f.runtime.payload for f in rest if f.runtime and f.runtime.payload})
        existing = [p for p in raw.get("other_payloads", []) if isinstance(p, str)]
        raw["other_payloads"] = sorted(set(existing) | set(payloads))
        raw["collapsed_rules"] = sorted({f.rule_id for f in rest})
        raw["collapsed_proofs"] = sorted({f.runtime.proof for f in rest if f.runtime})
        out.append(best.model_copy(update={"raw": raw}))
    return sorted(
        out,
        key=lambda f: (
            f.cwe,
            f.runtime.path if f.runtime else "",
            f.runtime.param or "" if f.runtime else "",
            f.rule_id,
        ),
    )
