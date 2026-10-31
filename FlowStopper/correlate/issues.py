"""Greedy one-to-one assignment, ambiguity rule, Issue construction, sort (Owner: B, P2-B6).
Also home of is_suppressed(issue) (DECISIONS D-12).
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from dataclasses import field as dc_field
from typing import Optional

from FlowStopper import cwe as cwe_mod
from FlowStopper.correlate.config import CorrelateConfig
from FlowStopper.correlate.explain import ambiguity_reason
from FlowStopper.correlate.matcher import Candidate
from FlowStopper.correlate.scoring import link_score
from FlowStopper.models import Finding, Issue, Label, LinkReason, Severity

# Lower rank sorts first.
SEVERITY_RANK: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


def is_suppressed(issue: Issue) -> bool:
    """Derived state (DECISIONS D-12, extended by DECISIONS_Dev2 B-15): an issue with findings, every
    one of which (code and runtime) is suppressed. Such issues sort last and never count as reported
    (B-2). A Confirmed issue always holds an unsuppressed runtime finding, so it is never suppressed.
    """
    findings = [*issue.code_findings, *issue.runtime_findings]
    return bool(findings) and all(f.suppressed for f in findings)


def issue_sort_key(issue: Issue) -> tuple:
    """Canonical prioritised order (spec P2-B6 step 6, FR-9).

    Confirmed first, then risk descending, then severity, CWE and issue id so the list is fully
    deterministic. Suppressed issues always sink to the bottom (D-12).
    """
    return (
        0 if issue.label is Label.CONFIRMED else 1,
        1 if is_suppressed(issue) else 0,
        -issue.risk,
        SEVERITY_RANK.get(issue.severity, 9),
        issue.cwe,
        issue.id,
    )


def sort_issues(issues: Sequence[Issue]) -> list[Issue]:
    """Return the issues in canonical prioritised order."""
    return sorted(issues, key=issue_sort_key)


def reported_issues(issues: Sequence[Issue]) -> list[Issue]:
    """Issues that count as reported: everything except the suppressed bucket (B-2)."""
    return [i for i in issues if not is_suppressed(i)]


# --------------------------------------------------------------------------- assignment (P2-B6 step 4)
@dataclass
class Assignment:
    """Outcome of linking: accepted edges plus the penalties for deliberate non-links."""

    links: list[Candidate] = dc_field(default_factory=list)
    # finding id -> the ambiguity reason to attach to the issue built from that finding
    penalties: dict[str, LinkReason] = dc_field(default_factory=dict)


def _edge_order(cand: Candidate, config: CorrelateConfig) -> tuple:
    # Highest score first; ids break ties so the greedy pass never depends on input order.
    return (-link_score(cand, config), cand.code.id, cand.runtime.id)


def assign(candidates: Sequence[Candidate], config: Optional[CorrelateConfig] = None) -> Assignment:
    """Greedy one-to-one matching with the ambiguity rule.

    Edges are taken strongest-first; each code and runtime finding is used at most once. Before any
    edge is accepted we check, per runtime finding, whether its best two candidates are effectively
    tied (within `ambiguity_margin`) without the parameter name separating them. If so we link
    *neither* and record why - a missed link is cheaper than a wrong one (spec section 4).
    """
    config = config or CorrelateConfig()
    result = Assignment()

    by_runtime: dict[str, list[Candidate]] = {}
    for cand in candidates:
        by_runtime.setdefault(cand.runtime.id, []).append(cand)

    blocked: set[str] = set()
    for runtime_id, cands in by_runtime.items():
        ranked = sorted(cands, key=lambda c: _edge_order(c, config))
        best = ranked[0]
        best_score = link_score(best, config)
        if best_score < config.link_min or len(ranked) < 2:
            continue
        second = ranked[1]
        second_score = link_score(second, config)
        # Round the gap: scores are 4-decimal quantities, and in binary floating point a genuine
        # 0.10 gap (1.0 vs 0.9) computes as 0.0999...8, which would read as a tie and lose the link.
        if round(best_score - second_score, 4) >= config.ambiguity_margin:
            continue  # a clear winner
        if best.param_match > second.param_match:
            continue  # the parameter name separates them, so the winner is justified

        tied = [c for c in ranked if round(best_score - link_score(c, config), 4) < config.ambiguity_margin]
        rt = best.runtime.runtime
        reason = ambiguity_reason(
            (rt.route_id or rt.path) if rt else "?",
            rt.param if rt else None,
            tied,
            best_score,
            second_score,
        )
        blocked.add(runtime_id)
        result.penalties[runtime_id] = reason
        for cand in tied:
            result.penalties[cand.code.id] = reason

    used_code: set[str] = set()
    used_runtime: set[str] = set()
    for cand in sorted(candidates, key=lambda c: _edge_order(c, config)):
        if cand.runtime.id in blocked:
            continue
        if link_score(cand, config) < config.link_min:
            continue
        if cand.code.id in used_code or cand.runtime.id in used_runtime:
            continue
        used_code.add(cand.code.id)
        used_runtime.add(cand.runtime.id)
        result.links.append(cand)
    return result


# --------------------------------------------------------------------------- titles (P2-B6 step 5)
def _secret_identifier(finding: Finding) -> Optional[str]:
    """Pull the credential's name out of the SAST finding title, e.g. "... SECRET_KEY" -> SECRET_KEY.

    Generic by construction: the name comes from the scanned app's own data, never from a table in
    this package (R6).
    """
    match = re.search(r"([A-Za-z_][A-Za-z0-9_]*)\s*$", finding.title or "")
    return match.group(1) if match else None


def code_issue_title(finding: Finding) -> str:
    """Title for an issue that has a code location."""
    loc = finding.code
    assert loc is not None
    entry = cwe_mod.CATALOGUE.get(finding.cwe)
    name = entry.name if entry else f"CWE-{finding.cwe}"

    if cwe_mod.family_name(finding.cwe) == "hardcoded_secret":
        ident = _secret_identifier(finding)
        where = f"Hard-coded credential in {loc.file}"
        return f"{where} ({ident})" if ident else where

    where = loc.function or loc.file
    if finding.suppressed:
        return f"{name} in {where} (suppressed)"
    param = finding.taint.source_param if finding.taint else None
    suffix = f"(parameter '{param}')" if param else "(parameter unknown)"
    return f"{name} in {where} {suffix}"


def runtime_issue_title(finding: Finding) -> str:
    """Title for a runtime-only issue; host-wide findings keep the check's own wording."""
    rt = finding.runtime
    assert rt is not None
    entry = cwe_mod.CATALOGUE.get(finding.cwe)
    name = entry.name if entry else f"CWE-{finding.cwe}"
    if not rt.route_id:
        return f"{finding.title} (host-wide)"
    suffix = f" (parameter '{rt.param}')" if rt.param else ""
    return f"{name} at {rt.route_id}{suffix}"
