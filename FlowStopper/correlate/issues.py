"""Greedy one-to-one assignment, ambiguity rule, Issue construction, sort (Owner: B, P2-B6).
Also home of is_suppressed(issue) (DECISIONS D-12).
"""

from __future__ import annotations

from FlowStopper.models import Issue


def is_suppressed(issue: Issue) -> bool:
    """Derived state (DECISIONS D-12): an issue with no runtime findings whose code findings are
    all suppressed. Such issues sort last and never count as reported (B-2).
    """
    return bool(issue.code_findings) and not issue.runtime_findings and all(f.suppressed for f in issue.code_findings)
