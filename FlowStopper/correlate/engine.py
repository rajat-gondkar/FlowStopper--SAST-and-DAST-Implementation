"""Correlation entry point (Owner: B, P2-B6). Cross-developer interface (spec section 6).

dedupe -> candidates (hard route gate) -> score -> greedy one-to-one assignment with the
ambiguity rule -> issues + labels -> risk -> deterministic sort.
Must reproduce fixtures/expected_issues.json from the other fixtures (see fixtures/README.md).
"""

from __future__ import annotations

from typing import Optional

from FlowStopper.correlate.config import CorrelateConfig
from FlowStopper.models import Finding, Issue, Route


def correlate(
    sast: list[Finding],
    dast: list[Finding],
    routes: list[Route],
    config: Optional[CorrelateConfig] = None,
) -> list[Issue]:
    """Merge SAST and DAST findings into a prioritised list of issues."""
    raise NotImplementedError("P2-B6: correlator not implemented yet")
