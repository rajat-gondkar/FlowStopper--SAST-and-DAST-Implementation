"""CI gate for `--fail-on <label>:<severity>` (Owner: B, P5-B2, bonus B-6).

`FlowStopper scan --fail-on confirmed:high` exits with GATE_EXIT_CODE when any reported
(non-suppressed) issue with that label has severity >= the threshold. The CLI wiring lives in
Dev A's pipeline/cli; this module only parses the spec and evaluates the gate.
"""

from __future__ import annotations

from FlowStopper.correlate.issues import SEVERITY_RANK, is_suppressed
from FlowStopper.models import Issue, Label, Severity

GATE_EXIT_CODE = 2

ANY_LABEL = "any"
GATE_LABELS: frozenset[str] = frozenset({*(label.value for label in Label), ANY_LABEL})


def parse_fail_on(spec: str) -> tuple[str, Severity]:
    """Parse "<confirmed|code_only|runtime_only|any>:<severity>" (case-insensitive).

    Returns (label, threshold) where label is a `Label` value or "any". Raises ValueError for
    anything else (missing colon, unknown label, unknown severity, extra parts).
    """
    if not isinstance(spec, str):
        raise ValueError(f"--fail-on must be a string like 'confirmed:high', got {spec!r}")
    parts = spec.strip().lower().split(":")
    if len(parts) != 2:
        raise ValueError(f"--fail-on must look like '<label>:<severity>', got {spec!r}")
    label, severity = (p.strip() for p in parts)
    if label not in GATE_LABELS:
        allowed = ", ".join(sorted(GATE_LABELS))
        raise ValueError(f"--fail-on label must be one of {allowed}; got {label!r}")
    try:
        threshold = Severity(severity)
    except ValueError:
        allowed = ", ".join(s.value for s in Severity)
        raise ValueError(f"--fail-on severity must be one of {allowed}; got {severity!r}") from None
    return label, threshold


def gate_tripped(issues: list[Issue], spec: str) -> bool:
    """True if any non-suppressed issue matches the label (or "any") with severity >= threshold.

    Raises ValueError (from `parse_fail_on`) for a malformed spec.
    """
    label, threshold = parse_fail_on(spec)
    limit = SEVERITY_RANK[threshold]
    for issue in issues:
        if is_suppressed(issue):
            continue
        if label != ANY_LABEL and issue.label.value != label:
            continue
        if SEVERITY_RANK.get(issue.severity, len(SEVERITY_RANK)) <= limit:
            return True
    return False
