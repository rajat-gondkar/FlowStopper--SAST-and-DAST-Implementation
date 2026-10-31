"""findings.md export for manual verification by judges (Owner: B, P5-B4; DECISIONS D-03).

`render_markdown(issues, meta)` is called by Dev A's api.py and pipeline.py; keep the name and
signature.
"""

from __future__ import annotations

from typing import Optional

from FlowStopper.correlate.issues import is_suppressed, sort_issues
from FlowStopper.models import Issue, Label


def _one_line(text: object) -> str:
    """Collapse whitespace so a value cannot break the Markdown line structure."""
    return " ".join(str(text).split())


def render_markdown(issues: list[Issue], meta: Optional[dict] = None) -> str:
    """Readable findings list, prioritised; `meta` is the content of scan_meta.json (may be None)."""
    meta = meta or {}
    ordered = sort_issues(issues)
    reported = [i for i in ordered if not is_suppressed(i)]
    suppressed = [i for i in ordered if is_suppressed(i)]
    counts = {label: sum(1 for i in reported if i.label is label) for label in Label}

    lines = ["# FlowStopper findings", ""]
    lines.append(f"- Target: {_one_line(meta.get('target') or 'unknown')}")
    lines.append(f"- Scan: {_one_line(meta.get('scan_id') or 'n/a')}")
    lines.append(
        f"- Reported: {len(reported)} ({counts[Label.CONFIRMED]} confirmed, {counts[Label.CODE_ONLY]} code only, "
        f"{counts[Label.RUNTIME_ONLY]} runtime only); suppressed: {len(suppressed)}"
    )
    lines.append("")
    for n, issue in enumerate(reported, 1):
        lines.append(
            f"{n}. **[{issue.label.value}] {_one_line(issue.title)}** - CWE-{issue.cwe}, "
            f"{issue.severity.value}, risk {issue.risk} (`{issue.id}`)"
        )
    return "\n".join(lines) + "\n"
