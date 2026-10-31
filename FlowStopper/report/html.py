"""Self-contained HTML report (Owner: B, P5-B1). Escape all dynamic text (R7).

`render_html(issues, meta)` is called by Dev A's api.py and pipeline.py; keep the name and signature.
Templates live in FlowStopper/report/templates/ (package-data). Autoescape is always on, so every
value passed to a template is HTML-escaped unless a template explicitly marks it safe (none do).
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from jinja2 import Environment, FileSystemLoader, StrictUndefined

from FlowStopper.correlate.issues import is_suppressed, sort_issues
from FlowStopper.models import Issue, Label

TEMPLATES_DIR = Path(__file__).parent / "templates"
REPORT_TEMPLATE = "report.html"

_env = Environment(
    loader=FileSystemLoader(str(TEMPLATES_DIR)),
    autoescape=True,  # R7: every template here is HTML
    undefined=StrictUndefined,
    trim_blocks=True,
    lstrip_blocks=True,
    keep_trailing_newline=True,
)


def _label_counts(issues: list[Issue]) -> dict[str, int]:
    counts = {label.value: 0 for label in Label}
    for issue in issues:
        counts[issue.label.value] += 1
    return counts


def render_html(issues: list[Issue], meta: Optional[dict] = None) -> str:
    """Render the report page for `issues`; `meta` is the content of scan_meta.json (may be None)."""
    meta = meta or {}
    ordered = sort_issues(issues)
    reported = [i for i in ordered if not is_suppressed(i)]
    suppressed = [i for i in ordered if is_suppressed(i)]
    return _env.get_template(REPORT_TEMPLATE).render(
        meta=meta,
        reported=reported,
        suppressed=suppressed,
        counts=_label_counts(reported),
        total=len(reported),
    )
