"""Self-contained HTML report (Owner: B, P5-B1). Escape all dynamic text (R7).

`render_html(issues, meta)` is called by Dev A's api.py and pipeline.py; keep the name and signature.

One offline page: inline CSS only, no scripts, fonts, images or other external assets. Templates live
in FlowStopper/report/templates/ (package-data). Autoescape is always on and no template marks a
value safe, so every piece of scan data (payloads, evidence, snippets, titles, meta) is HTML-escaped.
Hard-coded secret values are masked in snippets (B-22).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from jinja2 import Environment, FileSystemLoader, StrictUndefined

from FlowStopper.models import CodeLocation, Finding, Issue, RuntimeLocation
from FlowStopper.report import common

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


@dataclass
class OtherFinding:
    """A finding merged into the issue besides the primary ones, for the "also seen" list."""

    engine: str
    rule_id: str
    where: str


@dataclass
class IssueView:
    issue: Issue
    rank: int
    anchor: str
    label_text: str
    where: str
    cwe_name: str
    cwe_url: str
    owasp: Optional[str]
    code: Optional[CodeLocation]
    snippet: list[common.SnippetLine]
    source: Optional[CodeLocation]
    source_param: Optional[str]
    call_chain: list[str]
    runtime: Optional[RuntimeLocation]
    fix: list[tuple[str, str]]
    others: list[OtherFinding] = field(default_factory=list)
    suppressions: list[tuple[str, str]] = field(default_factory=list)


def _finding_where(finding: Finding) -> str:
    if finding.code is not None:
        return common.code_where(finding.code)
    if finding.runtime is not None:
        rt = finding.runtime
        param = f" ({rt.param})" if rt.param else ""
        return f"{rt.method} {rt.url}{param}"
    return ""


def _others(issue: Issue) -> list[OtherFinding]:
    primary_code = issue.primary_code
    primary_rt = issue.primary_runtime
    out: list[OtherFinding] = []
    for f in issue.code_findings:
        if primary_code is not None and f.code == primary_code:
            continue
        out.append(OtherFinding(f.engine.value, f.rule_id, _finding_where(f)))
    for f in issue.runtime_findings:
        if primary_rt is not None and f.runtime == primary_rt:
            continue
        out.append(OtherFinding(f.engine.value, f.rule_id, _finding_where(f)))
    return out


def _taint(issue: Issue) -> tuple[Optional[CodeLocation], Optional[str], list[str]]:
    for f in issue.code_findings:
        if f.taint is not None and (f.code == issue.primary_code or issue.primary_code is None):
            return f.taint.source_location, f.taint.source_param, list(f.taint.call_chain)
    return None, None, []


def _view(issue: Issue, rank: int) -> IssueView:
    source, source_param, chain = _taint(issue)
    return IssueView(
        issue=issue,
        rank=rank,
        anchor=f"issue-{issue.id}",
        label_text=common.LABEL_TEXT[issue.label],
        where=common.issue_where(issue),
        cwe_name=common.cwe_name(issue.cwe),
        cwe_url=common.cwe_url(issue.cwe),
        owasp=common.owasp_for(issue),
        code=issue.primary_code,
        snippet=common.snippet_lines(issue.cwe, issue.primary_code) if issue.primary_code else [],
        source=source,
        source_param=source_param,
        call_chain=chain if len(chain) > 1 else [],
        runtime=issue.primary_runtime,
        fix=common.fix_blocks(common.fix_text(issue)),
        others=_others(issue),
        suppressions=[(r, common.explain_suppression(r)) for r in common.suppress_reasons(issue)],
    )


def _duration(meta: dict) -> Optional[str]:
    total = (meta.get("timings_s") or {}).get("total")
    if isinstance(total, (int, float)):
        return f"{total:.1f} s"
    return None


def render_html(issues: list[Issue], meta: Optional[dict] = None) -> str:
    """Render the report page for `issues`; `meta` is the content of scan_meta.json (may be None)."""
    meta = dict(meta or {})
    reported, suppressed = common.split_issues(issues)
    return _env.get_template(REPORT_TEMPLATE).render(
        meta=meta,
        duration=_duration(meta),
        version=(meta.get("versions") or {}).get("FlowStopper"),
        reported=[_view(i, n) for n, i in enumerate(reported, 1)],
        suppressed=[_view(i, n) for n, i in enumerate(suppressed, 1)],
        counts=common.label_counts(reported),
        severities=common.severity_counts(reported),
        total=len(reported),
        owasp_url=common.OWASP_URL,
    )
