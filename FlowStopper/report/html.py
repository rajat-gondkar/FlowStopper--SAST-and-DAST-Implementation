"""Self-contained HTML report (Owner: B, P5-B1; multi-tab redesign P6, B-27/B-28). Escape all dynamic text (R7).

`render_html(issues, meta)` is called by Dev A's api.py and pipeline.py; the name and the two positional
parameters stay. `eval_report` is an optional keyword-only addition (B-28): the JSON `FlowStopper eval
--out` writes. Only its counts, rates and run time are shown, never answer-key contents.

One offline page: inline CSS and inline SVG only, no scripts, fonts, images or other external assets.
Tabs are CSS-only and driven by the URL hash (B-27). Templates live in FlowStopper/report/templates/
(package-data). Autoescape is always on and no template marks a value safe, so every piece of scan data
(payloads, evidence, snippets, titles, meta) is HTML-escaped. Hard-coded secret values are masked in
snippets (B-22).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from jinja2 import Environment, FileSystemLoader, StrictUndefined

from FlowStopper.correlate.config import CorrelateConfig
from FlowStopper.models import CodeLocation, Finding, Issue, Label, RuntimeLocation
from FlowStopper.report import common

TEMPLATES_DIR = Path(__file__).parent / "templates"
REPORT_TEMPLATE = "report.html"
FIX_FIRST = 3  # issues shown as "Fix first" cards on the Overview tab
PROOF_LINE_MAX = 160  # characters of runtime evidence on a "Fix first" card

_env = Environment(
    loader=FileSystemLoader(str(TEMPLATES_DIR)),
    autoescape=True,  # R7: every template here is HTML
    undefined=StrictUndefined,
    trim_blocks=True,
    lstrip_blocks=True,
    keep_trailing_newline=True,
)

TABS: tuple[tuple[str, str], ...] = (
    ("overview", "Overview"),
    ("issues", "Issues"),
    ("evaluation", "Evaluation"),
    ("method", "Schema and method"),
    ("suppressed", "Suppressed"),
)


@dataclass
class OtherFinding:
    """A finding merged into the issue besides the primary ones, for the "also merged" list."""

    engine: str
    rule_id: str
    where: str


@dataclass
class IssueView:
    issue: Issue
    rank: int
    anchor: str
    label_text: str
    severity_text: str
    where: str
    endpoint: str  # "METHOD /path" of the runtime proof, "" when there is none
    code_where: str  # "file:line" of the code location, "" when there is none
    proof_line: str  # one sentence of proof for the "Fix first" cards
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


def _clip(text: str, limit: int) -> str:
    text = " ".join(text.split())
    if len(text) <= limit:
        return text
    cut = text[: limit - 1].rsplit(" ", 1)[0]
    return cut.rstrip(" ,;:") + "\u2026"


def _proof_line(issue: Issue) -> str:
    rt = issue.primary_runtime
    if rt is not None and rt.evidence:
        return _clip(rt.evidence, PROOF_LINE_MAX)
    if rt is not None:
        return f"{rt.proof.capitalize()} proof on {common.runtime_where(rt)}."
    if issue.primary_code is not None and issue.label is Label.CODE_ONLY:
        return f"Found in code at {common.code_where(issue.primary_code)}; not proven at runtime."
    return ""


def _view(issue: Issue, rank: int) -> IssueView:
    source, source_param, chain = _taint(issue)
    return IssueView(
        issue=issue,
        rank=rank,
        anchor=f"issue-{rank}",
        label_text=common.LABEL_TEXT[issue.label],
        severity_text=issue.severity.value.capitalize(),
        where=common.issue_where(issue),
        endpoint=common.runtime_where(issue.primary_runtime),
        code_where=common.code_where(issue.primary_code),
        proof_line=_proof_line(issue),
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
    if not isinstance(total, (int, float)) or isinstance(total, bool):
        return None
    if total < 60:
        return f"{total:.1f} s"
    minutes, seconds = divmod(round(total), 60)
    return f"{minutes} min {seconds} s"


# Month names spelled out here so the output never depends on the process locale (determinism).
_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")


def human_time(value: object) -> Optional[str]:
    """ISO-8601 timestamp from scan_meta as "31 Oct 2026, 21:47 UTC"; unparseable text is returned as-is.

    Uses only the given value, never the clock. A naive timestamp is taken to be UTC (storage writes UTC).
    """
    if not value:
        return None
    text = str(value)
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return text
    dt = dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)
    return f"{dt.day} {_MONTHS[dt.month - 1]} {dt.year}, {dt.hour:02d}:{dt.minute:02d} UTC"


def _top(reported: list[Issue]) -> Optional[Issue]:
    """The highest-risk reported issue (first in canonical order on ties)."""
    return max(reported, key=lambda i: i.risk) if reported else None


def _severity_segments(severities: dict[str, int], total: int) -> list[tuple[str, int, float]]:
    """(severity, count, percent of the bar) for each non-empty severity, in severity order."""
    if not total:
        return []
    return [(sev, n, round(n * 100 / total, 2)) for sev, n in severities.items() if n]


@dataclass(frozen=True)
class EvalView:
    """What the Evaluation tab shows. Built only from aggregate fields of the eval JSON (no key contents)."""

    present: bool
    rows: list[common.EvalRow]
    summary: str
    app: Optional[str]
    scan_id: Optional[str]
    evaluated: Optional[str]
    scan_mismatch: bool


def _eval_view(report: Optional[dict], meta: dict) -> EvalView:
    present = isinstance(report, dict) and isinstance(report.get("metrics"), dict)
    rows = common.eval_rows(report if present else None)
    source = report.get("source") if present and isinstance(report.get("source"), dict) else {}
    scan_id = source.get("scan_id") if isinstance(source.get("scan_id"), str) else None
    app = report.get("app") if present and isinstance(report.get("app"), str) else None
    meta_scan = meta.get("scan_id")
    return EvalView(
        present=present,
        rows=rows,
        summary=common.eval_summary(rows),
        app=app,
        scan_id=scan_id,
        evaluated=human_time(report.get("evaluated_at")) if present else None,
        scan_mismatch=bool(present and scan_id and meta_scan and scan_id != meta_scan),
    )


def render_html(issues: list[Issue], meta: Optional[dict] = None, *, eval_report: Optional[dict] = None) -> str:
    """Render the report page for `issues`.

    `meta` is the content of scan_meta.json (may be None). `eval_report` is the JSON written by
    `FlowStopper eval --out` (may be None: the Evaluation tab then says the scan was not evaluated).
    """
    meta = dict(meta or {})
    reported, suppressed = common.split_issues(issues)
    reported_views = [_view(i, n) for n, i in enumerate(reported, 1)]
    severities = common.severity_counts(reported)
    config = CorrelateConfig()
    return _env.get_template(REPORT_TEMPLATE).render(
        meta=meta,
        tabs=TABS,
        scanned=human_time(meta.get("started_at")),
        scanned_iso=str(meta.get("started_at") or ""),
        duration=_duration(meta),
        version=(meta.get("versions") or {}).get("FlowStopper"),
        reported=reported_views,
        fix_first=reported_views[:FIX_FIRST],
        suppressed=[_view(i, n) for n, i in enumerate(suppressed, 1)],
        counts=common.label_counts(reported),
        severities=severities,
        segments=_severity_segments(severities, len(reported)),
        top=_top(reported),
        total=len(reported),
        owasp_url=common.OWASP_URL,
        ev=_eval_view(eval_report, meta),
        label_definitions=[(common.LABEL_TEXT[k], k.value, v) for k, v in common.LABEL_DEFINITIONS.items()],
        severity_bands=[(s.value, s.value.capitalize(), band) for s, band in common.SEVERITY_BANDS],
        schema=[(m.__name__, common.schema_fields(m)) for m in common.SCHEMA_MODELS],
        rules=common.correlation_rules(config),
        risk_rules=common.risk_rules(config),
        link_min=config.link_min,
    )
