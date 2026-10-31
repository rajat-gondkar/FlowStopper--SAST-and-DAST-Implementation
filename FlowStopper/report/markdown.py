"""findings.md export for manual verification by judges (Owner: B, P5-B4; DECISIONS D-03).

`render_markdown(issues, meta)` is called by Dev A's api.py and pipeline.py; keep the name and
signature.

Layout: header (target, scan, counts), a prioritised summary table, one section per reported issue
(label, severity/risk, CWE/OWASP, runtime proof, code location + snippet, why linked, reproduce, fix)
and the suppressed bucket with reasons. Scan data is untrusted: in prose, `<`, `>` and `&` are
entity-escaped so a Markdown renderer never sees raw HTML (R7); values in inline code and fenced
blocks are fenced with a delimiter longer than any backtick run they contain. Hard-coded secret
values are masked (B-22).
"""

from __future__ import annotations

import re
from typing import Optional

from FlowStopper.models import Issue
from FlowStopper.report import common


# --------------------------------------------------------------------------- escaping
def _text(value: object) -> str:
    """Prose: one line, HTML-significant characters and Markdown emphasis/link syntax neutralised."""
    s = " ".join(str(value).split())
    s = s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    # `_` is left alone: GitHub-flavoured Markdown never emphasises inside a word (db.find_user).
    return re.sub(r"([\\`*\[\]|])", r"\\\1", s)


def _code(value: object, cell: bool = False) -> str:
    """Inline code span that survives backticks in the value; `cell=True` also escapes `|` for tables."""
    s = " ".join(str(value).split())
    if cell:
        s = s.replace("|", "\\|")
    longest = max((len(m) for m in re.findall(r"`+", s)), default=0)
    fence = "`" * (longest + 1)
    pad = " " if s.startswith("`") or s.endswith("`") or longest else ""
    return f"{fence}{pad}{s}{pad}{fence}"


def _block(text: str, lang: str = "") -> list[str]:
    """Fenced code block that survives ``` inside the content."""
    longest = max((len(m) for m in re.findall(r"`{3,}", text)), default=0)
    fence = "`" * max(3, longest + 1)
    return [f"{fence}{lang}", *text.rstrip("\n").split("\n"), fence]


# --------------------------------------------------------------------------- sections
def _header(meta: dict, reported: list[Issue], suppressed: list[Issue]) -> list[str]:
    counts = common.label_counts(reported)
    lines = ["# FlowStopper findings", ""]
    lines.append(f"- **Target:** {_code(meta.get('target') or 'unknown')}")
    if meta.get("source"):
        lines.append(f"- **Source:** {_code(meta['source'])}")
    if meta.get("scan_id"):
        lines.append(f"- **Scan:** {_code(meta['scan_id'])}")
    if meta.get("started_at"):
        lines.append(f"- **Scanned:** {_text(meta['started_at'])}")
    total = (meta.get("timings_s") or {}).get("total")
    if isinstance(total, (int, float)):
        lines.append(f"- **Duration:** {total:.1f} s")
    if meta.get("truncated"):
        lines.append("- **Note:** the DAST time budget was reached; some runtime checks did not run.")
    lines.append(
        f"- **Reported:** {len(reported)} ({counts['confirmed']} confirmed, {counts['code_only']} code only, "
        f"{counts['runtime_only']} runtime only); **suppressed:** {len(suppressed)}"
    )
    return lines


def _summary(reported: list[Issue]) -> list[str]:
    lines = ["", "## Prioritised issues", ""]
    if not reported:
        return [*lines, "No reported issues."]
    lines += ["| # | Label | Severity | Risk | CWE | Issue | Location |", "|---|---|---|---|---|---|---|"]
    for n, issue in enumerate(reported, 1):
        where = common.issue_where(issue)
        lines.append(
            f"| {n} | {common.LABEL_TEXT[issue.label]} | {issue.severity.value} | {issue.risk:.1f} | "
            f"CWE-{issue.cwe} | [{_text(issue.title)}](#{_anchor(n)}) | {_code(where, cell=True) if where else ''} |"
        )
    return lines


def _anchor(n: int) -> str:
    return f"issue-{n}"


def _runtime(issue: Issue) -> list[str]:
    rt = issue.primary_runtime
    if rt is None:
        return []
    out = [f"- **Request:** {_code(f'{rt.method} {rt.url}')}"]
    if rt.param:
        where = f" in {rt.param_location.value}" if rt.param_location else ""
        out.append(f"- **Parameter:** {_code(rt.param)}{where}")
    if rt.payload:
        out.append(f"- **Payload:** {_code(rt.payload)}")
    out.append(f"- **Proof:** {_code(rt.proof)}")
    if rt.evidence:
        out.append(f"- **Evidence:** {_text(rt.evidence)}")
    return out


def _code_location(issue: Issue) -> list[str]:
    loc = issue.primary_code
    if loc is None:
        return []
    out = [f"- **Code:** {_code(common.code_where(loc))}" + (f" in {_code(loc.function)}" if loc.function else "")]
    for f in issue.code_findings:
        if f.taint is not None and f.taint.source_param and f.code == loc:
            src = f.taint.source_location
            at = f" (read at {_code(common.code_where(src))})" if src else ""
            out.append(f"- **Source parameter:** {_code(f.taint.source_param)}{at}")
            if len(f.taint.call_chain) > 1:
                out.append(f"- **Call chain:** {' -> '.join(_code(c) for c in f.taint.call_chain)}")
            break
    lines = common.snippet_lines(issue.cwe, loc)
    if lines:
        width = len(str(lines[-1].number))
        body = "\n".join(f"{'>' if ln.hot else ' '} {ln.number:>{width}} | {ln.text}" for ln in lines)
        out += ["", *_block(body)]
    return out


def _reasons(issue: Issue) -> list[str]:
    if not issue.reasons:
        return []
    title = "Why these were linked" if issue.label.value == "confirmed" else "Correlation notes"
    out = ["", f"**{title}:**", ""]
    for r in issue.reasons:
        out.append(f"- {_code(r.kind)} ({r.weight:+.2f}): {_text(r.detail)}")
    return out


def _fix(issue: Issue) -> list[str]:
    blocks = common.fix_blocks(common.fix_text(issue))
    if not blocks:
        return []
    out = ["", "**How to fix:**", ""]
    for kind, text in blocks:
        out += _block(text) if kind == "code" else [_text(text)]
        out.append("")
    return out[:-1]


def _detail(n: int, issue: Issue) -> list[str]:
    owasp = common.owasp_for(issue)
    lines = [
        "",
        f'<a id="{_anchor(n)}"></a>',
        "",
        f"### {n}. [{common.LABEL_TEXT[issue.label]}] {_text(issue.title)}",
        "",
        f"- **ID:** {_code(issue.id)}",
        f"- **Severity:** {issue.severity.value}, risk {issue.risk:.1f}/10 (CVSS {issue.cvss:.1f})",
        f"- **CWE:** [CWE-{issue.cwe}]({common.cwe_url(issue.cwe)}) {_text(common.cwe_name(issue.cwe))}"
        + (f"; **OWASP:** {_text(owasp)}" if owasp else ""),
    ]
    if issue.link_score is not None:
        lines.append(
            f"- **Link score:** {issue.link_score:.2f}"
            + (f", verified by {issue.verified_by}" if issue.verified_by else "")
        )
    lines += _runtime(issue)
    lines += _code_location(issue)
    lines += _reasons(issue)
    rt = issue.primary_runtime
    if rt is not None and rt.repro_curl:
        lines += ["", "**Reproduce:**", "", *_block(rt.repro_curl, "sh")]
    lines += _fix(issue)
    return lines


def _suppressed(suppressed: list[Issue]) -> list[str]:
    lines = ["", f"## Suppressed (safe / unreachable): {len(suppressed)}", ""]
    if not suppressed:
        return [*lines, "Nothing was suppressed."]
    lines += ["| Issue | CWE | Location | Why suppressed |", "|---|---|---|---|"]
    for issue in suppressed:
        reasons = "; ".join(
            f"{_code(r, cell=True)} {_text(common.explain_suppression(r))}" for r in common.suppress_reasons(issue)
        )
        where = common.issue_where(issue)
        location = _code(where, cell=True) if where else ""
        lines.append(f"| {_text(issue.title)} | CWE-{issue.cwe} | {location} | {reasons or 'no reason recorded'} |")
    return lines


def render_markdown(issues: list[Issue], meta: Optional[dict] = None) -> str:
    """Readable findings list, prioritised; `meta` is the content of scan_meta.json (may be None)."""
    meta = dict(meta or {})
    reported, suppressed = common.split_issues(issues)
    lines = _header(meta, reported, suppressed)
    lines += _summary(reported)
    if reported:
        lines += ["", "## Issue details"]
        for n, issue in enumerate(reported, 1):
            lines += _detail(n, issue)
    lines += _suppressed(suppressed)
    return "\n".join(lines).rstrip("\n") + "\n"
