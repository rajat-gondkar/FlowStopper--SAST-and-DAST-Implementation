"""Helpers shared by the HTML, SARIF and Markdown reports (Owner: B, Phase 5).

Everything here returns plain data (strings, tuples); escaping is the renderer's job (Jinja2
autoescape for HTML, R7). Nothing here is app-specific (R6).
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Optional

from FlowStopper import cwe as cwe_mod
from FlowStopper.correlate.issues import is_suppressed, sort_issues
from FlowStopper.models import CodeLocation, Issue, Label, Severity
from FlowStopper.report.fixes import fix_for

LABEL_TEXT: dict[Label, str] = {
    Label.CONFIRMED: "Confirmed",
    Label.CODE_ONLY: "Code only",
    Label.RUNTIME_ONLY: "Runtime only",
}

SEVERITY_ORDER: tuple[Severity, ...] = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
)


# --------------------------------------------------------------------------- partitioning
def split_issues(issues: Sequence[Issue]) -> tuple[list[Issue], list[Issue]]:
    """(reported, suppressed), each in canonical prioritised order (Confirmed first, then risk)."""
    ordered = sort_issues(issues)
    return [i for i in ordered if not is_suppressed(i)], [i for i in ordered if is_suppressed(i)]


def label_counts(issues: Sequence[Issue]) -> dict[str, int]:
    counts = {label.value: 0 for label in Label}
    for issue in issues:
        counts[issue.label.value] += 1
    return counts


def severity_counts(issues: Sequence[Issue]) -> dict[str, int]:
    counts = {sev.value: 0 for sev in SEVERITY_ORDER}
    for issue in issues:
        counts[issue.severity.value] += 1
    return counts


# --------------------------------------------------------------------------- CWE / OWASP
def cwe_name(cwe: int) -> str:
    entry = cwe_mod.CATALOGUE.get(cwe)
    return entry.name if entry else f"CWE-{cwe}"


def cwe_url(cwe: int) -> str:
    return f"https://cwe.mitre.org/data/definitions/{cwe}.html"


def owasp_for(issue: Issue) -> Optional[str]:
    if issue.owasp_2025:
        return issue.owasp_2025
    entry = cwe_mod.CATALOGUE.get(issue.cwe)
    return entry.owasp_2025 if entry else None


OWASP_URL = cwe_mod.OWASP_2025_URL


# --------------------------------------------------------------------------- secret masking (B-22)
SECRET_FAMILY = "hardcoded_secret"
MASK_KEEP = 2
MASK = "***"

# A quoted string literal (single or double quotes, optional Python string prefix). Non-greedy and
# escape-aware so `"a\"b"` is one literal.
_QUOTED = re.compile(r"""(?P<prefix>(?<!\w)[rRbBuUfF]{1,2})?(?P<q>['"])(?P<body>(?:\\.|(?!(?P=q)).)*)(?P=q)""")
# An unquoted `KEY = value` / `KEY: value` line (.env, .ini, YAML); comments are left alone.
_UNQUOTED = re.compile(
    r"^(?P<lead>\s*(?:export\s+)?[A-Za-z_][\w.\-]*\s*[=:]\s*)(?P<value>[^\s#'\"][^#]*?)(?P<tail>\s*)$"
)


def is_secret_cwe(cwe: int) -> bool:
    return cwe_mod.family_name(cwe) == SECRET_FAMILY


def mask_value(value: str) -> str:
    """Keep the first MASK_KEEP characters, replace the rest with MASK; short values are fully masked."""
    if len(value) <= MASK_KEEP:
        return MASK
    return value[:MASK_KEEP] + MASK


def mask_secret_line(line: str) -> str:
    """Mask every quoted literal on the line; else the value of an unquoted `KEY = value` line."""
    if line.lstrip().startswith(("#", ";", "//")):
        return line  # a comment: nothing assigned here
    masked, n = _QUOTED.subn(lambda m: f"{m['prefix'] or ''}{m['q']}{mask_value(m['body'])}{m['q']}", line)
    if n:
        return masked
    m = _UNQUOTED.match(line)
    if m and m["value"].strip():
        return f"{m['lead']}{mask_value(m['value'].strip())}{m['tail']}"
    return line


def mask_secret_text(text: str) -> str:
    return "\n".join(mask_secret_line(line) for line in text.split("\n"))


def display_snippet(cwe: int, snippet: str) -> str:
    """The snippet as the report shows it: hard-coded secret values masked (B-22)."""
    return mask_secret_text(snippet) if is_secret_cwe(cwe) else snippet


@dataclass(frozen=True)
class SnippetLine:
    number: int
    text: str
    hot: bool  # one of the offending lines (line_start..line_end)


def snippet_lines(cwe: int, loc: CodeLocation) -> list[SnippetLine]:
    """Number the snippet lines and mark the offending ones.

    SAST snippets carry one line of leading context unless the finding starts on line 1 (and up to
    12 lines in total); a snippet with no more lines than the finding spans has none.
    """
    lines = display_snippet(cwe, loc.snippet).splitlines()
    span = max(loc.line_end - loc.line_start + 1, 1)
    lead = 1 if len(lines) > span and loc.line_start > 1 else 0
    first = loc.line_start - lead
    return [SnippetLine(first + n, text, loc.line_start <= first + n <= loc.line_end) for n, text in enumerate(lines)]


# --------------------------------------------------------------------------- suppression reasons
TRACEBACK_REASON = "dast:debug-traceback-reflection"
_SAFE_TEXT = {
    "sql-parameterised": "the query is parameterised, so input is bound as data",
    "subprocess-list-no-shell": "subprocess runs an argument list without a shell",
    "subprocess-no-shell": "subprocess runs without a shell",
}


def suppress_reasons(issue: Issue) -> list[str]:
    """Distinct suppress_reason values of the issue's findings, sorted."""
    found = {f.suppress_reason for f in (*issue.code_findings, *issue.runtime_findings) if f.suppressed}
    return sorted(r for r in found if r)


def explain_suppression(reason: str) -> str:
    """Plain-English meaning of a suppress_reason code."""
    if reason.startswith("sanitized:"):
        names = reason[len("sanitized:") :].replace("+", ", ")
        return f"input passes through a sanitiser ({names}) before the sink"
    if reason.startswith("safe:"):
        pattern = reason[len("safe:") :]
        return _SAFE_TEXT.get(pattern, f"recognised safe pattern ({pattern})")
    if reason == "unreachable":
        return "the code is not reachable from any route"
    if reason == TRACEBACK_REASON:
        return "the payload is only reflected inside a debug traceback (5xx), reported as a verbose error instead"
    return reason


# --------------------------------------------------------------------------- locations
def code_where(loc: Optional[CodeLocation]) -> str:
    if loc is None:
        return ""
    lines = f"{loc.line_start}" if loc.line_end == loc.line_start else f"{loc.line_start}-{loc.line_end}"
    return f"{loc.file}:{lines}"


def issue_where(issue: Issue) -> str:
    """Short location for tables: file:line when there is code, else METHOD path (or host-wide)."""
    if issue.primary_code is not None:
        return code_where(issue.primary_code)
    rt = issue.primary_runtime
    if rt is None:
        return ""
    return f"{rt.method} {rt.route_id.split(' ', 1)[-1] if rt.route_id else rt.path}"


# --------------------------------------------------------------------------- fix text
_FENCE = re.compile(r"^```[\w+-]*\s*$")


def fix_text(issue: Issue) -> str:
    """The issue's fix suggestion; issues from an older issues.json (no `fix`) get one generated."""
    return issue.fix or fix_for(issue)


def fix_blocks(text: Optional[str]) -> list[tuple[str, str]]:
    """Split fix text into ("text", paragraph) and ("code", block) parts at ``` fences."""
    if not text:
        return []
    blocks: list[tuple[str, str]] = []
    buf: list[str] = []
    in_code = False

    def flush(kind: str) -> None:
        body = "\n".join(buf).strip("\n")
        if body.strip():
            if kind == "text":
                blocks.extend(("text", p.strip()) for p in re.split(r"\n\s*\n", body) if p.strip())
            else:
                blocks.append(("code", body))
        buf.clear()

    for line in text.split("\n"):
        if _FENCE.match(line.strip()):
            flush("code" if in_code else "text")
            in_code = not in_code
            continue
        buf.append(line)
    flush("code" if in_code else "text")
    return blocks
