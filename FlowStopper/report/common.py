"""Helpers shared by the HTML, SARIF and Markdown reports (Owner: B, Phase 5).

Everything here returns plain data (strings, tuples); escaping is the renderer's job (Jinja2
autoescape for HTML, R7). Nothing here is app-specific (R6).
"""

from __future__ import annotations

import enum
import inspect
import re
import types
import typing
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal, Optional, Union

from pydantic import BaseModel

from FlowStopper import cwe as cwe_mod
from FlowStopper.correlate.config import CorrelateConfig
from FlowStopper.correlate.issues import is_suppressed, sort_issues
from FlowStopper.models import CodeLocation, Finding, Issue, Label, LinkReason, RuntimeLocation, Severity, TaintInfo
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

LABEL_DEFINITIONS: dict[Label, str] = {
    Label.CONFIRMED: "Found in the source code and proven against the running app, and the two were linked.",
    Label.CODE_ONLY: "Found in the source code; no runtime check proved it.",
    Label.RUNTIME_ONLY: "Proven against the running app; no matching code location was found.",
}

# CVSS 3.1 qualitative bands, as FlowStopper.cwe.severity_from_score applies them (spec section 8).
SEVERITY_BANDS: tuple[tuple[Severity, str], ...] = (
    (Severity.CRITICAL, "9.0-10.0"),
    (Severity.HIGH, "7.0-8.9"),
    (Severity.MEDIUM, "4.0-6.9"),
    (Severity.LOW, "0.1-3.9"),
    (Severity.INFO, "0.0"),
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


def runtime_where(rt: Optional[RuntimeLocation]) -> str:
    """`METHOD /path`, using the resolved route template when there is one."""
    if rt is None:
        return ""
    return f"{rt.method} {rt.route_id.split(' ', 1)[-1] if rt.route_id else rt.path}"


def issue_where(issue: Issue) -> str:
    """Short location for tables: file:line when there is code, else METHOD path (or host-wide)."""
    if issue.primary_code is not None:
        return code_where(issue.primary_code)
    return runtime_where(issue.primary_runtime)


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


# --------------------------------------------------------------------------- evaluation (Evaluation tab)
# PRD / build spec section 4 "Metrics": (good, great, higher_is_better). Rates are fractions, run
# time is seconds. Comparisons are strict, as the spec writes them (> 60%, < 20%). These are generic
# product targets, not app-specific; tests pin them to FlowStopper.evalkit.metrics.TARGETS.
TARGET_CODE_DETECTION = (0.60, 0.85, True)
TARGET_RUNTIME_DETECTION = (0.50, 0.80, True)
TARGET_CORRECT_LINKS = (0.50, 0.80, True)
TARGET_WRONG_LINKS = (0.20, 0.05, False)
TARGET_FALSE_ALARMS = (0.30, 0.10, False)
TARGET_UNSEEN_APP = (0.40, 0.65, True)  # correct-link rate on a second, unseen app
TARGET_RUN_TIME_S = (15 * 60.0, 5 * 60.0, False)

# (key in the eval JSON, display name, numerator field, denominator field, definition, targets)
EVAL_METRICS: tuple[tuple[str, str, str, str, str, tuple[float, float, bool]], ...] = (
    ("code_detection", "Code detection", "found", "total", "planted code bugs found by SAST", TARGET_CODE_DETECTION),
    (
        "runtime_detection",
        "Runtime detection",
        "found",
        "total",
        "planted runtime bugs found by DAST",
        TARGET_RUNTIME_DETECTION,
    ),
    (
        "correct_links",
        "Correct links",
        "found",
        "total",
        "planted code/runtime pairs merged into one Confirmed issue",
        TARGET_CORRECT_LINKS,
    ),
    (
        "wrong_links",
        "Wrong links",
        "count",
        "confirmed",
        "Confirmed issues that join two different planted bugs",
        TARGET_WRONG_LINKS,
    ),
    (
        "false_alarms",
        "False alarms",
        "count",
        "reported",
        "reported issues that overlap a known-safe decoy",
        TARGET_FALSE_ALARMS,
    ),
    ("unseen_app", "Unseen app", "found", "total", "correct-link rate on a second, unseen app", TARGET_UNSEEN_APP),
)
EVAL_METRIC_COUNT = len(EVAL_METRICS) + 1  # + run time
RUN_TIME_SCALE_S = 20 * 60.0  # the run-time bar spans 0-20 min so both targets fit on it

STATUS_TEXT = {"great": "Great", "good": "Good", "below": "Below Good", "not_measured": "Not measured"}


@dataclass(frozen=True)
class EvalRow:
    key: str
    name: str
    definition: str
    status: str  # great | good | below | not_measured
    value_text: str  # "76.9%" / "6.5 s" / "Not measured"
    count_text: str  # "10/13" or ""
    good_text: str  # ">60%"
    great_text: str  # ">85%"
    higher_is_better: bool
    value_pct: Optional[float]  # position on the bar, 0-100; None when not measured
    good_pct: float
    great_pct: float
    note: str = ""

    @property
    def status_text(self) -> str:
        return STATUS_TEXT[self.status]


def grade(value: float, good: float, great: float, higher_is_better: bool) -> str:
    """great / good / below, with the spec's strict comparisons (a value exactly on a line misses it)."""
    if higher_is_better:
        return "great" if value > great else "good" if value > good else "below"
    return "great" if value < great else "good" if value < good else "below"


def _number(value: object) -> Optional[float]:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


def _fmt_pct(value: float) -> str:
    return f"{value * 100:.1f}%".replace(".0%", "%")


def _fmt_seconds(seconds: float) -> str:
    return f"{seconds:.1f} s" if seconds < 120 else f"{seconds / 60:.1f} min"


def _target_text(threshold: float, higher: bool, *, seconds: bool = False) -> str:
    sign = ">" if higher else "<"
    return f"{sign}{threshold / 60:.0f} min" if seconds else f"{sign}{threshold * 100:.0f}%"


def _rate_row(
    key: str, name: str, num_key: str, den_key: str, definition: str, targets: tuple[float, float, bool], data: object
) -> EvalRow:
    good, great, higher = targets
    common_args = dict(
        key=key,
        name=name,
        definition=definition,
        good_text=_target_text(good, higher),
        great_text=_target_text(great, higher),
        higher_is_better=higher,
        good_pct=good * 100,
        great_pct=great * 100,
    )
    num = _number(data.get(num_key)) if isinstance(data, dict) else None
    den = _number(data.get(den_key)) if isinstance(data, dict) else None
    if num is None or den is None or den <= 0:
        note = "nothing to measure (empty denominator)" if den == 0 else ""
        if key == "unseen_app" and not isinstance(data, dict):
            note = "the Correct links rate of a scan of the held-out app; not part of this evaluation"
        return EvalRow(
            status="not_measured", value_text="Not measured", count_text="", value_pct=None, note=note, **common_args
        )
    rate = _number(data.get("rate"))
    rate = num / den if rate is None else rate
    return EvalRow(
        status=grade(rate, good, great, higher),
        value_text=_fmt_pct(rate),
        count_text=f"{num:.0f}/{den:.0f}",
        value_pct=max(0.0, min(rate * 100, 100.0)),
        **common_args,
    )


def eval_rows(report: Optional[dict]) -> list[EvalRow]:
    """One row per PRD metric from an eval JSON (`FlowStopper eval --out`). Only counts and rates are read.

    Missing or malformed values become "Not measured", never zero.
    """
    report = report if isinstance(report, dict) else {}
    metrics = report.get("metrics") if isinstance(report.get("metrics"), dict) else {}
    rows = [_rate_row(k, n, num, den, d, t, metrics.get(k)) for k, n, num, den, d, t in EVAL_METRICS]
    good, great, higher = TARGET_RUN_TIME_S
    seconds = _number(report.get("run_time_s"))
    time_args = dict(
        key="run_time",
        name="Run time",
        definition="scan + correlate + report",
        good_text=_target_text(good, higher, seconds=True),
        great_text=_target_text(great, higher, seconds=True),
        higher_is_better=higher,
        good_pct=good / RUN_TIME_SCALE_S * 100,
        great_pct=great / RUN_TIME_SCALE_S * 100,
    )
    if seconds is None or seconds < 0:
        rows.append(
            EvalRow(status="not_measured", value_text="Not measured", count_text="", value_pct=None, **time_args)
        )
    else:
        rows.append(
            EvalRow(
                status=grade(seconds, good, great, higher),
                value_text=_fmt_seconds(seconds),
                count_text="",
                value_pct=min(seconds / RUN_TIME_SCALE_S * 100, 100.0),
                **time_args,
            )
        )
    return rows


def eval_summary(rows: Sequence[EvalRow]) -> str:
    """Counts per status, e.g. "5 of 7 at Great, 1 at Good, 0 below Good, 1 not measured"."""
    n = {s: sum(1 for r in rows if r.status == s) for s in STATUS_TEXT}
    return (
        f"{n['great']} of {len(rows)} at Great, {n['good']} at Good, "
        f"{n['below']} below Good, {n['not_measured']} not measured"
    )


# --------------------------------------------------------------------------- schema (Schema and method tab)
# Meanings for every field of the shared models. The field names and types are read from the pydantic
# models at render time; tests fail if a field is added to a model without a meaning here.
FIELD_MEANINGS: dict[str, dict[str, str]] = {
    "Finding": {
        "id": "Stable hash of engine, rule, CWE and location; the same bug gets the same id on every scan.",
        "engine": "Which half found it: SAST (source code) or DAST (running app).",
        "tool": "The FlowStopper component that produced it.",
        "rule_id": "The detection rule that fired.",
        "cwe": "CWE number of the weakness.",
        "title": "One-line description.",
        "severity": "CVSS 3.1 severity band of the CWE.",
        "confidence": "How sure the rule is, from 0 to 1.",
        "code": "Where in the source code (SAST findings).",
        "runtime": "The request that proved it against the running app (DAST findings).",
        "taint": "Data flow from an HTTP parameter to the dangerous call (SAST injection findings).",
        "suppressed": "True when the finding was judged safe or unreachable.",
        "suppress_reason": "Machine code for why it was suppressed.",
        "raw": "Rule-specific extra data.",
    },
    "CodeLocation": {
        "file": "POSIX path relative to the source root.",
        "line_start": "First offending line.",
        "line_end": "Last offending line.",
        "function": "Qualified name of the enclosing function.",
        "snippet": "The offending lines (at most 12).",
    },
    "RuntimeLocation": {
        "method": "HTTP method sent.",
        "url": "Full URL requested.",
        "path": "Path only, without the query string.",
        "route_id": "The matching route from the route map, when known.",
        "param": "Parameter that carried the payload.",
        "param_location": "Where the parameter was sent.",
        "payload": "The harmless test value that was sent.",
        "proof": "Kind of proof observed in the response.",
        "request": "Raw HTTP request text, with credentials redacted.",
        "response_excerpt": "First part of the response (at most 2 KB).",
        "evidence": "One-line human explanation of the proof.",
        "repro_curl": "A curl command that reproduces it.",
    },
    "TaintInfo": {
        "source_param": "HTTP parameter that feeds the dangerous call.",
        "source_kind": "Where that parameter comes from.",
        "source_location": "Where the parameter is read in the code.",
        "call_chain": "Functions from the route handler down to the dangerous call.",
        "entry_routes": "Routes from which this flow is reachable.",
        "sanitizers_seen": "Sanitisers the data passes through.",
    },
    "LinkReason": {
        "kind": "Machine name of the evidence.",
        "detail": "Human-readable explanation.",
        "weight": "Contribution to the link score.",
    },
    "Issue": {
        "id": "Stable fingerprint of the issue.",
        "cwe": "CWE number.",
        "title": "One-line description.",
        "label": "Confirmed, Code only or Runtime only.",
        "severity": "CVSS 3.1 severity band.",
        "cvss": "CVSS 3.1 base score of the CWE.",
        "risk": "Priority score from 0 to 10 (see Risk score).",
        "code_findings": "SAST findings merged into this issue.",
        "runtime_findings": "DAST findings merged into this issue.",
        "primary_code": "The code location shown first.",
        "primary_runtime": "The runtime proof shown first.",
        "link_score": "Score of the code-runtime link (Confirmed only).",
        "reasons": "Evidence for the link, or why no link was made.",
        "verified_by": "What proved it at runtime: the DAST run or a targeted auto-verify probe.",
        "fix": "Suggested fix.",
        "owasp_2025": "OWASP Top 10:2025 category.",
        "first_seen_scan": "First scan that reported this issue.",
        "last_seen_scan": "Latest scan that reported this issue.",
    },
}
SCHEMA_MODELS: tuple[type[BaseModel], ...] = (Finding, CodeLocation, RuntimeLocation, TaintInfo, Issue, LinkReason)

_PRIMITIVE_NAMES = {str: "string", int: "integer", float: "number", bool: "boolean", dict: "object"}


def type_text(annotation: object) -> str:
    """A short, JSON-flavoured type name for a model field annotation."""
    if annotation is type(None):
        return "null"
    origin = typing.get_origin(annotation)
    args = typing.get_args(annotation)
    if origin in (Union, types.UnionType):
        return " | ".join(type_text(a) for a in args)
    if origin is Literal:
        return " | ".join(f'"{a}"' for a in args)
    if origin is list:
        return f"list[{type_text(args[0])}]" if args else "list"
    if origin is dict:
        return "object"
    if inspect.isclass(annotation):
        if issubclass(annotation, enum.Enum):
            return " | ".join(f'"{m.value}"' for m in annotation)
        if issubclass(annotation, BaseModel):
            return annotation.__name__
        if annotation in _PRIMITIVE_NAMES:
            return _PRIMITIVE_NAMES[annotation]
    return str(annotation)


@dataclass(frozen=True)
class SchemaField:
    name: str
    type: str
    required: bool
    meaning: str


def schema_fields(model: type[BaseModel]) -> list[SchemaField]:
    """Field, type and meaning for each field of `model`, in declaration order."""
    meanings = FIELD_MEANINGS[model.__name__]
    out = []
    for name, info in model.model_fields.items():
        text = type_text(info.annotation)
        bounds = [str(getattr(m, attr)) for m in info.metadata for attr in ("ge", "le") if hasattr(m, attr)]
        if len(bounds) == 2:
            text += f" ({bounds[0]}-{bounds[1]})"
        out.append(SchemaField(name, text, info.is_required(), meanings[name]))
    return out


# --------------------------------------------------------------------------- correlation rules
def _w(x: float) -> str:
    return f"{x:.2f}"


def correlation_rules(config: Optional[CorrelateConfig] = None) -> list[tuple[str, str]]:
    """The correlator's rules in plain words, with the numbers read from its configuration."""
    c = config or CorrelateConfig()
    return [
        (
            "Same kind of weakness",
            "A code finding and a runtime finding are only compared when their CWEs belong to the same family "
            "(for example both SQL injection).",
        ),
        (
            "Route gate",
            "The runtime request must hit a route that leads to the code: the taint flow starts in that route's "
            f"handler (route match {_w(c.route_chain_origin)}), the code sits inside the handler "
            f"({_w(c.route_handler_span)}), or the code is reachable from it ({_w(c.route_reachable)}). "
            "No route match, no link.",
        ),
        (
            "Link score",
            f"score = {_w(c.w_route)} x route match + {_w(c.w_param)} x same parameter + {_w(c.w_method)} x same "
            f"HTTP method + {_w(c.w_specificity)} x route specificity. When the code side names no parameter, the "
            f"parameter match counts {_w(c.param_unknown)}.",
        ),
        ("Threshold", f"A pair is linked into a Confirmed issue only when its score is at least {_w(c.link_min)}."),
        (
            "One to one, strongest first",
            "Pairs are accepted from the highest score down; each finding is used in at most one link.",
        ),
        (
            "Ambiguity rule",
            f"If a runtime finding's two best candidates are within {_w(c.ambiguity_margin)} of each other and the "
            "parameter name does not separate them, neither is linked. A missed link is cheaper than a wrong one.",
        ),
    ]


def risk_rules(config: Optional[CorrelateConfig] = None) -> list[str]:
    c = config or CorrelateConfig()
    return [
        "risk = CVSS base score x the factors below, clamped to 0-10.",
        f"Route requires login: x {c.factor_auth:g}.",
        f"Proof is only a response difference: x {c.factor_differential_only:g}.",
        f"Never observed at runtime (Code only): x {c.factor_code_only:g}.",
        f"Runtime only with confidence below {c.low_conf_threshold:g}: x {c.factor_low_conf_runtime:g}.",
    ]
