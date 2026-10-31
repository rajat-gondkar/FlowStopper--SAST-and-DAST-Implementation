"""Section 4 metrics with Appendix C matching rules (Owner: B, P1-B5).

Must reproduce fixtures/expected_metrics.json from fixtures/expected_issues.json + answer_key.json.

Definitions (spec section 4), all computed from a correlated Issue list vs an answer key:
- code detection    = planted code-located vulns a SAST finding matches / planted code-located vulns
- runtime detection = planted runtime-located vulns a DAST finding matches / planted runtime vulns
- correct links     = planted pairs whose code+runtime both land in one Confirmed issue / planted pairs
- wrong links       = Confirmed issues joining two different planted bugs (or a decoy) / Confirmed issues
- false alarms      = reported (non-suppressed) issues whose code overlaps a decoy / reported issues

Matching rules (spec Appendix C):
- code match: same normalised relative file, same CWE family, finding line range overlaps
  [line_start-3, line_end+3].
- runtime match: same CWE family; method equal (or key method omitted); the finding's concrete path
  matches the key path template (<...>/{...} are wildcards; "*" matches any/host-wide); param equal
  when the key names one.

Exact-match precedence (decision B-14): the +/-3 fuzz can make a decoy's window cover a genuine
planted vuln a few lines away. A code finding that exactly matches a planted vuln (same file + CWE
family, overlapping the planted range with no fuzz) is therefore not counted against a decoy unless it
also overlaps that decoy's own unfuzzed range (exact-vs-exact stays a false alarm, the pessimistic
choice). The same rule decides which decoys a finding joins in the wrong-link count, so the two never
disagree. Detection matching and LINE_FUZZ are unchanged.

Detection counts any matching finding, suppressed or not (suppression is a reporting decision, not a
detection one); false alarms and links look only at reported / Confirmed issues.
"""

from __future__ import annotations

import posixpath
import re

from FlowStopper import cwe
from FlowStopper.correlate.issues import is_suppressed
from FlowStopper.evalkit.keyschema import AnswerKey, KeyDecoy, KeyRuntime
from FlowStopper.models import Finding, Issue, Label

LINE_FUZZ = 3  # Appendix C: overlap against [line_start-3, line_end+3]
_TOKEN = re.compile(r"[<{][^<>{}]*[>}]")  # <int:id>, <path:p>, {id}, {id:path}


# --------------------------------------------------------------------------- path + line helpers
def _norm_path(path: str) -> str:
    """Normalise a relative POSIX path for comparison (separators, ./, leading /)."""
    if not path:
        return ""
    collapsed = posixpath.normpath(path.replace("\\", "/"))
    return "" if collapsed == "." else collapsed.lstrip("/")


def _ranges_overlap(a_start: int, a_end: int, b_start: int, b_end: int) -> bool:
    return a_start <= b_end and a_end >= b_start


def _path_regex(template: str) -> re.Pattern[str]:
    """Compile a path template into an anchored regex. `<...>`/`{...}` become wildcards
    (`.+` for path converters, else `[^/]+`); a trailing slash is tolerated.
    """
    out: list[str] = []
    i = 0
    for m in _TOKEN.finditer(template):
        out.append(re.escape(template[i : m.start()]))
        inner = m.group(0)[1:-1].lower()
        out.append(".+" if "path" in inner else "[^/]+")
        i = m.end()
    out.append(re.escape(template[i:]))
    return re.compile(r"^" + "".join(out) + r"/?$")


# --------------------------------------------------------------------------- finding <-> key matching
def _code_matches(f: Finding, kcwe: int, kfile: str, kstart: int, kend: int) -> bool:
    c = f.code
    if c is None or not cwe.same_family(f.cwe, kcwe):
        return False
    if _norm_path(c.file) != _norm_path(kfile):
        return False
    return _ranges_overlap(c.line_start, c.line_end, kstart - LINE_FUZZ, kend + LINE_FUZZ)


def _exact_code_match(f: Finding, kcwe: int, kfile: str, kstart: int, kend: int) -> bool:
    """Like _code_matches, but against the unfuzzed [kstart, kend] range."""
    c = f.code
    if c is None or not cwe.same_family(f.cwe, kcwe):
        return False
    if _norm_path(c.file) != _norm_path(kfile):
        return False
    return _ranges_overlap(c.line_start, c.line_end, kstart, kend)


def _decoy_hit(f: Finding, d: KeyDecoy, key: AnswerKey) -> bool:
    """Whether code finding `f` counts against decoy `d`, with exact-planted-match precedence (B-14)."""
    if not _code_matches(f, d.cwe, d.file, d.line_start, d.line_end):
        return False
    if _exact_code_match(f, d.cwe, d.file, d.line_start, d.line_end):
        return True  # overlaps the decoy itself: always a false alarm
    exact_planted = any(
        v.code and _exact_code_match(f, v.cwe, v.code.file, v.code.line_start, v.code.line_end) for v in key.vulns
    )
    return not exact_planted


def _runtime_matches(f: Finding, kr: KeyRuntime, kcwe: int) -> bool:
    rt = f.runtime
    if rt is None or not cwe.same_family(f.cwe, kcwe):
        return False
    if kr.method and rt.method.upper() != kr.method:
        return False
    if kr.path != "*" and not _path_regex(kr.path).match(rt.path or ""):
        return False
    if kr.param is not None and (rt.param or "") != kr.param:
        return False
    return True


# --------------------------------------------------------------------------- per-finding set lookups
def _all_findings(issues: list[Issue]) -> list[Finding]:
    seen: dict[str, Finding] = {}
    for issue in issues:
        for f in issue.code_findings + issue.runtime_findings:
            seen[f.id] = f
    return list(seen.values())


def _rate(num: int, den: int) -> float:
    return round(num / den, 4) if den else 0.0


# --------------------------------------------------------------------------- the five metrics
def compute_metrics(issues: list[Issue], key: AnswerKey) -> dict:
    findings = _all_findings(issues)
    code_findings = [f for f in findings if f.code is not None]
    runtime_findings = [f for f in findings if f.runtime is not None]

    # --- code / runtime detection ---
    code_vulns = [v for v in key.vulns if v.code is not None]
    code_found = sum(
        1
        for v in code_vulns
        if any(_code_matches(f, v.cwe, v.code.file, v.code.line_start, v.code.line_end) for f in code_findings)
    )
    runtime_vulns = [v for v in key.vulns if v.runtime is not None]
    runtime_found = sum(
        1 for v in runtime_vulns if any(_runtime_matches(f, v.runtime, v.cwe) for f in runtime_findings)
    )

    # --- correct links ---
    confirmed = [i for i in issues if i.label is Label.CONFIRMED]
    pairs = key.by_kind("pair")
    correct = 0
    for p in pairs:
        if any(
            any(_code_matches(f, p.cwe, p.code.file, p.code.line_start, p.code.line_end) for f in i.code_findings)
            and any(_runtime_matches(f, p.runtime, p.cwe) for f in i.runtime_findings)
            for i in confirmed
        ):
            correct += 1

    # --- wrong links ---
    pair_ids = {p.id for p in pairs}
    wrong = 0
    for i in confirmed:
        code_ids: set[str] = set()
        for f in i.code_findings:
            code_ids |= {
                v.id
                for v in key.vulns
                if v.code and _code_matches(f, v.cwe, v.code.file, v.code.line_start, v.code.line_end)
            }
            code_ids |= {d.id for d in key.decoys if _decoy_hit(f, d, key)}
        runtime_ids: set[str] = set()
        for f in i.runtime_findings:
            runtime_ids |= {v.id for v in key.vulns if v.runtime and _runtime_matches(f, v.runtime, v.cwe)}
        if (code_ids & runtime_ids) & pair_ids:
            continue  # a shared planted pair joins both sides -> correct
        if code_ids and runtime_ids:
            wrong += 1  # joins two different planted bugs (or one to a decoy)

    # --- false alarms ---
    reported = [i for i in issues if not is_suppressed(i)]
    false_alarms = sum(1 for i in reported if any(_decoy_hit(f, d, key) for f in i.code_findings for d in key.decoys))

    return {
        "code_detection": {"found": code_found, "total": len(code_vulns), "rate": _rate(code_found, len(code_vulns))},
        "runtime_detection": {
            "found": runtime_found,
            "total": len(runtime_vulns),
            "rate": _rate(runtime_found, len(runtime_vulns)),
        },
        "correct_links": {"found": correct, "total": len(pairs), "rate": _rate(correct, len(pairs))},
        "wrong_links": {"count": wrong, "confirmed": len(confirmed), "rate": _rate(wrong, len(confirmed))},
        "false_alarms": {"count": false_alarms, "reported": len(reported), "rate": _rate(false_alarms, len(reported))},
    }


# --------------------------------------------------------------------------- section 4 targets
# The five rate metrics, in the order the spec lists them.
METRIC_KEYS = ("code_detection", "runtime_detection", "correct_links", "wrong_links", "false_alarms")
_LABELS = {
    "code_detection": "Code detection",
    "runtime_detection": "Runtime detection",
    "correct_links": "Correct links",
    "wrong_links": "Wrong links",
    "false_alarms": "False alarms",
    "run_time": "Run time",
}
# Numerator / denominator field of each metric's dict.
_NUMERATOR = {k: ("count" if k in ("wrong_links", "false_alarms") else "found") for k in METRIC_KEYS}
_DENOMINATOR = {
    "code_detection": "total",
    "runtime_detection": "total",
    "correct_links": "total",
    "wrong_links": "confirmed",
    "false_alarms": "reported",
}

# Spec section 4: (good, great, higher_is_better). Rates are fractions; run time is in seconds.
# "Unseen app" is not here on purpose: it is the correct-link rate of the held-out app, so it is read
# off the Correct links row when evaluating that app's scan, not computed from any single scan.
TARGETS: dict[str, tuple[float, float, bool]] = {
    "code_detection": (0.60, 0.85, True),
    "runtime_detection": (0.50, 0.80, True),
    "correct_links": (0.50, 0.80, True),
    "wrong_links": (0.20, 0.05, False),
    "false_alarms": (0.30, 0.10, False),
    "run_time": (15 * 60.0, 5 * 60.0, False),
}


def _grade(value: float, good: float, great: float, higher_is_better: bool) -> str:
    """Spec section 4 uses strict comparisons (> 60%, < 20%), so a value exactly on a line misses it."""
    if higher_is_better:
        return "great" if value > great else "good" if value > good else "below"
    return "great" if value < great else "good" if value < good else "below"


def assess(metrics: dict, run_time_s: float | None = None) -> dict[str, str]:
    """Grade each metric against its section 4 target: great / good / below / n/a.

    A metric with an empty denominator is "n/a", not graded: 0 wrong links out of 0 Confirmed issues
    says nothing about link quality, and rating it "great" would reward linking nothing at all.
    """
    out: dict[str, str] = {}
    for key in METRIC_KEYS:
        m = metrics[key]
        if not m[_DENOMINATOR[key]]:
            out[key] = "n/a"
            continue
        good, great, higher = TARGETS[key]
        out[key] = _grade(m["rate"], good, great, higher)
    if run_time_s is not None:
        good, great, higher = TARGETS["run_time"]
        out["run_time"] = _grade(run_time_s, good, great, higher)
    return out


def _duration(seconds: float) -> str:
    return f"{seconds:.1f} s" if seconds < 120 else f"{seconds / 60:.1f} min"


def _target_text(key: str, threshold: float) -> str:
    higher = TARGETS[key][2]
    sign = ">" if higher else "<"
    if key == "run_time":
        return f"{sign}{threshold / 60:.0f} min"
    return f"{sign}{threshold * 100:.0f}%"


def format_metrics_table(m: dict, run_time_s: float | None = None) -> str:
    """Render the section 4 metrics with their Good/Great targets as a fixed-width table.

    `run_time_s` adds the Run time row when the scan's total duration is known. Deterministic: the
    same metrics always render the same text.
    """
    status = assess(m, run_time_s)
    rows: list[tuple[str, ...]] = []
    for key in METRIC_KEYS:
        d = m[key]
        den = d[_DENOMINATOR[key]]
        good, great, _ = TARGETS[key]
        rate = f"{d['rate'] * 100:.1f}%" if den else "-"
        rows.append(
            (
                _LABELS[key],
                f"{d[_NUMERATOR[key]]}/{den}",
                rate,
                _target_text(key, good),
                _target_text(key, great),
                status[key],
            )
        )
    if run_time_s is not None:
        good, great, _ = TARGETS["run_time"]
        rows.append(
            (
                _LABELS["run_time"],
                "",
                _duration(run_time_s),
                _target_text("run_time", good),
                _target_text("run_time", great),
                status["run_time"],
            )
        )

    header = ("Metric", "Count", "Value", "Good", "Great", "Status")
    widths = [max(len(r[i]) for r in [header, *rows]) for i in range(len(header))]

    def line(cells: tuple[str, ...]) -> str:
        first = cells[0].ljust(widths[0])
        rest = [c.rjust(w) for c, w in zip(cells[1:], widths[1:], strict=True)]
        return "  ".join([first, *rest]).rstrip()

    sep = "  ".join("-" * w for w in widths)
    return "\n".join([line(header), sep, *(line(r) for r in rows)])
