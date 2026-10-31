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

Detection counts any matching finding, suppressed or not (suppression is a reporting decision, not a
detection one); false alarms and links look only at reported / Confirmed issues.
"""

from __future__ import annotations

import posixpath
import re

from FlowStopper import cwe
from FlowStopper.correlate.issues import is_suppressed
from FlowStopper.evalkit.keyschema import AnswerKey, KeyRuntime
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
            code_ids |= {d.id for d in key.decoys if _code_matches(f, d.cwe, d.file, d.line_start, d.line_end)}
        runtime_ids: set[str] = set()
        for f in i.runtime_findings:
            runtime_ids |= {v.id for v in key.vulns if v.runtime and _runtime_matches(f, v.runtime, v.cwe)}
        if (code_ids & runtime_ids) & pair_ids:
            continue  # a shared planted pair joins both sides -> correct
        if code_ids and runtime_ids:
            wrong += 1  # joins two different planted bugs (or one to a decoy)

    # --- false alarms ---
    reported = [i for i in issues if not is_suppressed(i)]
    false_alarms = sum(
        1
        for i in reported
        if any(_code_matches(f, d.cwe, d.file, d.line_start, d.line_end) for f in i.code_findings for d in key.decoys)
    )

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


def format_metrics_table(m: dict) -> str:
    """Render the section 4 metrics as a compact fixed-width table (deterministic)."""
    cd, rd, cl, wl, fa = (
        m["code_detection"],
        m["runtime_detection"],
        m["correct_links"],
        m["wrong_links"],
        m["false_alarms"],
    )

    def pct(x: float) -> str:
        return f"{x * 100:.1f}%"

    rows = [
        ("Code detection", f"{cd['found']}/{cd['total']}", pct(cd["rate"])),
        ("Runtime detection", f"{rd['found']}/{rd['total']}", pct(rd["rate"])),
        ("Correct links", f"{cl['found']}/{cl['total']}", pct(cl["rate"])),
        ("Wrong links", f"{wl['count']}/{wl['confirmed']}", pct(wl["rate"])),
        ("False alarms", f"{fa['count']}/{fa['reported']}", pct(fa["rate"])),
    ]
    w = max(len(r[0]) for r in rows)
    header = f"{'Metric'.ljust(w)}  {'Count':>7}  {'Rate':>7}"
    sep = f"{'-' * w}  {'-' * 7}  {'-' * 7}"
    body = [f"{name.ljust(w)}  {count:>7}  {rate:>7}" for name, count, rate in rows]
    return "\n".join([header, sep, *body])
