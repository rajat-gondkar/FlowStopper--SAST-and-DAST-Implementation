"""HTML report tests (Owner: B, P5-B1): content, ordering, suppressed bucket, R7 escaping, offline
self-containment and hard-coded secret masking (B-22). Also unit tests for report/common.py.
"""

from __future__ import annotations

import re

import pytest

from FlowStopper.correlate.issues import is_suppressed
from FlowStopper.models import CodeLocation, Finding, Issue, Label, LinkReason
from FlowStopper.report import common
from FlowStopper.report.html import render_html

EVIL = "<script>alert('x')</script>"
ESCAPED_TAG = "&lt;script&gt;"


def _confirmed(issues: list[Issue]) -> Issue:
    return next(i for i in issues if i.label is Label.CONFIRMED)


def _suppressed(issues: list[Issue]) -> Issue:
    return next(i for i in issues if is_suppressed(i))


def _secret_issue(snippet: str, line_start: int = 12) -> Issue:
    loc = CodeLocation(file="settings.py", line_start=line_start, line_end=line_start, snippet=snippet)
    finding = Finding(
        id="f" * 40,
        engine="sast",
        tool="FlowStopper-secrets",
        rule_id="py.secret.assign",
        cwe=798,
        title="Hard-coded secret assigned to TOKEN",
        severity="critical",
        confidence=0.9,
        code=loc,
    )
    return Issue(
        id="0123456789abcdef",
        cwe=798,
        title="Hard-coded credential in settings.py (TOKEN)",
        label=Label.CODE_ONLY,
        severity="critical",
        cvss=9.1,
        risk=5.46,
        code_findings=[finding],
        primary_code=loc,
    )


# --------------------------------------------------------------------------- content
def test_summary_header_counts_and_meta(fixture_expected_issues):
    meta = {
        "target": "http://127.0.0.1:9",
        "source": "src",
        "started_at": "2026-11-01T00:00:00Z",
        "scan_id": "abc123",
        "timings_s": {"total": 4.25},
        "versions": {"FlowStopper": "9.9.9"},
    }
    page = render_html(fixture_expected_issues, meta)
    for text in ("http://127.0.0.1:9", "2026-11-01T00:00:00Z", "abc123", "4.2 s", "FlowStopper 9.9.9"):
        assert text in page
    reported = [i for i in fixture_expected_issues if not is_suppressed(i)]
    confirmed = sum(1 for i in reported if i.label is Label.CONFIRMED)
    assert f'<div class="n">{len(reported)}</div><div class="k">Reported issues</div>' in page
    assert f'<div class="n">{confirmed}</div><div class="k"><span class="dot confirmed"></span>Confirmed</div>' in page


def test_truncated_scan_shows_a_banner(fixture_expected_issues):
    assert "time budget was reached" in render_html(fixture_expected_issues, {"truncated": True})
    assert "time budget was reached" not in render_html(fixture_expected_issues, {"truncated": False})


def test_table_is_prioritised_confirmed_first(fixture_expected_issues):
    page = render_html(list(reversed(fixture_expected_issues)))
    table = page.split("<h2>Issue details</h2>")[0]
    order = re.findall(r'href="#issue-([0-9a-f]{16})"', table)
    labels = [next(i.label for i in fixture_expected_issues if i.id == x) for x in order]
    first_other = next(n for n, label in enumerate(labels) if label is not Label.CONFIRMED)
    assert all(label is Label.CONFIRMED for label in labels[:first_other])
    assert Label.CONFIRMED not in labels[first_other:]
    risks = [next(i.risk for i in fixture_expected_issues if i.id == x) for x in order[first_other:]]
    assert risks == sorted(risks, reverse=True)


def test_confirmed_detail_shows_everything_fr8(fixture_expected_issues):
    issue = _confirmed(fixture_expected_issues).model_copy(update={"fix": "Use parameters.\n\n```python\nq(x)\n```"})
    page = render_html([issue])
    rt, code = issue.primary_runtime, issue.primary_code
    expected = [
        f'id="issue-{issue.id}"',
        "Confirmed",
        f"{issue.risk:.1f} / 10",
        f"{issue.cvss:.1f}",
        f"{rt.method} {rt.url}",
        rt.param,
        rt.proof,
        f"{code.file}:{code.line_start}",
        code.function,
        f"CWE-{issue.cwe}",
        issue.owasp_2025,
        "Why these were linked",
        "How to fix",
        "<pre>q(x)</pre>",
        "Reproduce",
    ]
    for text in expected:
        assert text in page, text
    from markupsafe import escape

    for raw in (rt.payload, rt.evidence, rt.repro_curl, *(r.detail for r in issue.reasons)):
        assert str(escape(raw)) in page, raw
    assert 'class="line hot"' in page  # the offending line is highlighted


def test_suppressed_section_is_collapsed_and_explains_reasons(fixture_expected_issues):
    page = render_html(fixture_expected_issues)
    supp = _suppressed(fixture_expected_issues)
    section = page.split('<details class="suppressed">')[1]
    assert '<details class="suppressed" open' not in page
    assert supp.title in section
    for reason in common.suppress_reasons(supp):
        assert reason in section
    assert f'id="issue-{supp.id}"' not in page  # not in the reported list or details


@pytest.mark.parametrize(
    ("reason", "needle"),
    [
        ("sanitized:html.escape", "html.escape"),
        ("sanitized:a+b", "a, b"),
        ("safe:sql-parameterised", "parameterised"),
        ("safe:subprocess-list-no-shell", "without a shell"),
        ("unreachable", "not reachable"),
        ("dast:debug-traceback-reflection", "debug traceback"),
        ("safe:something-new", "something-new"),
    ],
)
def test_every_suppress_reason_is_explained(reason, needle):
    assert needle in common.explain_suppression(reason)


def test_suppressed_dast_traceback_reason_is_rendered(fixture_expected_issues):
    issue = next(i for i in fixture_expected_issues if i.label is Label.RUNTIME_ONLY and i.runtime_findings)
    rf = issue.runtime_findings[0].model_copy(
        update={"suppressed": True, "suppress_reason": "dast:debug-traceback-reflection"}
    )
    page = render_html([issue.model_copy(update={"runtime_findings": [rf]})])
    assert "dast:debug-traceback-reflection" in page.split('<details class="suppressed">')[1]


# --------------------------------------------------------------------------- R7 escaping
def test_all_dynamic_text_is_escaped(fixture_expected_issues):
    base = _confirmed(fixture_expected_issues)
    rt = base.primary_runtime.model_copy(
        update={
            "evidence": EVIL,
            "payload": EVIL,
            "url": f"http://127.0.0.1/x?q={EVIL}",
            "repro_curl": f"curl '{EVIL}'",
            "request": EVIL,
            "response_excerpt": EVIL,
            "param": EVIL,
        }
    )
    code = base.primary_code.model_copy(update={"snippet": EVIL, "function": EVIL, "file": EVIL})
    evil = base.model_copy(
        update={
            "title": EVIL,
            "primary_runtime": rt,
            "primary_code": code,
            "reasons": [LinkReason(kind="same_cwe", detail=EVIL, weight=0.0)],
            "fix": f"{EVIL}\n\n```\n{EVIL}\n```",
            "owasp_2025": EVIL,
        }
    )
    supp = _suppressed(fixture_expected_issues)
    sf = supp.code_findings[0].model_copy(update={"suppress_reason": EVIL})
    supp = supp.model_copy(update={"title": EVIL, "code_findings": [sf]})
    page = render_html([evil, supp], {"target": EVIL, "source": EVIL, "scan_id": EVIL, "started_at": EVIL})
    assert "<script" not in page.lower()
    assert "alert('x')" not in page  # quotes are escaped too
    assert page.count(ESCAPED_TAG) >= 15


def test_page_is_self_contained_and_offline(fixture_expected_issues):
    page = render_html(fixture_expected_issues, {"target": "http://127.0.0.1:9"})
    lowered = page.lower()
    for marker in ("<script", "<link", "<img", "<iframe", "@import", "url(", " src="):
        assert marker not in lowered, marker
    assert "<style>" in page


# --------------------------------------------------------------------------- secret masking (B-22)
def test_secret_value_is_masked_in_the_report():
    issue = _secret_issue('# signing key\nTOKEN = "sk_live_abcdef123456"\n')
    page = render_html([issue])
    assert "sk_live_abcdef123456" not in page
    assert "sk***" in page


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ('TOKEN = "sk_live_abcdef"', 'TOKEN = "sk***"'),
        ("    KEY = 'abcdef'", "    KEY = 'ab***'"),
        ('PW = b"hunter2"', 'PW = b"hu***"'),
        ('cfg = {"password": "s3cret"}', 'cfg = {"pa***": "s3***"}'),
        ("DB_PASSWORD=plainvalue", "DB_PASSWORD=pl***"),
        ("api_key: abcdef123", "api_key: ab***"),
        ('X = "ab"', 'X = "***"'),
        ("# a comment: with a colon", "# a comment: with a colon"),
        ("", ""),
    ],
)
def test_mask_secret_line(line, expected):
    assert common.mask_secret_line(line) == expected


def test_only_secret_cwes_are_masked():
    assert common.display_snippet(89, 'q = "SELECT 1"') == 'q = "SELECT 1"'
    assert common.display_snippet(798, 'k = "abcdef"') == 'k = "ab***"'
    assert common.display_snippet(321, 'k = "abcdef"') == 'k = "ab***"'


# --------------------------------------------------------------------------- snippet numbering
@pytest.mark.parametrize(
    ("snippet", "start", "end", "numbers", "hot"),
    [
        ("a\nb\nc", 10, 10, [9, 10, 11], [10]),  # one line of context each side
        ("a\nb", 1, 1, [1, 2], [1]),  # first line of the file: no leading context
        ("a\nb", 20, 20, [19, 20], [20]),  # last line of the file: no trailing context
        ("a", 5, 5, [5], [5]),  # no context at all
        ("a\nb\nc\nd", 7, 8, [6, 7, 8, 9], [7, 8]),  # multi-line finding
    ],
)
def test_snippet_lines(snippet, start, end, numbers, hot):
    loc = CodeLocation(file="f.py", line_start=start, line_end=end, snippet=snippet)
    lines = common.snippet_lines(89, loc)
    assert [ln.number for ln in lines] == numbers
    assert [ln.number for ln in lines if ln.hot] == hot


def test_fix_blocks_split_text_and_code():
    text = "What is wrong.\n\n```python\nx = 1\ny = 2\n```\n\nTip: be careful."
    assert common.fix_blocks(text) == [
        ("text", "What is wrong."),
        ("code", "x = 1\ny = 2"),
        ("text", "Tip: be careful."),
    ]
    assert common.fix_blocks(None) == []
    assert common.fix_blocks("```\nunterminated") == [("code", "unterminated")]
