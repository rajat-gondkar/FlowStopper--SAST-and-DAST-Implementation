"""Markdown findings list tests (Owner: B, P5-B4 / D-03): layout, content, suppressed bucket,
escaping of untrusted scan data (R7), secret masking (B-22) and determinism.
"""

from __future__ import annotations

import re

from FlowStopper.correlate.issues import is_suppressed
from FlowStopper.models import Label, LinkReason
from FlowStopper.report import common
from FlowStopper.report.markdown import render_markdown

EVIL = "<script>alert(1)</script>"
META = {"target": "http://127.0.0.1:9", "scan_id": "s1", "source": "src", "timings_s": {"total": 2.0}}


def _confirmed(issues):
    return next(i for i in issues if i.label is Label.CONFIRMED)


def test_layout_and_counts(fixture_expected_issues):
    text = render_markdown(fixture_expected_issues, META)
    reported = [i for i in fixture_expected_issues if not is_suppressed(i)]
    assert text.startswith("# FlowStopper findings\n")
    for heading in ("## Prioritised issues", "## Issue details", "## Suppressed (safe / unreachable): 1"):
        assert heading in text
    assert "`http://127.0.0.1:9`" in text and "2.0 s" in text
    assert f"**Reported:** {len(reported)} (" in text
    for n in range(1, len(reported) + 1):
        assert f'<a id="issue-{n}"></a>' in text and f"](#issue-{n})" in text
    assert text.count("\n### ") == len(reported)


def test_detail_has_everything_a_judge_needs(fixture_expected_issues):
    issue = _confirmed(fixture_expected_issues)
    text = render_markdown([issue])
    rt, code = issue.primary_runtime, issue.primary_code
    for needle in (
        f"`{issue.id}`",
        f"`{rt.method} {rt.url}`",
        f"`{rt.param}`",
        f"`{rt.payload}`",
        f"`{code.file}:{code.line_start}`",
        f"`{code.function}`",
        f"CWE-{issue.cwe}",
        issue.owasp_2025,
        "**Why these were linked:**",
        "**Reproduce:**",
        rt.repro_curl,
        "**How to fix:**",
        "What is wrong:",
        "Prevention:",
    ):
        assert needle in text, needle
    assert re.search(rf"^> +{code.line_start} \| ", text, re.M)  # the offending snippet line is marked


def test_suppressed_table_explains_reasons(fixture_expected_issues):
    text = render_markdown(fixture_expected_issues)
    section = text.split("## Suppressed")[1]
    supp = next(i for i in fixture_expected_issues if is_suppressed(i))
    for reason in common.suppress_reasons(supp):
        assert f"`{reason}`" in section
        assert common.explain_suppression(reason) in section
    assert supp.id not in text


def test_untrusted_text_never_reaches_markdown_as_raw_html(fixture_expected_issues):
    base = _confirmed(fixture_expected_issues)
    rt = base.primary_runtime.model_copy(update={"evidence": EVIL})
    evil = base.model_copy(
        update={
            "title": EVIL,
            "primary_runtime": rt,
            "reasons": [LinkReason(kind="same_cwe", detail=EVIL, weight=0.0)],
            "fix": f"{EVIL}\n\n```\nok()\n```",
        }
    )
    text = render_markdown([evil], {"target": "http://127.0.0.1:9", "started_at": EVIL})
    assert "<script" not in text
    assert "&lt;script&gt;" in text


def test_payload_stays_inside_code_even_with_backticks_and_pipes(fixture_expected_issues):
    base = _confirmed(fixture_expected_issues)
    rt = base.primary_runtime.model_copy(update={"payload": "a`b|c<x>"})
    text = render_markdown([base.model_copy(update={"primary_runtime": rt})])
    assert "`` a`b|c<x> ``" in text  # CommonMark strips one padding space on each side


def test_table_cells_escape_pipes(fixture_expected_issues):
    base = _confirmed(fixture_expected_issues)
    code = base.primary_code.model_copy(update={"file": "a|b.py"})
    text = render_markdown([base.model_copy(update={"primary_code": code, "title": "x | y"})])
    row = next(line for line in text.splitlines() if line.startswith("| 1 |"))
    assert len(re.findall(r"(?<!\\)\|", row)) == 8  # 7 cells, no extra column
    assert "x \\| y" in row and "a\\|b.py" in row


def test_secret_values_are_masked(fixture_expected_issues):
    secret = next(i for i in fixture_expected_issues if i.cwe == 798)
    raw = secret.primary_code.snippet
    text = render_markdown([secret])
    assert "s3cr3t-fixture-key-123" in raw
    assert "s3cr3t-fixture-key-123" not in text
    assert '"s3***"' in text


def test_deterministic_and_meta_optional(fixture_expected_issues):
    a = render_markdown(fixture_expected_issues, None)
    assert a == render_markdown(list(reversed(fixture_expected_issues)), None)
    assert "`unknown`" in a
    assert render_markdown([], None).count("No reported issues.") == 1
