"""Report entry points used by Dev A's api.py / pipeline.py (Owner: B, Phase 5 step 0).

Pins the names and signatures `render_html`, `to_sarif` and `render_markdown`, that each works with
and without `meta`, skips suppressed issues from the reported list, and that HTML escapes (R7).
"""

from __future__ import annotations

import json

from FlowStopper.correlate.issues import is_suppressed
from FlowStopper.report.html import render_html
from FlowStopper.report.markdown import render_markdown
from FlowStopper.report.sarif import to_sarif

META = {"scan_id": "scan-1", "target": "http://127.0.0.1:9", "started_at": "2026-11-01T00:00:00Z"}


def test_render_html_with_and_without_meta(fixture_expected_issues):
    for meta in (None, META):
        page = render_html(fixture_expected_issues, meta)
        assert page.lstrip().startswith("<!DOCTYPE html>")
        reported = [i for i in fixture_expected_issues if not is_suppressed(i)]
        for issue in reported:
            assert issue.id in page
    assert "http://127.0.0.1:9" in render_html(fixture_expected_issues, META)


def test_render_html_escapes_dynamic_text(fixture_expected_issues):
    evil = fixture_expected_issues[0].model_copy(update={"title": "<script>alert(1)</script>"})
    page = render_html([evil], {"target": "<img src=x onerror=alert(2)>"})
    assert "<script>alert(1)</script>" not in page
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page
    assert "<img src=x" not in page


def test_to_sarif_minimal_structure(fixture_expected_issues):
    for meta in (None, META):
        log = to_sarif(fixture_expected_issues, meta)
        json.dumps(log)  # serialisable
        assert log["version"] == "2.1.0"
        assert len(log["runs"]) == 1
        run = log["runs"][0]
        assert run["tool"]["driver"]["name"] == "FlowStopper"
        reported = [i for i in fixture_expected_issues if not is_suppressed(i)]
        assert len(run["results"]) == len(reported)
        rule_ids = [r["id"] for r in run["tool"]["driver"]["rules"]]
        assert len(rule_ids) == len(set(rule_ids)) == len({i.cwe for i in reported})
        assert {r["ruleId"] for r in run["results"]} == set(rule_ids)


def test_render_markdown_lists_reported_issues(fixture_expected_issues):
    for meta in (None, META):
        text = render_markdown(fixture_expected_issues, meta)
        assert text.startswith("# FlowStopper findings")
        for issue in fixture_expected_issues:
            assert (issue.id in text) is (not is_suppressed(issue))


def test_outputs_are_deterministic(fixture_expected_issues):
    shuffled = list(reversed(fixture_expected_issues))
    assert render_html(fixture_expected_issues, META) == render_html(shuffled, META)
    assert to_sarif(fixture_expected_issues, META) == to_sarif(shuffled, META)
    assert render_markdown(fixture_expected_issues, META) == render_markdown(shuffled, META)
