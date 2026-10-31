"""Fixture consistency (P0-J4). The fixtures are the cross-team oracle for the correlator and eval."""

from __future__ import annotations

import subprocess
import sys

from FlowStopper import ids
from FlowStopper.evalkit.keyschema import load_key
from FlowStopper.models import Label
from tests.conftest import FIXTURES, ROOT


def test_fixtures_are_generated_from_script():
    r = subprocess.run(
        [sys.executable, "scripts/build_fixtures.py", "--check"], cwd=ROOT, capture_output=True, text=True
    )
    assert r.returncode == 0, r.stdout + r.stderr


def test_finding_ids_follow_rules(fixture_sast, fixture_dast):
    for f in fixture_sast + fixture_dast:
        assert f.id == ids.finding_id(f), f"{f.rule_id}: expected id {ids.finding_id(f)}"


def test_routes_are_consistent(fixture_routes):
    for r in fixture_routes:
        assert r.id == f"{r.method} {r.path_template}"
        assert r.path_regex.startswith("^") and r.path_regex.endswith("$")


def test_required_cases_present(fixture_expected_issues):
    labels = [i.label for i in fixture_expected_issues]
    assert labels.count(Label.CONFIRMED) == 2
    assert any(i.label is Label.CODE_ONLY and i.cwe == 798 for i in fixture_expected_issues)
    assert any(i.label is Label.RUNTIME_ONLY and i.cwe == 693 for i in fixture_expected_issues)
    tie = [i for i in fixture_expected_issues if any(r.kind == "ambiguity_penalty" for r in i.reasons)]
    assert sorted(i.label.value for i in tie) == ["code_only", "code_only", "runtime_only"]
    suppressed = [i for i in fixture_expected_issues if i.code_findings and all(f.suppressed for f in i.code_findings)]
    assert len(suppressed) == 1 and suppressed[0] is fixture_expected_issues[-1]


def test_issue_ids_and_links(fixture_expected_issues, fixture_sast, fixture_dast):
    known = {f.id for f in fixture_sast + fixture_dast}
    used = []
    for issue in fixture_expected_issues:
        assert issue.id == ids.issue_id(issue, host="127.0.0.1:8080")
        used += [f.id for f in issue.code_findings + issue.runtime_findings]
        if issue.label is Label.CONFIRMED:
            assert issue.code_findings and issue.runtime_findings and issue.verified_by == "dast"
            assert abs(sum(r.weight for r in issue.reasons) - issue.link_score) < 1e-9
    assert sorted(used) == sorted(known), "every fixture finding appears in exactly one issue"


def test_answer_key_validates():
    key = load_key(FIXTURES / "answer_key.json")
    assert len(key.by_kind("pair")) == 5 and len(key.decoys) == 1
