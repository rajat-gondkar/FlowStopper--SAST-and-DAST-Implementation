"""CI gate tests (Owner: B, P5-B2 / B-6): `--fail-on <label>:<severity>` parsing and evaluation."""

from __future__ import annotations

import pytest

from FlowStopper.correlate.issues import is_suppressed
from FlowStopper.models import Issue, Label, Severity
from FlowStopper.report.gate import GATE_EXIT_CODE, gate_tripped, parse_fail_on


def _by(issues: list[Issue], label: Label, severity: Severity, suppressed: bool = False) -> Issue:
    for issue in issues:
        if issue.label is label and issue.severity is severity and is_suppressed(issue) is suppressed:
            return issue
    raise AssertionError(f"fixture has no {label.value}/{severity.value} issue (suppressed={suppressed})")


def test_exit_code_is_two():
    assert GATE_EXIT_CODE == 2


@pytest.mark.parametrize(
    ("spec", "expected"),
    [
        ("confirmed:high", ("confirmed", Severity.HIGH)),
        ("CONFIRMED:HIGH", ("confirmed", Severity.HIGH)),
        ("Code_Only:Critical", ("code_only", Severity.CRITICAL)),
        ("runtime_only:medium", ("runtime_only", Severity.MEDIUM)),
        ("any:low", ("any", Severity.LOW)),
        ("ANY:info", ("any", Severity.INFO)),
        ("  confirmed:high  ", ("confirmed", Severity.HIGH)),
    ],
)
def test_parse_fail_on_accepts_every_label_case_insensitively(spec, expected):
    assert parse_fail_on(spec) == expected


@pytest.mark.parametrize(
    "spec",
    ["", "confirmed", "confirmed:", ":high", "bogus:high", "confirmed:urgent", "confirmed:high:x", "code-only:high"],
)
def test_parse_fail_on_rejects_anything_else(spec):
    with pytest.raises(ValueError):
        parse_fail_on(spec)


def test_gate_tripped_raises_on_a_malformed_spec(fixture_expected_issues):
    with pytest.raises(ValueError):
        gate_tripped(fixture_expected_issues, "confirmed-high")


def test_confirmed_high_trips_on_a_confirmed_critical(fixture_expected_issues):
    issues = [_by(fixture_expected_issues, Label.CONFIRMED, Severity.CRITICAL)]
    assert gate_tripped(issues, "confirmed:high")
    assert gate_tripped(issues, "confirmed:critical")


def test_threshold_is_inclusive_and_ordered(fixture_expected_issues):
    medium = [_by(fixture_expected_issues, Label.CONFIRMED, Severity.MEDIUM)]
    assert not gate_tripped(medium, "confirmed:high")
    assert gate_tripped(medium, "confirmed:medium")
    assert gate_tripped(medium, "confirmed:low")


def test_label_must_match_unless_any(fixture_expected_issues):
    runtime = [_by(fixture_expected_issues, Label.RUNTIME_ONLY, Severity.CRITICAL)]
    assert not gate_tripped(runtime, "confirmed:low")
    assert not gate_tripped(runtime, "code_only:low")
    assert gate_tripped(runtime, "runtime_only:critical")
    assert gate_tripped(runtime, "any:critical")


def test_suppressed_issues_never_trip_the_gate(fixture_expected_issues):
    suppressed = [_by(fixture_expected_issues, Label.CODE_ONLY, Severity.CRITICAL, suppressed=True)]
    assert is_suppressed(suppressed[0])
    for spec in ("code_only:info", "any:info"):
        assert not gate_tripped(suppressed, spec)


def test_empty_list_never_trips():
    assert not gate_tripped([], "any:info")


def test_whole_fixture(fixture_expected_issues):
    assert gate_tripped(fixture_expected_issues, "confirmed:high")
    assert gate_tripped(fixture_expected_issues, "code_only:critical")
    assert gate_tripped(fixture_expected_issues, "any:info")
