"""SARIF 2.1.0 export tests (Owner: B, P5-B2 / B-6): required structure, levels, code locations,
runtime web request/response (with the properties fallback), fingerprints, masking, determinism.

The output was also validated once against the official OASIS SARIF 2.1.0 JSON schema (0 errors on
the fixtures and a live Mock A scan); these tests pin the required keys without a schema dependency.
"""

from __future__ import annotations

import json

import pytest

from FlowStopper.correlate.issues import is_suppressed
from FlowStopper.models import CodeLocation, Finding, Issue, Label, Severity
from FlowStopper.report.sarif import FINGERPRINT_KEY, level_for, to_sarif

META = {
    "scan_id": "s1",
    "status": "completed",
    "started_at": "2026-11-01T00:00:00+00:00",
    "finished_at": "2026-11-01T00:00:05+00:00",
    "target": "http://127.0.0.1:9",
    "versions": {"FlowStopper": "1.2.3"},
}
PROPERTY_KEYS = {"label", "risk", "cwe", "owasp", "url", "param"}


def _run(issues, meta=META) -> dict:
    log = to_sarif(issues, meta)
    assert json.loads(json.dumps(log)) == log  # plain JSON
    return log["runs"][0]


def _reported(issues):
    return sorted((i for i in issues if not is_suppressed(i)), key=lambda i: i.id)


def test_required_top_level_keys(fixture_expected_issues):
    for meta in (None, META):
        log = to_sarif(fixture_expected_issues, meta)
        assert log["version"] == "2.1.0"
        assert "sarif-2.1.0" in log["$schema"]
        assert isinstance(log["runs"], list) and len(log["runs"]) == 1
        driver = log["runs"][0]["tool"]["driver"]
        assert driver["name"] == "FlowStopper"
        assert isinstance(driver["rules"], list)
        assert isinstance(log["runs"][0]["results"], list)


def test_one_rule_per_cwe_and_one_result_per_reported_issue(fixture_expected_issues):
    run = _run(fixture_expected_issues)
    rules = run["tool"]["driver"]["rules"]
    reported = _reported(fixture_expected_issues)
    assert [r["id"] for r in rules] == [f"CWE-{c}" for c in sorted({i.cwe for i in reported})]
    for rule in rules:
        assert rule["shortDescription"]["text"]
        assert rule["helpUri"].startswith("https://cwe.mitre.org/")
    results = run["results"]
    assert len(results) == len(reported)
    assert sorted(r["partialFingerprints"][FINGERPRINT_KEY] for r in results) == [i.id for i in reported]
    for result in results:
        assert rules[result["ruleIndex"]]["id"] == result["ruleId"]
        assert result["message"]["text"]
        assert result["level"] in {"error", "warning", "note"}


def test_suppressed_issues_are_not_results(fixture_expected_issues):
    run = _run(fixture_expected_issues)
    ids = {r["partialFingerprints"][FINGERPRINT_KEY] for r in run["results"]}
    for issue in fixture_expected_issues:
        assert (issue.id in ids) is (not is_suppressed(issue))


@pytest.mark.parametrize(
    ("severity", "level"),
    [
        (Severity.CRITICAL, "error"),
        (Severity.HIGH, "error"),
        (Severity.MEDIUM, "warning"),
        (Severity.LOW, "note"),
        (Severity.INFO, "note"),
    ],
)
def test_level_mapping(severity, level, fixture_expected_issues):
    assert level_for(severity) == level
    issue = _reported(fixture_expected_issues)[0].model_copy(update={"severity": severity})
    assert _run([issue])["results"][0]["level"] == level


def test_properties_carry_label_risk_cwe_owasp_url_param(fixture_expected_issues):
    by_id = {i.id: i for i in fixture_expected_issues}
    for result in _run(fixture_expected_issues)["results"]:
        issue = by_id[result["partialFingerprints"][FINGERPRINT_KEY]]
        props = result["properties"]
        assert PROPERTY_KEYS <= set(props)
        assert props["label"] == issue.label.value
        assert props["risk"] == issue.risk
        assert props["cwe"] == issue.cwe
        assert props["owasp"]
        if issue.primary_runtime is not None:
            assert props["url"] == issue.primary_runtime.url
            assert props["param"] == issue.primary_runtime.param


def test_code_results_have_relative_physical_locations(fixture_expected_issues):
    by_id = {i.id: i for i in fixture_expected_issues}
    seen = 0
    for result in _run(fixture_expected_issues)["results"]:
        issue = by_id[result["partialFingerprints"][FINGERPRINT_KEY]]
        if issue.primary_code is None:
            assert "locations" not in result
            continue
        seen += 1
        physical = result["locations"][0]["physicalLocation"]
        uri = physical["artifactLocation"]["uri"]
        assert uri == issue.primary_code.file
        assert not uri.startswith("/") and "\\" not in uri and "://" not in uri
        assert physical["artifactLocation"]["uriBaseId"] == "SRCROOT"
        region = physical["region"]
        assert region["startLine"] == issue.primary_code.line_start
        assert region["endLine"] == issue.primary_code.line_end
        assert region["snippet"]["text"]
        if "contextRegion" in physical:
            ctx = physical["contextRegion"]
            assert ctx["startLine"] <= region["startLine"] <= region["endLine"] <= ctx["endLine"]
    assert seen


def test_runtime_results_have_web_request_and_response(fixture_expected_issues):
    issue = next(i for i in fixture_expected_issues if i.label is Label.CONFIRMED)
    result = _run([issue])["results"][0]
    rt = issue.primary_runtime
    req = result["webRequest"]
    assert req["target"] == rt.url and req["method"] == rt.method
    assert req["parameters"] == {rt.param: rt.payload}
    assert req["version"] == "1.1" and req["headers"]["Host"]
    resp = result["webResponse"]
    assert resp["statusCode"] == 500 and resp["protocol"] == "HTTP" and resp["version"] == "1.1"
    props = result["properties"]
    assert props["request"] == rt.request and props["evidence"] == rt.evidence and props["proof"] == rt.proof


def test_body_only_excerpt_becomes_the_response_body(fixture_expected_issues):
    """The live DAST client stores only the body excerpt; it still lands in webResponse."""
    issue = next(i for i in fixture_expected_issues if i.label is Label.CONFIRMED)
    rt = issue.primary_runtime.model_copy(update={"response_excerpt": "...body only..."})
    result = _run([issue.model_copy(update={"primary_runtime": rt})])["results"][0]
    assert result["webResponse"] == {"protocol": "HTTP", "body": {"text": "...body only..."}}
    assert result["webRequest"]["target"] == rt.url


def test_recorded_status_fills_status_code(fixture_expected_issues):
    issue = next(i for i in fixture_expected_issues if i.label is Label.CONFIRMED)
    rt = issue.primary_runtime.model_copy(update={"response_excerpt": "moved"})
    rf = issue.runtime_findings[0].model_copy(update={"runtime": rt, "raw": {"status": 302}})
    issue = issue.model_copy(update={"primary_runtime": rt, "runtime_findings": [rf]})
    assert _run([issue])["results"][0]["webResponse"]["statusCode"] == 302


def test_meta_fills_version_invocation_and_automation(fixture_expected_issues):
    run = _run(fixture_expected_issues)
    assert run["tool"]["driver"]["version"] == "1.2.3"
    assert run["automationDetails"]["id"] == "flowstopper/s1"
    assert run["invocations"][0]["executionSuccessful"] is True
    assert run["invocations"][0]["startTimeUtc"] == META["started_at"]
    assert run["properties"]["target"] == META["target"]
    bare = _run(fixture_expected_issues, None)
    assert "automationDetails" not in bare and bare["tool"]["driver"]["version"]


def test_secret_values_are_masked_in_snippets():
    loc = CodeLocation(file="settings.py", line_start=3, line_end=3, snippet='# key\nTOKEN = "sk_live_abcdef"\n')
    finding = Finding(
        id="e" * 40,
        engine="sast",
        tool="FlowStopper-secrets",
        rule_id="py.secret.assign",
        cwe=798,
        title="Hard-coded secret assigned to TOKEN",
        severity="critical",
        confidence=0.9,
        code=loc,
    )
    issue = Issue(
        id="fedcba9876543210",
        cwe=798,
        title="Hard-coded credential in settings.py (TOKEN)",
        label=Label.CODE_ONLY,
        severity="critical",
        cvss=9.1,
        risk=5.46,
        code_findings=[finding],
        primary_code=loc,
    )
    text = json.dumps(to_sarif([issue]))
    assert "sk_live_abcdef" not in text
    assert "sk***" in text


def test_deterministic_and_order_independent(fixture_expected_issues):
    a = json.dumps(to_sarif(fixture_expected_issues, META), sort_keys=False)
    b = json.dumps(to_sarif(list(reversed(fixture_expected_issues)), META), sort_keys=False)
    assert a == b
