"""Eval harness metrics (P1-B5, spec section 4 + Appendix C). Owner: B.

The golden test reproduces fixtures/expected_metrics.json from fixtures/expected_issues.json vs
fixtures/answer_key.json; the rest exercise the Appendix C matching branches that the fixture does
not (path-template wildcards, omitted method, wrong link, false alarm).
"""

from __future__ import annotations

import json

from typer.testing import CliRunner

from FlowStopper.cli import app
from FlowStopper.correlate.issues import is_suppressed
from FlowStopper.evalkit.keyschema import AnswerKey, load_key
from FlowStopper.evalkit.metrics import compute_metrics, format_metrics_table
from FlowStopper.models import (
    CodeLocation,
    Engine,
    Finding,
    Issue,
    Label,
    RuntimeLocation,
    Severity,
)
from tests.conftest import FIXTURES, load_json


def _code_finding(cwe: int, file: str, line: int, suppressed: bool = False) -> Finding:
    return Finding(
        id=f"c:{cwe}:{file}:{line}",
        engine=Engine.SAST,
        tool="FlowStopper-taint",
        rule_id="r",
        cwe=cwe,
        title="t",
        severity=Severity.HIGH,
        confidence=0.9,
        code=CodeLocation(file=file, line_start=line, line_end=line),
        suppressed=suppressed,
    )


def _runtime_finding(cwe: int, method: str, path: str, param: str | None) -> Finding:
    return Finding(
        id=f"r:{cwe}:{method}:{path}:{param}",
        engine=Engine.DAST,
        tool="FlowStopper-dast",
        rule_id="r",
        cwe=cwe,
        title="t",
        severity=Severity.HIGH,
        confidence=0.9,
        runtime=RuntimeLocation(method=method, url=f"http://h{path}", path=path, param=param, proof="error"),
    )


def _issue(label: Label, code=(), runtime=()) -> Issue:
    code = list(code)
    runtime = list(runtime)
    return Issue(
        id="i",
        cwe=(code or runtime)[0].cwe,
        title="t",
        label=label,
        severity=Severity.HIGH,
        cvss=9.8,
        risk=9.8,
        code_findings=code,
        runtime_findings=runtime,
        primary_code=code[0].code if code else None,
        primary_runtime=runtime[0].runtime if runtime else None,
    )


# --------------------------------------------------------------------------- golden reproduction
def test_fixture_metrics_reproduced(fixture_expected_issues):
    key = load_key(FIXTURES / "answer_key.json")
    got = compute_metrics(fixture_expected_issues, key)
    expected = load_json("expected_metrics.json")
    expected.pop("_comment", None)
    assert got == expected


def test_run_eval_writes_and_matches(tmp_path):
    out = tmp_path / "metrics.json"
    from FlowStopper.evalkit.runner import run_eval

    metrics, written = run_eval(FIXTURES / "answer_key.json", FIXTURES / "expected_issues.json", out)
    assert written == out and out.exists()
    on_disk = json.loads(out.read_text())
    expected = load_json("expected_metrics.json")
    expected.pop("_comment", None)
    assert metrics == expected == on_disk


def test_eval_cli_on_fixtures(tmp_path):
    out = tmp_path / "m.json"
    result = CliRunner().invoke(
        app,
        [
            "eval",
            "--key",
            str(FIXTURES / "answer_key.json"),
            "--issues",
            str(FIXTURES / "expected_issues.json"),
            "--out",
            str(out),
        ],
    )
    assert result.exit_code == 0, result.output
    assert "Code detection" in result.output and out.exists()


def test_eval_cli_requires_issues():
    result = CliRunner().invoke(app, ["eval", "--key", str(FIXTURES / "answer_key.json")])
    assert result.exit_code == 1 and "issues" in result.output


# --------------------------------------------------------------------------- matching-rule branches
def test_path_template_wildcard_and_method_omitted():
    # key path uses a converter token and omits the method -> any method, any id segment matches
    key = AnswerKey.model_validate(
        {
            "app": "t",
            "vulns": [
                {
                    "id": "V1",
                    "cwe": 89,
                    "kind": "pair",
                    "code": {"file": "svc/db.py", "line_start": 10, "line_end": 10},
                    "runtime": {"path": "/api/orders/<int:id>", "param": "id"},
                }
            ],
        }
    )
    issue = _issue(
        Label.CONFIRMED,
        code=[_code_finding(89, "svc/db.py", 11)],  # within +-3 fuzz
        runtime=[_runtime_finding(89, "POST", "/api/orders/42", "id")],
    )
    m = compute_metrics([issue], key)
    assert m["code_detection"]["found"] == 1
    assert m["runtime_detection"]["found"] == 1
    assert m["correct_links"] == {"found": 1, "total": 1, "rate": 1.0}
    assert m["wrong_links"]["count"] == 0


def test_param_none_is_not_param_specific():
    key = AnswerKey.model_validate(
        {
            "app": "t",
            "vulns": [{"id": "H1", "cwe": 693, "kind": "runtime_only", "runtime": {"path": "*", "param": None}}],
        }
    )
    issue = _issue(Label.RUNTIME_ONLY, runtime=[_runtime_finding(693, "GET", "/anything", None)])
    m = compute_metrics([issue], key)
    assert m["runtime_detection"] == {"found": 1, "total": 1, "rate": 1.0}


def test_wrong_link_counted():
    key = AnswerKey.model_validate(
        {
            "app": "t",
            "vulns": [
                {
                    "id": "P1",
                    "cwe": 89,
                    "kind": "pair",
                    "code": {"file": "a.py", "line_start": 10, "line_end": 10},
                    "runtime": {"method": "GET", "path": "/a", "param": "id"},
                },
                {
                    "id": "P2",
                    "cwe": 89,
                    "kind": "pair",
                    "code": {"file": "b.py", "line_start": 20, "line_end": 20},
                    "runtime": {"method": "GET", "path": "/b", "param": "q"},
                },
            ],
        }
    )
    # a Confirmed issue whose code matches P1 but whose runtime matches P2 -> a wrong link
    bad = _issue(
        Label.CONFIRMED,
        code=[_code_finding(89, "a.py", 10)],
        runtime=[_runtime_finding(89, "GET", "/b", "q")],
    )
    m = compute_metrics([bad], key)
    assert m["wrong_links"] == {"count": 1, "confirmed": 1, "rate": 1.0}
    assert m["correct_links"]["found"] == 0


def test_false_alarm_on_decoy_overlap_only_when_reported():
    key = AnswerKey.model_validate(
        {
            "app": "t",
            "vulns": [
                {"id": "S1", "cwe": 798, "kind": "code_only", "code": {"file": "x.py", "line_start": 1, "line_end": 1}}
            ],
            "decoys": [
                {"id": "D1", "cwe": 89, "file": "c.py", "line_start": 5, "line_end": 5, "reason": "parameterised"}
            ],
        }
    )
    reported_fa = _issue(Label.CODE_ONLY, code=[_code_finding(89, "c.py", 6)])  # overlaps decoy, not suppressed
    suppressed = _issue(Label.CODE_ONLY, code=[_code_finding(89, "c.py", 5, suppressed=True)])  # excluded
    m = compute_metrics([reported_fa, suppressed], key)
    assert m["false_alarms"] == {"count": 1, "reported": 1, "rate": 1.0}


def test_is_suppressed_rule():
    assert is_suppressed(_issue(Label.CODE_ONLY, code=[_code_finding(89, "a.py", 1, suppressed=True)])) is True
    assert is_suppressed(_issue(Label.CODE_ONLY, code=[_code_finding(89, "a.py", 1, suppressed=False)])) is False
    assert (
        is_suppressed(
            _issue(
                Label.CONFIRMED,
                code=[_code_finding(89, "a.py", 1, suppressed=True)],
                runtime=[_runtime_finding(89, "GET", "/a", "id")],
            )
        )
        is False
    )


def test_format_table_is_deterministic():
    key = load_key(FIXTURES / "answer_key.json")
    m = compute_metrics([Issue.model_validate(i) for i in load_json("expected_issues.json")], key)
    table = format_metrics_table(m)
    assert "Code detection" in table and "100.0%" in table and "Runtime detection" in table
