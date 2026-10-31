"""`FlowStopper report` CLI tests (Owner: B, P5 step 5) incl. the CI-gate exit-code test (P5-B2 / B-6).

Exit codes: 0 ok, 1 error, 2 gate tripped. Input errors must never exit 2.
"""

from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from FlowStopper.cli import app
from FlowStopper.models import Label, Severity
from FlowStopper.report.gate import GATE_EXIT_CODE
from tests.conftest import FIXTURES

ISSUES = FIXTURES / "expected_issues.json"


def _invoke(*args: str):
    return CliRunner().invoke(app, ["report", *args])


@pytest.fixture
def meta_file(tmp_path):
    path = tmp_path / "scan_meta.json"
    path.write_text(json.dumps({"scan_id": "s1", "target": "http://127.0.0.1:9", "timings_s": {"total": 1.5}}))
    return path


def test_writes_all_three_formats(tmp_path, meta_file):
    html, sarif, md = tmp_path / "r" / "r.html", tmp_path / "r" / "r.sarif", tmp_path / "r" / "r.md"
    res = _invoke(
        "--issues", str(ISSUES), "--meta", str(meta_file), "--html", str(html), "--sarif", str(sarif), "--md", str(md)
    )
    assert res.exit_code == 0, res.output
    assert html.read_text(encoding="utf-8").startswith("<!DOCTYPE html>")
    assert "http://127.0.0.1:9" in html.read_text(encoding="utf-8")
    log = json.loads(sarif.read_text(encoding="utf-8"))
    assert log["version"] == "2.1.0" and log["runs"][0]["automationDetails"]["id"] == "flowstopper/s1"
    assert md.read_text(encoding="utf-8").startswith("# FlowStopper findings")
    assert "9 issue(s): 8 reported, 1 suppressed" in res.output


def test_meta_is_optional(tmp_path):
    out = tmp_path / "r.md"
    res = _invoke("--issues", str(ISSUES), "--md", str(out))
    assert res.exit_code == 0, res.output
    assert out.exists()


def test_output_is_byte_identical_across_runs(tmp_path, meta_file):
    a, b = tmp_path / "a.sarif", tmp_path / "b.sarif"
    assert _invoke("--issues", str(ISSUES), "--meta", str(meta_file), "--sarif", str(a)).exit_code == 0
    assert _invoke("--issues", str(ISSUES), "--meta", str(meta_file), "--sarif", str(b)).exit_code == 0
    assert a.read_bytes() == b.read_bytes()


# --------------------------------------------------------------------------- the CI gate
def test_gate_trips_with_exit_code_2_on_a_confirmed_high(tmp_path):
    sarif = tmp_path / "r.sarif"
    res = _invoke("--issues", str(ISSUES), "--sarif", str(sarif), "--fail-on", "confirmed:high")
    assert res.exit_code == GATE_EXIT_CODE == 2, res.output
    assert sarif.exists()  # reports are written before the gate decides
    assert "tripped by 1 issue(s)" in res.output


def test_gate_passes_with_exit_code_0(tmp_path):
    issues = [i for i in json.loads(ISSUES.read_text()) if i["label"] != Label.CONFIRMED.value]
    path = tmp_path / "issues.json"
    path.write_text(json.dumps(issues))
    res = _invoke("--issues", str(path), "--fail-on", "confirmed:low")
    assert res.exit_code == 0, res.output
    assert "passed" in res.output


def test_gate_ignores_suppressed_issues(tmp_path):
    raw = json.loads(ISSUES.read_text())
    only_suppressed = [i for i in raw if all(f["suppressed"] for f in i["code_findings"] + i["runtime_findings"])]
    assert only_suppressed and only_suppressed[0]["severity"] == Severity.CRITICAL.value
    path = tmp_path / "issues.json"
    path.write_text(json.dumps(only_suppressed))
    assert _invoke("--issues", str(path), "--fail-on", "any:info").exit_code == 0


@pytest.mark.parametrize(
    "args",
    [
        [],  # no --issues
        ["--issues", "ISSUES"],  # nothing to do
        ["--issues", "ISSUES", "--fail-on", "confirmed-high"],  # malformed gate
        ["--issues", "MISSING", "--md", "OUT"],
        ["--issues", "BADJSON", "--md", "OUT"],
        ["--issues", "NOTLIST", "--md", "OUT"],
        ["--issues", "ISSUES", "--meta", "BADJSON", "--md", "OUT"],
    ],
)
def test_input_errors_exit_1_never_the_gate_code(tmp_path, args):
    bad = tmp_path / "bad.json"
    bad.write_text("{nope")
    not_list = tmp_path / "obj.json"
    not_list.write_text("{}")
    subst = {
        "ISSUES": str(ISSUES),
        "MISSING": str(tmp_path / "missing.json"),
        "BADJSON": str(bad),
        "NOTLIST": str(not_list),
        "OUT": str(tmp_path / "out.md"),
    }
    res = _invoke(*[subst.get(a, a) for a in args])
    assert res.exit_code == 1, res.output
