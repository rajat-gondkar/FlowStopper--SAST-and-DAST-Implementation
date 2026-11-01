"""`FlowStopper eval` on stored scans + the organiser-key converter (P3-B1). Owner: B.

The fixture metrics are the oracle: evaluating a stored scan must give exactly the numbers that
evaluating the same issues from a file gives, which pins the storage round trip as well as the
eval wiring. One test drives Dev A's real pipeline (fake DAST, real SAST, real store) so the
P3-A1 -> P3-B1 hand-off is exercised end to end.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from FlowStopper import pipeline
from FlowStopper.cli import app
from FlowStopper.cwe import get_cwe
from FlowStopper.evalkit import convert_organiser_key as conv
from FlowStopper.evalkit.keyschema import AnswerKey, load_key
from FlowStopper.evalkit.metrics import TARGETS, assess, compute_metrics, format_metrics_table
from FlowStopper.evalkit.runner import (
    EvalError,
    build_report,
    issues_from_file,
    issues_from_scan,
    run_eval,
    unplanted_issues,
)
from FlowStopper.ids import runtime_finding_id
from FlowStopper.models import DastResult, Engine, Finding, Issue, Label, ParamLocation, RuntimeLocation, Severity
from FlowStopper.storage import Storage
from tests.conftest import FIXTURES, load_json
from tests.sast_helpers import make_tree

KEY = FIXTURES / "answer_key.json"


def _expected_metrics() -> dict:
    expected = load_json("expected_metrics.json")
    expected.pop("_comment", None)
    return expected


def _store_scan(db: Path, issues: list[Issue], *, status: str = "completed", total: float = 12.5, when: str) -> str:
    with Storage(db) as store:
        sid = store.start_scan(source_path="src", target_url="http://127.0.0.1:8080", started_at=when)
        store.save_issues(sid, issues)
        store.finish_scan(sid, status=status, timings={"sast": 1.0, "total": total})
    return sid


# --------------------------------------------------------------------------- --scan
def test_stored_scan_reproduces_the_fixture_metrics(tmp_path, fixture_expected_issues):
    """Store round trip + eval: same numbers as scoring the file directly (suppressed issues included)."""
    db = tmp_path / "scans.db"
    sid = _store_scan(db, fixture_expected_issues, when="2026-01-01T00:00:00+00:00")
    report, written = run_eval(KEY, out_path=tmp_path / "m.json", scan_id=sid, db_path=db)
    assert report["metrics"] == _expected_metrics()
    assert report["source"] == {"kind": "scan", "scan_id": sid, "issues": None, "db": db.as_posix()}
    assert report["run_time_s"] == 12.5
    assert json.loads(written.read_text(encoding="utf-8"))["metrics"] == _expected_metrics()


def test_scan_and_file_sources_agree(tmp_path, fixture_expected_issues):
    db = tmp_path / "scans.db"
    sid = _store_scan(db, fixture_expected_issues, when="2026-01-01T00:00:00+00:00")
    from_scan, _ = run_eval(KEY, out_path=tmp_path / "a.json", scan_id=sid, db_path=db)
    from_file, _ = run_eval(KEY, FIXTURES / "expected_issues.json", tmp_path / "b.json")
    assert from_scan["metrics"] == from_file["metrics"]
    assert from_scan["unplanted"] == from_file["unplanted"]


def test_latest_picks_the_newest_completed_scan(tmp_path, fixture_expected_issues):
    db = tmp_path / "scans.db"
    older = _store_scan(db, fixture_expected_issues, when="2026-01-01T00:00:00+00:00", total=1.0)
    newer = _store_scan(db, fixture_expected_issues[:1], when="2026-01-02T00:00:00+00:00", total=2.0)
    _store_scan(db, [], status="failed", when="2026-01-03T00:00:00+00:00")  # newest, but failed
    source = issues_from_scan("latest", db)
    assert source.scan_id == newer != older
    assert len(source.issues) == 1 and source.run_time_s == 2.0


def test_failed_scan_is_refused(tmp_path, fixture_expected_issues):
    db = tmp_path / "scans.db"
    sid = _store_scan(db, fixture_expected_issues, status="failed", when="2026-01-01T00:00:00+00:00")
    with pytest.raises(EvalError, match="failed"):
        issues_from_scan(sid, db)


def test_unknown_scan_missing_db_and_no_completed_scan(tmp_path):
    with pytest.raises(EvalError, match="no scan database"):
        issues_from_scan("abc", tmp_path / "missing.db")
    db = tmp_path / "scans.db"
    _store_scan(db, [], status="failed", when="2026-01-01T00:00:00+00:00")
    with pytest.raises(EvalError, match="unknown scan id"):
        issues_from_scan("nope", db)
    with pytest.raises(EvalError, match="no completed scan"):
        issues_from_scan("latest", db)


def test_run_eval_needs_exactly_one_source(tmp_path):
    with pytest.raises(EvalError):
        run_eval(KEY, out_path=tmp_path / "m.json")
    with pytest.raises(EvalError):
        run_eval(KEY, FIXTURES / "expected_issues.json", tmp_path / "m.json", scan_id="x")


# --------------------------------------------------------------------------- --issues + scan_meta.json
def test_issues_file_picks_up_sibling_scan_meta(tmp_path):
    out = tmp_path / "out"
    out.mkdir()
    (out / "issues.json").write_text((FIXTURES / "expected_issues.json").read_text(encoding="utf-8"), encoding="utf-8")
    (out / "scan_meta.json").write_text(
        json.dumps({"scan_id": "s-123", "timings_s": {"total": 42.0}}), encoding="utf-8"
    )
    source = issues_from_file(out / "issues.json")
    assert (source.scan_id, source.run_time_s) == ("s-123", 42.0)


def test_issues_file_without_meta_has_unknown_run_time():
    source = issues_from_file(FIXTURES / "expected_issues.json")
    assert source.run_time_s is None and source.scan_id is None


def test_bad_issues_file_is_an_eval_error(tmp_path):
    bad = tmp_path / "issues.json"
    bad.write_text("{not json", encoding="utf-8")
    with pytest.raises(EvalError, match="not a valid issues.json"):
        issues_from_file(bad)
    with pytest.raises(EvalError, match="cannot read"):
        issues_from_file(tmp_path / "missing.json")


# --------------------------------------------------------------------------- targets / grading
def test_assess_grades_fixture_metrics():
    status = assess(_expected_metrics(), run_time_s=12.5)
    assert status == {
        "code_detection": "great",  # 100%
        "runtime_detection": "good",  # 66.7%: > 50% but not > 80%
        "correct_links": "below",  # 40%: not > 50%
        "wrong_links": "great",  # 0 of 2
        "false_alarms": "great",  # 0 of 8
        "run_time": "great",  # 12.5 s < 5 min
    }


def test_targets_are_strict_comparisons():
    """Spec section 4 says > 60% / < 20%: a value exactly on the line does not reach it."""
    m = _expected_metrics()
    m["code_detection"] = {"found": 6, "total": 10, "rate": 0.6}
    m["wrong_links"] = {"count": 1, "confirmed": 20, "rate": 0.05}
    status = assess(m)
    assert status["code_detection"] == "below"
    assert status["wrong_links"] == "good"
    assert "run_time" not in status  # not graded when unknown


def test_empty_denominator_is_not_graded():
    """0 wrong links out of 0 Confirmed issues must not score 'great' - nothing was linked."""
    m = _expected_metrics()
    m["wrong_links"] = {"count": 0, "confirmed": 0, "rate": 0.0}
    m["correct_links"] = {"found": 0, "total": 0, "rate": 0.0}
    status = assess(m)
    assert status["wrong_links"] == "n/a" and status["correct_links"] == "n/a"


def test_run_time_grades():
    m = _expected_metrics()
    assert assess(m, 299.0)["run_time"] == "great"
    assert assess(m, 600.0)["run_time"] == "good"
    assert assess(m, 900.0)["run_time"] == "below"


def test_table_shows_targets_status_and_run_time():
    table = format_metrics_table(_expected_metrics(), run_time_s=12.5)
    for text in ("Good", "Great", "Status", ">60%", ">85%", "<20%", "<5%", "Run time", "12.5 s", "<15 min"):
        assert text in table, text
    assert format_metrics_table(_expected_metrics()) == format_metrics_table(_expected_metrics())
    assert "Run time" not in format_metrics_table(_expected_metrics())


def test_target_table_matches_spec_section_4():
    assert TARGETS["code_detection"][:2] == (0.60, 0.85)
    assert TARGETS["runtime_detection"][:2] == (0.50, 0.80)
    assert TARGETS["correct_links"][:2] == (0.50, 0.80)
    assert TARGETS["wrong_links"][:2] == (0.20, 0.05)
    assert TARGETS["false_alarms"][:2] == (0.30, 0.10)
    assert TARGETS["run_time"][:2] == (900.0, 300.0)


# --------------------------------------------------------------------------- unplanted + report hygiene
def _unplanted_issue() -> Issue:
    finding = Finding(
        id="extra",
        engine=Engine.DAST,
        tool="FlowStopper-dast",
        rule_id="dast.passive.version-banner",
        cwe=497,
        title="banner",
        severity=Severity.MEDIUM,
        confidence=0.8,
        runtime=RuntimeLocation(method="GET", url="http://h/", path="/", proof="header"),
    )
    return Issue(
        id="extra-issue",
        cwe=497,
        title="banner",
        label=Label.RUNTIME_ONLY,
        severity=Severity.MEDIUM,
        cvss=5.3,
        risk=5.3,
        runtime_findings=[finding],
        primary_runtime=finding.runtime,
    )


def test_unplanted_counts_reported_issues_matching_nothing(fixture_expected_issues):
    key = load_key(KEY)
    assert unplanted_issues(fixture_expected_issues, key) == []  # every fixture issue is planted or a decoy
    extra = _unplanted_issue()
    assert [i.id for i in unplanted_issues([*fixture_expected_issues, extra], key)] == ["extra-issue"]


def test_report_issue_counts_split_reported_and_suppressed(fixture_expected_issues):
    report = build_report(load_key(KEY), KEY, issues_from_file(FIXTURES / "expected_issues.json"))
    # 9 issues: 8 reported + the suppressed list-form subprocess decoy (matches false_alarms.reported)
    assert report["issues"] == {"total": 9, "reported": 8, "suppressed": 1}
    assert report["issues"]["reported"] == report["metrics"]["false_alarms"]["reported"]


def test_report_paths_are_relative_to_the_working_directory(tmp_path, monkeypatch):
    """No machine-specific prefixes in a committed metrics file."""
    monkeypatch.chdir(FIXTURES.parent)
    report = build_report(load_key(KEY), KEY.resolve(), issues_from_file((FIXTURES / "expected_issues.json").resolve()))
    assert report["key"] == "fixtures/answer_key.json"
    assert report["source"]["issues"] == "fixtures/expected_issues.json"
    elsewhere = tmp_path / "issues.json"  # outside the working directory: kept as given
    elsewhere.write_text((FIXTURES / "expected_issues.json").read_text(encoding="utf-8"), encoding="utf-8")
    assert build_report(load_key(KEY), KEY, issues_from_file(elsewhere))["source"]["issues"] == elsewhere.as_posix()


def test_report_holds_counts_not_app_details(fixture_expected_issues):
    """R5: a metrics report for the organisers' app must be safe to commit - no code paths or routes."""
    source = issues_from_file(FIXTURES / "expected_issues.json")
    report = build_report(load_key(KEY), KEY, source)
    text = json.dumps({k: v for k, v in report.items() if k not in ("key", "source")})
    for leak in ("services/store.py", "views/search.py", "/api/items", "SECRET_KEY", "category"):
        assert leak not in text, leak


# --------------------------------------------------------------------------- CLI
def test_eval_cli_scores_a_stored_scan(tmp_path, fixture_expected_issues):
    db = tmp_path / "scans.db"
    sid = _store_scan(db, fixture_expected_issues, when="2026-01-01T00:00:00+00:00")
    out = tmp_path / "m.json"
    res = CliRunner().invoke(app, ["eval", "--key", str(KEY), "--scan", sid, "--db", str(db), "--out", str(out)])
    assert res.exit_code == 0, res.output
    assert f"scan {sid}" in res.output and "Correct links" in res.output and "Run time" in res.output
    assert json.loads(out.read_text(encoding="utf-8"))["metrics"] == _expected_metrics()


def test_eval_cli_latest(tmp_path, fixture_expected_issues):
    db = tmp_path / "scans.db"
    _store_scan(db, fixture_expected_issues, when="2026-01-01T00:00:00+00:00")
    res = CliRunner().invoke(
        app, ["eval", "--key", str(KEY), "--scan", "latest", "--db", str(db), "-o", str(tmp_path / "m.json")]
    )
    assert res.exit_code == 0, res.output


def test_eval_cli_rejects_both_or_neither_source(tmp_path):
    neither = CliRunner().invoke(app, ["eval", "--key", str(KEY)])
    both = CliRunner().invoke(
        app, ["eval", "--key", str(KEY), "--scan", "x", "--issues", str(FIXTURES / "expected_issues.json")]
    )
    assert neither.exit_code == 1 and both.exit_code == 1
    assert "exactly one" in neither.output


def test_eval_cli_reports_unknown_scan_and_bad_key(tmp_path, fixture_expected_issues):
    db = tmp_path / "scans.db"
    _store_scan(db, fixture_expected_issues, when="2026-01-01T00:00:00+00:00")
    res = CliRunner().invoke(app, ["eval", "--key", str(KEY), "--scan", "nope", "--db", str(db)])
    assert res.exit_code == 1 and "unknown scan id" in res.output

    bad_key = tmp_path / "key.json"
    bad_key.write_text(json.dumps({"app": "x", "vulns": [{"id": "V1"}]}), encoding="utf-8")
    res = CliRunner().invoke(app, ["eval", "--key", str(bad_key), "--issues", str(FIXTURES / "expected_issues.json")])
    assert res.exit_code == 1 and "not a valid answer key" in res.output


# --------------------------------------------------------------------------- end to end with Dev A's pipeline
SHOP = {
    "shop/__init__.py": "",
    "shop/app.py": """
        import sqlite3
        from flask import Flask, request

        app = Flask(__name__)
        API_KEY = "AKIAIOSFODNN7EXAMPLE"

        @app.route("/items")
        def items():
            category = request.args.get("category", "")
            db = sqlite3.connect("shop.db")
            return str(db.execute("SELECT * FROM items WHERE category = '" + category + "'").fetchall())
    """,
}
SHOP_KEY = {
    "app": "eval-e2e-shop",
    "vulns": [
        {
            "id": "E1",
            "cwe": 89,
            "kind": "pair",
            "code": {"file": "shop/app.py", "line_start": 11, "line_end": 11},
            "runtime": {"method": "GET", "path": "/items", "param": "category"},
        },
        {"id": "E2", "cwe": 798, "kind": "code_only", "code": {"file": "shop/app.py", "line_start": 5, "line_end": 5}},
    ],
}


def test_eval_scores_a_real_pipeline_scan(tmp_path, monkeypatch):
    """P3-A1 -> P3-B1: scan (real SAST, faked DAST, real correlator + store), then `eval --scan latest`."""

    async def fake_dast(target_url, routes, config):
        route = next(r for r in routes if r.path_template == "/items")
        info = get_cwe(89)
        finding = Finding(
            id=runtime_finding_id(Engine.DAST, "dast.sqli.error", 89, "GET", route.id, "category"),
            engine=Engine.DAST,
            tool="FlowStopper-dast",
            rule_id="dast.sqli.error",
            cwe=89,
            title="SQL injection",
            severity=info.severity,
            confidence=0.9,
            runtime=RuntimeLocation(
                method="GET",
                url=f"{target_url}/items?category=x%27",
                path="/items",
                route_id=route.id,
                param="category",
                param_location=ParamLocation.QUERY,
                payload="x'",
                proof="error",
            ),
        )
        return DastResult(findings=[finding], stats={"requests": 1})

    monkeypatch.setattr(pipeline, "run_dast", fake_dast)
    source = make_tree(tmp_path / "src", SHOP)
    db = tmp_path / "scans.db"
    result = pipeline.run_pipeline(source, "http://127.0.0.1:5999", tmp_path / "out", db_path=db)

    key_path = tmp_path / "key.json"
    key_path.write_text(json.dumps(SHOP_KEY), encoding="utf-8")
    report, _ = run_eval(key_path, out_path=tmp_path / "m.json", scan_id="latest", db_path=db)

    assert report["source"]["scan_id"] == result.scan_id
    m = report["metrics"]
    assert m["code_detection"] == {"found": 2, "total": 2, "rate": 1.0}
    assert m["runtime_detection"] == {"found": 1, "total": 1, "rate": 1.0}
    assert m["correct_links"] == {"found": 1, "total": 1, "rate": 1.0}
    assert m["wrong_links"]["count"] == 0
    assert report["run_time_s"] == result.meta["timings_s"]["total"]

    # the file-based path over the pipeline's own output gives the same answer
    from_file, _ = run_eval(key_path, result.issues_path, tmp_path / "m2.json")
    assert from_file["metrics"] == m and from_file["source"]["scan_id"] == result.scan_id


# --------------------------------------------------------------------------- converter
CSV_KEY = """\
ID,Vulnerability,Location,HTTP Method,Endpoint,Parameter,Status,Notes
V1,SQL Injection,app/views/orders.py:80-95,GET,/api/orders,id,,
V2,CWE-798,app\\config.py:7,,,,,hard-coded key
V3,Missing Security Headers,,,*,,,host-wide
V4,XSS,app/views/search.py:12,get,http://target:5000/search?q=1,q,,
D1,SQL Injection,app/views/products.py:40-46,,,,decoy,parameterised query
"""


def _write(tmp_path: Path, name: str, text: str) -> Path:
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def test_converter_handles_a_typical_csv(tmp_path):
    key = conv.convert_file(_write(tmp_path, "raw.csv", CSV_KEY), app="organisers-app", strip_prefix="app")
    by_id = {v.id: v for v in key.vulns}
    assert by_id["V1"].kind == "pair" and by_id["V1"].cwe == 89
    assert (by_id["V1"].code.file, by_id["V1"].code.line_start, by_id["V1"].code.line_end) == (
        "views/orders.py",
        80,
        95,
    )
    assert by_id["V1"].runtime.method == "GET" and by_id["V1"].runtime.param == "id"
    assert by_id["V2"].kind == "code_only" and by_id["V2"].code.file == "config.py"  # \ and prefix removed
    assert by_id["V3"].kind == "runtime_only" and by_id["V3"].runtime.path == "*"
    assert by_id["V4"].runtime.path == "/search" and by_id["V4"].runtime.method == "GET"  # URL -> path
    assert [d.id for d in key.decoys] == ["D1"] and key.decoys[0].reason == "parameterised query"


def test_converter_reads_json_with_a_container_and_decoys(tmp_path):
    raw = {
        "findings": [
            {
                "ref": "A",
                "type": "Command Injection",
                "file": "svc/net.py",
                "line": "21",
                "route": "/ping",
                "param": "host",
            },
            {"ref": "B", "type": "Path Traversal", "file": "svc/files.py", "line": "9-12"},
        ],
        "decoys": [{"ref": "C", "type": "XSS", "file": "svc/view.py", "line": "4", "comment": "escaped"}],
    }
    key = conv.convert_file(_write(tmp_path, "raw.json", json.dumps(raw)), app="x")
    assert [(v.id, v.cwe, v.kind) for v in key.vulns] == [("A", 78, "pair"), ("B", 22, "code_only")]
    assert key.vulns[1].code.line_end == 12
    assert key.decoys[0].id == "C" and key.decoys[0].reason == "escaped"


def test_converter_map_override_and_boolean_decoy_column(tmp_path):
    text = "Ref,VulnClass,Src,Ln,is_decoy\nX1,89,a.py,3,no\nX2,79,b.py,5,yes\n"
    key = conv.convert_file(
        _write(tmp_path, "raw.csv", text), app="x", overrides={"cwe": "VulnClass", "file": "Src", "line_start": "Ln"}
    )
    assert [v.id for v in key.vulns] == ["X1"] and [d.id for d in key.decoys] == ["X2"]


def test_converter_errors_are_specific(tmp_path):
    with pytest.raises(conv.ConvertError, match="no CWE"):
        conv.convert_file(_write(tmp_path, "a.csv", "id,file,line\n1,a.py,3\n"), app="x")
    with pytest.raises(conv.ConvertError, match="row 1: cannot read a CWE"):
        conv.convert_file(_write(tmp_path, "b.csv", "id,cwe,file,line\n1,Quantum Leak,a.py,3\n"), app="x")
    with pytest.raises(conv.ConvertError, match="no readable line"):
        conv.convert_file(_write(tmp_path, "c.csv", "id,cwe,file,line\n1,89,a.py,\n"), app="x")
    with pytest.raises(conv.ConvertError, match="needs a code location"):
        conv.convert_file(_write(tmp_path, "d.csv", "id,cwe,file,path\n1,89,,\n"), app="x")
    with pytest.raises(conv.ConvertError, match="unknown field"):
        conv.convert_file(_write(tmp_path, "e.csv", "id,cwe\n1,89\n"), app="x", overrides={"colour": "id"})
    with pytest.raises(conv.ConvertError, match="no rows"):
        conv.convert_file(_write(tmp_path, "f.csv", "id,cwe\n"), app="x")


def test_converted_key_validates_and_is_usable_by_eval(tmp_path):
    key = conv.convert_file(_write(tmp_path, "raw.csv", CSV_KEY), app="organisers-app")
    assert isinstance(AnswerKey.model_validate(key.model_dump(mode="json")), AnswerKey)
    metrics = compute_metrics([], key)
    # V1, V2, V4 have a code location; V1, V3, V4 a runtime one; V1 and V4 are pairs. D1 is a decoy.
    assert metrics["code_detection"]["total"] == 3
    assert metrics["runtime_detection"]["total"] == 3
    assert metrics["correct_links"]["total"] == 2


def test_git_ignore_guard():
    assert conv.is_git_ignored_path(Path("keys/answer_key.json"))
    assert conv.is_git_ignored_path(Path("some/dir/keys/k.json"))
    assert conv.is_git_ignored_path(Path("out/organisers.key.json"))
    assert not conv.is_git_ignored_path(Path("docs/answer_key.json"))
    assert not conv.is_git_ignored_path(Path("monkeys.json"))


def test_converter_cli_writes_and_warns_outside_keys(tmp_path, capsys):
    raw = _write(tmp_path, "raw.csv", CSV_KEY)
    safe_out = tmp_path / "keys" / "answer_key.json"
    assert conv.main([str(raw), "-o", str(safe_out), "--app", "organisers-app"]) == 0
    assert load_key(safe_out).app == "organisers-app"
    assert "WARNING" not in capsys.readouterr().err

    risky_out = tmp_path / "answer_key.json"
    assert conv.main([str(raw), "-o", str(risky_out)]) == 0
    assert "rule R5" in capsys.readouterr().err

    assert conv.main([str(tmp_path / "missing.csv")]) == 1
