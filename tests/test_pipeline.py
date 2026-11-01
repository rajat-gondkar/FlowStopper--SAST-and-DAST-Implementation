"""P3-A1 pipeline + `FlowStopper scan` tests (Owner: A).

Offline: real SAST on a synthetic Flask tree, a fake `run_dast` returning a canned DastResult, the
real correlator and real storage on a tmp_path DB. The scope-guard test uses the real `run_dast`,
which refuses the target before opening any connection (R3). The live Mock A test is marked
`integration` and skips itself when nothing is listening.
"""

from __future__ import annotations

import json
import os
import socket
import sys
from pathlib import Path
from urllib.parse import urlsplit

import pytest
from typer.testing import CliRunner

from FlowStopper import pipeline
from FlowStopper.cli import EX_USAGE, app, main
from FlowStopper.correlate.autoverify import AutoVerifyResult
from FlowStopper.cwe import get_cwe
from FlowStopper.dast.config import DastConfig
from FlowStopper.ids import runtime_finding_id
from FlowStopper.models import DastResult, Engine, Finding, Label, ParamLocation, Route, RuntimeLocation
from FlowStopper.pipeline import PipelineError, run_pipeline
from FlowStopper.storage import Storage
from tests.conftest import ROOT
from tests.sast_helpers import make_tree

TARGET = "http://127.0.0.1:5999"  # never contacted: DAST is faked in every test but the scope one

APP = {
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

        @app.route("/about")
        def about():
            return "about"
    """,
}


def _runtime(cwe: int, rule_id: str, path: str, param: str, route_id: str | None) -> Finding:
    info = get_cwe(cwe)
    return Finding(
        id=runtime_finding_id(Engine.DAST, rule_id, cwe, "GET", route_id or path, param),
        engine=Engine.DAST,
        tool="FlowStopper-dast",
        rule_id=rule_id,
        cwe=cwe,
        title=f"{info.name} at {path}",
        severity=info.severity,
        confidence=0.9,
        runtime=RuntimeLocation(
            method="GET",
            url=f"{TARGET}{path}?{param}=x",
            path=path,
            route_id=route_id,
            param=param,
            param_location=ParamLocation.QUERY,
            payload="x'",
            proof="error",
            evidence="canned finding",
        ),
    )


class FakeDast:
    """Stands in for `run_dast`: records its inputs and returns a canned result."""

    def __init__(self, *, truncated: bool = False, error: Exception | None = None) -> None:
        self.truncated = truncated
        self.error = error
        self.calls: list[tuple[str, list[Route], DastConfig]] = []

    async def __call__(self, target_url: str, routes: list[Route], config: DastConfig) -> DastResult:
        self.calls.append((target_url, routes, config))
        if self.error is not None:
            raise self.error
        items = next(r for r in routes if r.path_template == "/items")
        findings = [
            _runtime(89, "dast.sqli.error", "/items", "category", items.id),  # links to the SAST flow
            _runtime(79, "dast.xss.reflected", "/echo", "q", None),  # no code side: runtime-only
        ]
        stats = {"requests": 42, "findings": len(findings), "truncated": self.truncated, "seed": config.seed}
        return DastResult(findings=findings, stats=stats)


@pytest.fixture
def source(tmp_path) -> Path:
    return make_tree(tmp_path / "src", APP)


@pytest.fixture
def fake_dast(monkeypatch) -> FakeDast:
    fake = FakeDast()
    monkeypatch.setattr(pipeline, "run_dast", fake)
    return fake


class FakeAutoVerify:
    """Stands in for `auto_verify`: records its inputs, upgrades nothing, sends no request."""

    def __init__(self, *, error: Exception | None = None) -> None:
        self.error = error
        self.calls: list[tuple[str, DastConfig, float | None]] = []

    async def __call__(self, issues, routes, target_url, dast_config, correlate_config=None, deadline=None):
        self.calls.append((target_url, dast_config, deadline))
        if self.error is not None:
            raise self.error
        eligible = sum(1 for i in issues if i.label is Label.CODE_ONLY)
        return AutoVerifyResult(issues=list(issues), stats={"eligible": eligible, "upgraded": 0, "truncated": False})


@pytest.fixture(autouse=True)
def fake_autoverify(monkeypatch) -> FakeAutoVerify:
    """Keeps every test offline: auto-verify would otherwise send probes to the target."""
    fake = FakeAutoVerify()
    monkeypatch.setattr(pipeline, "auto_verify", fake)
    return fake


def _scan(source: Path, out: Path, db: Path, **kwargs):
    return run_pipeline(source, TARGET, out, db_path=db, **kwargs)


def test_scan_writes_issues_and_meta(source, tmp_path, fake_dast):
    result = _scan(source, tmp_path / "out", tmp_path / "scans.db")

    issues = json.loads((tmp_path / "out" / "issues.json").read_text(encoding="utf-8"))
    meta = json.loads((tmp_path / "out" / "scan_meta.json").read_text(encoding="utf-8"))
    assert [i["id"] for i in issues] == [i.id for i in result.issues]
    labels = {i.label for i in result.issues}
    assert {Label.CONFIRMED, Label.CODE_ONLY, Label.RUNTIME_ONLY} <= labels  # SQLi pair, secret, XSS
    # DAST was seeded with the SAST routes.
    ((target, routes, _),) = fake_dast.calls
    assert target == TARGET and routes == result.sast.routes

    assert meta["scan_id"] == result.scan_id and meta["status"] == "completed"
    assert set(meta["timings_s"]) == {"sast", "dast", "correlate", "autoverify", "store", "write", "total"}
    assert all(isinstance(v, float) and v >= 0 for v in meta["timings_s"].values())
    assert meta["seed"] == 0
    assert meta["truncated"] is False
    assert meta["versions"]["FlowStopper"] and meta["versions"]["python"] and meta["versions"]["httpx"]
    assert meta["counts"]["issues"]["total"] == len(issues)
    assert meta["counts"]["dast_findings"] == 2


def test_issues_json_holds_no_run_specific_data(source, tmp_path, fake_dast):
    result = _scan(source, tmp_path / "out", tmp_path / "scans.db")
    text = (tmp_path / "out" / "issues.json").read_text(encoding="utf-8")
    assert result.scan_id not in text
    assert result.meta["started_at"] not in text


def test_two_scans_give_identical_issues(source, tmp_path, fake_dast):
    db = tmp_path / "scans.db"
    first = _scan(source, tmp_path / "out1", db)
    second = _scan(source, tmp_path / "out2", db)

    assert first.scan_id != second.scan_id  # two real scans, even when both start in the same second
    assert [i.id for i in first.issues] == [i.id for i in second.issues]
    assert (tmp_path / "out1" / "issues.json").read_bytes() == (tmp_path / "out2" / "issues.json").read_bytes()
    assert first.meta["counts"] == second.meta["counts"]
    with Storage(db) as store:
        # Upsert on issues.id: the second scan re-saved the same rows instead of adding new ones.
        assert sorted(i.id for i in store.get_issues(include_suppressed=True)) == sorted(i.id for i in first.issues)
        assert store.counts_by_label(first.scan_id) == store.counts_by_label(second.scan_id)
        scan = store.get_scan(second.scan_id)
        assert scan["status"] == "completed" and scan["seed"] == 0 and "total" in scan["timings"]


def test_truncated_dast_still_completes(source, tmp_path, monkeypatch):
    monkeypatch.setattr(pipeline, "run_dast", FakeDast(truncated=True))
    result = _scan(source, tmp_path / "out", tmp_path / "scans.db")
    meta = json.loads(result.meta_path.read_text(encoding="utf-8"))
    assert meta["status"] == "completed" and meta["truncated"] is True
    assert (tmp_path / "out" / "issues.json").is_file()


def test_failing_stage_raises_and_marks_the_scan_failed(source, tmp_path, monkeypatch):
    monkeypatch.setattr(pipeline, "run_dast", FakeDast(error=RuntimeError("boom")))
    db = tmp_path / "scans.db"
    with pytest.raises(PipelineError) as err:
        _scan(source, tmp_path / "out", db)
    assert err.value.stage == "dast"
    assert not (tmp_path / "out" / "issues.json").exists()
    with Storage(db) as store:
        (scan,) = store.list_scans()
        assert scan["status"] == "failed" and "sast" in scan["timings"]


# --------------------------------------------------------------------------- CLI


def test_cli_scan_maps_options_onto_dast_config(source, tmp_path, monkeypatch, fake_dast):
    monkeypatch.chdir(tmp_path)  # the default DB path (.flowstopper/scans.db) lands in tmp_path
    args = ["scan", "--source", str(source), "--target", TARGET, "--out", "o", "--time-budget", "7"]
    args += ["--allow-host", "svc", "--allow-mutating", "--keep-secrets", "--seed", "5"]
    res = CliRunner().invoke(app, args)
    assert res.exit_code == 0, res.output
    assert "confirmed 1" in res.output
    ((_, _, config),) = fake_dast.calls
    assert config.extra_allowed_hosts == ["svc"]
    assert (config.time_budget_s, config.allow_mutating, config.keep_secrets, config.seed) == (7, True, True, 5)
    assert (tmp_path / "o" / "issues.json").is_file() and (tmp_path / ".flowstopper" / "scans.db").is_file()
    assert json.loads((tmp_path / "o" / "scan_meta.json").read_text(encoding="utf-8"))["seed"] == 5


def test_scan_auto_verifies_after_correlation(source, tmp_path, fake_dast, fake_autoverify):
    result = _scan(source, tmp_path / "out", tmp_path / "scans.db", autoverify_budget_s=9)
    ((target, config, deadline),) = fake_autoverify.calls
    assert target == TARGET and config is fake_dast.calls[0][2] and deadline is not None
    meta = json.loads(result.meta_path.read_text(encoding="utf-8"))
    assert meta["autoverify"]["enabled"] is True and meta["autoverify"]["upgraded"] == 0
    assert meta["autoverify"]["eligible"] == sum(1 for i in result.issues if i.label is Label.CODE_ONLY)
    assert "autoverify" in meta["timings_s"]


def test_scan_without_autoverify_sends_no_probes(source, tmp_path, fake_dast, fake_autoverify):
    result = _scan(source, tmp_path / "out", tmp_path / "scans.db", autoverify=False)
    assert fake_autoverify.calls == []
    assert result.meta["autoverify"] == {"enabled": False} and "autoverify" not in result.meta["timings_s"]


def test_autoverify_scope_refusal_fails_the_scan(source, tmp_path, fake_dast, monkeypatch):
    monkeypatch.setattr(pipeline, "auto_verify", FakeAutoVerify(error=pipeline.ScopeError(TARGET, "not allowed")))
    with pytest.raises(PipelineError) as err:
        _scan(source, tmp_path / "out", tmp_path / "scans.db")
    assert err.value.stage == "autoverify" and "R3" in str(err.value)


def test_cli_scan_passes_auth_config_to_dast_and_autoverify(source, tmp_path, monkeypatch, fake_dast, fake_autoverify):
    monkeypatch.chdir(tmp_path)
    auth_file = tmp_path / "auth.json"
    login = {"url": f"{TARGET}/login", "method": "POST", "json_body": {"username": "u", "password": "pw-zq81"}}
    auth_file.write_text(json.dumps({"login": login, "headers": {"X-Env": "env-zq82"}}), encoding="utf-8")
    args = ["scan", "--source", str(source), "--target", TARGET, "--out", "o", "--auth-config", str(auth_file)]
    args += ["--header", "X-Extra: hdr-zq83", "--cookie", "sid=ck-zq84", "--autoverify-budget", "5"]
    res = CliRunner().invoke(app, args)
    assert res.exit_code == 0, res.output
    ((_, _, config),) = fake_dast.calls
    assert config.auth is not None and config.auth.login is not None
    assert config.auth.headers == {"X-Env": "env-zq82", "X-Extra": "hdr-zq83"}
    assert config.auth.cookies == {"sid": "ck-zq84"}
    ((_, av_config, _),) = fake_autoverify.calls
    assert av_config.auth == config.auth  # auto-verify authenticates the same way DAST did
    # R7: no credential value reaches scan_meta.json or the store; only the shape is recorded.
    meta_text = (tmp_path / "o" / "scan_meta.json").read_text(encoding="utf-8")
    with Storage(tmp_path / ".flowstopper" / "scans.db") as store:
        (scan,) = store.list_scans()
        stored = json.dumps(scan, default=str)
    for secret in ("pw-zq81", "env-zq82", "hdr-zq83", "ck-zq84"):
        assert secret not in meta_text and secret not in stored, secret
    snap = json.loads(meta_text)["config"]["dast"]["auth"]
    assert snap["header_names"] == ["X-Env", "X-Extra"] and snap["cookie_names"] == ["sid"]
    assert snap["login"]["redacted"] is True and "json_body" not in snap["login"]


def test_cli_scan_no_autoverify_flag(source, tmp_path, monkeypatch, fake_dast, fake_autoverify):
    monkeypatch.chdir(tmp_path)
    res = CliRunner().invoke(
        app, ["scan", "--source", str(source), "--target", TARGET, "--out", "o", "--no-autoverify"]
    )
    assert res.exit_code == 0, res.output
    assert fake_autoverify.calls == []


def test_cli_scan_rejects_a_bad_auth_config(source, tmp_path, monkeypatch, fake_dast):
    monkeypatch.chdir(tmp_path)
    bad = tmp_path / "auth.json"
    bad.write_text("{not json", encoding="utf-8")
    res = CliRunner().invoke(app, ["scan", "--source", str(source), "--target", TARGET, "--auth-config", str(bad)])
    assert res.exit_code == 1 and "authentication" in res.output
    assert fake_dast.calls == []


def test_cli_scan_refuses_an_out_of_scope_target(source, tmp_path, monkeypatch):
    """Real run_dast: the R3 guard refuses the host before any connection is opened."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("ALLOWED_HOSTS", raising=False)
    res = CliRunner().invoke(app, ["scan", "--source", str(source), "--target", "http://example.com", "--out", "o"])
    assert res.exit_code == 1
    assert "R3" in res.output
    assert not (tmp_path / "o" / "issues.json").exists()


def test_cli_scan_rejects_a_bad_source_dir(tmp_path, monkeypatch, fake_dast):
    monkeypatch.chdir(tmp_path)
    res = CliRunner().invoke(app, ["scan", "--source", str(tmp_path / "missing"), "--target", TARGET])
    assert res.exit_code == 1
    assert "not a directory" in res.output
    assert fake_dast.calls == []


REPORT_FILES = ("issues.json", "scan_meta.json", "report.html", "issues.sarif", "findings.md")


def test_cli_scan_writes_the_reports_next_to_issues_json(source, tmp_path, monkeypatch, fake_dast):
    monkeypatch.chdir(tmp_path)
    res = CliRunner().invoke(app, ["scan", "--source", str(source), "--target", TARGET, "--out", "o"])
    assert res.exit_code == 0, res.output
    out = tmp_path / "o"
    assert all((out / name).is_file() for name in REPORT_FILES)
    assert (out / "report.html").read_text(encoding="utf-8").startswith("<!DOCTYPE html>")
    assert isinstance(json.loads((out / "issues.sarif").read_text(encoding="utf-8")), dict)
    assert (out / "findings.md").read_text(encoding="utf-8").strip()
    assert "report.html" in res.output and "issues.sarif" in res.output and "findings.md" in res.output


def test_cli_fail_on_trips_the_gate_and_still_writes_outputs(source, tmp_path, monkeypatch, fake_dast):
    monkeypatch.chdir(tmp_path)
    res = CliRunner().invoke(
        app, ["scan", "--source", str(source), "--target", TARGET, "--out", "o", "--fail-on", "confirmed:high"]
    )
    assert res.exit_code == 2, res.output  # the Confirmed SQLi is critical, which is >= high
    assert all((tmp_path / "o" / name).is_file() for name in REPORT_FILES)


def _main_exit(monkeypatch, *args: str) -> int:
    """Run the real console entry point (`cli.main`), which owns the exit-code mapping (A-64)."""
    monkeypatch.setattr(sys, "argv", ["FlowStopper", *args])
    with pytest.raises(SystemExit) as exc:
        main()
    return exc.value.code


@pytest.mark.parametrize(
    ("spec", "code"),
    [("confirmed:high", 2), ("CONFIRMED:critical", 2), ("any:critical", 2), ("runtime_only:high", 0)],
)
def test_main_gate_exit_codes(source, tmp_path, monkeypatch, fake_dast, spec, code):
    monkeypatch.chdir(tmp_path)
    # The only runtime-only issue is the medium XSS, so runtime_only:high stays open.
    assert _main_exit(monkeypatch, "scan", "--source", str(source), "--target", TARGET, "--fail-on", spec) == code


def test_main_invalid_fail_on_is_a_usage_error_before_scanning(source, tmp_path, monkeypatch, fake_dast, capsys):
    monkeypatch.chdir(tmp_path)
    args = ["scan", "--source", str(source), "--target", TARGET, "--out", "o", "--fail-on", "code-only:high"]
    assert _main_exit(monkeypatch, *args) == EX_USAGE
    assert "--fail-on" in capsys.readouterr().err
    assert fake_dast.calls == [] and not (tmp_path / "o").exists()


def test_main_exit_codes_for_usage_errors_and_failures(tmp_path, monkeypatch, fake_dast):
    monkeypatch.chdir(tmp_path)
    assert _main_exit(monkeypatch, "scan", "--bogus") == EX_USAGE
    assert _main_exit(monkeypatch, "no-such-command") == EX_USAGE
    assert _main_exit(monkeypatch, "--version") == 0
    assert _main_exit(monkeypatch, "scan", "--help") == 0
    assert _main_exit(monkeypatch, "scan", "--source", str(tmp_path / "missing"), "--target", TARGET) == 1


def test_cli_scan_db_option_and_env(source, tmp_path, monkeypatch, fake_dast):
    monkeypatch.chdir(tmp_path)
    res = CliRunner().invoke(app, ["scan", "--source", str(source), "--target", TARGET, "--out", "o", "--db", "x/s.db"])
    assert res.exit_code == 0, res.output
    assert (tmp_path / "x" / "s.db").is_file()
    monkeypatch.setenv("FLOWSTOPPER_DB", str(tmp_path / "env" / "e.db"))
    res = CliRunner().invoke(app, ["scan", "--source", str(source), "--target", TARGET, "--out", "o2"])
    assert res.exit_code == 0, res.output
    assert (tmp_path / "env" / "e.db").is_file() and not (tmp_path / ".flowstopper").exists()


def test_run_pipeline_uses_a_reserved_scan_id(source, tmp_path, fake_dast):
    db = tmp_path / "scans.db"
    with Storage(db) as store:
        store.start_scan(source_path=str(source), target_url=TARGET, config={}, seed=0, scan_id="reserved01")
    result = _scan(source, tmp_path / "out", db, scan_id="reserved01")
    assert result.scan_id == "reserved01" and result.meta["scan_id"] == "reserved01"
    with Storage(db) as store:
        (scan,) = store.list_scans()  # upserted, not duplicated
        assert scan["id"] == "reserved01" and scan["status"] == "completed"


# --------------------------------------------------------------------------- live (optional)

MOCK_A_URL = os.environ.get("FLOWSTOPPER_MOCK_A_URL", "http://127.0.0.1:5050")


def _reachable(url: str) -> bool:
    parts = urlsplit(url)
    try:
        with socket.create_connection((parts.hostname, parts.port or 80), timeout=0.5):
            return True
    except OSError:
        return False


@pytest.mark.integration
def test_live_scan_of_mock_a(tmp_path):
    if not _reachable(MOCK_A_URL):
        pytest.skip(f"Mock A is not running at {MOCK_A_URL}")
    result = run_pipeline(ROOT / "apps" / "mock_a", MOCK_A_URL, tmp_path / "out", db_path=tmp_path / "scans.db")
    assert result.meta["status"] == "completed"
    assert result.meta["counts"]["issues"]["confirmed"] >= 1
    assert (tmp_path / "out" / "issues.json").is_file()


# --------------------------------------------------------------------------- scan --key (scores on the report)
KEY = {
    "schema_version": "1",
    "app": "scored-demo-app",
    "language": "python",
    "vulns": [
        {
            "id": "V1",
            "cwe": 89,
            "kind": "pair",
            "code": {"file": "shop/app.py", "line_start": 1, "line_end": 40},
            "runtime": {"method": "GET", "path": "/items", "param": "category"},
        }
    ],
    "decoys": [],
}


def _write_key(tmp_path, data=None) -> Path:
    path = tmp_path / "key.json"
    path.write_text(json.dumps(KEY if data is None else data), encoding="utf-8")
    return path


def test_cli_scan_key_scores_the_scan_and_fills_the_evaluation_tab(source, tmp_path, monkeypatch, fake_dast):
    monkeypatch.chdir(tmp_path)
    res = CliRunner().invoke(
        app, ["scan", "--source", str(source), "--target", TARGET, "--out", "o", "--key", str(_write_key(tmp_path))]
    )
    assert res.exit_code == 0, res.output
    assert "Code detection" in res.output and "Correct links" in res.output  # the table is printed
    evaluation = json.loads((tmp_path / "o" / "evaluation.json").read_text(encoding="utf-8"))
    assert evaluation["app"] == "scored-demo-app" and set(evaluation["metrics"]) >= {"code_detection", "correct_links"}
    html = (tmp_path / "o" / "report.html").read_text(encoding="utf-8")
    assert "scored-demo-app" in html and "Not evaluated" not in html


def test_cli_scan_without_key_says_not_evaluated(source, tmp_path, monkeypatch, fake_dast):
    monkeypatch.chdir(tmp_path)
    res = CliRunner().invoke(app, ["scan", "--source", str(source), "--target", TARGET, "--out", "o"])
    assert res.exit_code == 0, res.output
    assert not (tmp_path / "o" / "evaluation.json").exists()
    assert "Not evaluated" in (tmp_path / "o" / "report.html").read_text(encoding="utf-8")


def test_cli_scan_rejects_a_bad_key_before_scanning(source, tmp_path, monkeypatch, fake_dast):
    monkeypatch.chdir(tmp_path)
    bad = _write_key(tmp_path, {"app": "x", "vulns": [{"id": "V1", "cwe": 89, "kind": "pair"}]})
    res = CliRunner().invoke(app, ["scan", "--source", str(source), "--target", TARGET, "--key", str(bad)])
    assert res.exit_code == 1 and "answer key" in res.output
    assert fake_dast.calls == [], "a bad key must fail before any request is sent"


def test_scan_records_its_output_folder_in_the_store_but_not_in_scan_meta(source, tmp_path, fake_dast):
    result = _scan(source, tmp_path / "out", tmp_path / "scans.db")
    with Storage(tmp_path / "scans.db") as store:
        row = store.get_scan(result.scan_id)
    assert row["config"]["output"]["dir"] == str((tmp_path / "out").resolve())
    assert "output" not in result.meta["config"]  # a local path does not belong in the shared meta file


# --------------------------------------------------------------------------- scan --unseen-from
FIRST_RUN = {
    "app": "held-out-demo",
    "evaluated_at": "2026-10-31T22:16:12+00:00",
    "metrics": {"correct_links": {"found": 6, "total": 10, "rate": 0.6}},
}


def _first_run_file(tmp_path, data=None) -> Path:
    path = tmp_path / "first_run.json"
    path.write_text(json.dumps(FIRST_RUN if data is None else data), encoding="utf-8")
    return path


def test_cli_scan_unseen_from_fills_the_unseen_app_row_with_the_first_run(source, tmp_path, monkeypatch, fake_dast):
    monkeypatch.chdir(tmp_path)
    args = ["scan", "--source", str(source), "--target", TARGET, "--out", "o", "--key", str(_write_key(tmp_path))]
    res = CliRunner().invoke(app, args + ["--unseen-from", str(_first_run_file(tmp_path))])
    assert res.exit_code == 0, res.output
    saved = json.loads((tmp_path / "o" / "evaluation.json").read_text(encoding="utf-8"))
    assert saved["metrics"]["unseen_app"] == {
        "found": 6,
        "total": 10,
        "rate": 0.6,
        "note": "First run on held-out-demo (2026-10-31), before any tuning. Not the current score.",
    }
    html = (tmp_path / "o" / "report.html").read_text(encoding="utf-8")
    assert "6/10" in html and "First run on held-out-demo" in html and "not part of this evaluation" not in html


def test_cli_scan_without_unseen_from_leaves_the_row_unmeasured(source, tmp_path, monkeypatch, fake_dast):
    monkeypatch.chdir(tmp_path)
    args = ["scan", "--source", str(source), "--target", TARGET, "--out", "o", "--key", str(_write_key(tmp_path))]
    assert CliRunner().invoke(app, args).exit_code == 0
    saved = json.loads((tmp_path / "o" / "evaluation.json").read_text(encoding="utf-8"))
    assert "unseen_app" not in saved["metrics"]
    assert "not part of this evaluation" in (tmp_path / "o" / "report.html").read_text(encoding="utf-8")


@pytest.mark.parametrize(
    "bad",
    [
        {"metrics": {}},
        {"metrics": {"correct_links": {"found": 3, "total": 0}}},
        {"metrics": {"correct_links": {"found": 11, "total": 10}}},
    ],
)
def test_cli_scan_rejects_a_bad_unseen_from_file_before_scanning(source, tmp_path, monkeypatch, fake_dast, bad):
    monkeypatch.chdir(tmp_path)
    args = ["scan", "--source", str(source), "--target", TARGET, "--key", str(_write_key(tmp_path))]
    res = CliRunner().invoke(app, args + ["--unseen-from", str(_first_run_file(tmp_path, bad))])
    assert res.exit_code == 1 and "--unseen-from" in res.output
    assert fake_dast.calls == []


def test_cli_scan_unseen_from_needs_a_key(source, tmp_path, monkeypatch, fake_dast):
    monkeypatch.chdir(tmp_path)
    args = ["scan", "--source", str(source), "--target", TARGET, "--unseen-from", str(_first_run_file(tmp_path))]
    res = CliRunner().invoke(app, args)
    assert res.exit_code == 1 and "needs --key" in res.output and fake_dast.calls == []
