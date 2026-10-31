"""P3-A1 pipeline + `FlowStopper scan` tests (Owner: A).

Offline: real SAST on a synthetic Flask tree, a fake `run_dast` returning a canned DastResult, the
real correlator and real storage on a tmp_path DB. The scope-guard test uses the real `run_dast`,
which refuses the target before opening any connection (R3). The live Mock A test is marked
`integration` and skips itself when nothing is listening.
"""

from __future__ import annotations

import json
import logging
import os
import socket
from pathlib import Path
from urllib.parse import urlsplit

import pytest
from typer.testing import CliRunner

from FlowStopper import pipeline
from FlowStopper.cli import app
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
    assert set(meta["timings_s"]) == {"sast", "dast", "correlate", "store", "write", "total"}
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


def test_cli_fail_on_is_a_logged_no_op_until_p5(source, tmp_path, monkeypatch, fake_dast, caplog):
    monkeypatch.chdir(tmp_path)
    with caplog.at_level(logging.WARNING, logger="FlowStopper.pipeline"):
        res = CliRunner().invoke(
            app, ["scan", "--source", str(source), "--target", TARGET, "--out", "o", "--fail-on", "confirmed:high"]
        )
    assert res.exit_code == 0, res.output  # a Confirmed critical SQLi exists, yet no gate fires yet
    assert any("not implemented until P5" in r.getMessage() for r in caplog.records)


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
