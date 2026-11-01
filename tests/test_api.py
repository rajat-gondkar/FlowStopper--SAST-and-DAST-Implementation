"""P5-A1 HTTP API tests (Owner: A).

Offline: FastAPI's TestClient, real SAST on a synthetic Flask tree, a fake `run_dast` / `auto_verify`
(the same fakes as tests/test_pipeline.py), the real correlator and a tmp_path SQLite store.
TestClient runs a request's background tasks before `post()` returns, so a 202 scan has finished
by the time the next request is made. The live Mock A test skips itself when nothing is listening.
"""

from __future__ import annotations

import json

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from FlowStopper import api, pipeline
from FlowStopper.api import create_app
from FlowStopper.cli import app as cli_app
from FlowStopper.correlate.issues import is_suppressed, sort_issues
from FlowStopper.storage import Storage
from tests.conftest import ROOT
from tests.sast_helpers import make_tree
from tests.test_pipeline import APP, MOCK_A_URL, TARGET, FakeAutoVerify, FakeDast, _reachable


@pytest.fixture
def source(tmp_path):
    return make_tree(tmp_path / "src", APP)


@pytest.fixture
def fake_dast(monkeypatch) -> FakeDast:
    fake = FakeDast()
    monkeypatch.setattr(pipeline, "run_dast", fake)
    return fake


@pytest.fixture(autouse=True)
def fake_autoverify(monkeypatch) -> FakeAutoVerify:
    fake = FakeAutoVerify()
    monkeypatch.setattr(pipeline, "auto_verify", fake)
    return fake


@pytest.fixture
def db_path(tmp_path):
    return tmp_path / "scans.db"


@pytest.fixture
def client(db_path, tmp_path):
    return TestClient(create_app(db_path, tmp_path / "api"))


def _post(client: TestClient, source, target: str = TARGET, **options):
    return client.post("/scans", json={"source_path": str(source), "target_url": target, "options": options})


def _scan_ids(db_path) -> list[str]:
    if not db_path.exists():
        return []
    with Storage(db_path) as store:
        return [s["id"] for s in store.list_scans()]


def test_health(client):
    res = client.get("/health")
    assert res.status_code == 200 and res.json()["status"] == "ok" and res.json()["version"]


def test_post_scan_returns_202_and_completes_in_the_background(client, source, fake_dast):
    res = _post(client, source)
    assert res.status_code == 202, res.text
    body = res.json()
    scan_id = body["scan_id"]
    assert body["status"] == "running" and res.headers["location"] == f"/scans/{scan_id}"

    scan = client.get(f"/scans/{scan_id}").json()
    assert scan["status"] == "completed" and scan["error"] is None
    assert "total" in scan["timings_s"] and "dast" in scan["timings_s"]
    assert scan["counts"]["total"] > 0 and scan["counts"]["confirmed"] == 1
    assert scan["truncated"] is False
    assert scan["source"] == str(source) and scan["target"] == TARGET
    assert "config" not in scan
    ((target, _, _),) = fake_dast.calls
    assert target == TARGET


def test_post_scan_maps_options_onto_the_dast_config(client, source, fake_dast, fake_autoverify):
    res = _post(client, source, time_budget=7, allow_host=["svc"], allow_mutating=True, seed=5, autoverify_budget=3)
    assert res.status_code == 202, res.text
    ((_, _, config),) = fake_dast.calls
    assert config.extra_allowed_hosts == ["svc"]
    assert (config.time_budget_s, config.allow_mutating, config.keep_secrets, config.seed) == (7, True, False, 5)
    assert config.auth is None
    assert len(fake_autoverify.calls) == 1
    assert client.get(f"/scans/{res.json()['scan_id']}").json()["seed"] == 5


def test_post_scan_without_autoverify(client, source, fake_dast, fake_autoverify):
    assert _post(client, source, autoverify=False).status_code == 202
    assert fake_autoverify.calls == []


def test_unknown_ids_are_404(client):
    for path in ("/scans/nope", "/issues/nope", "/scans/nope/report", "/scans/nope/sarif"):
        assert client.get(path).status_code == 404, path


def test_failed_scan_is_reported_and_has_no_report(client, source, monkeypatch):
    monkeypatch.setattr(pipeline, "run_dast", FakeDast(error=RuntimeError("boom")))
    res = _post(client, source)
    assert res.status_code == 202
    scan_id = res.json()["scan_id"]
    scan = client.get(f"/scans/{scan_id}").json()
    assert scan["status"] == "failed" and "dast" in scan["error"] and "boom" in scan["error"]
    assert client.get(f"/scans/{scan_id}/report").status_code == 409
    assert client.get(f"/scans/{scan_id}/sarif").status_code == 409


def test_scope_refusal_is_a_400_and_starts_nothing(client, source, db_path, fake_dast, monkeypatch):
    monkeypatch.delenv("ALLOWED_HOSTS", raising=False)
    res = _post(client, source, target="http://example.com")
    assert res.status_code == 400 and "R3" in res.json()["detail"]
    assert fake_dast.calls == [] and _scan_ids(db_path) == []


def test_allow_host_widens_the_scope_like_the_cli(client, source, fake_dast, monkeypatch):
    monkeypatch.delenv("ALLOWED_HOSTS", raising=False)
    assert _post(client, source, target="http://svc:8080", allow_host=["svc"]).status_code == 202


def test_bad_source_path_is_a_400(client, tmp_path, db_path, fake_dast):
    res = _post(client, tmp_path / "missing")
    assert res.status_code == 400 and "not a directory" in res.json()["detail"]
    assert fake_dast.calls == [] and _scan_ids(db_path) == []


def test_malformed_bodies_are_422(client, source, fake_dast):
    assert _post(client, source, bogus=1).status_code == 422
    assert client.post("/scans", json={"target_url": TARGET}).status_code == 422
    assert client.post("/scans", content=b"{not json", headers={"content-type": "application/json"}).status_code == 422
    assert fake_dast.calls == []


@pytest.fixture
def seeded(db_path, fixture_expected_issues):
    with Storage(db_path) as store:
        store.start_scan(source_path="src", target_url=TARGET, config={}, seed=0, scan_id="seeded0001")
        store.save_issues("seeded0001", fixture_expected_issues)
        store.finish_scan("seeded0001", status="completed", timings={"total": 1.0})
    return fixture_expected_issues


def test_issue_filters(client, seeded):
    reported = [i for i in seeded if not is_suppressed(i)]
    everything = client.get("/issues", params={"include_suppressed": "true"}).json()
    assert len(everything) == len(seeded) == 9
    default = client.get("/issues").json()
    assert len(default) == len(reported) == 8
    assert default == client.get("/issues", params={"scan_id": "seeded0001"}).json()

    confirmed = client.get("/issues", params={"label": "confirmed"}).json()
    assert confirmed and all(i["label"] == "confirmed" for i in confirmed)
    assert len(confirmed) == sum(1 for i in reported if i.label.value == "confirmed")
    sqli = client.get("/issues", params={"cwe": 89}).json()
    assert sqli and all(i["cwe"] == 89 for i in sqli)
    risky = client.get("/issues", params={"min_risk": 6.0, "scan_id": "seeded0001"}).json()
    assert risky and all(i["risk"] >= 6.0 for i in risky)
    assert len(risky) == sum(1 for i in reported if i.risk >= 6.0)
    assert [i["id"] for i in default] == [i.id for i in sort_issues(reported)]  # prioritised order
    assert client.get("/issues", params={"label": "bogus"}).status_code == 422


def test_get_issue_returns_the_full_issue(client, seeded):
    issue = next(i for i in seeded if i.label.value == "confirmed")
    body = client.get(f"/issues/{issue.id}").json()
    assert body == issue.model_dump(mode="json")
    for key in ("id", "cwe", "severity", "label", "risk", "title", "fix", "reasons", "primary_code", "primary_runtime"):
        assert key in body, key
    assert body["primary_code"]["file"] and body["primary_runtime"]["url"]  # FR-8: file/line and URL/param


def test_report_and_sarif(client, seeded):
    report = client.get("/scans/seeded0001/report")
    assert report.status_code == 200 and report.headers["content-type"].startswith("text/html")
    assert report.text.startswith("<!DOCTYPE html>")
    sarif = client.get("/scans/seeded0001/sarif")
    assert sarif.status_code == 200 and sarif.headers["content-type"].startswith("application/sarif+json")
    assert isinstance(json.loads(sarif.text), dict)


def test_credentials_are_never_echoed(client, source, fake_dast):
    auth = {
        "headers": {"X-Api": "hdr-zq91"},
        "cookies": {"sid": "ck-zq92"},
        "login": {"url": TARGET + "/login", "json_body": {"user": "u", "password": "pw-zq93"}},
    }
    secrets = ("hdr-zq91", "ck-zq92", "pw-zq93")
    res = _post(client, source, auth=auth)
    assert res.status_code == 202, res.text
    ((_, _, config),) = fake_dast.calls
    assert config.auth is not None and config.auth.headers == {"X-Api": "hdr-zq91"}  # used, not echoed
    scan_id = res.json()["scan_id"]
    texts = [res.text]
    for path in (f"/scans/{scan_id}", "/issues?include_suppressed=true", f"/scans/{scan_id}/report"):
        texts.append(client.get(path).text)
    texts.append(client.get(f"/scans/{scan_id}/sarif").text)
    for text in texts:
        for secret in secrets:
            assert secret not in text, secret

    bad = _post(client, source, auth={"login": {"json_body": {"password": "pw-zq93"}}})  # login.url missing
    assert bad.status_code == 422 and "pw-zq93" not in bad.text


def test_failure_messages_are_scrubbed_of_credentials(client, source, monkeypatch):
    monkeypatch.setattr(pipeline, "run_dast", FakeDast(error=RuntimeError("login rejected for pw-zq94")))
    res = _post(client, source, auth={"login": {"url": TARGET + "/login", "json_body": {"password": "pw-zq94"}}})
    scan = client.get(f"/scans/{res.json()['scan_id']}").json()
    assert scan["status"] == "failed" and "pw-zq94" not in scan["error"] and "[REDACTED]" in scan["error"]


def test_reposting_gives_the_same_issue_ids(client, source, fake_dast):
    first = _post(client, source).json()["scan_id"]
    second = _post(client, source).json()["scan_id"]
    assert first != second

    def ids(scan_id: str) -> list[str]:
        return sorted(
            i["id"] for i in client.get("/issues", params={"scan_id": scan_id, "include_suppressed": True}).json()
        )

    assert ids(first) == ids(second) and ids(first)
    assert len(client.get("/issues", params={"include_suppressed": True}).json()) == len(ids(first))  # upserted


def test_serve_binds_loopback_by_default(monkeypatch, tmp_path):
    monkeypatch.delenv("FLOWSTOPPER_DB", raising=False)
    monkeypatch.delenv("FLOWSTOPPER_OUT", raising=False)
    calls = []
    monkeypatch.setattr(api.uvicorn, "run", lambda app, **kw: calls.append((app, kw)))
    res = CliRunner().invoke(cli_app, ["serve", "--db", str(tmp_path / "s.db")])
    assert res.exit_code == 0, res.output
    ((served, kwargs),) = calls
    assert isinstance(served, FastAPI) and kwargs == {"host": "127.0.0.1", "port": 8000}
    assert served.state.db_path == tmp_path / "s.db"


@pytest.mark.integration
def test_live_api_scan_of_mock_a(tmp_path):
    if not _reachable(MOCK_A_URL):
        pytest.skip(f"Mock A is not running at {MOCK_A_URL}")
    client = TestClient(create_app(tmp_path / "scans.db", tmp_path / "api"))
    res = client.post("/scans", json={"source_path": str(ROOT / "apps" / "mock_a"), "target_url": MOCK_A_URL})
    assert res.status_code == 202, res.text
    scan_id = res.json()["scan_id"]
    scan = client.get(f"/scans/{scan_id}").json()
    assert scan["status"] == "completed" and scan["counts"]["confirmed"] >= 1
    assert client.get(f"/scans/{scan_id}/report").status_code == 200


# --------------------------------------------------------------------------- scores for CLI-run scans
def test_report_of_a_cli_scan_shows_its_scores(source, tmp_path, monkeypatch, fake_dast, db_path):
    """`scan --key` writes evaluation.json; the API finds it through the folder recorded in the store."""
    from tests.test_pipeline import KEY

    key = tmp_path / "key.json"
    key.write_text(json.dumps(KEY), encoding="utf-8")
    out = tmp_path / "cli_out"
    res = CliRunner().invoke(
        cli_app,
        [
            "scan",
            "--source",
            str(source),
            "--target",
            TARGET,
            "--out",
            str(out),
            "--db",
            str(db_path),
            "--key",
            str(key),
        ],
    )
    assert res.exit_code == 0, res.output
    (scan_id,) = _scan_ids(db_path)
    # an API pointed at a different out_root still finds the CLI scan's files
    client = TestClient(create_app(db_path, tmp_path / "elsewhere"))
    html = client.get(f"/scans/{scan_id}/report").text
    assert "scored-demo-app" in html and "Not evaluated" not in html
    assert client.get(f"/scans/{scan_id}").json()["truncated"] is False  # meta found via the recorded folder too


def test_report_of_an_unscored_cli_scan_says_not_evaluated(source, tmp_path, fake_dast, db_path):
    res = CliRunner().invoke(
        cli_app,
        ["scan", "--source", str(source), "--target", TARGET, "--out", str(tmp_path / "o"), "--db", str(db_path)],
    )
    assert res.exit_code == 0, res.output
    (scan_id,) = _scan_ids(db_path)
    client = TestClient(create_app(db_path, tmp_path / "elsewhere"))
    assert "Not evaluated" in client.get(f"/scans/{scan_id}/report").text
