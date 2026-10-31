"""SQLite storage tests (P2-B5). Owner: B. Covers FR-6 upsert/idempotency and the filters."""

from __future__ import annotations

import json

from FlowStopper.correlate.issues import is_suppressed, sort_issues
from FlowStopper.models import (
    CodeLocation,
    Engine,
    Finding,
    Issue,
    Label,
    RuntimeLocation,
    Severity,
)
from FlowStopper.storage import Storage, make_scan_id


def _db(tmp_path) -> Storage:
    return Storage(tmp_path / "scans.db")


def _code_finding(cwe: int = 89, suppressed: bool = False) -> Finding:
    return Finding(
        id=f"code-{cwe}-{int(suppressed)}",
        engine=Engine.SAST,
        tool="FlowStopper-taint",
        rule_id="py.sqli.concat",
        cwe=cwe,
        title="SQLi",
        severity=Severity.CRITICAL,
        confidence=0.9,
        code=CodeLocation(file="svc/db.py", line_start=10, line_end=10, function="svc.db.q"),
        suppressed=suppressed,
        suppress_reason="safe:parameterised" if suppressed else None,
    )


def _runtime_finding(cwe: int = 89) -> Finding:
    return Finding(
        id=f"rt-{cwe}",
        engine=Engine.DAST,
        tool="FlowStopper-dast",
        rule_id="dast.sqli.error",
        cwe=cwe,
        title="SQLi",
        severity=Severity.CRITICAL,
        confidence=0.9,
        runtime=RuntimeLocation(method="GET", url="http://h/x?id=1'", path="/x", param="id", proof="error"),
    )


def _issue(
    iid: str,
    *,
    cwe: int = 89,
    label: Label = Label.CONFIRMED,
    risk: float = 9.8,
    severity: Severity = Severity.CRITICAL,
    code=(),
    runtime=(),
) -> Issue:
    code = list(code)
    runtime = list(runtime)
    return Issue(
        id=iid,
        cwe=cwe,
        title=f"issue {iid}",
        label=label,
        severity=severity,
        cvss=9.8,
        risk=risk,
        code_findings=code,
        runtime_findings=runtime,
        primary_code=code[0].code if code else None,
        primary_runtime=runtime[0].runtime if runtime else None,
    )


# --------------------------------------------------------------------------- schema / scans
def test_schema_created_and_scan_round_trip(tmp_path):
    with _db(tmp_path) as db:
        sid = db.start_scan(source_path="src", target_url="http://localhost", config={"a": 1}, seed=7)
        scan = db.get_scan(sid)
        assert scan is not None
        assert scan["status"] == "running" and scan["seed"] == 7
        assert scan["config"] == {"a": 1} and scan["source_path"] == "src"

        db.finish_scan(sid, timings={"sast": 1.5})
        scan = db.get_scan(sid)
        assert scan["status"] == "completed" and scan["finished_at"]
        assert scan["timings"] == {"sast": 1.5}


def test_unknown_scan_returns_none(tmp_path):
    with _db(tmp_path) as db:
        assert db.get_scan("nope") is None
        assert db.get_issue("nope") is None
        assert db.issue_history("nope") is None


def test_scan_ids_differ_per_run_but_are_pure(tmp_path):
    a = make_scan_id("src", "http://h", "2026-01-01T00:00:00+00:00")
    b = make_scan_id("src", "http://h", "2026-01-01T00:00:00+00:00")
    c = make_scan_id("src", "http://h", "2026-01-01T00:00:01+00:00")
    assert a == b and a != c and len(a) == 16


def test_list_scans(tmp_path):
    with _db(tmp_path) as db:
        db.start_scan(target_url="http://a", started_at="2026-01-01T00:00:00+00:00")
        db.start_scan(target_url="http://b", started_at="2026-01-02T00:00:00+00:00")
        scans = db.list_scans()
        assert len(scans) == 2 and scans[0]["target_url"] == "http://b"  # newest first


# --------------------------------------------------------------------------- findings
def test_findings_saved_and_filtered_by_engine(tmp_path):
    with _db(tmp_path) as db:
        sid = db.start_scan(target_url="http://localhost")
        db.save_findings(sid, [_code_finding(), _runtime_finding()])
        assert len(db.get_findings(sid)) == 2
        assert len(db.get_findings(sid, engine="sast")) == 1
        assert db.get_findings(sid, engine="dast")[0].rule_id == "dast.sqli.error"


def test_findings_round_trip_preserves_the_model(tmp_path):
    with _db(tmp_path) as db:
        sid = db.start_scan(target_url="http://localhost")
        original = _code_finding(suppressed=True)
        db.save_findings(sid, [original])
        assert db.get_findings(sid)[0] == original


def test_saving_findings_twice_is_idempotent(tmp_path):
    with _db(tmp_path) as db:
        sid = db.start_scan(target_url="http://localhost")
        findings = [_code_finding(), _runtime_finding()]
        db.save_findings(sid, findings)
        db.save_findings(sid, findings)
        assert len(db.get_findings(sid)) == 2  # no duplicate rows


# --------------------------------------------------------------------------- issues / FR-6
def test_issue_upsert_keeps_first_seen_and_advances_last_seen(tmp_path):
    with _db(tmp_path) as db:
        first = db.start_scan(target_url="http://localhost", started_at="2026-01-01T00:00:00+00:00")
        db.save_issues(first, [_issue("iss-1")])
        second = db.start_scan(target_url="http://localhost", started_at="2026-01-02T00:00:00+00:00")
        db.save_issues(second, [_issue("iss-1")])

        history = db.issue_history("iss-1")
        assert history["first_seen_scan"] == first  # never moves
        assert history["last_seen_scan"] == second  # advances
        assert len(db.get_issues()) == 1  # one row, not two


def test_rescanning_identical_input_is_idempotent(tmp_path):
    """FR-6: same issues saved twice -> same ids and counts."""
    issues = [_issue("a"), _issue("b", cwe=79, risk=6.1, severity=Severity.MEDIUM)]
    with _db(tmp_path) as db:
        sid = db.start_scan(target_url="http://localhost")
        db.save_issues(sid, issues)
        before = [i.id for i in db.get_issues(scan_id=sid)]
        db.save_issues(sid, issues)
        after = [i.id for i in db.get_issues(scan_id=sid)]
        assert before == after and len(after) == 2


def test_code_only_issue_becoming_confirmed_keeps_its_id(tmp_path):
    """The spec's key identity rule: a Code-only issue upgraded to Confirmed is the same issue."""
    code_only = _issue("stable-id", label=Label.CODE_ONLY, risk=5.9, code=[_code_finding()])
    confirmed = _issue(
        "stable-id", label=Label.CONFIRMED, risk=9.8, code=[_code_finding()], runtime=[_runtime_finding()]
    )
    with _db(tmp_path) as db:
        s1 = db.start_scan(target_url="http://localhost", started_at="2026-01-01T00:00:00+00:00")
        db.save_issues(s1, [code_only])
        s2 = db.start_scan(target_url="http://localhost", started_at="2026-01-02T00:00:00+00:00")
        db.save_issues(s2, [confirmed])

        assert len(db.get_issues()) == 1
        assert db.get_issue("stable-id").label is Label.CONFIRMED  # latest state
        # the historical snapshot still shows what that scan reported
        assert db.get_issues(scan_id=s1)[0].label is Label.CODE_ONLY
        assert db.counts_by_label(s1) == {"code_only": 1}
        assert db.counts_by_label(s2) == {"confirmed": 1}


def test_issue_round_trip_preserves_nested_findings(tmp_path):
    original = _issue("nested", code=[_code_finding()], runtime=[_runtime_finding()])
    with _db(tmp_path) as db:
        sid = db.start_scan(target_url="http://localhost")
        db.save_issues(sid, [original])
        assert db.get_issue("nested") == original


# --------------------------------------------------------------------------- filters / ordering
def _mixed() -> list[Issue]:
    return [
        _issue("conf-low", label=Label.CONFIRMED, risk=6.1, cwe=79, severity=Severity.MEDIUM),
        _issue("conf-high", label=Label.CONFIRMED, risk=9.8, cwe=89),
        _issue("rt", label=Label.RUNTIME_ONLY, risk=4.2, cwe=693, severity=Severity.MEDIUM),
        _issue("code", label=Label.CODE_ONLY, risk=5.5, cwe=798, code=[_code_finding(798)]),
        _issue("suppressed", label=Label.CODE_ONLY, risk=5.9, cwe=78, code=[_code_finding(78, suppressed=True)]),
    ]


def test_prioritised_order_confirmed_first_then_risk(tmp_path):
    with _db(tmp_path) as db:
        sid = db.start_scan(target_url="http://localhost")
        db.save_issues(sid, _mixed())
        ids = [i.id for i in db.get_issues(scan_id=sid)]
        assert ids[:2] == ["conf-high", "conf-low"]  # confirmed first, risk desc
        assert ids[2] == "code" and ids[3] == "rt"  # then risk desc among the rest
        assert "suppressed" not in ids  # hidden by default (B-2)


def test_include_suppressed_puts_them_last(tmp_path):
    with _db(tmp_path) as db:
        sid = db.start_scan(target_url="http://localhost")
        db.save_issues(sid, _mixed())
        ids = [i.id for i in db.get_issues(scan_id=sid, include_suppressed=True)]
        assert ids[-1] == "suppressed" and len(ids) == 5


def test_filters_by_label_cwe_and_min_risk(tmp_path):
    with _db(tmp_path) as db:
        sid = db.start_scan(target_url="http://localhost")
        db.save_issues(sid, _mixed())
        assert [i.id for i in db.get_issues(scan_id=sid, label="confirmed")] == ["conf-high", "conf-low"]
        assert [i.id for i in db.get_issues(scan_id=sid, cwe=693)] == ["rt"]
        assert [i.id for i in db.get_issues(scan_id=sid, min_risk=6.0)] == ["conf-high", "conf-low"]
        # the same filters work against the latest-state table too
        assert [i.id for i in db.get_issues(label="confirmed")] == ["conf-high", "conf-low"]
        assert [i.id for i in db.get_issues(min_risk=9.0)] == ["conf-high"]


def test_scan_scoped_query_ignores_other_scans(tmp_path):
    with _db(tmp_path) as db:
        s1 = db.start_scan(target_url="http://a", started_at="2026-01-01T00:00:00+00:00")
        s2 = db.start_scan(target_url="http://b", started_at="2026-01-02T00:00:00+00:00")
        db.save_issues(s1, [_issue("only-in-s1")])
        db.save_issues(s2, [_issue("only-in-s2")])
        assert [i.id for i in db.get_issues(scan_id=s1)] == ["only-in-s1"]
        assert [i.id for i in db.get_issues(scan_id=s2)] == ["only-in-s2"]
        assert len(db.get_issues()) == 2


def test_storage_ordering_matches_the_shared_sort_helper(tmp_path):
    issues = _mixed()
    with _db(tmp_path) as db:
        sid = db.start_scan(target_url="http://localhost")
        db.save_issues(sid, issues)
        from_db = [i.id for i in db.get_issues(scan_id=sid, include_suppressed=True)]
    assert from_db == [i.id for i in sort_issues(issues)]  # one source of truth for ordering


def test_is_suppressed_helper_contract():
    assert is_suppressed(_issue("x", code=[_code_finding(suppressed=True)], label=Label.CODE_ONLY)) is True
    assert is_suppressed(_issue("y", code=[_code_finding()], label=Label.CODE_ONLY)) is False
    # a suppressed code finding plus runtime proof is NOT suppressed
    assert is_suppressed(_issue("z", code=[_code_finding(suppressed=True)], runtime=[_runtime_finding()])) is False


def test_database_file_is_created_with_parent_dirs(tmp_path):
    path = tmp_path / "nested" / "dir" / "scans.db"
    with Storage(path) as db:
        db.start_scan(target_url="http://localhost")
    assert path.exists()


def test_config_json_is_stable(tmp_path):
    with _db(tmp_path) as db:
        sid = db.start_scan(target_url="http://localhost", config={"b": 2, "a": 1})
        row = db.conn.execute("SELECT config_json FROM scans WHERE id = ?", (sid,)).fetchone()
        assert row["config_json"] == json.dumps({"a": 1, "b": 2}, sort_keys=True)  # deterministic
