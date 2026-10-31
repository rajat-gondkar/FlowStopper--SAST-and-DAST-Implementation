"""Auto-verify tests (P4-B4 / B-1). Owner: B. Offline via httpx.MockTransport.

A Code-only issue whose taint names an entry route and a source param is re-tested with the one
matching DAST check against exactly that (route, param). Pinned here: the upgrade to Confirmed on a
vulnerable app, no upgrade on a safe one, zero requests for ineligible issues, the scope guard (R3),
the deadline, Appendix B payloads only (R4), determinism, and an unchanged CLI without --target.
"""

from __future__ import annotations

import json
import re
import time

import httpx
import pytest
from typer.testing import CliRunner

from FlowStopper.cli import app as cli
from FlowStopper.correlate.autoverify import auto_verify
from FlowStopper.correlate.engine import correlate
from FlowStopper.dast.config import DastConfig
from FlowStopper.models import (
    CodeLocation,
    DastResult,
    Engine,
    Finding,
    Issue,
    Label,
    LinkReason,
    ParamLocation,
    Route,
    RouteParam,
    SastResult,
    Severity,
    TaintInfo,
)
from FlowStopper.scope import ScopeError
from tests.conftest import FIXTURES

Q = ParamLocation.QUERY
BASE = "http://localhost:5050"
HTML = {"content-type": "text/html"}

ROUTES = [
    Route(
        id="GET /items",
        method="GET",
        path_template="/items",
        path_regex="^/items$",
        handler="app.items",
        file="app.py",
        line_start=1,
        line_end=10,
        params=[RouteParam(name="category", location=Q)],
    ),
    Route(
        id="DELETE /items",
        method="DELETE",
        path_template="/items",
        path_regex="^/items$",
        handler="app.delete_items",
        file="app.py",
        line_start=20,
        line_end=30,
        params=[RouteParam(name="category", location=Q)],
    ),
]


def _code(
    *,
    fid: str = "c-sqli",
    cwe: int = 89,
    line: int = 5,
    param: str | None = "category",
    entry_routes: tuple[str, ...] = ("GET /items",),
    suppressed: bool = False,
) -> Finding:
    return Finding(
        id=fid,
        engine=Engine.SAST,
        tool="FlowStopper-taint",
        rule_id="py.sqli.concat.execute" if cwe == 89 else "py.secret.hardcoded",
        cwe=cwe,
        title="Hard-coded credential SECRET_KEY" if cwe == 798 else "SQL built from request data",
        severity=Severity.HIGH,
        confidence=0.9,
        code=CodeLocation(file="app.py", line_start=line, line_end=line, function="app.items"),
        taint=(
            None
            if cwe == 798
            else TaintInfo(source_param=param, source_kind=Q, call_chain=["app.items"], entry_routes=list(entry_routes))
        ),
        suppressed=suppressed,
        suppress_reason="sanitised" if suppressed else None,
    )


def vulnerable_app(request: httpx.Request) -> httpx.Response:
    if request.url.path == "/items":
        v = request.url.params.get("category", "")
        if "'" in v or '"' in v:
            return httpx.Response(500, text="sqlite3.OperationalError: unrecognized token", headers=HTML)
        return httpx.Response(200, text="<html>items</html>", headers=HTML)
    return httpx.Response(404, text="<html>not found</html>", headers=HTML)


def safe_app(request: httpx.Request) -> httpx.Response:
    if request.url.path == "/items":
        return httpx.Response(200, text="<html>items</html>", headers=HTML)
    return httpx.Response(404, text="<html>not found</html>", headers=HTML)


class Recorder:
    """A MockTransport handler wrapper that keeps every request it saw."""

    def __init__(self, handler) -> None:
        self.handler = handler
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return self.handler(request)


def _config(**kw) -> DastConfig:
    return DastConfig(**{"allowed_hosts": ["localhost"], "seed": 11, **kw})


async def _verify(issues, handler=vulnerable_app, **kw):
    rec = Recorder(handler)
    result = await auto_verify(issues, ROUTES, BASE, _config(), transport=httpx.MockTransport(rec), **kw)
    return result, rec


def _code_only(code: Finding) -> Issue:
    [issue] = correlate([code], [], ROUTES)
    assert issue.label is Label.CODE_ONLY
    return issue


# --------------------------------------------------------------------------- upgrade
async def test_code_only_sqli_is_upgraded_to_confirmed():
    before = _code_only(_code())
    result, rec = await _verify([before])

    [after] = result.issues
    assert after.label is Label.CONFIRMED
    assert after.verified_by == "auto-verify"
    assert after.id == before.id  # storage keeps identity
    assert after.code_findings == before.code_findings
    assert len(after.runtime_findings) == 1 and after.runtime_findings[0].raw["auto_verify"] is True
    assert after.runtime_findings[0].runtime.route_id == "GET /items"
    assert after.runtime_findings[0].runtime.param == "category"
    kinds = [r.kind for r in after.reasons]
    assert kinds[0] == "same_cwe" and kinds[-1] == "auto_verified"
    assert abs(sum(r.weight for r in after.reasons) - after.link_score) < 1e-9
    assert after.link_score >= 0.7
    assert [f.id for f in result.findings_added] == [after.runtime_findings[0].id]
    assert result.stats["upgraded"] == 1 and result.stats["eligible"] == 1
    assert rec.requests, "the probe should have been sent"
    assert {r.url.path for r in rec.requests} == {"/items"}  # only the issue's route, nothing crawled


async def test_safe_app_stays_code_only():
    before = _code_only(_code())
    result, rec = await _verify([before], handler=safe_app)
    assert result.issues == [before]
    assert result.findings_added == []
    assert result.stats["upgraded"] == 0 and result.stats["not_reproduced"] == 1
    assert rec.requests  # it was probed, it just did not reproduce


# --------------------------------------------------------------------------- eligibility
async def test_ineligible_issues_are_never_probed():
    penalty = LinkReason(kind="ambiguity_penalty", detail="not linked: tie", weight=-0.95)
    ambiguous = _code_only(_code(fid="amb", line=6)).model_copy(update={"reasons": [penalty]})
    suppressed = _code_only(_code(fid="sup", line=7, suppressed=True))
    secret = _code_only(_code(fid="sec", cwe=798, line=8))
    routeless = _code_only(_code(fid="nor", line=9, entry_routes=()))
    unknown_route = _code_only(_code(fid="unk", line=10, entry_routes=("GET /nowhere",)))
    no_param = _code_only(_code(fid="nop", line=11, param=None))
    delete_only = _code_only(_code(fid="del", line=12, entry_routes=("DELETE /items",)))
    issues = [ambiguous, suppressed, secret, routeless, unknown_route, no_param, delete_only]

    result, rec = await _verify(issues)

    assert rec.requests == []
    assert result.stats["eligible"] == 0 and result.stats["requests"] == 0
    assert [i.model_dump() for i in result.issues] == [i.model_dump() for i in correlate_sort(issues)]
    assert result.stats["skipped"] == {
        "ambiguous": 1,
        "cwe_not_checkable": 1,
        "no_entry_route": 3,
        "no_source_param": 1,
        "suppressed": 1,
    }


def correlate_sort(issues):
    from FlowStopper.correlate.issues import sort_issues

    return sort_issues(issues)


async def test_confirmed_and_runtime_only_issues_are_untouched(fixture_sast, fixture_dast, fixture_routes):
    issues = correlate(fixture_sast, fixture_dast, fixture_routes)
    rec = Recorder(safe_app)
    result = await auto_verify(issues, fixture_routes, BASE, _config(), transport=httpx.MockTransport(rec))
    for before, after in zip(issues, result.issues, strict=True):
        if before.label is not Label.CODE_ONLY:
            assert after == before


# --------------------------------------------------------------------------- budget + scope
async def test_expired_deadline_sends_nothing_and_marks_truncated():
    result, rec = await _verify([_code_only(_code())], deadline=time.monotonic() - 1)
    assert rec.requests == []
    assert result.stats["truncated"] is True and result.stats["not_reached"] == 1
    assert result.issues[0].label is Label.CODE_ONLY


async def test_out_of_scope_target_raises_before_any_request():
    rec = Recorder(vulnerable_app)
    with pytest.raises(ScopeError):
        await auto_verify(
            [_code_only(_code())], ROUTES, "http://evil.com", _config(), transport=httpx.MockTransport(rec)
        )
    assert rec.requests == []


# --------------------------------------------------------------------------- R4 + determinism
_ALLOWED = [
    re.compile(r"^(test|1|a\.txt)$"),  # benign baseline / control values
    re.compile(r"""^.*?(?:'|"|'\)|'")$"""),  # error-based suffixes
    re.compile(r"^.+?' (?:AND|OR) '[a-z]+'='[a-z]+$"),  # boolean string context
    re.compile(r"^.+? AND 1=[12]$"),  # boolean numeric context
]


async def test_only_appendix_b_payload_shapes_are_sent():
    for handler in (vulnerable_app, safe_app):
        _, rec = await _verify([_code_only(_code())], handler=handler)
        sent = [r.url.params.get("category", "") for r in rec.requests]
        assert sent
        offenders = [p for p in sent if not any(rx.match(p) for rx in _ALLOWED)]
        assert offenders == [], f"non-Appendix-B payloads sent (R4 violation): {offenders}"


async def test_deterministic_for_a_fixed_seed():
    issue = _code_only(_code())
    first, _ = await _verify([issue])
    second, _ = await _verify([issue])
    assert [i.model_dump(mode="json") for i in first.issues] == [i.model_dump(mode="json") for i in second.issues]
    assert first.issues[0].label is Label.CONFIRMED


# --------------------------------------------------------------------------- CLI
def _write_inputs(tmp_path, fixture_sast, fixture_dast, fixture_routes):
    sast_path, dast_path = tmp_path / "sast.json", tmp_path / "dast.json"
    sast_path.write_text(SastResult(routes=fixture_routes, findings=fixture_sast).model_dump_json(), encoding="utf-8")
    dast_path.write_text(DastResult(findings=fixture_dast).model_dump_json(), encoding="utf-8")
    return sast_path, dast_path


def test_cli_without_target_is_byte_identical(tmp_path, fixture_sast, fixture_dast, fixture_routes):
    sast_path, dast_path = _write_inputs(tmp_path, fixture_sast, fixture_dast, fixture_routes)
    out_path = tmp_path / "issues.json"
    result = CliRunner().invoke(
        cli, ["correlate", "--sast", str(sast_path), "--dast", str(dast_path), "--out", str(out_path)]
    )
    assert result.exit_code == 0, result.output
    assert "auto-verify" not in result.output
    expected = json.loads((FIXTURES / "expected_issues.json").read_text(encoding="utf-8"))
    assert out_path.read_text(encoding="utf-8") == json.dumps(expected, indent=2) + "\n"


def test_cli_refuses_out_of_scope_target(tmp_path, fixture_sast, fixture_dast, fixture_routes):
    sast_path, dast_path = _write_inputs(tmp_path, fixture_sast, fixture_dast, fixture_routes)
    out_path = tmp_path / "issues.json"
    result = CliRunner().invoke(
        cli,
        ["correlate", "--sast", str(sast_path), "--dast", str(dast_path), "--out", str(out_path)]
        + ["--target", "http://evil.com"],
    )
    assert result.exit_code == 1 and "out-of-scope" in result.output
    assert not out_path.exists()
