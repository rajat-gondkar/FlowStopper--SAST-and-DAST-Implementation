"""Correlator tests (P2-B6) - the judged core. Owner: B.

The headline test is the golden one: `correlate()` over the fixture SAST/DAST findings must
reproduce `fixtures/expected_issues.json` exactly - same ids, order, labels, risk and reasons.
The rest pin the individual rules (hard route gate, param normalisation, ambiguity, idempotency).
"""

from __future__ import annotations

import json

from FlowStopper.correlate.config import CorrelateConfig
from FlowStopper.correlate.dedupe import dedupe_code, dedupe_runtime
from FlowStopper.correlate.engine import correlate, infer_host
from FlowStopper.correlate.issues import assign, is_suppressed
from FlowStopper.correlate.matcher import generate_candidates, normalise_param, specificity_of
from FlowStopper.correlate.scoring import link_score
from FlowStopper.models import (
    CodeLocation,
    Engine,
    Finding,
    Label,
    ParamLocation,
    Route,
    RouteParam,
    RuntimeLocation,
    Severity,
    TaintInfo,
)
from tests.conftest import FIXTURES

Q = ParamLocation.QUERY


# --------------------------------------------------------------------------- the golden test
def test_correlator_reproduces_expected_issues(fixture_sast, fixture_dast, fixture_routes):
    produced = correlate(fixture_sast, fixture_dast, fixture_routes)
    expected = json.loads((FIXTURES / "expected_issues.json").read_text(encoding="utf-8"))
    got = [i.model_dump(mode="json") for i in produced]
    assert len(got) == len(expected), f"{len(got)} issues, expected {len(expected)}"
    for index, (a, b) in enumerate(zip(got, expected, strict=True)):
        assert a == b, f"issue #{index} ({b.get('id')}) differs:\nproduced={a}\nexpected={b}"
    assert got == expected


def test_every_finding_lands_in_exactly_one_issue(fixture_sast, fixture_dast, fixture_routes):
    issues = correlate(fixture_sast, fixture_dast, fixture_routes)
    used = [f.id for i in issues for f in i.code_findings + i.runtime_findings]
    assert sorted(used) == sorted(f.id for f in fixture_sast + fixture_dast)
    assert len(used) == len(set(used)), "a finding was used twice"


def test_idempotency_two_runs_identical(fixture_sast, fixture_dast, fixture_routes):
    """FR-6: running the pipeline twice on identical input yields identical ids and counts."""
    first = correlate(fixture_sast, fixture_dast, fixture_routes)
    second = correlate(fixture_sast, fixture_dast, fixture_routes)
    assert [i.id for i in first] == [i.id for i in second]
    assert [i.model_dump(mode="json") for i in first] == [i.model_dump(mode="json") for i in second]


def test_input_order_does_not_change_output(fixture_sast, fixture_dast, fixture_routes):
    normal = correlate(fixture_sast, fixture_dast, fixture_routes)
    shuffled = correlate(list(reversed(fixture_sast)), list(reversed(fixture_dast)), list(reversed(fixture_routes)))
    assert [i.model_dump(mode="json") for i in normal] == [i.model_dump(mode="json") for i in shuffled]


def test_fixture_labels_and_scores(fixture_sast, fixture_dast, fixture_routes):
    issues = correlate(fixture_sast, fixture_dast, fixture_routes)
    confirmed = [i for i in issues if i.label is Label.CONFIRMED]
    assert len(confirmed) == 2
    for issue in confirmed:
        assert issue.verified_by == "dast"
        assert abs(sum(r.weight for r in issue.reasons) - issue.link_score) < 1e-9
        assert any(r.kind == "same_cwe" for r in issue.reasons)
    # the ambiguous case: one runtime-only + two code-only, all carrying the penalty
    penalised = [i for i in issues if any(r.kind == "ambiguity_penalty" for r in i.reasons)]
    assert sorted(i.label.value for i in penalised) == ["code_only", "code_only", "runtime_only"]
    # suppressed decoy sorts last and is never reported
    assert is_suppressed(issues[-1]) and issues[-1].cwe == 78


# --------------------------------------------------------------------------- builders for unit cases
def _code(
    cwe: int,
    file: str,
    line: int,
    function: str | None,
    *,
    param: str | None = None,
    chain: tuple[str, ...] = (),
    entry: tuple[str, ...] = (),
    suppressed: bool = False,
    fid: str | None = None,
) -> Finding:
    return Finding(
        id=fid or f"c-{cwe}-{file}-{line}",
        engine=Engine.SAST,
        tool="FlowStopper-taint",
        rule_id="py.rule",
        cwe=cwe,
        title="code finding",
        severity=Severity.CRITICAL,
        confidence=0.9,
        code=CodeLocation(file=file, line_start=line, line_end=line, function=function),
        taint=TaintInfo(source_param=param, call_chain=list(chain), entry_routes=list(entry)),
        suppressed=suppressed,
    )


def _runtime(cwe: int, route_id: str | None, param: str | None, *, method: str = "GET", path: str = "/x") -> Finding:
    return Finding(
        id=f"r-{cwe}-{route_id}-{param}",
        engine=Engine.DAST,
        tool="FlowStopper-dast",
        rule_id="dast.rule",
        cwe=cwe,
        title="runtime finding",
        severity=Severity.CRITICAL,
        confidence=0.9,
        runtime=RuntimeLocation(
            method=method,
            url=f"http://127.0.0.1:8080{path}",
            path=path,
            route_id=route_id,
            param=param,
            proof="error",
        ),
    )


def _route(rid: str, handler: str, file: str, start: int, end: int, reachable=(), auth=False) -> Route:
    method, template = rid.split(" ", 1)
    return Route(
        id=rid,
        method=method,
        path_template=template,
        path_regex="^x$",
        handler=handler,
        file=file,
        line_start=start,
        line_end=end,
        params=[RouteParam(name="id", location=Q)],
        auth_required=auth,
        reachable_functions=list(reachable),
    )


ROUTE = _route("GET /a", "views.a.handler", "views/a.py", 10, 20, reachable=["svc.helper"])


# --------------------------------------------------------------------------- the hard route gate
def test_route_gate_rejects_unrelated_code_even_with_same_cwe_and_param():
    code = _code(89, "other/file.py", 5, "other.thing", param="id")  # no entry route, not in span
    issues = correlate([code], [_runtime(89, "GET /a", "id")], [ROUTE])
    assert {i.label for i in issues} == {Label.CODE_ONLY, Label.RUNTIME_ONLY}
    assert not [i for i in issues if i.label is Label.CONFIRMED]


def test_route_gate_accepts_chain_origin_span_and_reachable():
    chain = _code(89, "svc/db.py", 3, "svc.db.q", param="id", chain=("views.a.handler",), entry=("GET /a",))
    span = _code(89, "views/a.py", 15, "views.a.handler", param="id", chain=("views.a.handler",))
    reach = _code(89, "svc/helper.py", 2, "svc.helper", param="id", chain=("views.a.handler",))
    cands = generate_candidates([chain, span, reach], [_runtime(89, "GET /a", "id")], [ROUTE], CorrelateConfig())
    kinds = {c.route_kind: c.route_match for c in cands}
    assert kinds == {"route_chain_origin": 1.0, "route_handler_span": 0.9, "route_reachable": 0.8}


def test_suppressed_code_is_never_linked():
    code = _code(89, "svc/db.py", 3, "svc.db.q", param="id", entry=("GET /a",), suppressed=True)
    issues = correlate([code], [_runtime(89, "GET /a", "id")], [ROUTE])
    assert not [i for i in issues if i.label is Label.CONFIRMED]
    assert any(is_suppressed(i) for i in issues)


def test_different_cwe_family_is_never_linked():
    code = _code(79, "svc/db.py", 3, "svc.db.q", param="id", entry=("GET /a",))
    issues = correlate([code], [_runtime(89, "GET /a", "id")], [ROUTE])
    assert not [i for i in issues if i.label is Label.CONFIRMED]


def test_cmdi_family_cwe_77_and_78_do_link():
    code = _code(77, "svc/sh.py", 3, "svc.sh.run", param="id", chain=("views.a.handler",), entry=("GET /a",))
    issues = correlate([code], [_runtime(78, "GET /a", "id")], [ROUTE])
    assert [i.label for i in issues] == [Label.CONFIRMED]


# --------------------------------------------------------------------------- components
def test_param_normalisation():
    assert normalise_param("ID") == "id"
    assert normalise_param("tags[]") == "tags"
    assert normalise_param("user.profile.name") == "name"
    assert normalise_param(None) == "" and normalise_param("  ") == ""


def test_param_mismatch_blocks_a_link_below_threshold():
    code = _code(89, "svc/db.py", 3, "svc.db.q", param="other", chain=("views.a.handler",), entry=("GET /a",))
    cand = generate_candidates([code], [_runtime(89, "GET /a", "id")], [ROUTE], CorrelateConfig())[0]
    assert cand.param_match == 0.0
    assert link_score(cand, CorrelateConfig()) == 0.65  # 0.50 route + 0.05 spec + 0.10 method
    assert not [i for i in correlate([code], [_runtime(89, "GET /a", "id")], [ROUTE]) if i.label is Label.CONFIRMED]


def test_specificity_needs_chain_and_named_param():
    assert specificity_of(_code(89, "f.py", 1, "f.g", param="id", chain=("h",))) == 1.0
    assert specificity_of(_code(89, "f.py", 1, "f.g", param=None, chain=("h",))) == 0.5
    assert specificity_of(_code(89, "f.py", 1, "f.g", param="id", chain=())) == 0.5


def test_method_mismatch_lowers_the_score():
    code = _code(89, "svc/db.py", 3, "svc.db.q", param="id", chain=("views.a.handler",), entry=("GET /a",))
    cand = generate_candidates([code], [_runtime(89, "GET /a", "id", method="POST")], [ROUTE], CorrelateConfig())[0]
    assert cand.method_match == 0.0
    assert link_score(cand, CorrelateConfig()) == 0.9  # still links: 0.50 + 0.35 + 0.05


# --------------------------------------------------------------------------- ambiguity rule
def _tied_inputs():
    a = _code(89, "views/r.py", 12, "views.r.report", chain=("views.r.report",), entry=("GET /r",), fid="code-a")
    b = _code(89, "views/r.py", 20, "views.r.report", chain=("views.r.report",), entry=("GET /r",), fid="code-b")
    route = _route("GET /r", "views.r.report", "views/r.py", 6, 24)
    return a, b, route


def test_ambiguous_tie_is_not_linked():
    a, b, route = _tied_inputs()
    runtime = _runtime(89, "GET /r", "start")
    issues = correlate([a, b], [runtime], [route])
    assert not [i for i in issues if i.label is Label.CONFIRMED], "a tie must not be linked"
    assert sorted(i.label.value for i in issues) == ["code_only", "code_only", "runtime_only"]
    for issue in issues:
        reason = next(r for r in issue.reasons if r.kind == "ambiguity_penalty")
        assert "the SAST source param is unknown" in reason.detail
        assert reason.weight < 0


def test_param_name_breaks_the_tie_and_allows_a_link():
    a, b, route = _tied_inputs()
    named = _code(
        89, "views/r.py", 12, "views.r.report", param="start", chain=("views.r.report",), entry=("GET /r",), fid="named"
    )
    issues = correlate([named, b], [_runtime(89, "GET /r", "start")], [route])
    confirmed = [i for i in issues if i.label is Label.CONFIRMED]
    assert len(confirmed) == 1 and confirmed[0].primary_code.line_start == 12


def test_near_tie_outside_the_margin_still_links():
    # chain-origin (1.0) vs reachable (0.8) -> 0.1 apart in route terms, 0.10 in score: not ambiguous
    strong = _code(89, "svc/db.py", 3, "svc.db.q", param="id", chain=("views.a.handler",), entry=("GET /a",))
    weak = _code(89, "svc/helper.py", 2, "svc.helper", param="id", chain=("views.a.handler",))
    issues = correlate([strong, weak], [_runtime(89, "GET /a", "id")], [ROUTE])
    confirmed = [i for i in issues if i.label is Label.CONFIRMED]
    assert len(confirmed) == 1 and confirmed[0].primary_code.file == "svc/db.py"


def test_one_to_one_assignment():
    """Two runtime findings and two code findings: each is used at most once."""
    a = _code(89, "svc/db.py", 3, "svc.db.q", param="id", chain=("views.a.handler",), entry=("GET /a",))
    b = _code(89, "svc/db2.py", 4, "svc.db2.q", param="q", chain=("views.a.handler",), entry=("GET /a",))
    issues = correlate([a, b], [_runtime(89, "GET /a", "id"), _runtime(89, "GET /a", "q")], [ROUTE])
    confirmed = [i for i in issues if i.label is Label.CONFIRMED]
    assert len(confirmed) == 2
    assert len({i.primary_code.file for i in confirmed}) == 2


def test_assign_with_no_candidates_is_empty():
    result = assign([], CorrelateConfig())
    assert result.links == [] and result.penalties == {}


# --------------------------------------------------------------------------- labels, risk, ids
def test_host_wide_runtime_issue_uses_the_host_for_its_id():
    finding = _runtime(693, None, None, path="/")
    issues = correlate([], [finding], [])
    assert len(issues) == 1
    assert issues[0].label is Label.RUNTIME_ONLY
    assert "host-wide" in issues[0].title
    assert infer_host([finding]) == "127.0.0.1:8080"


def test_code_only_issue_keeps_its_id_when_it_becomes_confirmed():
    code = _code(89, "svc/db.py", 3, "svc.db.q", param="id", chain=("views.a.handler",), entry=("GET /a",))
    code_only = correlate([code], [], [ROUTE])[0]
    confirmed = correlate([code], [_runtime(89, "GET /a", "id")], [ROUTE])[0]
    assert code_only.label is Label.CODE_ONLY and confirmed.label is Label.CONFIRMED
    assert code_only.id == confirmed.id  # identity survives the upgrade (spec section 7)


def test_risk_factors():
    code = _code(89, "svc/db.py", 3, "svc.db.q", param="id", chain=("views.a.handler",), entry=("GET /a",))
    # code-only: 9.8 * 0.6
    assert correlate([code], [], [ROUTE])[0].risk == 5.88
    # confirmed on an open route: full cvss
    assert correlate([code], [_runtime(89, "GET /a", "id")], [ROUTE])[0].risk == 9.8
    # confirmed on an authenticated route: * 0.85
    auth_route = _route("GET /a", "views.a.handler", "views/a.py", 10, 20, auth=True)
    assert correlate([code], [_runtime(89, "GET /a", "id")], [auth_route])[0].risk == 8.33


def test_risk_drops_for_differential_only_proof():
    finding = _runtime(89, "GET /a", "id")
    differential = finding.model_copy(update={"runtime": finding.runtime.model_copy(update={"proof": "differential"})})
    issues = correlate([], [differential], [ROUTE])
    assert issues[0].risk == 8.82  # 9.8 * 0.9


def test_risk_drops_for_low_confidence_runtime_only():
    weak = _runtime(89, "GET /a", "id").model_copy(update={"confidence": 0.5})
    assert correlate([], [weak], [ROUTE])[0].risk == 8.82  # 9.8 * 0.9


def test_severity_cvss_and_owasp_come_from_the_catalogue():
    issue = correlate([_code(798, "settings.py", 4, None)], [], [])[0]
    assert issue.cvss == 9.1 and issue.severity is Severity.CRITICAL
    assert issue.owasp_2025 == "A07:2025 - Authentication Failures"
    assert issue.label is Label.CODE_ONLY  # secrets are code-only by nature


def test_unknown_cwe_does_not_crash():
    issue = correlate([_code(12345, "a.py", 1, "a.f")], [], [])[0]
    assert issue.cvss == 0.0 and issue.owasp_2025 is None


def test_empty_input():
    assert correlate([], [], []) == []


# --------------------------------------------------------------------------- dedupe
def test_dedupe_collapses_identical_code_and_runtime_findings():
    a = _code(89, "svc/db.py", 3, "svc.db.q", param="id", fid="dup-1")
    b = _code(89, "svc/db.py", 3, "svc.db.q", param="id", fid="dup-2")
    assert len(dedupe_code([a, b])) == 1
    r1 = _runtime(89, "GET /a", "id")
    r2 = _runtime(89, "GET /a", "ID")  # param compared case-insensitively
    assert len(dedupe_runtime([r1, r2])) == 1


def test_dedupe_keeps_distinct_findings_and_is_pure(fixture_sast, fixture_dast):
    assert len(dedupe_code(fixture_sast)) == len(fixture_sast)
    assert len(dedupe_runtime(fixture_dast)) == len(fixture_dast)
    # representatives are returned unchanged, so correlator output stays byte-identical to input
    assert {f.id for f in dedupe_code(fixture_sast)} == {f.id for f in fixture_sast}


def test_dedupe_prefers_higher_confidence():
    low = _code(89, "svc/db.py", 3, "svc.db.q", param="id", fid="low").model_copy(update={"confidence": 0.5})
    high = _code(89, "svc/db.py", 3, "svc.db.q", param="id", fid="high").model_copy(update={"confidence": 0.95})
    assert dedupe_code([low, high])[0].id == "high"


# --------------------------------------------------------------------------- CLI
def test_correlate_cli_round_trip(tmp_path, fixture_sast, fixture_dast, fixture_routes):
    from typer.testing import CliRunner

    from FlowStopper.cli import app as cli
    from FlowStopper.models import DastResult, Issue, SastResult

    sast_path = tmp_path / "sast.json"
    dast_path = tmp_path / "dast.json"
    out_path = tmp_path / "issues.json"
    sast_path.write_text(SastResult(routes=fixture_routes, findings=fixture_sast).model_dump_json(), encoding="utf-8")
    dast_path.write_text(DastResult(findings=fixture_dast).model_dump_json(), encoding="utf-8")

    result = CliRunner().invoke(
        cli,
        ["correlate", "--sast", str(sast_path), "--dast", str(dast_path), "--out", str(out_path)],
    )
    assert result.exit_code == 0, result.output
    assert "confirmed 2" in result.output

    written = [Issue.model_validate(i) for i in json.loads(out_path.read_text(encoding="utf-8"))]
    expected = json.loads((FIXTURES / "expected_issues.json").read_text(encoding="utf-8"))
    assert [i.model_dump(mode="json") for i in written] == expected


def test_correlate_cli_reports_missing_input(tmp_path):
    from typer.testing import CliRunner

    from FlowStopper.cli import app as cli

    result = CliRunner().invoke(cli, ["correlate", "--sast", str(tmp_path / "nope.json")])
    assert result.exit_code == 1 and "could not read" in result.output
