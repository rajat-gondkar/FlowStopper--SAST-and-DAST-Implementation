"""Link-explanation tests (P4-B3). Owner: B.

Every Confirmed issue must say why its two findings were joined: one reason each for the CWE family,
the route evidence, the parameter and the method, with details naming the route and parameter, and
weights that add up to the stored link_score.
"""

from __future__ import annotations

from FlowStopper.correlate.config import CorrelateConfig
from FlowStopper.correlate.engine import correlate
from FlowStopper.correlate.explain import auto_verified_reason, link_reasons
from FlowStopper.correlate.matcher import CHAIN_ORIGIN, HANDLER_SPAN, REACHABLE, Candidate, generate_candidates
from FlowStopper.correlate.scoring import link_score
from FlowStopper.models import Issue, Label
from tests.test_correlate import ROUTE, _code, _runtime

ROUTE_KINDS = {CHAIN_ORIGIN, HANDLER_SPAN, REACHABLE}


def _assert_explained(issue: Issue) -> None:
    kinds = [r.kind for r in issue.reasons]
    assert kinds.count("same_cwe") == 1
    assert sum(1 for k in kinds if k in ROUTE_KINDS) == 1
    assert kinds.count("same_param") == 1
    assert kinds.count("same_method") == 1
    for reason in issue.reasons:
        assert reason.detail and "?" not in reason.detail and "None" not in reason.detail
    route_id = issue.primary_runtime.route_id if issue.primary_runtime else None
    assert route_id
    route_reason = next(r for r in issue.reasons if r.kind in ROUTE_KINDS)
    assert route_id in route_reason.detail
    param = issue.primary_runtime.param
    param_reason = next(r for r in issue.reasons if r.kind == "same_param")
    assert param and f"'{param}'" in param_reason.detail
    assert issue.link_score is not None
    assert abs(sum(r.weight for r in issue.reasons) - issue.link_score) < 1e-9


def _confirmed(code, runtime) -> Issue:
    issues = correlate([code], [runtime], [ROUTE])
    confirmed = [i for i in issues if i.label is Label.CONFIRMED]
    assert len(confirmed) == 1
    return confirmed[0]


def _reason(issue: Issue, kind: str):
    return next(r for r in issue.reasons if r.kind == kind)


# --------------------------------------------------------------------------- route kinds
def test_route_chain_origin_is_explained():
    code = _code(89, "svc/db.py", 3, "svc.db.q", param="id", chain=("views.a.handler",), entry=("GET /a",))
    issue = _confirmed(code, _runtime(89, "GET /a", "id"))
    _assert_explained(issue)
    assert "views.a.handler" in _reason(issue, CHAIN_ORIGIN).detail


def test_route_handler_span_is_explained():
    code = _code(89, "views/a.py", 15, "views.a.handler", param="id", chain=("views.a.handler",))
    issue = _confirmed(code, _runtime(89, "GET /a", "id"))
    _assert_explained(issue)
    assert "views/a.py:15" in _reason(issue, HANDLER_SPAN).detail


def test_route_reachable_is_explained():
    code = _code(89, "svc/helper.py", 2, "svc.helper", param="id", chain=("views.a.handler",))
    issue = _confirmed(code, _runtime(89, "GET /a", "id"))
    _assert_explained(issue)
    assert "svc.helper" in _reason(issue, REACHABLE).detail


# --------------------------------------------------------------------------- param and method
def test_param_unknown_is_explained_as_partial_credit():
    code = _code(89, "svc/db.py", 3, "svc.db.q", param=None, entry=("GET /a",))
    issue = _confirmed(code, _runtime(89, "GET /a", "id"))
    _assert_explained(issue)
    detail = _reason(issue, "same_param").detail
    assert "could not name" in detail and "partial credit" in detail and "unknown" in detail


def test_param_mismatch_is_explained():
    # Below the link threshold, so it never becomes Confirmed; the candidate's reasons still explain it.
    code = _code(89, "svc/db.py", 3, "svc.db.q", param="name", chain=("views.a.handler",), entry=("GET /a",))
    cands = generate_candidates([code], [_runtime(89, "GET /a", "id")], [ROUTE], CorrelateConfig())
    assert len(cands) == 1
    config = CorrelateConfig()
    reasons = link_reasons(cands[0], config)
    reason = next(r for r in reasons if r.kind == "same_param")
    assert reason.weight == 0.0 and reason.detail == "DAST param 'id' != SAST source param 'name'"
    assert abs(sum(r.weight for r in reasons) - link_score(cands[0], config)) < 1e-9
    assert not [i for i in correlate([code], [_runtime(89, "GET /a", "id")], [ROUTE]) if i.label is Label.CONFIRMED]


def test_method_mismatch_is_explained():
    code = _code(89, "svc/db.py", 3, "svc.db.q", param="id", chain=("views.a.handler",), entry=("GET /a",))
    issue = _confirmed(code, _runtime(89, "GET /a", "id", method="POST"))
    _assert_explained(issue)
    reason = _reason(issue, "same_method")
    assert reason.weight == 0.0 and reason.detail == "DAST method POST != route method GET"


def test_missing_fields_never_render_a_bare_question_mark():
    code = _code(89, "svc/helper.py", 2, None, param=None, chain=("views.a.handler",))
    runtime = _runtime(89, "GET /a", None)
    cand = Candidate(
        code=code,
        runtime=runtime,
        route=None,
        route_match=0.8,
        route_kind=REACHABLE,
        param_match=0.5,
        method_match=0.0,
        specificity=0.5,
    )
    for reason in link_reasons(cand, CorrelateConfig()):
        assert "?" not in reason.detail and "None" not in reason.detail
    route_detail = next(r for r in link_reasons(cand, CorrelateConfig()) if r.kind == REACHABLE).detail
    assert "svc/helper.py:2" in route_detail and "GET /a" in route_detail


# --------------------------------------------------------------------------- invariant on the fixture
def test_every_confirmed_fixture_issue_is_fully_explained(fixture_sast, fixture_dast, fixture_routes):
    confirmed = [i for i in correlate(fixture_sast, fixture_dast, fixture_routes) if i.label is Label.CONFIRMED]
    assert confirmed
    for issue in confirmed:
        _assert_explained(issue)


# --------------------------------------------------------------------------- auto-verify helper
def test_auto_verified_reason_has_zero_weight():
    reason = auto_verified_reason("sqli", "GET /a", "id", "error", "'")
    assert reason.kind == "auto_verified" and reason.weight == 0.0
    assert "sqli" in reason.detail and "GET /a" in reason.detail and "'id'" in reason.detail
    missing = auto_verified_reason("xss", None, None, None, None)
    assert "?" not in missing.detail and "None" not in missing.detail
