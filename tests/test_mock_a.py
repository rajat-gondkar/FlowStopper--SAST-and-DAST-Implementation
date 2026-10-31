"""Mock A fixture app (P1-A4): route extraction + answer-key/source consistency (Owner: A).

These guard against drift between apps/mock_a and apps/mock_a/answer_key.json: every keyed code
location must land inside the named function, and every keyed runtime path must be a real route.
"""

from __future__ import annotations

from FlowStopper.evalkit.keyschema import load_key
from FlowStopper.sast.index import build_index
from FlowStopper.sast.routes import extract_routes
from tests.conftest import ROOT

MOCK_A = ROOT / "apps" / "mock_a"

# The planted runtime endpoints (spec Appendix D), as route templates.
KEYED_ENDPOINTS = {
    "/api/orders",
    "/login",
    "/search",
    "/product/<id>",
    "/api/ping",
    "/admin/backup",
    "/download",
    "/docs/<path:name>",
    "/go",
    "/api/crash",
}


def test_mock_a_route_extraction():
    index = build_index(MOCK_A)
    routes = extract_routes(index)
    templates = {r.path_template for r in routes}
    assert len(routes) == 25
    assert KEYED_ENDPOINTS <= templates
    by_id = {r.id: r for r in routes}
    # cross-file handler params and method handling
    login_post = by_id["POST /login"]
    assert {(p.name, p.location.value) for p in login_post.params} >= {
        ("username", "form"),
        ("password", "form"),
        ("next", "query"),
    }
    assert ("id", "query") in {(p.name, p.location.value) for p in by_id["GET /api/orders"].params}
    assert ("note", "query") in {(p.name, p.location.value) for p in by_id["GET /product/<id>"].params}


def test_mock_a_answer_key_matches_source():
    key = load_key(MOCK_A / "answer_key.json")
    index = build_index(MOCK_A)
    templates = {r.path_template for r in extract_routes(index)}

    for vuln in key.vulns:
        if vuln.code is not None and vuln.code.function:
            fn = index.function_at(vuln.code.file, vuln.code.line_start)
            assert fn is not None, f"{vuln.id}: no function at {vuln.code.file}:{vuln.code.line_start}"
            assert fn.qualname == vuln.code.function, f"{vuln.id}: {fn.qualname} != {vuln.code.function}"
        if vuln.runtime is not None and vuln.runtime.path != "*":
            assert vuln.runtime.path in templates, f"{vuln.id}: runtime path {vuln.runtime.path} is not a route"


def test_mock_a_decoy_locations_are_real_functions():
    key = load_key(MOCK_A / "answer_key.json")
    index = build_index(MOCK_A)
    for decoy in key.decoys:
        fn = index.function_at(decoy.file, decoy.line_start)
        # every decoy sits inside a function body (secrets decoy D08 is module-level, so allow None there)
        assert fn is not None or decoy.cwe == 798, f"{decoy.id}: no function at {decoy.file}:{decoy.line_start}"
