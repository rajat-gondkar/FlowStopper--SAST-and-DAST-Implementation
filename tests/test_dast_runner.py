"""DAST runner + CLI tests (P2-B4). Owner: B. A whole vulnerable app, offline via MockTransport.

The fixture app plants one bug of each injection type plus passive misconfigurations, and a safe
decoy endpoint, so the runner is exercised end-to-end: discovery -> passive -> active checks ->
verification -> collapse -> DastResult.
"""

from __future__ import annotations

import json
import subprocess

import httpx
import pytest
from typer.testing import CliRunner

from FlowStopper.cli import app
from FlowStopper.dast import runner
from FlowStopper.dast.config import DastConfig
from FlowStopper.dast.runner import allowed_methods, injectable_params, order_endpoints, run_dast
from FlowStopper.dast.types import Endpoint, Param
from FlowStopper.models import ParamLocation, Route
from FlowStopper.scope import ScopeError

Q = ParamLocation.QUERY
BASE = "http://localhost:5050"
PASSWD = "root:x:0:0:root:/root:/bin/bash\n"

HEADERS_HTML = {"content-type": "text/html", "server": "Werkzeug/2.0.1"}


def _route(method: str, template: str, params: tuple[str, ...] = ()) -> Route:
    from FlowStopper.models import RouteParam

    return Route(
        id=f"{method} {template}",
        method=method,
        path_template=template,
        path_regex="^x$",
        handler=f"h{template}",
        file="app.py",
        line_start=1,
        line_end=5,
        params=[RouteParam(name=n, location=Q) for n in params],
    )


ROUTES = [
    _route("GET", "/items", ("category",)),  # SQLi (error-based)
    _route("GET", "/search", ("q",)),  # reflected XSS
    _route("GET", "/ping", ("host",)),  # command injection
    _route("GET", "/download", ("file",)),  # path traversal
    _route("GET", "/go", ("next",)),  # open redirect
    _route("GET", "/products", ("id",)),  # safe decoy
]


def vulnerable_app(request: httpx.Request) -> httpx.Response:
    path = request.url.path
    p = request.url.params
    raw_query = request.url.query.decode()

    if path == "/":
        return httpx.Response(200, text="<html>home</html>", headers=HEADERS_HTML)
    if path == "/items":
        v = p.get("category", "")
        if "'" in v or '"' in v:
            return httpx.Response(500, text="sqlite3.OperationalError: unrecognized token", headers=HEADERS_HTML)
        return httpx.Response(200, text="<html>items</html>", headers=HEADERS_HTML)
    if path == "/search":
        return httpx.Response(200, text=f"<h1>Results for {p.get('q', '')}</h1>", headers=HEADERS_HTML)
    if path == "/ping":
        host = p.get("host", "")
        out = subprocess.run(["/bin/sh", "-c", f"echo {host}"], capture_output=True, text=True, timeout=5).stdout
        return httpx.Response(200, text=out, headers={"content-type": "text/plain"})
    if path == "/download":
        v = p.get("file", "")
        if ".." in v or v.startswith("/etc/") or "%2f" in raw_query.lower():
            return httpx.Response(200, text=PASSWD, headers={"content-type": "text/plain"})
        return httpx.Response(200, text="file contents", headers={"content-type": "text/plain"})
    if path == "/go":
        return httpx.Response(302, headers={"location": p.get("next", "/")})
    if path == "/products":  # decoy: parameterised query, nothing reflected or executed
        return httpx.Response(200, text="<html>products</html>", headers=HEADERS_HTML)
    return httpx.Response(404, text="<html>not found</html>", headers=HEADERS_HTML)


def _endpoint_with_param(path: str, pname: str, value: str = "1") -> tuple[Endpoint, Param]:
    param = Param(pname, Q, value)
    return Endpoint("GET", f"{BASE}{path}", path, route_id=f"GET {path}", params=[param]), param


def _config(**kw) -> DastConfig:
    base = dict(allowed_hosts=["localhost"], seed=11, concurrency=4, crawl_max_urls=12)
    base.update(kw)
    return DastConfig(**base)


async def _scan(handler=vulnerable_app, routes=None, **kw):
    cfg = _config(**kw)
    import FlowStopper.dast.client as client_mod

    original = client_mod.httpx.AsyncClient
    transport = httpx.MockTransport(handler)

    def patched(*args, **kwargs):
        kwargs["transport"] = transport
        return original(*args, **kwargs)

    client_mod.httpx.AsyncClient = patched  # type: ignore[assignment]
    try:
        return await run_dast(BASE, ROUTES if routes is None else routes, cfg)
    finally:
        client_mod.httpx.AsyncClient = original  # type: ignore[assignment]


# --------------------------------------------------------------------------- end-to-end
async def test_runner_finds_all_five_injection_types():
    result = await _scan()
    by_cwe = {f.cwe for f in result.findings}
    for cwe in (89, 79, 78, 22, 601):
        assert cwe in by_cwe, f"CWE-{cwe} not found; got {sorted(by_cwe)}"


async def test_runner_reports_passive_findings():
    result = await _scan()
    passive_rules = {f.rule_id for f in result.findings if f.rule_id.startswith("dast.passive.")}
    assert "dast.passive.csp-missing" in passive_rules
    assert result.stats["passive_findings"] >= 1


async def test_decoy_endpoint_produces_no_finding():
    result = await _scan()
    paths = {f.runtime.path for f in result.findings if f.runtime and f.runtime.param}
    assert "/products" not in paths


async def test_findings_are_sorted_and_unique():
    result = await _scan()
    keys = [
        (f.cwe, f.runtime.path if f.runtime else "", (f.runtime.param or "") if f.runtime else "", f.rule_id)
        for f in result.findings
    ]
    assert keys == sorted(keys)
    assert len({f.id for f in result.findings}) == len(result.findings)


async def test_every_active_finding_carries_full_evidence():
    result = await _scan()
    for f in result.findings:
        rt = f.runtime
        assert rt is not None and rt.evidence and rt.repro_curl and rt.request
        assert f.code is None  # DAST never sets a code location
        if rt.param:  # active findings carry a payload and verification metadata
            assert rt.payload and f.raw.get("verification", {}).get("reproduced") is True


async def test_scan_is_deterministic_including_payloads():
    first = await _scan()
    second = await _scan()
    assert [f.id for f in first.findings] == [f.id for f in second.findings]
    assert [f.runtime.payload for f in first.findings] == [f.runtime.payload for f in second.findings]


async def test_stats_shape():
    result = await _scan()
    s = result.stats
    for key in (
        "target",
        "seed",
        "endpoints_scanned",
        "endpoints_from_routes",
        "params_tested",
        "requests",
        "findings",
        "truncated",
        "elapsed_s",
        "methods",
    ):
        assert key in s, f"missing stat {key}"
    assert s["truncated"] is False
    assert s["endpoints_from_routes"] >= len(ROUTES)
    assert s["requests"] > 0


# --------------------------------------------------------------------------- safety policies
async def test_out_of_scope_target_is_refused_before_any_request():
    with pytest.raises(ScopeError):
        await run_dast("http://evil.com", [], _config())


def test_delete_is_never_allowed():
    assert "DELETE" not in allowed_methods(_config())
    assert "DELETE" not in allowed_methods(_config(allow_mutating=True))


def test_method_policy_default_and_mutating():
    assert allowed_methods(_config()) == frozenset({"GET", "POST", "HEAD", "OPTIONS"})
    assert allowed_methods(_config(allow_mutating=True)) == frozenset(
        {"GET", "POST", "HEAD", "OPTIONS", "PUT", "PATCH"}
    )


async def test_mutating_endpoints_skipped_by_default():
    put_route = _route("PUT", "/items", ("category",))
    result = await _scan(routes=[put_route])
    assert "PUT" not in result.stats["methods"]
    assert all(f.runtime.method != "PUT" for f in result.findings if f.runtime)


async def test_time_budget_truncates_cleanly():
    """A spent budget stops the active phase, keeps what was already collected, and says so.

    The budget covers active checks only: discovery and the single passive pass run first and are
    unaffected, so their findings must survive a zero budget rather than being thrown away.
    """
    result = await _scan(time_budget_s=0)
    assert result.stats["truncated"] is True
    assert result.stats["params_tested"] == 0
    # Assert the findings are actually there: `all(...)` over an empty list passes vacuously, so
    # without this the test would also pass if truncation discarded everything.
    assert result.findings, "passive findings collected before the budget expired must be preserved"
    assert result.stats["passive_findings"] == len(result.findings)
    assert all(f.rule_id.startswith("dast.passive.") for f in result.findings)


async def test_expired_deadline_stops_a_unit_before_it_sends_anything():
    """Graceful stop at the unit level: no checks run, no payloads sent, truncation recorded."""
    import time

    from FlowStopper.dast.checks.base import CheckContext
    from FlowStopper.dast.client import DastClient
    from FlowStopper.scope import ScopeGuard

    cfg = _config()
    client = DastClient(ScopeGuard(["localhost"]), cfg, transport=httpx.MockTransport(vulnerable_app))
    ctx = CheckContext.create(client, BASE, cfg)
    endpoint, param = _endpoint_with_param("/items", "category")
    state = runner._State()

    found = await runner._scan_param(ctx, endpoint, param, deadline=time.monotonic() - 1.0, state=state)
    await client.aclose()

    assert found == []
    assert state.truncated is True
    assert state.checks_run == 0 and ctx.sent_payloads == []


async def test_generous_budget_is_not_truncated():
    result = await _scan(time_budget_s=240)
    assert result.stats["truncated"] is False and result.stats["params_tested"] > 0


async def test_only_appendix_b_payload_shapes_leave_the_runner():
    """R4 at the runner level: every injected value matches a catalogued shape."""
    import re

    allowed = [
        re.compile(r"^(test|1|a\.txt|/home)$"),
        re.compile(r"""^.*?(?:'|"|'\)|'")$"""),  # error-based suffixes on any original value
        re.compile(r"^.+?' (?:AND|OR) '[a-z]+'='[a-z]+$"),
        re.compile(r"^.+? AND 1=[12]$"),
        re.compile(r"""^sdc[a-z]+(?:<"'>|"onmouseover=x)$"""),
        re.compile(r"^.+?(?:;|\||&&|\$\(|`|\n)\s*echo sdc[a-z]+\$\(\(\d+\*\d+\)\)X[`)]?$", re.S),
        re.compile(r"^(?:\.\./)+etc/passwd$|^(?:\.\.\.\.//)+etc/passwd$|^(?:\.\.%2f)+etc%2fpasswd$|^/etc/passwd$"),
        re.compile(r"^(?://|https://|/\\|///)sdc[a-z]+\.invalid/?$"),
        re.compile(r"^https://sdc-probe\.invalid$"),  # the single passive CORS probe
    ]
    sent: list[str] = []
    cfg = _config()
    import FlowStopper.dast.client as client_mod
    from FlowStopper.dast.checks.base import CheckContext

    original_create = CheckContext.create
    holder: dict[str, CheckContext] = {}

    def spy(cls_client, base_url, config=None):  # pragma: no cover - thin shim
        ctx = original_create(cls_client, base_url, config)
        holder["ctx"] = ctx
        return ctx

    original_async = client_mod.httpx.AsyncClient
    transport = httpx.MockTransport(vulnerable_app)

    def patched(*args, **kwargs):
        kwargs["transport"] = transport
        return original_async(*args, **kwargs)

    client_mod.httpx.AsyncClient = patched  # type: ignore[assignment]
    CheckContext.create = staticmethod(spy)  # type: ignore[assignment]
    try:
        await run_dast(BASE, ROUTES, cfg)
    finally:
        client_mod.httpx.AsyncClient = original_async  # type: ignore[assignment]
        CheckContext.create = original_create  # type: ignore[assignment]

    sent = holder["ctx"].sent_payloads
    assert sent, "the runner should have injected something"
    offenders = [p for p in sent if not any(rx.match(p) for rx in allowed)]
    assert offenders == [], f"non-Appendix-B payloads sent (R4): {sorted(set(offenders))[:5]}"


# --------------------------------------------------------------------------- ordering helpers
def test_route_endpoints_are_scanned_before_crawled_ones():
    eps = [
        Endpoint("GET", f"{BASE}/crawled", "/crawled", route_id=None, source="crawl"),
        Endpoint("GET", f"{BASE}/seeded", "/seeded", route_id="GET /seeded", source="seed"),
    ]
    assert [e.path for e in order_endpoints(eps)] == ["/seeded", "/crawled"]


def test_priority_param_names_tested_first():
    ep = Endpoint(
        "GET",
        f"{BASE}/x",
        "/x",
        params=[Param("zzz", Q, "1"), Param("next", Q, "/"), Param("aaa", Q, "1"), Param("id", Q, "1")],
    )
    names = [p.name for p in injectable_params(ep)]
    assert names[0] == "next" and names[1] == "id"  # Appendix B order, then the rest alphabetically
    assert names[2:] == ["aaa", "zzz"]


def test_non_injectable_params_are_not_scanned():
    ep = Endpoint(
        "GET",
        f"{BASE}/x",
        "/x",
        params=[Param("Cookie", ParamLocation.COOKIE, "a"), Param("q", Q, "1")],
    )
    assert [p.name for p in injectable_params(ep)] == ["q"]


def test_priority_list_matches_appendix_b_size():
    assert len(runner.PRIORITY_PARAMS) == len(set(runner.PRIORITY_PARAMS)) == 22


# --------------------------------------------------------------------------- CLI
def test_dast_cli_refuses_out_of_scope_target(tmp_path):
    result = CliRunner().invoke(app, ["dast", "http://evil.com", "--out", str(tmp_path / "d.json")])
    assert result.exit_code == 1
    assert "R3" in result.output or "out-of-scope" in result.output


def test_dast_cli_reports_bad_routes_file(tmp_path):
    bad = tmp_path / "routes.json"
    bad.write_text("{not json", encoding="utf-8")
    result = CliRunner().invoke(app, ["dast", "http://localhost", "--routes", str(bad)])
    assert result.exit_code == 1 and "--routes" in result.output


def test_load_routes_accepts_list_and_wrapped(tmp_path):
    from FlowStopper.dast.commands import load_routes

    routes = [r.model_dump(mode="json") for r in ROUTES[:2]]
    flat = tmp_path / "routes.json"
    flat.write_text(json.dumps(routes), encoding="utf-8")
    wrapped = tmp_path / "sast.json"
    wrapped.write_text(json.dumps({"routes": routes, "findings": []}), encoding="utf-8")
    assert len(load_routes(flat)) == 2
    assert len(load_routes(wrapped)) == 2
    assert load_routes(None) == []
