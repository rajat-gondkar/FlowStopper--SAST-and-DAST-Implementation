"""DAST authentication tests (P4-B1, BACKLOG item 7). Owner: B. Offline via httpx.MockTransport.

The headline test reproduces the benchmark app's flow exactly: POST /login with JSON credentials
returns the JWT in the **Authorization response header**, and /search answers 403 to anything that
does not send it back. Without login support no check ever reaches the vulnerable code, which is why
that app's SQLi was a runtime miss in the Phase 3 baseline.
"""

from __future__ import annotations

import json

import httpx
import pytest

from FlowStopper.dast import runner
from FlowStopper.dast.checks import sqli
from FlowStopper.dast.checks.base import CheckContext
from FlowStopper.dast.client import REDACTED, DastClient
from FlowStopper.dast.config import AuthConfig, DastConfig, LoginStep
from FlowStopper.dast.types import Endpoint, Param
from FlowStopper.models import ParamLocation, Route, RouteParam
from FlowStopper.scope import ScopeError, ScopeGuard

BASE = "http://localhost:8100"
TOKEN = "eyJhbGciOiJIUzI1NiJ9.payload.signature"
GUARD = ScopeGuard(["localhost", "127.0.0.1"])
Q = ParamLocation.QUERY
JSON = ParamLocation.JSON


def _client(handler, config: DastConfig) -> DastClient:
    return DastClient(GUARD, config, transport=httpx.MockTransport(handler))


# --------------------------------------------------------------------------- the benchmark app's flow
def bench_like_app(request: httpx.Request) -> httpx.Response:
    """POST /login -> token in the Authorization *response header*; /search needs it back."""
    path = request.url.path
    if path == "/login" and request.method == "POST":
        try:
            creds = json.loads(request.content.decode() or "{}")
        except ValueError:
            creds = {}
        if creds.get("username") == "admin" and creds.get("password") == "admin123":
            return httpx.Response(
                200,
                json={"Authenticated": True, "User": "admin"},
                headers={"Authorization": TOKEN},
            )
        return httpx.Response(404, json={"Error": "No User here..."})

    if path == "/search":
        if request.headers.get("Authorization") != TOKEN:
            return httpx.Response(403, json={"Error": "Not Authenticated!"})
        # authenticated: now the injection is reachable
        try:
            term = str(json.loads(request.content.decode() or "{}").get("search", ""))
        except ValueError:
            term = ""
        if "'" in term or '"' in term:
            return httpx.Response(500, text="sqlite3.OperationalError: unrecognized token")
        return httpx.Response(200, json={"results": []})

    return httpx.Response(404, json={"Error": "not found"})


def _bench_config(**kw) -> DastConfig:
    base = dict(
        allowed_hosts=["localhost"],
        seed=3,
        auth=AuthConfig(
            login=LoginStep(
                url=f"{BASE}/login",
                json_body={"username": "admin", "password": "admin123"},
                token_response_header="Authorization",
                token_request_header="Authorization",
            )
        ),
    )
    base.update(kw)
    return DastConfig(**base)


async def test_login_copies_the_response_header_token():
    config = _bench_config()
    async with _client(bench_like_app, config) as client:
        result = await client.authenticate()
        assert result.ok and result.attempted and result.configured
        assert result.token_header == "Authorization" and result.status == 200
        # the token now rides on every later request
        ex = await client.request("POST", f"{BASE}/search", json={"search": "x"})
        assert ex.status == 200, "authenticated request should pass the login wall"


async def test_without_login_the_vulnerable_route_is_unreachable():
    """The Phase 3 baseline miss, reproduced: no auth -> 403 -> the check can never fire."""
    plain = DastConfig(allowed_hosts=["localhost"], seed=3)
    async with _client(bench_like_app, plain) as client:
        ex = await client.request("POST", f"{BASE}/search", json={"search": "x'"})
        assert ex.status == 403 and "Not Authenticated" in ex.body


async def test_sqli_check_finds_the_bug_only_once_authenticated():
    param = Param("search", JSON, "x")
    endpoint = Endpoint("POST", f"{BASE}/search", "/search", route_id="POST /search", params=[param])

    plain = DastConfig(allowed_hosts=["localhost"], seed=3)
    async with _client(bench_like_app, plain) as client:
        ctx = CheckContext.create(client, BASE, plain)
        assert await sqli.run(ctx, endpoint, param) == [], "unauthenticated: nothing is reachable"

    config = _bench_config()
    async with _client(bench_like_app, config) as client:
        assert (await client.authenticate()).ok
        ctx = CheckContext.create(client, BASE, config)
        findings = await sqli.run(ctx, endpoint, param)
    assert len(findings) == 1
    assert findings[0].cwe == 89 and findings[0].runtime.proof == "error"


async def test_runner_authenticates_before_scanning_and_records_it(monkeypatch):
    route = Route(
        id="POST /search",
        method="POST",
        path_template="/search",
        path_regex="^/search$",
        handler="app.search_customer",
        file="app/app.py",
        line_start=246,
        line_end=265,
        params=[RouteParam(name="search", location=JSON)],
    )
    config = _bench_config(concurrency=4, crawl_max_urls=5)
    transport = httpx.MockTransport(bench_like_app)
    import FlowStopper.dast.client as client_mod

    original = client_mod.httpx.AsyncClient

    def patched(*args, **kwargs):
        kwargs["transport"] = transport
        return original(*args, **kwargs)

    monkeypatch.setattr(client_mod.httpx, "AsyncClient", patched)
    result = await runner.run_dast(BASE, [route], config)

    assert result.stats["auth"]["ok"] is True
    assert result.stats["auth"]["token_header"] == "Authorization"
    assert any(f.cwe == 89 for f in result.findings), "the authenticated SQLi should now be found"


# --------------------------------------------------------------------------- static credentials
async def test_a_header_param_does_not_clobber_the_session_token():
    """Regression: the bug that made the first authenticated bench run score identically to no auth.

    A route that *reads* `Authorization` is listed by SAST as having an `Authorization` header
    parameter. `build_request` fills every non-injected parameter with a benign value, so it was
    overwriting the real token with `test` and un-authenticating every single request.
    """
    param = Param("search", JSON, "x")
    endpoint = Endpoint(
        "POST",
        f"{BASE}/search",
        "/search",
        route_id="POST /search",
        params=[Param("Authorization", ParamLocation.HEADER, "test"), param],
    )
    config = _bench_config()
    async with _client(bench_like_app, config) as client:
        assert (await client.authenticate()).ok
        ctx = CheckContext.create(client, BASE, config)
        # the benign baseline must already be authenticated, not bounced to the login wall
        baseline = await ctx.baseline(endpoint, param)
        assert baseline.sample.status == 200, f"header param clobbered the token: {baseline.sample.body[:80]}"
        findings = await sqli.run(ctx, endpoint, param)
    assert len(findings) == 1 and findings[0].cwe == 89


async def test_a_header_param_is_still_sent_when_no_token_reserves_it():
    """Without a session token the header param keeps its benign value - the fix is targeted."""
    seen: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["x-tenant"] = request.headers.get("X-Tenant", "")
        return httpx.Response(200, text="ok")

    param = Param("q", Q, "1")
    endpoint = Endpoint(
        "GET",
        f"{BASE}/items",
        "/items",
        params=[Param("X-Tenant", ParamLocation.HEADER, "acme"), param],
    )
    config = DastConfig(allowed_hosts=["localhost"], seed=1)
    async with _client(handler, config) as client:
        ctx = CheckContext.create(client, BASE, config)
        await ctx.send(endpoint, param, "probe")
    assert seen["x-tenant"] == "acme"


async def test_static_headers_and_cookies_are_sent():
    seen: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["auth"] = request.headers.get("Authorization", "")
        seen["cookie"] = request.headers.get("Cookie", "")
        return httpx.Response(200, text="ok")

    config = DastConfig(
        allowed_hosts=["localhost"],
        auth=AuthConfig(headers={"Authorization": "Bearer preissued"}, cookies={"session": "abc"}),
    )
    async with _client(handler, config) as client:
        result = await client.authenticate()  # nothing to do, but must not fail
        assert result.ok and not result.attempted and result.configured
        await client.get(f"{BASE}/anything")
    assert seen["auth"] == "Bearer preissued"
    assert "session=abc" in seen["cookie"]


async def test_explicit_headers_win_over_config():
    seen: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["auth"] = request.headers.get("Authorization", "")
        return httpx.Response(200, text="ok")

    config = DastConfig(allowed_hosts=["localhost"], auth=AuthConfig(headers={"Authorization": "from-config"}))
    client = DastClient(GUARD, config, headers={"Authorization": "explicit"}, transport=httpx.MockTransport(handler))
    async with client:
        await client.get(f"{BASE}/x")
    assert seen["auth"] == "explicit"


# --------------------------------------------------------------------------- cookie-session login
async def test_cookie_login_keeps_the_jar():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/signin":
            return httpx.Response(200, text="welcome", headers={"set-cookie": "sid=xyz; Path=/"})
        return httpx.Response(200, text=request.headers.get("cookie", ""))

    config = DastConfig(
        allowed_hosts=["localhost"],
        auth=AuthConfig(login=LoginStep(url=f"{BASE}/signin", form_data={"u": "a", "p": "b"})),
    )
    async with _client(handler, config) as client:
        result = await client.authenticate()
        assert result.ok and result.cookies and "cookie" in result.detail
        ex = await client.get(f"{BASE}/profile")
    assert "sid=xyz" in ex.body


async def test_cookie_login_that_sets_nothing_is_reported_not_silent():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="ok")  # 200 but no cookie: not actually a session

    config = DastConfig(
        allowed_hosts=["localhost"], auth=AuthConfig(login=LoginStep(url=f"{BASE}/signin", form_data={"u": "a"}))
    )
    async with _client(handler, config) as client:
        result = await client.authenticate()
    assert result.attempted and not result.ok and "no cookie" in result.detail


# --------------------------------------------------------------------------- token from a JSON body
async def test_token_from_a_json_field_with_a_prefix():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/auth":
            return httpx.Response(200, json={"data": {"token": "t0ken"}})
        return httpx.Response(200, text=request.headers.get("X-Api-Key", ""))

    config = DastConfig(
        allowed_hosts=["localhost"],
        auth=AuthConfig(
            login=LoginStep(
                url=f"{BASE}/auth",
                json_body={"u": "a"},
                token_json_field="data.token",
                token_request_header="X-Api-Key",
                token_prefix="Bearer ",
            )
        ),
    )
    async with _client(handler, config) as client:
        assert (await client.authenticate()).ok
        ex = await client.get(f"{BASE}/x")
    assert ex.body == "Bearer t0ken"


async def test_missing_token_is_a_failure_with_a_reason():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"nothing": "here"})

    config = DastConfig(
        allowed_hosts=["localhost"],
        auth=AuthConfig(login=LoginStep(url=f"{BASE}/auth", json_body={}, token_json_field="data.token")),
    )
    async with _client(handler, config) as client:
        result = await client.authenticate()
    assert result.attempted and not result.ok and "no token found" in result.detail


# --------------------------------------------------------------------------- failures and safety
async def test_rejected_credentials_are_reported():
    config = _bench_config(
        auth=AuthConfig(
            login=LoginStep(
                url=f"{BASE}/login",
                json_body={"username": "admin", "password": "wrong"},
                token_response_header="Authorization",
            )
        )
    )
    async with _client(bench_like_app, config) as client:
        result = await client.authenticate()
    assert result.attempted and not result.ok and result.status == 404


async def test_unreachable_login_is_reported_not_raised():
    def dead(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    config = _bench_config()
    async with _client(dead, config) as client:
        result = await client.authenticate()
    assert result.attempted and not result.ok and "ConnectError" in result.detail


async def test_out_of_scope_login_url_is_refused(caplog):
    """R3: a login URL outside the allow-list is a configuration error, not a soft failure."""
    config = DastConfig(
        allowed_hosts=["localhost"],
        auth=AuthConfig(login=LoginStep(url="http://evil.com/login", json_body={"u": "a"})),
    )
    async with _client(bench_like_app, config) as client:
        with pytest.raises(ScopeError):
            await client.authenticate()


async def test_no_auth_configured_is_a_no_op():
    async with _client(bench_like_app, DastConfig(allowed_hosts=["localhost"])) as client:
        result = await client.authenticate()
    assert result.ok and not result.attempted and not result.configured


async def test_token_is_redacted_in_the_audit_trail():
    """R7: the stored request text and repro curl must not leak the session token."""
    config = _bench_config()
    async with _client(bench_like_app, config) as client:
        assert (await client.authenticate()).ok
        ex = await client.request("POST", f"{BASE}/search", json={"search": "x"})
    assert TOKEN not in ex.request_text and REDACTED in ex.request_text
    assert TOKEN not in ex.repro_curl


async def test_auth_result_stats_never_carry_the_token():
    config = _bench_config()
    async with _client(bench_like_app, config) as client:
        stats = (await client.authenticate()).as_stats()
    assert TOKEN not in str(stats)
    assert stats["token_header"] == "Authorization" and stats["ok"] is True


def test_login_step_expects_token_flag():
    assert LoginStep(url="u", token_response_header="Authorization").expects_token
    assert LoginStep(url="u", token_json_field="a.b").expects_token
    assert not LoginStep(url="u", form_data={"u": "a"}).expects_token
    assert AuthConfig().is_configured is False
    assert AuthConfig(headers={"a": "b"}).is_configured is True
