"""Passive / misconfiguration check tests (P2-B2). Owner: B. Offline via httpx.MockTransport.

Each check is asserted to fire on a sloppy app, stay quiet on a hardened one, report **once per
host** with affected paths, and carry no code location (RUNTIME_ONLY by nature).
"""

from __future__ import annotations

import httpx

from FlowStopper.dast.checks import passive
from FlowStopper.dast.checks.base import CheckContext
from FlowStopper.dast.client import DastClient
from FlowStopper.dast.config import DastConfig
from FlowStopper.dast.types import Endpoint, Param
from FlowStopper.models import ParamLocation
from FlowStopper.scope import ScopeGuard

GUARD = ScopeGuard(["localhost"])
HARDENED_HEADERS = {
    "content-type": "text/html",
    "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    "x-frame-options": "DENY",
}
ENDPOINTS = [
    Endpoint("GET", "http://localhost/", "/"),
    Endpoint("GET", "http://localhost/search", "/search"),
]


def _ctx(handler, base: str = "http://localhost") -> CheckContext:
    cfg = DastConfig(seed=3)
    guard = ScopeGuard(["localhost"])
    client = DastClient(guard, cfg, transport=httpx.MockTransport(handler))
    return CheckContext.create(client, base, cfg)


async def _run(handler, base: str = "http://localhost", endpoints=None) -> list:
    ctx = _ctx(handler, base)
    findings = await passive.run(ctx, endpoints if endpoints is not None else ENDPOINTS)
    await ctx.client.aclose()
    return findings


def _by_rule(findings) -> dict[str, object]:
    return {f.rule_id: f for f in findings}


# --------------------------------------------------------------------------- fixture apps
def _sloppy(request: httpx.Request) -> httpx.Response:
    """No security headers, leaky banner, flagless cookie, reflective CORS, traceback on 404."""
    path = request.url.path
    headers = {
        "content-type": "text/html",
        "server": "Werkzeug/2.0.1 Python/3.11.2",
        "x-powered-by": "Express 4.18",
    }
    if path == "/":
        headers["set-cookie"] = "session=abc123; Path=/"
        origin = request.headers.get("origin")
        if origin:
            headers["access-control-allow-origin"] = origin
            headers["access-control-allow-credentials"] = "true"
        return httpx.Response(200, text="<html>home</html>", headers=headers)
    if path == "/.git/HEAD":
        return httpx.Response(200, text="ref: refs/heads/main\n", headers={"content-type": "text/plain"})
    if path == "/.env":
        return httpx.Response(200, text="SECRET_KEY=hunter2\nDB_PASSWORD=swordfish\n")
    if path == "/robots.txt":
        return httpx.Response(200, text="User-agent: *\nDisallow: /admin\n")
    if path == "/console":
        return httpx.Response(200, text="<h1>Werkzeug Debugger console</h1>", headers=headers)
    if path == "/files":
        return httpx.Response(200, text="<title>Index of /files</title><a href=x>x</a>", headers=headers)
    if path == "/search":
        return httpx.Response(200, text="<html>results</html>", headers=headers)
    # unknown path -> verbose traceback
    return httpx.Response(
        500,
        text='Traceback (most recent call last):\n  File "app.py", line 42, in view\n    boom()',
        headers=headers,
    )


def _hardened(request: httpx.Request) -> httpx.Response:
    path = request.url.path
    headers = dict(HARDENED_HEADERS)
    if path == "/":
        headers["set-cookie"] = "session=abc123; Path=/; HttpOnly; SameSite=Lax; Secure"
        return httpx.Response(200, text="<html>home</html>", headers=headers)
    if path in ("/search",):
        return httpx.Response(200, text="<html>results</html>", headers=headers)
    return httpx.Response(404, text="<html>not found</html>", headers=headers)


# --------------------------------------------------------------------------- security headers
async def test_missing_security_headers_reported_once_with_paths():
    found = _by_rule(await _run(_sloppy))
    csp = found["dast.passive.csp-missing"]
    assert csp.cwe == 693 and csp.runtime.proof == "header" and csp.code is None
    assert csp.raw["affected_paths"] == ["/", "/search"]
    assert "2 of 2 sampled paths" in csp.runtime.evidence
    assert "dast.passive.nosniff-missing" in found
    assert "dast.passive.referrer-policy-missing" in found
    assert found["dast.passive.clickjacking"].cwe == 1021


async def test_hardened_app_reports_no_header_findings():
    rules = _by_rule(await _run(_hardened))
    for rule in (
        "dast.passive.csp-missing",
        "dast.passive.nosniff-missing",
        "dast.passive.referrer-policy-missing",
        "dast.passive.clickjacking",
        "dast.passive.version-banner",
        "dast.passive.cors-permissive",
    ):
        assert rule not in rules, f"{rule} should not fire on a hardened app"


async def test_hsts_only_checked_over_https():
    # plain HTTP: HSTS is meaningless, so it must not be reported
    assert "dast.passive.hsts-missing" not in _by_rule(await _run(_sloppy))

    def https_app(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<html>hi</html>", headers={"content-type": "text/html"})

    guard = ScopeGuard(["localhost"])
    cfg = DastConfig(seed=3)
    client = DastClient(guard, cfg, transport=httpx.MockTransport(https_app))
    ctx = CheckContext.create(client, "https://localhost", cfg)
    findings = await passive.run(ctx, [Endpoint("GET", "https://localhost/", "/")])
    await client.aclose()
    assert "dast.passive.hsts-missing" in _by_rule(findings)


# --------------------------------------------------------------------------- cookies
async def test_cookie_flag_findings():
    found = _by_rule(await _run(_sloppy))
    httponly = found["dast.passive.cookie-httponly"]
    assert httponly.cwe == 1004 and httponly.raw["cookies"] == ["session"]
    assert found["dast.passive.cookie-samesite"].cwe == 1275
    # Secure is not flagged over plain HTTP (B-04)
    assert "dast.passive.cookie-secure" not in found


async def test_no_cookie_findings_when_flags_present():
    found = _by_rule(await _run(_hardened))
    assert not [r for r in found if r.startswith("dast.passive.cookie-")]


async def test_multiple_set_cookie_headers_are_all_inspected():
    def two_cookies(request: httpx.Request) -> httpx.Response:
        # two separate Set-Cookie headers: a plain dict would collapse them
        return httpx.Response(
            200,
            text="<html>hi</html>",
            headers=[
                ("content-type", "text/html"),
                ("set-cookie", "a=1; HttpOnly; SameSite=Lax"),
                ("set-cookie", "b=2; Path=/"),  # missing both flags
            ],
        )

    found = _by_rule(await _run(two_cookies, endpoints=[Endpoint("GET", "http://localhost/", "/")]))
    assert found["dast.passive.cookie-httponly"].raw["cookies"] == ["b"]


# --------------------------------------------------------------------------- CORS
async def test_permissive_cors_reflected_origin():
    f = _by_rule(await _run(_sloppy))["dast.passive.cors-permissive"]
    assert f.cwe == 942
    assert f.raw["access_control_allow_origin"] == passive.CORS_PROBE_ORIGIN
    assert f.raw["allow_credentials"] is True and f.confidence == 0.9


async def test_wildcard_cors_reported():
    def wildcard(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            text="<html>hi</html>",
            headers={"content-type": "text/html", "access-control-allow-origin": "*"},
        )

    f = _by_rule(await _run(wildcard, endpoints=[Endpoint("GET", "http://localhost/", "/")]))
    assert f["dast.passive.cors-permissive"].raw["access_control_allow_origin"] == "*"


async def test_strict_cors_not_reported():
    def strict(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            text="<html>hi</html>",
            headers={"content-type": "text/html", "access-control-allow-origin": "https://localhost"},
        )

    assert "dast.passive.cors-permissive" not in _by_rule(
        await _run(strict, endpoints=[Endpoint("GET", "http://localhost/", "/")])
    )


# --------------------------------------------------------------------------- banners / errors / files
async def test_version_banner_reported():
    f = _by_rule(await _run(_sloppy))["dast.passive.version-banner"]
    assert f.cwe == 497 and "server" in f.raw["banners"]


async def test_banner_without_version_is_ignored():
    def plain_banner(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<html>hi</html>", headers={"content-type": "text/html", "server": "nginx"})

    assert "dast.passive.version-banner" not in _by_rule(
        await _run(plain_banner, endpoints=[Endpoint("GET", "http://localhost/", "/")])
    )


async def test_verbose_error_and_debug_console():
    found = _by_rule(await _run(_sloppy))
    err = found["dast.passive.verbose-error"]
    assert err.cwe == 209 and err.runtime.proof == "error"
    assert found["dast.passive.debug-console"].cwe == 489


async def test_exposed_files_reported_with_robots_informational():
    found = _by_rule(await _run(_sloppy))
    git = found["dast.passive.exposed-git-HEAD"]
    env = found["dast.passive.exposed-env"]
    robots = found["dast.passive.exposed-robotstxt"]
    assert git.cwe == 538 and env.cwe == 538
    assert robots.cwe == 200 and robots.confidence == 0.3  # informational only
    assert "informational" in robots.runtime.evidence


async def test_missing_files_not_reported():
    found = _by_rule(await _run(_hardened))
    assert not [r for r in found if r.startswith("dast.passive.exposed-")]


async def test_directory_listing_detected():
    found = _by_rule(
        await _run(
            _sloppy,
            endpoints=[Endpoint("GET", "http://localhost/", "/"), Endpoint("GET", "http://localhost/files", "/files")],
        )
    )
    assert found["dast.passive.directory-listing"].cwe == 548


# --------------------------------------------------------------------------- shape / determinism
async def test_findings_are_runtime_only_and_deterministic():
    first = await _run(_sloppy)
    second = await _run(_sloppy)
    assert [f.id for f in first] == [f.id for f in second]  # stable ids and order
    assert len({f.id for f in first}) == len(first)  # once per host, no duplicates
    for f in first:
        assert f.code is None and f.taint is None and f.engine.value == "dast"
        assert f.runtime is not None and f.runtime.param is None and f.runtime.payload is None
        assert f.runtime.evidence and f.runtime.repro_curl


def test_sample_paths_is_bounded_and_starts_at_root():
    eps = [Endpoint("GET", f"http://localhost/p{i}", f"/p{i}") for i in range(10)]
    eps.append(Endpoint("POST", "http://localhost/only-post", "/only-post"))
    paths = passive.sample_paths(eps)
    assert paths[0] == "/" and len(paths) == passive.SAMPLE_PATHS
    assert "/only-post" not in paths  # GET only


def _route(path: str, *params: str, method: str = "GET") -> Endpoint:
    """A route-map (seeded) endpoint with optional query params."""
    return Endpoint(
        method, f"http://localhost{path}", path, f"r{path}", [Param(p, ParamLocation.QUERY, "x") for p in params]
    )


def test_paramless_get_paths_keeps_only_parameterless_route_map_gets():
    eps = [
        _route("/b"),
        _route("/a"),
        _route("/with-q", "q"),
        _route("/posted", method="POST"),
        Endpoint("GET", "http://localhost/crawled", "/crawled", None, [], "crawl"),
        _route("/account/logout"),
        _route("/sign_off"),
    ]
    assert passive.paramless_get_paths(eps) == ["/a", "/b"]
    many = [_route(f"/p{i:03d}") for i in range(passive.ERROR_PROBE_LIMIT + 5)]
    assert len(passive.paramless_get_paths(many)) == passive.ERROR_PROBE_LIMIT


async def test_verbose_error_on_a_paramless_route_beyond_the_sample():
    """A-68: a param-less GET route outside the 5 sampled paths is still checked for tracebacks."""
    seen: list[str] = []

    def app(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.path)
        if request.url.path == "/z/fail":
            return httpx.Response(500, text='Traceback (most recent call last):\n  File "x.py", line 3, in v')
        if request.url.path in {"/", "/a", "/b", "/c", "/d", "/z/q", "/z/logout"}:
            return httpx.Response(200, text="<html>ok</html>", headers=HARDENED_HEADERS)
        return httpx.Response(404, text="<html>not found</html>", headers=HARDENED_HEADERS)

    eps = [_route(p) for p in ("/", "/a", "/b", "/c", "/d", "/z/fail", "/z/logout")] + [_route("/z/q", "q")]
    assert "/z/fail" not in passive.sample_paths(eps)
    ctx = _ctx(app)
    found = _by_rule(await passive.run(ctx, eps))
    await ctx.client.aclose()
    err = found["dast.passive.verbose-error"]
    assert (err.cwe, err.runtime.path, err.raw["affected_paths"]) == (209, "/z/fail", ["/z/fail"])
    assert seen.count("/z/fail") == 1  # one plain GET
    assert "/z/logout" not in seen and "/z/q" not in seen  # session-ending and param routes are not probed
    assert ctx.sent_payloads == [passive.CORS_PROBE_ORIGIN]  # R4: a plain GET injects nothing


async def test_only_the_cors_origin_probe_is_injected():
    """R4: passive checks inject exactly one value - the fixed CORS probe Origin."""
    ctx = _ctx(_sloppy)
    await passive.run(ctx, ENDPOINTS)
    await ctx.client.aclose()
    assert ctx.sent_payloads == [passive.CORS_PROBE_ORIGIN]
    assert passive.CORS_PROBE_ORIGIN.endswith(".invalid")  # can never resolve


async def test_unreachable_host_yields_nothing():
    def dead(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    assert await _run(dead) == []
