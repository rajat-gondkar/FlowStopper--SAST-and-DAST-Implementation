"""Endpoint discovery tests (P1-B2). Owner: B. Seeding is pure; crawl runs over MockTransport."""

from __future__ import annotations

import httpx

from FlowStopper.dast.client import DastClient
from FlowStopper.dast.config import DastConfig
from FlowStopper.dast.discovery import benign_value, crawl, discover, fill_path, seed_endpoints
from FlowStopper.dast.types import Endpoint
from FlowStopper.models import ParamLocation, Route, RouteParam
from FlowStopper.scope import ScopeGuard

GUARD = ScopeGuard(["localhost"])
BASE = "http://localhost:8080"


def _route(method, template, params=()):
    return Route(
        id=f"{method} {template}",
        method=method,
        path_template=template,
        path_regex="^x$",
        handler="h",
        file="f.py",
        line_start=1,
        line_end=2,
        params=list(params),
    )


# --------------------------------------------------------------------------- seeding (pure)
def test_fill_path_samples_by_converter():
    assert fill_path("/api/items/<int:id>") == "/api/items/1"
    assert fill_path("/docs/<path:name>") == "/docs/a.txt"
    assert fill_path("/u/<name>") == "/u/test"
    assert fill_path("/o/{order_id}") == "/o/test"
    assert fill_path("/f/{p:path}") == "/f/a.txt"


def test_benign_value_is_generic():
    assert benign_value("id") == "1"
    assert benign_value("user_id") == "1"
    assert benign_value("filename") == "a.txt"
    assert benign_value("q") == "test"


def test_seed_endpoints_fills_path_and_keeps_query_params():
    routes = [
        _route(
            "GET",
            "/api/items/<int:id>",
            [
                RouteParam(name="id", location=ParamLocation.PATH, required=True),
                RouteParam(name="q", location=ParamLocation.QUERY),
            ],
        )
    ]
    eps = seed_endpoints(routes, BASE)
    assert len(eps) == 1
    ep = eps[0]
    assert ep.path == "/api/items/1" and ep.route_id == "GET /api/items/<int:id>"
    # the PATH param is filled into the URL AND attached, so checks can inject into it (B-11)
    assert ep.param_names() == {"id", "q"}
    pid = next(p for p in ep.params if p.name == "id")
    assert pid.location is ParamLocation.PATH and pid.value == "1" and pid.segment == -1 and pid.required
    assert ep.source == "seed"


def test_seed_endpoints_attaches_path_params_in_any_segment():
    eps = seed_endpoints([_route("GET", "/api/<tenant>/orders/<int:id>")], BASE)
    by_name = {p.name: p for p in eps[0].params}
    assert set(by_name) == {"tenant", "id"}
    assert (by_name["tenant"].location, by_name["tenant"].segment, by_name["tenant"].value) == (
        ParamLocation.PATH,
        -3,
        "test",
    )
    assert (by_name["id"].segment, by_name["id"].value) == (-1, "1")


def test_seed_endpoints_path_param_names_flask_and_fastapi():
    flask, fastapi = seed_endpoints([_route("GET", "/docs/<path:name>"), _route("GET", "/f/{p:path}/{order_id}")], BASE)
    assert [(p.name, p.value, p.segment) for p in flask.params] == [("name", "a.txt", -1)]
    assert [(p.name, p.value, p.segment) for p in fastapi.params] == [("p", "a.txt", -2), ("order_id", "test", -1)]


def test_seed_endpoints_skips_segments_mixing_token_and_literal():
    eps = seed_endpoints([_route("GET", "/export/<int:id>.json")], BASE)
    assert eps[0].path == "/export/1.json"
    assert eps[0].params == []


# --------------------------------------------------------------------------- crawl
def _site(request: httpx.Request) -> httpx.Response:
    path = request.url.path
    if path == "/":
        html = """
          <html><body>
            <a href="/about">about</a>
            <a href="http://evil.com/x">offsite</a>
            <form action="/search" method="get"><input name="q"></form>
            <form action="/login" method="post"><input name="username"><input name="password"></form>
            <script>fetch("/api/data?id=1")</script>
          </body></html>
        """
        return httpx.Response(200, text=html, headers={"content-type": "text/html"})
    if path == "/robots.txt":
        return httpx.Response(200, text="User-agent: *\nDisallow: /secret\n", headers={"content-type": "text/plain"})
    if path == "/openapi.json":
        spec = '{"paths": {"/api/orders/{id}": {"get": {"parameters": [{"name": "fields", "in": "query"}]}}}}'
        return httpx.Response(200, text=spec, headers={"content-type": "application/json"})
    if path in ("/about", "/search", "/api/data", "/secret", "/api/orders/test"):
        return httpx.Response(200, text="<html>ok</html>", headers={"content-type": "text/html"})
    return httpx.Response(404, text="nope")


async def test_crawl_finds_links_forms_fetch_robots_openapi():
    async with DastClient(GUARD, transport=httpx.MockTransport(_site)) as client:
        eps = await crawl(client, BASE, DastConfig())
    by_key = {e.key: e for e in eps}
    assert ("GET", "/about") in by_key
    assert ("GET", "/search") in by_key and by_key[("GET", "/search")].param_names() == {"q"}
    post_login = by_key[("POST", "/login")]
    assert post_login.param_names() == {"username", "password"}
    assert all(p.location is ParamLocation.FORM for p in post_login.params)
    assert ("GET", "/api/data") in by_key  # from fetch() literal
    assert ("GET", "/secret") in by_key  # from robots Disallow
    assert ("GET", "/api/orders/test") in by_key  # from openapi (path filled)


async def test_crawl_stays_same_origin():
    async with DastClient(GUARD, transport=httpx.MockTransport(_site)) as client:
        eps = await crawl(client, BASE, DastConfig())
    assert all("evil.com" not in e.url for e in eps)


async def test_crawl_respects_url_budget():
    async with DastClient(GUARD, transport=httpx.MockTransport(_site)) as client:
        eps = await crawl(client, BASE, DastConfig(crawl_max_urls=2))
    assert len(eps) <= 10  # tight budget keeps discovery small (a couple of pages visited)


async def test_discover_merges_seeded_params_win():
    # a seeded GET /search carries param 'category'; the crawled /search has 'q' -> seeded must win
    routes = [_route("GET", "/search", [RouteParam(name="category", location=ParamLocation.QUERY)])]
    async with DastClient(GUARD, transport=httpx.MockTransport(_site)) as client:
        eps = await discover(client, BASE, routes, DastConfig())
    search = next(e for e in eps if e.key == ("GET", "/search"))
    assert search.source == "seed" and search.param_names() == {"category"}


def test_endpoint_dataclass_defaults():
    ep = Endpoint("GET", "http://localhost/x", "/x")
    assert ep.params == [] and ep.route_id is None and ep.key == ("GET", "/x")
