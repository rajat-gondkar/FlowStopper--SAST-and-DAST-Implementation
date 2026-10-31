"""Endpoint discovery (Owner: B, P1-B2): seeded from routes.json + same-origin crawl.

Seeding turns each Route into a concrete request (path params sampled by converter, known params
attached with benign values). The crawler walks the same origin (depth <= crawl_max_depth,
<= crawl_max_urls) following links/forms/`fetch`/`axios` literals and reading /robots.txt,
/sitemap.xml and /openapi.json. Seeded and crawled endpoints are merged; **seeded params win**.
Every fetch goes through the scope-guarded client (R3).
"""

from __future__ import annotations

import json
import re
from urllib.parse import parse_qsl, urljoin, urlsplit

import httpx
from bs4 import BeautifulSoup

from FlowStopper.dast.client import DastClient
from FlowStopper.dast.config import DastConfig
from FlowStopper.dast.types import Endpoint, Param
from FlowStopper.models import ParamLocation, Route
from FlowStopper.scope import ScopeError

_TOKEN = re.compile(r"[<{][^<>{}]*[>}]")
_FETCH = re.compile(r"""(?:fetch|axios(?:\.\w+)?)\s*\(\s*['"]([^'"]+)['"]""", re.I)
_LOC = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.I)
_HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}

NUMERIC_NAMES = {"id", "page", "limit", "offset", "count", "qty", "quantity", "num", "year", "month", "day"}
FILE_NAMES = {"file", "filename", "path", "template", "doc", "document", "img", "image", "attachment"}


# --------------------------------------------------------------------------- benign sample values
def benign_value(name: str) -> str:
    """A harmless placeholder value for a parameter, picked generically from its name (no app data)."""
    n = name.lower()
    if n in NUMERIC_NAMES or n.endswith("id") or n.endswith("_id"):
        return "1"
    if n in FILE_NAMES or n.endswith("file") or n.endswith("filename"):
        return "a.txt"
    return "test"


def _sample_path_value(token: str) -> str:
    inner = token[1:-1]
    if token[0] == "<":  # Flask: <converter:name> or <name>
        conv = inner.split(":", 1)[0] if ":" in inner else ""
    else:  # FastAPI/Starlette: {name:converter} or {name}
        conv = inner.split(":", 1)[1] if ":" in inner else ""
    conv = conv.lower()
    if conv == "path":
        return "a.txt"
    if conv == "uuid":
        return "00000000-0000-0000-0000-000000000000"
    if conv in {"int", "float"}:
        return "1"
    return "test"


def fill_path(template: str) -> str:
    """Replace `<...>`/`{...}` path tokens with benign concrete samples."""
    return _TOKEN.sub(lambda m: _sample_path_value(m.group(0)), template)


# --------------------------------------------------------------------------- seeding
def _abs(base_url: str, path: str) -> str:
    return base_url.rstrip("/") + "/" + path.lstrip("/")


def _path_token_name(token: str) -> str:
    inner = token[1:-1]
    if token[0] == "<":  # Flask: <converter:name> or <name>
        return inner.split(":", 1)[1] if ":" in inner else inner
    return inner.split(":", 1)[0]  # FastAPI/Starlette: {name:converter} or {name}


def path_params(template: str) -> list[Param]:
    """One PATH Param per path segment that is exactly one `<...>`/`{...}` token, in any position.

    `segment` is the segment index counted from the end, so it still points at the right segment
    once the template is joined onto a base URL that has its own path prefix. A segment mixing a
    token with literal text (`<id>.json`) is skipped: replacing the whole segment would drop the
    literal part and probe a different route.
    """
    segs = template.split("/")
    out: list[Param] = []
    for i, seg in enumerate(segs):
        if _TOKEN.fullmatch(seg):
            out.append(Param(_path_token_name(seg), ParamLocation.PATH, _sample_path_value(seg), True, i - len(segs)))
    return out


def seed_endpoints(routes: list[Route], base_url: str) -> list[Endpoint]:
    """One concrete Endpoint per Route (path filled; path and non-path params attached with benign values)."""
    out: list[Endpoint] = []
    for r in routes:
        path = fill_path(r.path_template)
        url = _abs(base_url, path)
        params = [
            Param(p.name, p.location, benign_value(p.name), p.required)
            for p in r.params
            if p.location is not ParamLocation.PATH
        ]
        params += path_params(r.path_template)
        out.append(
            Endpoint(
                method=r.method.upper(),
                url=url,
                path=urlsplit(url).path or path,
                route_id=r.id,
                params=params,
                source="seed",
            )
        )
    return out


# --------------------------------------------------------------------------- crawl helpers
def _origin(url: str) -> tuple[str, str, int]:
    s = urlsplit(url)
    port = s.port or (443 if s.scheme == "https" else 80)
    return (s.scheme, (s.hostname or "").lower(), port)


def _same_origin(a: str, b: str) -> bool:
    return _origin(a) == _origin(b)


def _query_params(url: str) -> list[Param]:
    seen: dict[str, Param] = {}
    for name, value in parse_qsl(urlsplit(url).query, keep_blank_values=True):
        seen.setdefault(name, Param(name, ParamLocation.QUERY, value or benign_value(name)))
    return list(seen.values())


def _parse_robots(body: str) -> list[str]:
    paths: list[str] = []
    for line in body.splitlines():
        low = line.strip().lower()
        if low.startswith(("allow:", "disallow:")):
            value = line.split(":", 1)[1].strip()
            if value and value != "/":
                paths.append(value)
    return paths


def _parse_openapi(body: str, base_url: str) -> list[Endpoint]:
    try:
        spec = json.loads(body)
        paths = spec["paths"]
    except (ValueError, KeyError, TypeError):
        return []
    out: list[Endpoint] = []
    for raw_path, item in paths.items():
        if not isinstance(item, dict):
            continue
        for method, op in item.items():
            if method.upper() not in _HTTP_METHODS or not isinstance(op, dict):
                continue
            filled = fill_path(str(raw_path))
            url = _abs(base_url, filled)
            params = [
                Param(p["name"], ParamLocation.QUERY, benign_value(p["name"]))
                for p in op.get("parameters", [])
                if isinstance(p, dict) and p.get("name") and p.get("in") == "query"
            ]
            out.append(Endpoint(method.upper(), url, urlsplit(url).path or filled, None, params, "crawl"))
    return out


def _add(endpoints: dict[tuple[str, str], Endpoint], ep: Endpoint) -> None:
    endpoints.setdefault(ep.key, ep)


def _extract_html(ex_body: str, page_url: str) -> tuple[list[Endpoint], list[str]]:
    """Return (endpoints, link_urls) found in an HTML page."""
    soup = BeautifulSoup(ex_body, "html.parser")
    endpoints: list[Endpoint] = []
    links: list[str] = []
    for a in soup.find_all("a", href=True):
        url = urljoin(page_url, a["href"])
        links.append(url)
        endpoints.append(Endpoint("GET", url, urlsplit(url).path or "/", None, _query_params(url), "crawl"))
    for form in soup.find_all("form"):
        method = (form.get("method") or "GET").upper()
        action = urljoin(page_url, form.get("action") or page_url)
        loc = ParamLocation.FORM if method in {"POST", "PUT", "PATCH"} else ParamLocation.QUERY
        names = [i.get("name") for i in form.find_all(["input", "textarea", "select"]) if i.get("name")]
        params = [Param(n, loc, benign_value(n)) for n in dict.fromkeys(names)]
        endpoints.append(Endpoint(method, action, urlsplit(action).path or "/", None, params, "crawl"))
        if method == "GET":
            links.append(action)
    for script in soup.find_all("script"):
        for m in _FETCH.finditer(script.string or ""):
            url = urljoin(page_url, m.group(1))
            links.append(url)
            endpoints.append(Endpoint("GET", url, urlsplit(url).path or "/", None, _query_params(url), "crawl"))
    return endpoints, links


# --------------------------------------------------------------------------- crawl
async def crawl(client: DastClient, base_url: str, config: DastConfig | None = None) -> list[Endpoint]:
    config = config or DastConfig()
    base = base_url.rstrip("/")
    endpoints: dict[tuple[str, str], Endpoint] = {}
    visited: set[str] = set()
    queue: list[tuple[str, int]] = [(base + "/", 0)]
    queue += [(base + sp, 0) for sp in ("/robots.txt", "/sitemap.xml", "/openapi.json", "/swagger.json")]

    while queue and len(visited) < config.crawl_max_urls:
        url, depth = queue.pop(0)
        path = urlsplit(url).path or "/"
        if path in visited:
            continue
        visited.add(path)
        try:
            ex = await client.get(url)
        except (ScopeError, httpx.HTTPError):
            continue

        if ex.status < 400:
            _add(endpoints, Endpoint("GET", url, path, None, _query_params(url), "crawl"))
        ctype = ex.response_headers.get("content-type", "").lower()

        if path.endswith("robots.txt"):
            for rel in _parse_robots(ex.body):
                _enqueue(queue, endpoints, base, urljoin(base + "/", rel), depth + 1, config, visited)
            continue
        if path.endswith(".xml"):
            for loc in _LOC.findall(ex.body):
                _enqueue(queue, endpoints, base, loc, depth + 1, config, visited)
            continue
        if path.endswith(".json"):
            for ep in _parse_openapi(ex.body, base):
                _add(endpoints, ep)
            continue
        if "html" not in ctype or depth >= config.crawl_max_depth:
            continue

        found, links = _extract_html(ex.body, url)
        for ep in found:
            if _same_origin(base + "/", ep.url):  # never emit an off-origin endpoint (we scan in-scope only)
                _add(endpoints, ep)
        for link in links:
            _enqueue(queue, endpoints, base, link, depth + 1, config, visited)

    return list(endpoints.values())


def _enqueue(
    queue: list[tuple[str, int]],
    endpoints: dict[tuple[str, str], Endpoint],
    base: str,
    url: str,
    depth: int,
    config: DastConfig,
    visited: set[str],
) -> None:
    if not _same_origin(base + "/", url) or depth > config.crawl_max_depth:
        return
    path = urlsplit(url).path or "/"
    if path in visited:
        return
    if len(visited) + len(queue) < config.crawl_max_urls:
        queue.append((url, depth))


# --------------------------------------------------------------------------- merge
async def discover(
    client: DastClient,
    base_url: str,
    routes: list[Route] | None = None,
    config: DastConfig | None = None,
) -> list[Endpoint]:
    """Seed from the route map, crawl the same origin, and merge (seeded params win)."""
    config = config or DastConfig()
    merged: dict[tuple[str, str], Endpoint] = {}
    for ep in await crawl(client, base_url, config):
        merged[ep.key] = ep
    for ep in seed_endpoints(routes or [], base_url):
        merged[ep.key] = ep  # seeded always wins on a key clash
    return sorted(merged.values(), key=lambda e: (e.path, e.method))
