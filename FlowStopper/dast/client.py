"""Async HTTP client behind the scope guard (Owner: B, P1-B1). Redaction (R7), repro_curl.

Every request is scope-checked before it is sent and on every redirect hop (R3). Redirects are NOT
followed by default; when a caller opts in, each hop is re-checked and an external hop is refused.
Authorization/Cookie values are redacted from the stored request text and repro curl unless
keep_secrets is set (R7). Response bodies are capped (<=64 KB kept in memory for analysis, <=2 KB
stored as the excerpt). Every exchange is recorded for the audit trail.
"""

from __future__ import annotations

import asyncio
import shlex
import time
from dataclasses import dataclass
from types import TracebackType
from typing import Optional
from urllib.parse import urljoin, urlsplit

import httpx

from FlowStopper.dast.config import DastConfig
from FlowStopper.scope import ScopeGuard

BODY_MAX = 64 * 1024  # kept in memory for checks to analyse
STORED_MAX = 2 * 1024  # persisted excerpt (Finding.response_excerpt)
REDACTED = "<redacted>"
REDACT_HEADERS = frozenset({"authorization", "cookie"})
MAX_REDIRECT_HOPS = 5


@dataclass
class HttpExchange:
    """One request/response, with a redacted audit view and a full-ish body for analysis."""

    method: str
    url: str
    path: str
    status: int
    request_headers: dict[str, str]
    response_headers: dict[str, str]
    request_text: str  # redacted raw request (audit)
    response_excerpt: str  # <= STORED_MAX
    body: str  # <= BODY_MAX, for checks (reflection/marker detection)
    elapsed_ms: float
    repro_curl: str

    @property
    def is_redirect(self) -> bool:
        return 300 <= self.status < 400 and "location" in {k.lower() for k in self.response_headers}


def _redact(headers: dict[str, str], keep_secrets: bool) -> dict[str, str]:
    if keep_secrets:
        return dict(headers)
    return {k: (REDACTED if k.lower() in REDACT_HEADERS else v) for k, v in headers.items()}


def _request_text(req: httpx.Request, keep_secrets: bool) -> str:
    target = req.url.raw_path.decode("ascii", "replace") or "/"
    lines = [f"{req.method} {target} HTTP/1.1"]
    for k, v in req.headers.items():
        shown = REDACTED if (not keep_secrets and k.lower() in REDACT_HEADERS) else v
        lines.append(f"{k}: {shown}")
    text = "\r\n".join(lines) + "\r\n\r\n"
    if req.content:
        text += req.content.decode("utf-8", "replace")[:STORED_MAX]
    return text


def _repro_curl(method: str, url: str, headers: dict[str, str], body: Optional[str], keep_secrets: bool) -> str:
    parts = ["curl", "-i"]
    if method.upper() != "GET":
        parts += ["-X", method.upper()]
    for k, v in headers.items():
        shown = REDACTED if (not keep_secrets and k.lower() in REDACT_HEADERS) else v
        parts += ["-H", shlex.quote(f"{k}: {shown}")]
    if body:
        parts += ["--data", shlex.quote(body)]
    parts.append(shlex.quote(url))
    return " ".join(parts)


class DastClient:
    """Scope-guarded async client. Use as `async with DastClient(guard, config) as client:`."""

    def __init__(
        self,
        scope: ScopeGuard,
        config: Optional[DastConfig] = None,
        *,
        headers: Optional[dict[str, str]] = None,
        cookies: Optional[dict[str, str]] = None,
        transport: Optional[httpx.BaseTransport] = None,
    ) -> None:
        self._scope = scope
        self._config = config or DastConfig()
        self._sem = asyncio.Semaphore(self._config.concurrency)
        self._rate_lock = asyncio.Lock()
        self._last_send = 0.0
        self.exchanges: list[HttpExchange] = []
        timeout = httpx.Timeout(self._config.total_timeout_s, connect=self._config.connect_timeout_s)
        self._client = httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=False,
            headers=headers,
            cookies=cookies,
            transport=transport,
        )

    async def __aenter__(self) -> DastClient:
        return self

    async def __aexit__(
        self,
        exc_type: Optional[type[BaseException]],
        exc: Optional[BaseException],
        tb: Optional[TracebackType],
    ) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._client.aclose()

    @property
    def keep_secrets(self) -> bool:
        return self._config.keep_secrets

    async def _rate_wait(self) -> None:
        rps = self._config.max_rps
        if not rps or rps <= 0:
            return
        async with self._rate_lock:
            gap = 1.0 / rps
            now = time.monotonic()
            wait = self._last_send + gap - now
            if wait > 0:
                await asyncio.sleep(wait)
            self._last_send = time.monotonic()

    async def _send_once(self, method: str, url: str, **kw: object) -> httpx.Response:
        async with self._sem:
            await self._rate_wait()
            self._scope.check(url)  # R3: check before every network send, including redirect hops
            last_exc: Optional[httpx.TransportError] = None
            for _attempt in range(2):  # retry once on connection reset / transport error
                try:
                    return await self._client.request(method, url, **kw)  # type: ignore[arg-type]
                except httpx.TransportError as e:
                    last_exc = e
            assert last_exc is not None
            raise last_exc

    def _record(
        self, method: str, resp: httpx.Response, sent_headers: dict[str, str], body_payload: Optional[str]
    ) -> HttpExchange:
        try:
            text = resp.text
        except Exception:  # pragma: no cover - undecodable body
            text = ""
        body = text[:BODY_MAX]
        try:
            elapsed = resp.elapsed.total_seconds() * 1000.0
        except (RuntimeError, AttributeError):  # pragma: no cover - MockTransport may not set it
            elapsed = 0.0
        final_url = str(resp.request.url)  # the URL actually sent, including any injected query
        ex = HttpExchange(
            method=method.upper(),
            url=final_url,
            path=urlsplit(final_url).path or "/",
            status=resp.status_code,
            request_headers=_redact(sent_headers, self.keep_secrets),
            response_headers=dict(resp.headers),
            request_text=_request_text(resp.request, self.keep_secrets),
            response_excerpt=text[:STORED_MAX],
            body=body,
            elapsed_ms=elapsed,
            repro_curl=_repro_curl(method, final_url, sent_headers, body_payload, self.keep_secrets),
        )
        self.exchanges.append(ex)
        return ex

    async def request(
        self,
        method: str,
        url: str,
        *,
        params: Optional[dict] = None,
        data: Optional[dict] = None,
        json: object = None,
        headers: Optional[dict[str, str]] = None,
        follow: bool = False,
        max_redirects: int = MAX_REDIRECT_HOPS,
    ) -> HttpExchange:
        """Send one request (optionally following in-scope redirects) and return the final exchange.

        Raises ScopeError if the URL - or any followed redirect hop - is out of scope.
        """
        sent_headers = dict(headers or {})
        body_payload = _body_repr(data, json)
        resp = await self._send_once(method, url, params=params, data=data, json=json, headers=headers)
        ex = self._record(method, resp, sent_headers, body_payload)
        hops = 0
        current = resp
        current_url = str(resp.request.url)
        while follow and current.is_redirect and hops < max_redirects:
            location = current.headers.get("location", "")
            next_url = urljoin(current_url, location)
            current = await self._send_once("GET", next_url)
            ex = self._record("GET", current, {}, None)
            current_url = next_url
            hops += 1
        return ex

    async def get(self, url: str, **kw: object) -> HttpExchange:
        return await self.request("GET", url, **kw)  # type: ignore[arg-type]

    async def login_post(
        self, url: str, *, data: Optional[dict] = None, json: object = None, headers: Optional[dict[str, str]] = None
    ) -> bool:
        """POST credentials and keep the resulting cookies in the jar. Returns True on a 2xx/3xx."""
        ex = await self.request("POST", url, data=data, json=json, headers=headers)
        return 200 <= ex.status < 400


def _body_repr(data: Optional[dict], json: object) -> Optional[str]:
    if data:
        return "&".join(f"{k}={v}" for k, v in data.items())
    if json is not None:
        import json as _json

        return _json.dumps(json)
    return None
