"""Async HTTP client behind the scope guard (Owner: B, P1-B1). Redaction (R7), repro_curl.

Every request is scope-checked before it is sent and on every redirect hop (R3). Redirects are NOT
followed by default; when a caller opts in, each hop is re-checked and an external hop is refused.
Authorization/Cookie values are redacted from the stored request text and repro curl unless
keep_secrets is set (R7). Response bodies are capped (<=64 KB kept in memory for analysis, <=2 KB
stored as the excerpt). Every exchange is recorded for the audit trail.
"""

from __future__ import annotations

import asyncio
import json as _json
import shlex
import time
from dataclasses import dataclass, field
from types import TracebackType
from typing import Optional
from urllib.parse import urljoin, urlsplit

import httpx

from FlowStopper.dast.config import DastConfig, LoginStep
from FlowStopper.scope import ScopeError, ScopeGuard

BODY_MAX = 64 * 1024  # kept in memory for checks to analyse
STORED_MAX = 2 * 1024  # persisted excerpt (Finding.response_excerpt)
REDACTED = "<redacted>"
REDACT_HEADERS = frozenset({"authorization", "cookie"})
MAX_REDIRECT_HOPS = 5


@dataclass
class AuthResult:
    """Outcome of the login step, surfaced in `DastResult.stats["auth"]`.

    `ok` is True when nothing was configured, so callers can treat it as "the scan may proceed".
    The token value itself is never stored here (R7) - only which header it was placed in.
    """

    configured: bool
    attempted: bool
    ok: bool
    status: Optional[int] = None
    token_header: Optional[str] = None
    cookies: bool = False
    detail: str = ""

    def as_stats(self) -> dict:
        return {
            "configured": self.configured,
            "attempted": self.attempted,
            "ok": self.ok,
            "status": self.status,
            "token_header": self.token_header,
            "cookies": self.cookies,
            "detail": self.detail,
        }


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
    # Raw Set-Cookie lines. Kept separately because several cookies arrive as repeated headers and
    # response_headers (a plain dict) would collapse them - the passive cookie-flag check needs each.
    set_cookies: list[str] = field(default_factory=list)

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
        # Static credentials from config, with explicit arguments taking precedence.
        auth = self._config.auth
        merged_headers = {**(auth.headers if auth else {}), **(headers or {})}
        merged_cookies = {**(auth.cookies if auth else {}), **(cookies or {})}
        timeout = httpx.Timeout(self._config.total_timeout_s, connect=self._config.connect_timeout_s)
        self._client = httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=False,
            headers=merged_headers or None,
            cookies=merged_cookies or None,
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

    @property
    def default_header_names(self) -> frozenset[str]:
        """Lower-cased names of the headers sent on every request (static auth + any login token)."""
        return frozenset(name.lower() for name in self._client.headers)

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
            set_cookies=list(resp.headers.get_list("set-cookie")),
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

    # ------------------------------------------------------------------ authentication (P4-B1 item 7)
    def set_default_header(self, name: str, value: str) -> None:
        """Send `name` on every later request (where a session token belongs)."""
        self._client.headers[name] = value

    async def authenticate(self) -> AuthResult:
        """Run the configured login step so later checks reach routes that need a session.

        Returns an AuthResult either way: a failed login is reported, not raised, because an
        unauthenticated scan still finds the public half of an app. The runner records it in
        `stats["auth"]` and logs a warning so a silently useless scan is impossible to miss.
        """
        auth = self._config.auth
        if auth is None or auth.login is None:
            return AuthResult(configured=auth.is_configured if auth else False, attempted=False, ok=True)

        step = auth.login
        try:
            ex = await self.request(
                step.method,
                step.url,
                data=step.form_data,
                json=step.json_body,
                headers=step.headers or None,
            )
        except ScopeError:
            raise  # an out-of-scope login URL is a configuration error, not a login failure (R3)
        except httpx.HTTPError as exc:
            return AuthResult(configured=True, attempted=True, ok=False, detail=f"{type(exc).__name__}: {exc}")

        if not 200 <= ex.status < 400:
            return AuthResult(configured=True, attempted=True, ok=False, status=ex.status, detail="login rejected")

        got_cookies = bool(ex.set_cookies) or bool(self._client.cookies)
        if not step.expects_token:
            # Cookie-based session: the jar already holds whatever was set.
            return AuthResult(
                configured=True,
                attempted=True,
                ok=got_cookies,
                status=ex.status,
                cookies=got_cookies,
                detail="session cookie stored" if got_cookies else "login succeeded but set no cookie",
            )

        token = _extract_token(ex, step)
        if not token:
            where = step.token_response_header or f"json:{step.token_json_field}"
            return AuthResult(
                configured=True, attempted=True, ok=False, status=ex.status, detail=f"no token found in {where}"
            )
        self.set_default_header(step.token_request_header, f"{step.token_prefix}{token}")
        return AuthResult(
            configured=True,
            attempted=True,
            ok=True,
            status=ex.status,
            token_header=step.token_request_header,
            cookies=got_cookies,
            detail=f"token copied to {step.token_request_header}",
        )


def _json_path(payload: object, dotted: str) -> Optional[str]:
    """Walk a dotted path into a decoded JSON body; None if any step is missing."""
    current = payload
    for part in dotted.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return str(current) if isinstance(current, (str, int, float)) else None


def _extract_token(ex: HttpExchange, step: LoginStep) -> Optional[str]:
    """The session token from a login response, by header or by JSON field."""
    if step.token_response_header:
        for name, value in ex.response_headers.items():
            if name.lower() == step.token_response_header.lower() and value.strip():
                return value.strip()
        return None
    if step.token_json_field:
        try:
            payload = _json.loads(ex.body)
        except ValueError:
            return None
        return _json_path(payload, step.token_json_field)
    return None


def _body_repr(data: Optional[dict], json: object) -> Optional[str]:
    if data:
        return "&".join(f"{k}={v}" for k, v in data.items())
    if json is not None:
        import json as _json

        return _json.dumps(json)
    return None
