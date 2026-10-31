"""DAST HTTP client tests (P1-B1). Owner: B. Offline via httpx.MockTransport (no network).

Asserts the scope guard gates every request and redirect hop (R3), redirects are not followed by
default, Authorization/Cookie are redacted unless keep_secrets (R7), repro_curl is built, bodies are
capped, cookies persist, and a transport reset is retried once.
"""

from __future__ import annotations

import httpx
import pytest

from FlowStopper.dast.client import BODY_MAX, STORED_MAX, DastClient
from FlowStopper.dast.config import DastConfig
from FlowStopper.scope import ScopeError, ScopeGuard

GUARD = ScopeGuard(["localhost", "127.0.0.1"])


def _client(handler, **kw) -> DastClient:
    return DastClient(GUARD, transport=httpx.MockTransport(handler), **kw)


def _ok(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, text="hello", headers={"content-type": "text/html"})


async def test_scope_blocks_out_of_scope_request():
    async with _client(_ok) as client:
        with pytest.raises(ScopeError):
            await client.get("http://evil.com/")
    assert client.exchanges == []  # nothing was sent


async def test_in_scope_request_recorded():
    async with _client(_ok) as client:
        ex = await client.get("http://localhost:5050/page")
        assert ex.status == 200 and ex.body == "hello" and ex.path == "/page"
        assert len(client.exchanges) == 1


async def test_redirects_not_followed_by_default():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/go":
            return httpx.Response(302, headers={"location": "http://localhost/dest"})
        return httpx.Response(200, text="arrived")

    async with _client(handler) as client:
        ex = await client.get("http://localhost/go")
        assert ex.status == 302 and ex.is_redirect
        assert len(client.exchanges) == 1  # did not follow


async def test_manual_follow_stays_in_scope():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/go":
            return httpx.Response(302, headers={"location": "http://localhost/dest"})
        return httpx.Response(200, text="arrived")

    async with _client(handler) as client:
        ex = await client.get("http://localhost/go", follow=True)
        assert ex.status == 200 and ex.body == "arrived"
        assert len(client.exchanges) == 2


async def test_manual_follow_refuses_external_hop():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "http://evil.com/steal"})

    async with _client(handler) as client:
        with pytest.raises(ScopeError):
            await client.get("http://localhost/go", follow=True)


async def test_authorization_redacted_in_audit_and_curl():
    async with _client(_ok) as client:
        ex = await client.get("http://localhost/x", headers={"Authorization": "Bearer sekret", "X-Trace": "1"})
    assert "sekret" not in ex.request_text and "<redacted>" in ex.request_text
    assert "sekret" not in ex.repro_curl
    assert "X-Trace: 1" in ex.repro_curl  # non-sensitive header kept


async def test_keep_secrets_disables_redaction():
    async with _client(_ok, headers=None) as client:
        client._config = DastConfig(keep_secrets=True)
        ex = await client.get("http://localhost/x", headers={"Authorization": "Bearer sekret"})
    assert "Bearer sekret" in ex.request_text and "Bearer sekret" in ex.repro_curl


async def test_body_excerpt_capped():
    big = "A" * (BODY_MAX * 2)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=big)

    async with _client(handler) as client:
        ex = await client.get("http://localhost/big")
    assert len(ex.response_excerpt) == STORED_MAX
    assert len(ex.body) == BODY_MAX


async def test_cookie_jar_persists():
    seen: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/set":
            return httpx.Response(200, headers={"set-cookie": "sid=abc; Path=/"})
        seen["cookie"] = request.headers.get("cookie", "")
        return httpx.Response(200, text="ok")

    async with _client(handler) as client:
        await client.get("http://localhost/set")
        await client.get("http://localhost/next")
    assert seen["cookie"] == "sid=abc"


async def test_retry_once_on_transport_error():
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            raise httpx.ConnectError("reset", request=request)
        return httpx.Response(200, text="recovered")

    async with _client(handler) as client:
        ex = await client.get("http://localhost/flaky")
    assert ex.status == 200 and calls["n"] == 2


async def test_post_body_in_curl():
    async with _client(_ok) as client:
        ex = await client.request("POST", "http://localhost/login", data={"u": "a", "p": "b"})
    assert "-X POST" in ex.repro_curl and "u=a&p=b" in ex.repro_curl
