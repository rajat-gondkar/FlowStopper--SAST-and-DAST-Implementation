"""Baseline fingerprint + differential tests (P1-B3). Owner: B. Offline via MockTransport."""

from __future__ import annotations

import httpx

from FlowStopper.dast.baseline import Fingerprint, differs, establish_baseline, normalise_body
from FlowStopper.dast.client import DastClient
from FlowStopper.scope import ScopeGuard

GUARD = ScopeGuard(["localhost"])


def _ex(text: str, status: int = 200):
    # build a real HttpExchange cheaply through the client recorder would need a response; use a stub
    from FlowStopper.dast.client import HttpExchange

    return HttpExchange(
        method="GET",
        url="http://localhost/x",
        path="/x",
        status=status,
        request_headers={},
        response_headers={},
        request_text="",
        response_excerpt=text[:2048],
        body=text,
        elapsed_ms=0.0,
        repro_curl="",
    )


def test_normalise_strips_volatile_tokens():
    a = normalise_body("<p>Now: 2024-01-01T10:00:00Z id=550e8400-e29b-41d4-a716-446655440000</p>")
    b = normalise_body("<p>Now: 2025-12-31T23:59:59Z id=00000000-0000-0000-0000-000000000000</p>")
    assert a == b  # only the timestamp and UUID differ


def test_fingerprint_equal_for_volatile_only_diff():
    fa = Fingerprint.of(_ex('<input name="csrf_token" value="abc123">hello'))
    fb = Fingerprint.of(_ex('<input name="csrf_token" value="zzz999">hello'))
    assert fa == fb and not differs(fa, fb)


def test_fingerprint_differs_on_real_content_and_status():
    base = Fingerprint.of(_ex("hello world"))
    assert differs(base, Fingerprint.of(_ex("hello world!!! extra results")))
    assert differs(base, Fingerprint.of(_ex("hello world", status=500)))


async def test_establish_baseline_stable():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<p>stable page</p>", headers={"content-type": "text/html"})

    async with DastClient(GUARD, transport=httpx.MockTransport(handler)) as client:
        bl = await establish_baseline(client, "GET", "http://localhost/p")
    assert bl.unstable is False
    assert bl.matches(bl.primary)


async def test_establish_baseline_unstable_when_body_changes():
    seq = iter(["one one one", "two two two different"])

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=next(seq))

    async with DastClient(GUARD, transport=httpx.MockTransport(handler)) as client:
        bl = await establish_baseline(client, "GET", "http://localhost/rnd")
    assert bl.unstable is True
