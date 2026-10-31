"""DAST check tests: SQLi + XSS (P1-B4). Owner: B. Offline vulnerable apps via MockTransport.

Covers error-based SQLi, boolean-differential SQLi, a safe (parameterised) decoy, reflected XSS,
an escaped-output decoy, a JSON (non-HTML) response, full finding evidence, the injectable-location
gate, and the R4 provenance rule (only Appendix B payload shapes are ever sent).
"""

from __future__ import annotations

import html as htmlmod
import re

import httpx

from FlowStopper.dast.checks import sqli, xss
from FlowStopper.dast.checks.base import CheckContext
from FlowStopper.dast.client import DastClient
from FlowStopper.dast.config import DastConfig
from FlowStopper.dast.types import Endpoint, Param
from FlowStopper.models import ParamLocation
from FlowStopper.scope import ScopeGuard

GUARD = ScopeGuard(["localhost"])
Q = ParamLocation.QUERY


def _ctx(handler) -> CheckContext:
    client = DastClient(GUARD, DastConfig(seed=1), transport=httpx.MockTransport(handler))
    return CheckContext.create(client, "http://localhost", DastConfig(seed=1))


def _endpoint(path: str, pname: str, value: str = "1") -> tuple[Endpoint, Param]:
    param = Param(pname, Q, value)
    ep = Endpoint("GET", f"http://localhost{path}", path, route_id=f"GET {path}", params=[param])
    return ep, param


# --------------------------------------------------------------------------- vulnerable fixtures
def _sqli_error_app(request: httpx.Request) -> httpx.Response:
    v = request.url.params.get("id", "")
    if "'" in v or '"' in v:
        return httpx.Response(
            500, text="sqlite3.OperationalError: unrecognized token", headers={"content-type": "text/html"}
        )
    return httpx.Response(200, text="rows: 3 items", headers={"content-type": "text/html"})


def _sqli_diff_app(request: httpx.Request) -> httpx.Response:
    v = request.url.params.get("q", "")
    if "1=2" in v:  # an always-false numeric condition shrinks the result set
        return httpx.Response(200, text="no rows", headers={"content-type": "text/html"})
    return httpx.Response(200, text="rows: alpha beta gamma", headers={"content-type": "text/html"})


def _sqli_safe_app(request: httpx.Request) -> httpx.Response:
    # parameterised query: the input never changes the response and never errors
    return httpx.Response(200, text="rows: alpha beta gamma", headers={"content-type": "text/html"})


def _xss_app(request: httpx.Request) -> httpx.Response:
    v = request.url.params.get("q", "")
    return httpx.Response(200, text=f"<h1>Results for {v}</h1>", headers={"content-type": "text/html"})


def _xss_escaped_app(request: httpx.Request) -> httpx.Response:
    v = request.url.params.get("q", "")
    return httpx.Response(200, text=f"<h1>{htmlmod.escape(v)}</h1>", headers={"content-type": "text/html"})


def _xss_json_app(request: httpx.Request) -> httpx.Response:
    v = request.url.params.get("q", "")
    return httpx.Response(200, text=f'{{"echo": "{v}"}}', headers={"content-type": "application/json"})


# --------------------------------------------------------------------------- SQLi
async def test_sqli_error_based_detected():
    ctx = _ctx(_sqli_error_app)
    ep, param = _endpoint("/items", "id", "1")
    findings = await sqli.run(ctx, ep, param)
    await ctx.client.aclose()
    assert len(findings) == 1
    f = findings[0]
    assert f.cwe == 89 and f.rule_id == "dast.sqli.error" and f.runtime.proof == "error"
    assert f.confidence == 0.9 and f.runtime.param == "id" and f.runtime.payload == "1'"


async def test_sqli_boolean_differential_detected():
    ctx = _ctx(_sqli_diff_app)
    ep, param = _endpoint("/report", "q", "test")
    findings = await sqli.run(ctx, ep, param)
    await ctx.client.aclose()
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "dast.sqli.differential" and f.runtime.proof == "differential"
    assert f.confidence == 0.8 and f.runtime.payload == "test AND 1=2"


async def test_sqli_safe_app_not_flagged():
    ctx = _ctx(_sqli_safe_app)
    ep, param = _endpoint("/products", "id", "1")
    findings = await sqli.run(ctx, ep, param)
    await ctx.client.aclose()
    assert findings == []


# --------------------------------------------------------------------------- XSS
async def test_xss_reflected_detected():
    ctx = _ctx(_xss_app)
    ep, param = _endpoint("/search", "q", "test")
    findings = await xss.run(ctx, ep, param)
    await ctx.client.aclose()
    assert len(findings) == 1
    f = findings[0]
    assert f.cwe == 79 and f.rule_id == "dast.xss.reflected" and f.runtime.proof == "echo"
    assert f.confidence == 0.9 and "reflected unencoded" in f.runtime.evidence


async def test_xss_escaped_output_not_flagged():
    ctx = _ctx(_xss_escaped_app)
    ep, param = _endpoint("/search", "q", "test")
    findings = await xss.run(ctx, ep, param)
    await ctx.client.aclose()
    assert findings == []


async def test_xss_json_response_not_flagged():
    ctx = _ctx(_xss_json_app)
    ep, param = _endpoint("/api/echo", "q", "test")
    findings = await xss.run(ctx, ep, param)
    await ctx.client.aclose()
    assert findings == []


# --------------------------------------------------------------------------- evidence + gating
async def test_finding_carries_full_evidence():
    ctx = _ctx(_sqli_error_app)
    ep, param = _endpoint("/items", "id", "1")
    f = (await sqli.run(ctx, ep, param))[0]
    await ctx.client.aclose()
    rt = f.runtime
    assert rt.payload and rt.proof and rt.evidence and rt.request and rt.response_excerpt and rt.repro_curl
    assert rt.url.startswith("http://localhost/items") and rt.route_id == "GET /items"


async def test_non_injectable_location_is_skipped():
    ctx = _ctx(_sqli_error_app)
    ep = Endpoint("GET", "http://localhost/x", "/x", params=[])
    header_param = Param("X-Trace", ParamLocation.HEADER, "1")
    assert await sqli.run(ctx, ep, header_param) == []
    assert await xss.run(ctx, ep, header_param) == []
    await ctx.client.aclose()
    assert ctx.sent_payloads == []  # nothing left the tool


# --------------------------------------------------------------------------- R4 payload provenance
_ALLOWED_PAYLOADS = [
    re.compile(r"^(test|1|a\.txt)$"),  # benign baseline values
    re.compile(r"""^(test|1|a\.txt)(?:'|"|'\)|'")$"""),  # error-based suffixes
    re.compile(r"^.+?' (?:AND|OR) '[a-z]+'='[a-z]+$"),  # boolean string context
    re.compile(r"^.+? AND 1=[12]$"),  # boolean numeric context
    re.compile(r"""^sdc[a-z]+(?:<"'>|"onmouseover=x)$"""),  # XSS canaries
]


def _is_appendix_b(payload: str) -> bool:
    return any(rx.match(payload) for rx in _ALLOWED_PAYLOADS)


async def test_only_appendix_b_payloads_are_sent():
    # drive both checks against vulnerable apps and assert every payload is an Appendix B shape (R4)
    ctx = _ctx(_sqli_error_app)
    e1, p1 = _endpoint("/items", "id", "1")
    await sqli.run(ctx, e1, p1)
    await ctx.client.aclose()

    ctx2 = _ctx(_sqli_diff_app)
    e2, p2 = _endpoint("/report", "q", "test")
    await sqli.run(ctx2, e2, p2)
    await ctx2.client.aclose()

    ctx3 = _ctx(_xss_app)
    e3, p3 = _endpoint("/search", "q", "test")
    await xss.run(ctx3, e3, p3)
    await ctx3.client.aclose()

    all_payloads = ctx.sent_payloads + ctx2.sent_payloads + ctx3.sent_payloads
    assert all_payloads, "checks should have sent something"
    offenders = [p for p in all_payloads if not _is_appendix_b(p)]
    assert offenders == [], f"non-Appendix-B payloads sent (R4 violation): {offenders}"
