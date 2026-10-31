"""DAST check tests: SQLi + XSS (P1-B4). Owner: B. Offline vulnerable apps via MockTransport.

Covers error-based SQLi, boolean-differential SQLi, the status-transition SQLi rule and its non-SQL
500 decoys (any-quote, int(), baseline 500), a safe (parameterised) decoy, reflected XSS,
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


_GENERIC_500 = "<title>500 Internal Server Error</title><h1>Internal Server Error</h1>"


def _sqli_status_app(request: httpx.Request) -> httpx.Response:
    # string-concatenated query that hides the DB error: an unbalanced ' breaks the SQL -> generic 500
    v = request.url.params.get("id", "")
    if v.count("'") % 2:
        return httpx.Response(500, text=_GENERIC_500, headers={"content-type": "text/html"})
    return httpx.Response(200, text="rows: 3 items", headers={"content-type": "text/html"})


def _any_quote_500_app(request: httpx.Request) -> httpx.Response:
    # rejects any quote character the same way - not SQL-specific
    v = request.url.params.get("id", "")
    if "'" in v or '"' in v:
        return httpx.Response(500, text=_GENERIC_500, headers={"content-type": "text/html"})
    return httpx.Response(200, text="rows: 3 items", headers={"content-type": "text/html"})


def _int_conversion_app(request: httpx.Request) -> httpx.Response:
    # int(value) with no error handling: anything non-numeric is a 500, quotes or not
    try:
        int(request.url.params.get("id", ""))
    except ValueError:
        return httpx.Response(500, text=_GENERIC_500, headers={"content-type": "text/html"})
    return httpx.Response(200, text="rows: 3 items", headers={"content-type": "text/html"})


def _always_500_app(request: httpx.Request) -> httpx.Response:
    return httpx.Response(500, text=_GENERIC_500, headers={"content-type": "text/html"})


def _xss_app(request: httpx.Request) -> httpx.Response:
    v = request.url.params.get("q", "")
    return httpx.Response(200, text=f"<h1>Results for {v}</h1>", headers={"content-type": "text/html"})


def _xss_escaped_app(request: httpx.Request) -> httpx.Response:
    v = request.url.params.get("q", "")
    return httpx.Response(200, text=f"<h1>{htmlmod.escape(v)}</h1>", headers={"content-type": "text/html"})


def _xss_traceback_app(request: httpx.Request) -> httpx.Response:
    # debug error page: the crashing input is echoed raw inside the 500 traceback
    v = request.url.params.get("q", "")
    body = f'<pre>Traceback (most recent call last):\n  File "app.py", line 9, in view\nValueError: {v}</pre>'
    return httpx.Response(500, text=body, headers={"content-type": "text/html"})


def _reflecting_404_app(request: httpx.Request) -> httpx.Response:
    # error handler that echoes the decoded request path raw into an HTML 404 page
    return httpx.Response(404, text=f"<p>{request.url.path} was not found</p>", headers={"content-type": "text/html"})


def _escaping_404_app(request: httpx.Request) -> httpx.Response:
    body = f"<p>{htmlmod.escape(request.url.path)} was not found</p>"
    return httpx.Response(404, text=body, headers={"content-type": "text/html"})


def _traceback_404_app(request: httpx.Request) -> httpx.Response:
    trace = 'Traceback (most recent call last):\n  File "app.py", line 9, in view\n'
    body = f"<pre>{trace}KeyError: {request.url.path}</pre>"
    return httpx.Response(500, text=body, headers={"content-type": "text/html"})


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


async def test_sqli_status_transition_detected_without_error_text():
    ctx = _ctx(_sqli_status_app)
    ep, param = _endpoint("/items", "id", "1")
    findings = await sqli.run(ctx, ep, param)
    await ctx.client.aclose()
    assert len(findings) == 1
    f = findings[0]
    assert f.cwe == 89 and f.rule_id == "dast.sqli.status" and f.runtime.proof == "error"
    assert f.confidence == 0.65 and f.runtime.payload == "1'"
    assert "status transition" in f.runtime.evidence and "not an error string" in f.runtime.evidence
    assert f.raw["baseline_status"] == 200 and f.raw["payload_status"] == 500


async def test_sqli_error_string_still_wins_over_status_rule():
    ctx = _ctx(_sqli_error_app)
    ep, param = _endpoint("/items", "id", "1")
    findings = await sqli.run(ctx, ep, param)
    await ctx.client.aclose()
    assert [(f.rule_id, f.confidence) for f in findings] == [("dast.sqli.error", 0.9)]


async def test_sqli_status_rule_ignores_non_sql_500s():
    # any-quote rejection, int() conversion, and an endpoint that is already 500 at baseline
    for app in (_any_quote_500_app, _int_conversion_app, _always_500_app):
        ctx = _ctx(app)
        ep, param = _endpoint("/items", "id", "1")
        findings = await sqli.run(ctx, ep, param)
        await ctx.client.aclose()
        assert findings == [], app.__name__


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


async def test_xss_in_5xx_traceback_is_suppressed():
    ctx = _ctx(_xss_traceback_app)
    ep, param = _endpoint("/crash", "q", "test")
    findings = await xss.run(ctx, ep, param)
    await ctx.client.aclose()
    assert len(findings) == 1
    f = findings[0]
    assert f.cwe == 79 and f.rule_id == "dast.xss.reflected"
    assert f.suppressed is True and f.suppress_reason == "dast:debug-traceback-reflection"
    assert f.confidence == 0.5 and "verbose-error" in f.runtime.evidence


async def test_xss_in_200_page_is_not_suppressed():
    ctx = _ctx(_xss_app)
    ep, param = _endpoint("/search", "q", "test")
    findings = await xss.run(ctx, ep, param)
    await ctx.client.aclose()
    assert [(f.suppressed, f.suppress_reason, f.confidence) for f in findings] == [(False, None, 0.9)]


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


# --------------------------------------------------------------------------- XSS: unknown-path probe (item 8)
async def test_unknown_path_reflection_is_one_route_less_finding():
    ctx = _ctx(_reflecting_404_app)
    findings = await xss.probe_unknown_path(ctx, "http://localhost")
    await ctx.client.aclose()
    assert len(findings) == 1
    f = findings[0]
    assert f.cwe == 79 and f.rule_id == "dast.xss.unknown_path" and f.confidence == 0.8
    rt = f.runtime
    assert rt.method == "GET" and rt.route_id is None and rt.param is None and rt.proof == "echo"
    assert "status 404" in rt.evidence and f.suppressed is False
    assert f.raw["verification"]["reproduced"] is True
    assert len(ctx.client.exchanges) == 2  # the hit plus one fresh-canary re-probe


async def test_unknown_path_finding_id_does_not_depend_on_the_seed():
    """The probed path carries the per-scan canary; the finding id must not (FR-6 idempotency)."""
    ids_by_seed = set()
    for seed in (0, 1, 7):
        cfg = DastConfig(seed=seed)
        client = DastClient(GUARD, cfg, transport=httpx.MockTransport(_reflecting_404_app))
        ctx = CheckContext.create(client, "http://localhost", cfg)
        (finding,) = await xss.probe_unknown_path(ctx, "http://localhost")
        await ctx.client.aclose()
        ids_by_seed.add(finding.id)
    assert len(ids_by_seed) == 1


async def test_unknown_path_escaped_404_not_flagged_and_sends_one_request():
    ctx = _ctx(_escaping_404_app)
    findings = await xss.probe_unknown_path(ctx, "http://localhost")
    await ctx.client.aclose()
    assert findings == []
    assert len(ctx.client.exchanges) == 1


async def test_unknown_path_traceback_reflection_is_suppressed():
    ctx = _ctx(_traceback_404_app)
    findings = await xss.probe_unknown_path(ctx, "http://localhost")
    await ctx.client.aclose()
    assert [(f.suppressed, f.suppress_reason, f.confidence) for f in findings] == [
        (True, "dast:debug-traceback-reflection", 0.5)
    ]


async def test_unknown_path_probe_sends_only_the_appendix_b_canary():
    ctx = _ctx(_reflecting_404_app)
    await xss.probe_unknown_path(ctx, "http://localhost")
    await ctx.client.aclose()
    assert len(ctx.sent_payloads) == 2
    assert all(re.match(r"""^sdc[a-z]+<"'>$""", p) and _is_appendix_b(p) for p in ctx.sent_payloads)
    assert ctx.sent_payloads[0] != ctx.sent_payloads[1]  # fresh canary on the re-probe


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

    ctx4 = _ctx(_sqli_status_app)  # the status-transition rule adds no new payload shape
    e4, p4 = _endpoint("/items", "id", "1")
    assert await sqli.run(ctx4, e4, p4)
    await ctx4.client.aclose()

    all_payloads = ctx.sent_payloads + ctx2.sent_payloads + ctx3.sent_payloads + ctx4.sent_payloads
    assert all_payloads, "checks should have sent something"
    offenders = [p for p in all_payloads if not _is_appendix_b(p)]
    assert offenders == [], f"non-Appendix-B payloads sent (R4 violation): {offenders}"
