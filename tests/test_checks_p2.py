"""DAST check tests: command injection, path traversal, open redirect (P2-B1). Owner: B.

Offline vulnerable/safe apps via httpx.MockTransport. Each check is asserted to (a) detect the real
bug with full evidence, (b) stay quiet on a safe look-alike, and (c) send only Appendix B payloads
(R4). The redirect tests additionally prove the scanner never follows the redirect or contacts the
canary host.
"""

from __future__ import annotations

import re
import shlex
import subprocess

import httpx

from FlowStopper.dast.checks import cmdi, redirect, traversal
from FlowStopper.dast.checks.base import CheckContext
from FlowStopper.dast.checks.redirect import redirect_host
from FlowStopper.dast.client import DastClient
from FlowStopper.dast.config import DastConfig
from FlowStopper.dast.types import Endpoint, Param
from FlowStopper.models import ParamLocation
from FlowStopper.scope import ScopeGuard

GUARD = ScopeGuard(["localhost"])
Q = ParamLocation.QUERY

PASSWD = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"


def _ctx(handler) -> CheckContext:
    cfg = DastConfig(seed=7)
    client = DastClient(GUARD, cfg, transport=httpx.MockTransport(handler))
    return CheckContext.create(client, "http://localhost", cfg)


def _endpoint(path: str, pname: str, value: str = "test") -> tuple[Endpoint, Param]:
    param = Param(pname, Q, value)
    ep = Endpoint("GET", f"http://localhost{path}", path, route_id=f"GET {path}", params=[param])
    return ep, param


# --------------------------------------------------------------------------- command injection
def _shell_app(request: httpx.Request) -> httpx.Response:
    """Emulates `os.system("ping " + host)`: runs the string through a real shell."""
    host = request.url.params.get("host", "")
    out = subprocess.run(["/bin/sh", "-c", f"echo pinging {host}"], capture_output=True, text=True, timeout=5).stdout
    return httpx.Response(200, text=out, headers={"content-type": "text/plain"})


def _shell_safe_app(request: httpx.Request) -> httpx.Response:
    """Emulates subprocess.run([...], shell=False): the value is echoed, never evaluated."""
    host = request.url.params.get("host", "")
    return httpx.Response(200, text=f"pinging {shlex.quote(host)}", headers={"content-type": "text/plain"})


async def test_cmdi_detected_via_evaluated_marker():
    ctx = _ctx(_shell_app)
    ep, param = _endpoint("/api/ping", "host", "127.0.0.1")
    findings = await cmdi.run(ctx, ep, param)
    await ctx.client.aclose()
    assert len(findings) == 1
    f = findings[0]
    assert f.cwe == 78 and f.rule_id == "dast.cmdi.marker" and f.runtime.proof == "marker"
    # the proof is the evaluated product, and it is NOT the literal expression
    marker = f.raw["marker"]
    assert marker in f.runtime.response_excerpt
    assert f.raw["expression"] not in f.runtime.response_excerpt


async def test_cmdi_reflection_only_is_not_flagged():
    # the payload is echoed back verbatim (unevaluated) -> must NOT be reported
    ctx = _ctx(_shell_safe_app)
    ep, param = _endpoint("/api/ping", "host", "127.0.0.1")
    findings = await cmdi.run(ctx, ep, param)
    await ctx.client.aclose()
    assert findings == []


# --------------------------------------------------------------------------- path traversal
def _traversal_app(request: httpx.Request) -> httpx.Response:
    raw_query = request.url.query.decode()
    value = request.url.params.get("file", "")
    # vulnerable: any value containing a traversal (or an absolute path) reads the file
    if ".." in value or value.startswith("/etc/") or "%2f" in raw_query.lower():
        return httpx.Response(200, text=PASSWD, headers={"content-type": "text/plain"})
    return httpx.Response(200, text="report contents", headers={"content-type": "text/plain"})


def _traversal_safe_app(request: httpx.Request) -> httpx.Response:
    """Emulates secure_filename + send_from_directory: traversal is stripped."""
    return httpx.Response(200, text="report contents", headers={"content-type": "text/plain"})


async def test_traversal_detected_with_file_proof():
    ctx = _ctx(_traversal_app)
    ep, param = _endpoint("/download", "file", "a.txt")
    findings = await traversal.run(ctx, ep, param)
    await ctx.client.aclose()
    assert len(findings) == 1
    f = findings[0]
    assert f.cwe == 22 and f.rule_id == "dast.traversal.file" and f.runtime.proof == "file"
    assert re.search(r"root:[x*!]*:0:0:", f.runtime.response_excerpt)


async def test_traversal_safe_app_not_flagged():
    ctx = _ctx(_traversal_safe_app)
    ep, param = _endpoint("/download", "file", "a.txt")
    findings = await traversal.run(ctx, ep, param)
    await ctx.client.aclose()
    assert findings == []


async def test_traversal_not_flagged_when_baseline_already_has_passwd():
    # a page that legitimately shows the pattern cannot support attribution -> stay quiet
    def always_passwd(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=PASSWD, headers={"content-type": "text/plain"})

    ctx = _ctx(always_passwd)
    ep, param = _endpoint("/docs", "file", "a.txt")
    findings = await traversal.run(ctx, ep, param)
    await ctx.client.aclose()
    assert findings == []


async def test_encoded_traversal_payload_is_not_double_encoded():
    """R4 fidelity: `..%2f` must reach the target as `%2f`, not re-encoded to `%252f`."""
    seen: list[str] = []

    def recorder(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.query.decode())
        return httpx.Response(200, text="nothing", headers={"content-type": "text/plain"})

    ctx = _ctx(recorder)
    ep, param = _endpoint("/download", "file", "a.txt")
    await traversal.run(ctx, ep, param)
    await ctx.client.aclose()
    encoded = [q for q in seen if "%2f" in q.lower()]
    assert encoded, "the pre-encoded Appendix B variant was never sent"
    assert all("%252f" not in q.lower() for q in encoded), f"payload was double-encoded: {encoded}"


# --------------------------------------------------------------------------- open redirect
def _redirect_app(request: httpx.Request) -> httpx.Response:
    nxt = request.url.params.get("next", "")
    return httpx.Response(302, headers={"location": nxt or "/"})


def _redirect_safe_app(request: httpx.Request) -> httpx.Response:
    """Emulates an allow-list check: off-site targets fall back to a local path."""
    nxt = request.url.params.get("next", "")
    target = nxt if nxt.startswith("/") and not nxt.startswith(("//", "/\\")) else "/home"
    return httpx.Response(302, headers={"location": target})


async def test_open_redirect_detected():
    ctx = _ctx(_redirect_app)
    ep, param = _endpoint("/go", "next", "/home")
    findings = await redirect.run(ctx, ep, param)
    await ctx.client.aclose()
    assert len(findings) == 1
    f = findings[0]
    assert f.cwe == 601 and f.rule_id == "dast.redirect.open" and f.runtime.proof == "redirect"
    assert f.raw["status"] == 302 and ".invalid" in f.raw["location"]


async def test_open_redirect_allowlisted_app_not_flagged():
    ctx = _ctx(_redirect_safe_app)
    ep, param = _endpoint("/go", "next", "/home")
    findings = await redirect.run(ctx, ep, param)
    await ctx.client.aclose()
    assert findings == []


async def test_redirect_is_never_followed_and_canary_never_contacted():
    requested_hosts: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested_hosts.append(request.url.host)
        return httpx.Response(302, headers={"location": request.url.params.get("next", "/")})

    ctx = _ctx(handler)
    ep, param = _endpoint("/go", "next", "/home")
    await redirect.run(ctx, ep, param)
    await ctx.client.aclose()
    assert set(requested_hosts) == {"localhost"}  # the .invalid canary was never contacted
    assert all(not h.endswith(".invalid") for h in requested_hosts)


def test_redirect_host_parses_bypass_forms():
    assert redirect_host("//evil.invalid/") == "evil.invalid"
    assert redirect_host("https://evil.invalid/x") == "evil.invalid"
    assert redirect_host("/\\evil.invalid") == "evil.invalid"
    assert redirect_host("///evil.invalid") == "evil.invalid"
    assert redirect_host("/local/path") == ""  # same-origin redirect is not a finding
    assert redirect_host("") == ""


# --------------------------------------------------------------------------- gating + R4 provenance
async def test_non_injectable_location_is_skipped():
    ctx = _ctx(_shell_app)
    ep = Endpoint("GET", "http://localhost/x", "/x", params=[])
    header_param = Param("X-Trace", ParamLocation.HEADER, "1")
    assert await cmdi.run(ctx, ep, header_param) == []
    assert await traversal.run(ctx, ep, header_param) == []
    assert await redirect.run(ctx, ep, header_param) == []
    await ctx.client.aclose()
    assert ctx.sent_payloads == []


_ALLOWED = [
    re.compile(r"^(test|1|a\.txt|127\.0\.0\.1|/home)$"),  # benign baseline values
    # cmdi: ORIG <sep> echo sdcRND$((A*B))X  (separators ; | && $() `` newline)
    re.compile(r"^.+?(?:;|\||&&|\$\(|`|\n)\s*echo sdc[a-z]+\$\(\(\d+\*\d+\)\)X[`)]?$", re.S),
    # traversal: the four Appendix B forms
    re.compile(r"^(?:\.\./)+etc/passwd$"),
    re.compile(r"^(?:\.\.\.\.//)+etc/passwd$"),
    re.compile(r"^(?:\.\.%2f)+etc%2fpasswd$"),
    re.compile(r"^/etc/passwd$"),
    # redirect: //h/, https://h/, /\h, ///h  with h = sdcRND.invalid
    re.compile(r"^(?://|https://|/\\|///)sdc[a-z]+\.invalid/?$"),
]


def _is_appendix_b(payload: str) -> bool:
    return any(rx.match(payload) for rx in _ALLOWED)


async def test_only_appendix_b_payloads_are_sent():
    sent: list[str] = []
    for handler, (path, pname, value), check in (
        (_shell_app, ("/api/ping", "host", "127.0.0.1"), cmdi),
        (_traversal_app, ("/download", "file", "a.txt"), traversal),
        (_redirect_app, ("/go", "next", "/home"), redirect),
    ):
        ctx = _ctx(handler)
        ep, param = _endpoint(path, pname, value)
        await check.run(ctx, ep, param)
        await ctx.client.aclose()
        sent += ctx.sent_payloads

    assert sent, "checks should have sent something"
    offenders = [p for p in sent if not _is_appendix_b(p)]
    assert offenders == [], f"non-Appendix-B payloads sent (R4 violation): {offenders}"


async def test_traversal_probes_only_the_benign_passwd_path():
    """R4: the only file the traversal check ever asks for is /etc/passwd (read-only)."""
    ctx = _ctx(_traversal_safe_app)
    ep, param = _endpoint("/download", "file", "a.txt")
    await traversal.run(ctx, ep, param)
    await ctx.client.aclose()
    probes = [p for p in ctx.sent_payloads if p != "a.txt"]
    assert probes and all(p.lower().endswith(("etc/passwd", "etc%2fpasswd")) for p in probes), probes
