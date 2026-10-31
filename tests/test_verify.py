"""Verification + collapse tests (P2-B3). Owner: B. Offline via httpx.MockTransport."""

from __future__ import annotations

import httpx

from FlowStopper.dast import verify
from FlowStopper.dast.checks import cmdi, redirect, sqli, traversal
from FlowStopper.dast.checks.base import CheckContext
from FlowStopper.dast.client import DastClient
from FlowStopper.dast.config import DastConfig
from FlowStopper.dast.types import Endpoint, Param
from FlowStopper.models import (
    Engine,
    Finding,
    ParamLocation,
    RuntimeLocation,
    Severity,
)
from FlowStopper.scope import ScopeGuard

GUARD = ScopeGuard(["localhost"])
Q = ParamLocation.QUERY
PASSWD = "root:x:0:0:root:/root:/bin/bash\n"


def _ctx(handler) -> CheckContext:
    cfg = DastConfig(seed=5)
    client = DastClient(GUARD, cfg, transport=httpx.MockTransport(handler))
    return CheckContext.create(client, "http://localhost", cfg)


def _endpoint(path: str, pname: str, value: str = "1") -> tuple[Endpoint, Param]:
    param = Param(pname, Q, value)
    return Endpoint("GET", f"http://localhost{path}", path, route_id=f"GET {path}", params=[param]), param


def _rt_finding(cwe: int, rule: str, proof: str, payload: str, conf: float = 0.9, param: str = "id") -> Finding:
    return Finding(
        id=f"{rule}:{payload}",
        engine=Engine.DAST,
        tool="FlowStopper-dast",
        rule_id=rule,
        cwe=cwe,
        title="t",
        severity=Severity.HIGH,
        confidence=conf,
        runtime=RuntimeLocation(
            method="GET",
            url="http://localhost/x",
            path="/x",
            route_id="GET /x",
            param=param,
            payload=payload,
            proof=proof,  # type: ignore[arg-type]
        ),
    )


# --------------------------------------------------------------------------- verification
async def test_genuine_sqli_is_confirmed_with_clean_control():
    def app(request: httpx.Request) -> httpx.Response:
        v = request.url.params.get("id", "")
        if "'" in v or '"' in v:
            return httpx.Response(500, text="sqlite3.OperationalError: unrecognized token")
        return httpx.Response(200, text="rows: 3")

    ctx = _ctx(app)
    ep, param = _endpoint("/items", "id")
    first = await sqli.run(ctx, ep, param)
    kept, outcomes = await verify.verify_findings(ctx, ep, param, first, sqli)
    await ctx.client.aclose()
    assert len(kept) == 1 and outcomes[0].confirmed
    assert outcomes[0].control_applied is True
    v = kept[0].raw["verification"]
    assert v["reproduced"] is True and v["control_applied"] is True


async def test_always_erroring_page_is_rejected_by_the_control():
    """The page shows a SQL error even for benign input -> not attributable to our payload."""
    calls = {"n": 0}

    def app(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        # the very first request (the baseline) looks clean, everything after always errors
        if calls["n"] <= 2:
            return httpx.Response(200, text="rows: 3")
        return httpx.Response(500, text="sqlite3.OperationalError: unrecognized token")

    ctx = _ctx(app)
    ep, param = _endpoint("/items", "id")
    first = await sqli.run(ctx, ep, param)
    assert first, "precondition: the check fires"
    kept, outcomes = await verify.verify_findings(ctx, ep, param, first, sqli)
    await ctx.client.aclose()
    assert kept == []
    assert not outcomes[0].confirmed and "control" in outcomes[0].reason


async def test_flaky_one_off_hit_is_rejected():
    """A single transient error that never reproduces must be dropped."""
    calls = {"n": 0}

    def app(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 3:  # one transient error right after the two baseline requests
            return httpx.Response(500, text="sqlite3.OperationalError: unrecognized token")
        return httpx.Response(200, text="rows: 3")

    ctx = _ctx(app)
    ep, param = _endpoint("/items", "id")
    first = await sqli.run(ctx, ep, param)
    assert first, "precondition: the check fires once"
    kept, outcomes = await verify.verify_findings(ctx, ep, param, first, sqli)
    await ctx.client.aclose()
    assert kept == []
    assert "second canary" in outcomes[0].reason


async def test_canary_bound_proof_records_control_not_applicable():
    def shell_app(request: httpx.Request) -> httpx.Response:
        import subprocess

        host = request.url.params.get("host", "")
        out = subprocess.run(["/bin/sh", "-c", f"echo {host}"], capture_output=True, text=True, timeout=5).stdout
        return httpx.Response(200, text=out)

    ctx = _ctx(shell_app)
    ep, param = _endpoint("/ping", "host", "127.0.0.1")
    first = await cmdi.run(ctx, ep, param)
    kept, outcomes = await verify.verify_findings(ctx, ep, param, first, cmdi)
    await ctx.client.aclose()
    assert len(kept) == 1
    assert outcomes[0].control_applied is False
    assert "canary-bound" in kept[0].raw["verification"]["detail"]
    # the second canary differs from the first: genuine independent confirmation
    assert kept[0].raw["verification"]["second_payload"] != kept[0].runtime.payload


async def test_traversal_control_rejects_a_page_that_always_shows_passwd():
    calls = {"n": 0}

    def app(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] <= 2:
            return httpx.Response(200, text="report")
        return httpx.Response(200, text=PASSWD)

    ctx = _ctx(app)
    ep, param = _endpoint("/download", "file", "a.txt")
    first = await traversal.run(ctx, ep, param)
    assert first
    kept, outcomes = await verify.verify_findings(ctx, ep, param, first, traversal)
    await ctx.client.aclose()
    assert kept == [] and "control" in outcomes[0].reason


async def test_redirect_control_rejects_unconditional_offsite_redirect():
    def app(request: httpx.Request) -> httpx.Response:
        # always redirects off-site regardless of input -> the param is not the cause
        return httpx.Response(302, headers={"location": "https://unrelated.invalid/"})

    ctx = _ctx(app)
    ep, param = _endpoint("/go", "next", "/home")
    first = await redirect.run(ctx, ep, param)
    kept, _ = await verify.verify_findings(ctx, ep, param, first, redirect)
    await ctx.client.aclose()
    assert kept == []


async def test_unreachable_target_during_retest_is_not_confirmed():
    calls = {"n": 0}

    def app(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] <= 3:
            v = request.url.params.get("id", "")
            if "'" in v:
                return httpx.Response(500, text="sqlite3.OperationalError: unrecognized token")
            return httpx.Response(200, text="rows: 3")
        raise httpx.ConnectError("gone", request=request)

    ctx = _ctx(app)
    ep, param = _endpoint("/items", "id")
    first = await sqli.run(ctx, ep, param)
    kept, outcomes = await verify.verify_findings(ctx, ep, param, first, sqli)
    await ctx.client.aclose()
    assert kept == [] and not outcomes[0].confirmed


# --------------------------------------------------------------------------- collapse
def test_collapse_keeps_strongest_proof_and_preserves_payloads():
    error = _rt_finding(89, "dast.sqli.error", "error", "1'", 0.9)
    diff = _rt_finding(89, "dast.sqli.differential", "differential", "1 AND 1=2", 0.8)
    out = verify.collapse([diff, error])
    assert len(out) == 1
    kept = out[0]
    assert kept.rule_id == "dast.sqli.error"  # error (5) beats differential (3)
    assert kept.raw["other_payloads"] == ["1 AND 1=2"]
    assert kept.raw["collapsed_rules"] == ["dast.sqli.differential"]
    assert kept.raw["collapsed_proofs"] == ["differential"]


def test_collapse_groups_by_cwe_route_and_param():
    a = _rt_finding(89, "dast.sqli.error", "error", "1'", param="id")
    b = _rt_finding(89, "dast.sqli.error", "error", "2'", param="q")  # different param
    c = _rt_finding(79, "dast.xss.reflected", "echo", "sdcx<\"'>", param="id")  # different cwe
    out = verify.collapse([a, b, c])
    assert len(out) == 3  # nothing merged


def test_collapse_merges_existing_other_payloads():
    first = _rt_finding(22, "dast.traversal.file", "file", "../../etc/passwd")
    first = first.model_copy(update={"raw": {"other_payloads": ["/etc/passwd"]}})
    second = _rt_finding(22, "dast.traversal.file", "file", "....//etc/passwd", 0.5)
    out = verify.collapse([first, second])
    assert out[0].raw["other_payloads"] == ["....//etc/passwd", "/etc/passwd"]


def test_collapse_is_deterministic_and_total():
    findings = [
        _rt_finding(601, "dast.redirect.open", "redirect", "//a.invalid/"),
        _rt_finding(89, "dast.sqli.error", "error", "1'"),
        _rt_finding(79, "dast.xss.reflected", "echo", "sdcx"),
    ]
    once = [f.id for f in verify.collapse(findings)]
    twice = [f.id for f in verify.collapse(list(reversed(findings)))]
    assert once == twice  # order of input does not change output
    assert [f.cwe for f in verify.collapse(findings)] == [79, 89, 601]  # sorted by cwe


def test_collapse_empty():
    assert verify.collapse([]) == []


def test_proof_strength_covers_every_model_proof():
    # keep the ranking table in sync with RuntimeLocation.proof (models.py, contract-v1)
    from typing import get_args

    from FlowStopper.models import RuntimeLocation as RL

    proofs = set(get_args(RL.model_fields["proof"].annotation))
    assert proofs <= set(verify.PROOF_STRENGTH), f"unranked proofs: {proofs - set(verify.PROOF_STRENGTH)}"
