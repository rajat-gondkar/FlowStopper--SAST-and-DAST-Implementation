"""B-1 auto-verify Code-only issues with one targeted safe probe (Owner: B, P4-B4).

A Code-only issue says "SAST sees a flow, DAST never proved it". When the taint analysis names both
the route the flow starts at and the HTTP parameter that feeds it, we can run the one matching DAST
check against exactly that (route, param) - no crawling, no other params - and, if the bug
reproduces, link the new runtime finding to the code finding and upgrade the issue to Confirmed.

Safety rules (DECISIONS_Dev2 B-18):
- **Scope (R3) and payloads (R4)**: the probe goes through the same scope-guarded DastClient and the
  same check modules as `dast`, so it sends only Appendix B payloads, and only after the target URL
  itself passed the scope guard.
- **Eligibility**: Code-only, not suppressed, not left unlinked by the ambiguity rule (re-linking it
  would bypass that rule), exactly one code finding, CWE in CHECKS, a named source param, and an
  entry route whose method the DAST method policy allows.
- **Re-link, never force**: the new runtime finding must win the normal candidate + assignment pass
  (route gate, link_min, ambiguity rule) against *every* unsuppressed code finding, and its id must
  not already belong to another issue. Otherwise the issue stays Code-only - a missed link is cheaper
  than a wrong one.
- **Budget**: runs last; the deadline is checked before every probe and an overrun stops cleanly
  with `stats["truncated"] = True`.
- **Deterministic**: issues are probed in id order, each with an RNG derived from (seed, issue id).
"""

from __future__ import annotations

import logging
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Optional

import httpx

from FlowStopper import cwe as cwe_mod
from FlowStopper.correlate.config import CorrelateConfig
from FlowStopper.correlate.engine import confirmed_issue
from FlowStopper.correlate.explain import auto_verified_reason
from FlowStopper.correlate.issues import assign, is_suppressed, sort_issues
from FlowStopper.correlate.matcher import generate_candidates, normalise_param
from FlowStopper.correlate.scoring import link_score
from FlowStopper.dast import discovery, verify
from FlowStopper.dast.checks import cmdi, redirect, sqli, traversal, xss
from FlowStopper.dast.checks.base import INJECTABLE, CheckContext
from FlowStopper.dast.client import DastClient
from FlowStopper.dast.config import DastConfig
from FlowStopper.dast.runner import allowed_methods
from FlowStopper.dast.types import Endpoint, Param
from FlowStopper.models import Finding, Issue, Label, ParamLocation, Route
from FlowStopper.scope import ScopeError, build_guard

logger = logging.getLogger("FlowStopper.correlate.autoverify")

# CWE of the code finding -> the one DAST check that can prove it (spec P4-B4).
CHECKS = {89: sqli, 78: cmdi, 22: traversal, 601: redirect, 79: xss}


@dataclass
class AutoVerifyResult:
    issues: list[Issue]
    findings_added: list[Finding] = field(default_factory=list)
    stats: dict = field(default_factory=dict)


@dataclass
class _Probe:
    """One eligible issue, resolved to a concrete (endpoint, param) and check."""

    issue: Issue
    code: Finding
    route: Route
    endpoint: Endpoint
    param: Param
    check: object


def _check_name(check: object) -> str:
    return getattr(check, "__name__", "unknown").rsplit(".", 1)[-1]


def _pick_route(code: Finding, routes_by_id: dict[str, Route], methods: frozenset[str]) -> Optional[Route]:
    """First entry route (taint order) that exists in the route map and that we may send to."""
    for route_id in code.taint.entry_routes if code.taint else []:
        route = routes_by_id.get(route_id)
        if route is not None and route.method.upper() in methods:
            return route
    return None


def _pick_param(endpoint: Endpoint, code: Finding) -> Optional[Param]:
    """The endpoint param SAST named as the source; else a new one at the SAST-reported location."""
    taint = code.taint
    assert taint is not None and taint.source_param
    wanted = normalise_param(taint.source_param)
    matches = [p for p in endpoint.params if normalise_param(p.name) == wanted]
    if taint.source_kind is not None:
        matches = [p for p in matches if p.location is taint.source_kind] or matches
    if matches:
        param = matches[0]
    else:
        default = ParamLocation.QUERY if endpoint.method.upper() in {"GET", "HEAD"} else ParamLocation.FORM
        location = taint.source_kind or default
        if location is ParamLocation.PATH:
            return None  # no path segment owns this name: rewriting the last segment would probe another route
        param = Param(taint.source_param, location, discovery.benign_value(taint.source_param))
    return param if param.location in INJECTABLE else None


def _probe_for(
    issue: Issue, routes_by_id: dict[str, Route], methods: frozenset[str], base: str
) -> tuple[Optional[_Probe], str]:
    """(probe, "") for an eligible issue, else (None, why it was skipped)."""
    if issue.label is not Label.CODE_ONLY:
        return None, "not_code_only"
    if is_suppressed(issue):
        return None, "suppressed"
    if any(r.kind == "ambiguity_penalty" for r in issue.reasons):
        return None, "ambiguous"
    if len(issue.code_findings) != 1:
        return None, "not_single_code_finding"
    code = issue.code_findings[0]
    if code.suppressed or code.code is None:
        return None, "suppressed"
    check = CHECKS.get(code.cwe)
    if check is None:
        return None, "cwe_not_checkable"
    if not (code.taint and code.taint.source_param):
        return None, "no_source_param"
    route = _pick_route(code, routes_by_id, methods)
    if route is None:
        return None, "no_entry_route"
    endpoint = discovery.seed_endpoints([route], base)[0]
    param = _pick_param(endpoint, code)
    if param is None:
        return None, "param_not_injectable"
    return _Probe(issue, code, route, endpoint, param, check), ""


def _pool(issues: Sequence[Issue]) -> list[Finding]:
    """Every unsuppressed code finding: the competitors the new runtime finding must beat."""
    return sorted(
        (f for i in issues for f in i.code_findings if not f.suppressed and f.code is not None),
        key=lambda f: f.id,
    )


def _relink(
    probe: _Probe,
    runtime: Finding,
    pool: Sequence[Finding],
    routes: Sequence[Route],
    config: CorrelateConfig,
) -> Optional[Issue]:
    """Confirmed issue for (probe.code, runtime) if the normal link rules pick exactly that pair."""
    candidates = generate_candidates(pool, [runtime], routes, config)
    links = assign(candidates, config).links
    if len(links) != 1 or links[0].code.id != probe.code.id:
        return None
    cand = links[0]
    if cand.route is None or cand.route.id != probe.route.id or link_score(cand, config) < config.link_min:
        return None
    issue = confirmed_issue(cand, config)
    if issue.id != probe.issue.id:  # storage keys history by issue id; never silently re-key
        return None
    rt = runtime.runtime
    assert rt is not None
    reason = auto_verified_reason(_check_name(probe.check), probe.route.id, rt.param, rt.proof, rt.payload)
    return issue.model_copy(update={"verified_by": "auto-verify", "reasons": [*issue.reasons, reason]})


async def _run_check(ctx: CheckContext, probe: _Probe) -> list[Finding]:
    """The check plus the same second-canary/control verification and collapse as the DAST runner."""
    found = await probe.check.run(ctx, probe.endpoint, probe.param)  # type: ignore[attr-defined]
    if not found:
        return []
    kept, _ = await verify.verify_findings(ctx, probe.endpoint, probe.param, found, probe.check)  # type: ignore[arg-type]
    return verify.collapse(kept)


async def auto_verify(
    issues: Sequence[Issue],
    routes: Sequence[Route],
    target_url: str,
    dast_config: Optional[DastConfig] = None,
    correlate_config: Optional[CorrelateConfig] = None,
    deadline: Optional[float] = None,
    transport: Optional[httpx.AsyncBaseTransport] = None,
) -> AutoVerifyResult:
    """Probe eligible Code-only issues against `target_url` and upgrade the ones that reproduce.

    `deadline` is a `time.monotonic()` instant (None = no limit). Raises ScopeError, before any
    request, when `target_url` is outside the allow-list (R3).
    """
    config = dast_config or DastConfig()
    cc = correlate_config or CorrelateConfig()
    guard = build_guard(config.allowed_hosts, extra_hosts=config.extra_allowed_hosts)
    guard.check(target_url)  # R3: refuse an out-of-scope target before opening a connection

    base = target_url.rstrip("/")
    routes = list(routes)
    routes_by_id = {r.id: r for r in routes}
    methods = allowed_methods(config)
    started = time.monotonic()

    skipped: dict[str, int] = {}
    probes: list[_Probe] = []
    for issue in sorted(issues, key=lambda i: i.id):
        probe, why = _probe_for(issue, routes_by_id, methods, base)
        if probe is None:
            if why != "not_code_only":
                skipped[why] = skipped.get(why, 0) + 1
        else:
            probes.append(probe)

    stats: dict = {
        "target": base,
        "seed": config.seed,
        "eligible": len(probes),
        "probed": 0,
        "upgraded": 0,
        "not_reproduced": 0,
        "relink_failed": 0,
        "already_linked": 0,
        "not_reached": 0,
        "errors": 0,
        "skipped": dict(sorted(skipped.items())),
        "truncated": False,
        "requests": 0,
        "payloads_sent": 0,
        "auth": None,
        "upgraded_ids": [],
    }

    def finish(updated: dict[str, Issue], added: list[Finding]) -> AutoVerifyResult:
        stats["elapsed_s"] = round(time.monotonic() - started, 2)
        stats["upgraded_ids"] = sorted(updated)
        out = [updated.get(i.id, i) for i in issues]
        return AutoVerifyResult(sort_issues(out), sorted(added, key=lambda f: f.id), stats)

    if not probes:
        return finish({}, [])
    if deadline is not None and time.monotonic() >= deadline:
        stats["truncated"] = True
        stats["not_reached"] = len(probes)
        return finish({}, [])

    pool = _pool(issues)
    taken = {f.id for i in issues for f in i.runtime_findings}
    updated: dict[str, Issue] = {}
    added: list[Finding] = []

    async with DastClient(guard, config, transport=transport) as client:
        ctx = CheckContext.create(client, base, config)
        auth = await client.authenticate()
        stats["auth"] = auth.as_stats()
        if auth.attempted and not auth.ok:
            logger.warning(
                "auto-verify login failed (%s); continuing unauthenticated", auth.detail or f"status {auth.status}"
            )

        for n, probe in enumerate(probes):
            if deadline is not None and time.monotonic() >= deadline:
                stats["truncated"] = True
                stats["not_reached"] = len(probes) - n
                break
            stats["probed"] += 1
            try:
                hits = await _run_check(ctx.derive(f"autoverify|{probe.issue.id}"), probe)
            except (ScopeError, httpx.HTTPError):
                stats["errors"] += 1
                continue
            hits = [h for h in hits if not h.suppressed and cwe_mod.same_family(probe.code.cwe, h.cwe)]
            if not hits:
                stats["not_reproduced"] += 1
                continue
            hit = hits[0]
            if hit.id in taken:
                stats["already_linked"] += 1  # the finding already belongs to another issue (one-to-one)
                continue
            runtime = hit.model_copy(update={"raw": {**hit.raw, "auto_verify": True}})
            issue = _relink(probe, runtime, pool, routes, cc)
            if issue is None:
                stats["relink_failed"] += 1
                continue
            taken.add(runtime.id)
            updated[issue.id] = issue
            added.append(runtime)
            stats["upgraded"] += 1

        stats["requests"] = len(client.exchanges)
        stats["payloads_sent"] = len(ctx.sent_payloads)

    return finish(updated, added)
