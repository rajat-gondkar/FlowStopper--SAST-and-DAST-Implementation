"""DAST orchestration (Owner: B, P2-B4). Cross-developer interface (spec section 6).

Every request goes through the scope guard (R3); only Appendix B payloads (R4).

Flow: scope-check the target -> discover endpoints (seeded by the SAST route map, then crawl) ->
run the host-wide passive checks once -> for every (endpoint, injectable param) run the active
checks, verify each hit with a second canary + control, and collapse payload duplicates.

Budgets and safety:
- **Time budget** (`time_budget_s`): governs the active check phase - it is checked before each
  (endpoint, param) unit and before each individual check, so an overrun stops cleanly mid-scan and
  sets `stats["truncated"] = True` instead of being killed. Discovery and the one-off passive pass
  run first and are not interruptible; a budget of 0 therefore yields passive findings only, marked
  truncated.
- **Concurrency**: units run under a semaphore; the client caps in-flight requests independently.
- **Method policy**: GET/POST/HEAD/OPTIONS by default, PUT/PATCH only with `allow_mutating`,
  **DELETE never** (not reachable by configuration).
- **Routes first**: endpoints that came from the route map are scanned before crawled ones, and
  Appendix B's prioritised parameter names are tested before the rest.
- **Deterministic**: each unit derives its own seeded RNG, and findings are sorted before returning.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Optional

import httpx

from FlowStopper.dast import discovery, verify
from FlowStopper.dast.checks import cmdi, passive, redirect, sqli, traversal, xss
from FlowStopper.dast.checks.base import INJECTABLE, CheckContext
from FlowStopper.dast.client import DastClient
from FlowStopper.dast.config import DastConfig
from FlowStopper.dast.types import Endpoint, Param
from FlowStopper.models import DastResult, Finding, Route
from FlowStopper.scope import ScopeError, build_guard

# Every active check runs for every injectable param; the order only affects reporting.
ACTIVE_CHECKS = (sqli, xss, cmdi, traversal, redirect)

logger = logging.getLogger("FlowStopper.dast")

SAFE_METHODS = frozenset({"GET", "POST", "HEAD", "OPTIONS"})
MUTATING_METHODS = frozenset({"PUT", "PATCH"})  # only with allow_mutating
FORBIDDEN_METHODS = frozenset({"DELETE"})  # never, by any configuration (R4)

# Appendix B: tested first, not exclusively.
PRIORITY_PARAMS = (
    "next",
    "url",
    "redirect",
    "return",
    "returnto",
    "continue",
    "dest",
    "target",
    "goto",
    "file",
    "path",
    "filename",
    "name",
    "page",
    "template",
    "id",
    "q",
    "query",
    "search",
    "cmd",
    "host",
    "ip",
)


@dataclass
class _State:
    """Mutable counters for stats; a scan touches this from one event loop only."""

    truncated: bool = False
    params_tested: int = 0
    checks_run: int = 0
    candidates: int = 0
    dropped: int = 0
    errors: int = 0
    unverified: list[str] = field(default_factory=list)


def allowed_methods(config: DastConfig) -> frozenset[str]:
    """Methods this scan may send. DELETE is never included."""
    allowed = set(SAFE_METHODS)
    if config.allow_mutating:
        allowed |= MUTATING_METHODS
    return frozenset(allowed - FORBIDDEN_METHODS)


def _param_sort_key(p: Param) -> tuple[int, str]:
    name = p.name.lower()
    rank = PRIORITY_PARAMS.index(name) if name in PRIORITY_PARAMS else len(PRIORITY_PARAMS)
    return (rank, name)


def injectable_params(endpoint: Endpoint) -> list[Param]:
    """Injectable params for an endpoint, Appendix B priority names first."""
    return sorted((p for p in endpoint.params if p.location in INJECTABLE), key=_param_sort_key)


def order_endpoints(endpoints: list[Endpoint]) -> list[Endpoint]:
    """Route-map endpoints first (spec P2-B4), then crawled ones; stable and deterministic."""
    return sorted(endpoints, key=lambda e: (e.route_id is None, e.path, e.method))


async def _scan_param(
    ctx: CheckContext,
    endpoint: Endpoint,
    param: Param,
    deadline: float,
    state: _State,
) -> list[Finding]:
    """Run every active check for one (endpoint, param), verify hits, collapse duplicates."""
    unit = ctx.derive(f"{endpoint.method} {endpoint.path}|{param.location.value}:{param.name}")
    hits: list[Finding] = []
    for check in ACTIVE_CHECKS:
        if time.monotonic() >= deadline:
            state.truncated = True
            break
        state.checks_run += 1
        try:
            found = await check.run(unit, endpoint, param)
        except (ScopeError, httpx.HTTPError):
            state.errors += 1
            continue
        if not found:
            continue
        state.candidates += len(found)
        try:
            kept, outcomes = await verify.verify_findings(unit, endpoint, param, found, check)
        except (ScopeError, httpx.HTTPError):
            state.errors += 1
            continue
        for o in outcomes:
            if not o.confirmed:
                state.dropped += 1
                state.unverified.append(f"{o.finding.rule_id} {endpoint.path} {param.name}: {o.reason}")
        hits += kept
    state.params_tested += 1
    return verify.collapse(hits)


async def run_dast(target_url: str, routes: list[Route], config: Optional[DastConfig] = None) -> DastResult:
    """Scan the running app at `target_url`, seeded by the SAST route map."""
    config = config or DastConfig()
    guard = build_guard(config.allowed_hosts, extra_hosts=config.extra_allowed_hosts)
    guard.check(target_url)  # R3: refuse an out-of-scope target before opening a connection

    base = target_url.rstrip("/")
    allowed = allowed_methods(config)
    state = _State()
    started = time.monotonic()
    # Taken literally: a budget of 0 means there is no time left, so the active phase is skipped
    # and the result is marked truncated rather than silently given a grace period.
    deadline = started + config.time_budget_s

    async with DastClient(guard, config) as client:
        ctx = CheckContext.create(client, base, config)

        # Authenticate first: routes behind a session answer 401/403 to everything otherwise, so
        # discovery and every check would be testing the login wall instead of the app (item 7).
        auth = await client.authenticate()
        if auth.attempted and not auth.ok:
            logger.warning(
                "DAST login failed (%s); continuing unauthenticated - routes requiring a session will not be reachable",
                auth.detail or f"status {auth.status}",
            )

        discovered = await discovery.discover(client, base, routes, config)
        endpoints = order_endpoints([e for e in discovered if e.method.upper() in allowed])

        passive_findings = await passive.run(ctx, endpoints)
        # Host-wide, not budgeted (like the passive pass): one unknown-path request carrying the XSS
        # canary, two on a hit (item 8, B-16).
        unknown_path_findings = await xss.probe_unknown_path(ctx.derive("xss-unknown-path"), base)
        passive_findings += unknown_path_findings

        units = [(e, p) for e in endpoints for p in injectable_params(e)]
        sem = asyncio.Semaphore(max(1, config.concurrency))

        async def worker(endpoint: Endpoint, param: Param) -> list[Finding]:
            if time.monotonic() >= deadline:
                state.truncated = True
                return []
            async with sem:
                if time.monotonic() >= deadline:
                    state.truncated = True
                    return []
                return await _scan_param(ctx, endpoint, param, deadline, state)

        gathered = await asyncio.gather(*(worker(e, p) for e, p in units), return_exceptions=True)

        active_findings: list[Finding] = []
        for result in gathered:
            if isinstance(result, BaseException):
                state.errors += 1
                continue
            active_findings += result

        requests_sent = len(client.exchanges)

    findings = sorted(
        passive_findings + active_findings,
        key=lambda f: (
            f.cwe,
            f.runtime.path if f.runtime else "",
            (f.runtime.param or "") if f.runtime else "",
            f.rule_id,
        ),
    )
    stats = {
        "target": base,
        "seed": config.seed,
        "endpoints_discovered": len(discovered),
        "endpoints_scanned": len(endpoints),
        "endpoints_from_routes": sum(1 for e in endpoints if e.route_id),
        "params_tested": state.params_tested,
        "checks_run": state.checks_run,
        "requests": requests_sent,
        "candidate_findings": state.candidates,
        "findings": len(findings),
        "passive_findings": len(passive_findings),
        "unknown_path_probe": len(unknown_path_findings),
        "dropped_unverified": state.dropped,
        "unverified_examples": sorted(state.unverified)[:10],
        "errors": state.errors,
        "truncated": state.truncated,
        "elapsed_s": round(time.monotonic() - started, 2),
        "time_budget_s": config.time_budget_s,
        "concurrency": config.concurrency,
        "methods": sorted(allowed),
        "allow_mutating": config.allow_mutating,
        "payloads_sent": len(ctx.sent_payloads),
        "auth": auth.as_stats(),
    }
    return DastResult(findings=findings, stats=stats)
