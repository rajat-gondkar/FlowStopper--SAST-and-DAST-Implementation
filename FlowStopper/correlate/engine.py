"""Correlation entry point (Owner: B, P2-B6). Cross-developer interface (spec section 6).

dedupe -> candidates (hard route gate) -> score -> greedy one-to-one assignment with the
ambiguity rule -> issues + labels -> risk -> deterministic sort.

Must reproduce fixtures/expected_issues.json from the other fixtures (see fixtures/README.md).
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Optional
from urllib.parse import urlsplit

from FlowStopper import cwe as cwe_mod
from FlowStopper import ids
from FlowStopper.correlate.config import CorrelateConfig
from FlowStopper.correlate.dedupe import dedupe_code, dedupe_runtime
from FlowStopper.correlate.explain import link_reasons
from FlowStopper.correlate.issues import (
    assign,
    code_issue_title,
    runtime_issue_title,
    sort_issues,
)
from FlowStopper.correlate.matcher import Candidate, generate_candidates
from FlowStopper.correlate.scoring import link_score, risk_score
from FlowStopper.models import Finding, Issue, Label, LinkReason, Route
from FlowStopper.report.fixes import fix_for


def _catalogue(cwe: int) -> tuple[float, object, Optional[str]]:
    """(cvss, severity, owasp) for a CWE; unknown CWEs degrade gracefully instead of raising."""
    entry = cwe_mod.CATALOGUE.get(cwe)
    if entry is None:
        return 0.0, cwe_mod.severity_from_score(0.0), None
    return entry.base_score, entry.severity, entry.owasp_2025


def infer_host(runtime_findings: Sequence[Finding]) -> Optional[str]:
    """Host for identifying host-wide issues (a missing header belongs to the host, not a route)."""
    for f in sorted(runtime_findings, key=lambda f: f.id):
        if f.runtime and f.runtime.url:
            netloc = urlsplit(f.runtime.url).netloc
            if netloc:
                return netloc
    return None


def _route_for_code(code: Finding, routes_by_id: dict[str, Route]) -> Optional[Route]:
    """The route a code-only finding is reached from, when the taint analysis named one."""
    taint = code.taint
    if not taint:
        return None
    for route_id in taint.entry_routes:
        route = routes_by_id.get(route_id)
        if route is not None:
            return route
    return None


def with_fix(issue: Issue) -> Issue:
    """The issue with its plain-English fix suggestion filled in (B-4, P5-B3, DECISIONS_Dev2 B-25)."""
    return issue.model_copy(update={"fix": fix_for(issue)})


def confirmed_issue(cand: Candidate, config: CorrelateConfig) -> Issue:
    """The Confirmed issue for one accepted link (also used by auto-verify, P4-B4)."""
    code, runtime = cand.code, cand.runtime
    assert code.code is not None and runtime.runtime is not None
    cvss, severity, owasp = _catalogue(code.cwe)
    reasons = link_reasons(cand, config)
    issue = Issue(
        id=ids.code_issue_id(code.cwe, code.code.file, code.code.function, code.code.line_start),
        cwe=code.cwe,
        title=code_issue_title(code),
        label=Label.CONFIRMED,
        severity=severity,  # type: ignore[arg-type]
        cvss=cvss,
        risk=risk_score(
            cvss=cvss,
            label=Label.CONFIRMED,
            runtime_findings=[runtime],
            route=cand.route,
            config=config,
        ),
        code_findings=[code],
        runtime_findings=[runtime],
        primary_code=code.code,
        primary_runtime=runtime.runtime,
        link_score=link_score(cand, config),
        reasons=reasons,
        verified_by="dast",
        owasp_2025=owasp,
    )
    return with_fix(issue)


_confirmed_issue = confirmed_issue  # backwards-compatible alias


def _code_only_issue(
    code: Finding, routes_by_id: dict[str, Route], penalty: Optional[LinkReason], config: CorrelateConfig
) -> Issue:
    assert code.code is not None
    cvss, severity, owasp = _catalogue(code.cwe)
    route = _route_for_code(code, routes_by_id)
    issue = Issue(
        id=ids.code_issue_id(code.cwe, code.code.file, code.code.function, code.code.line_start),
        cwe=code.cwe,
        title=code_issue_title(code),
        label=Label.CODE_ONLY,
        severity=severity,  # type: ignore[arg-type]
        cvss=cvss,
        risk=risk_score(cvss=cvss, label=Label.CODE_ONLY, runtime_findings=[], route=route, config=config),
        code_findings=[code],
        primary_code=code.code,
        reasons=[penalty] if penalty else [],
        owasp_2025=owasp,
    )
    return with_fix(issue)


def _runtime_only_issue(
    runtime: Finding,
    routes_by_id: dict[str, Route],
    host: Optional[str],
    penalty: Optional[LinkReason],
    config: CorrelateConfig,
) -> Issue:
    rt = runtime.runtime
    assert rt is not None
    cvss, severity, owasp = _catalogue(runtime.cwe)
    route = routes_by_id.get(rt.route_id) if rt.route_id else None
    key = rt.route_id or host
    if not key:
        key = rt.path  # last resort: a finding with neither route nor host still needs a stable id
    issue = Issue(
        id=ids.runtime_issue_id(runtime.cwe, key, rt.param),
        cwe=runtime.cwe,
        title=runtime_issue_title(runtime),
        label=Label.RUNTIME_ONLY,
        severity=severity,  # type: ignore[arg-type]
        cvss=cvss,
        risk=risk_score(
            cvss=cvss,
            label=Label.RUNTIME_ONLY,
            runtime_findings=[runtime],
            route=route,
            config=config,
        ),
        runtime_findings=[runtime],
        primary_runtime=rt,
        reasons=[penalty] if penalty else [],
        owasp_2025=owasp,
    )
    return with_fix(issue)


def correlate(
    sast: list[Finding],
    dast: list[Finding],
    routes: list[Route],
    config: Optional[CorrelateConfig] = None,
) -> list[Issue]:
    """Merge SAST and DAST findings into a prioritised list of issues.

    Every input finding ends up in exactly one issue: linked pairs become Confirmed, leftover code
    findings become Code-only, leftover runtime findings become Runtime-only. Pure function - the
    same inputs always produce the same ids, order and scores (FR-6 idempotency).
    """
    config = config or CorrelateConfig()
    code_findings = dedupe_code(sast)
    runtime_findings = dedupe_runtime(dast)
    routes_by_id = {r.id: r for r in routes}
    host = infer_host(runtime_findings)

    candidates = generate_candidates(code_findings, runtime_findings, routes, config)
    assignment = assign(candidates, config)

    issues: list[Issue] = []
    linked_code = {cand.code.id for cand in assignment.links}
    linked_runtime = {cand.runtime.id for cand in assignment.links}

    for cand in assignment.links:
        issues.append(confirmed_issue(cand, config))
    for code in code_findings:
        if code.id not in linked_code and code.code is not None:
            issues.append(_code_only_issue(code, routes_by_id, assignment.penalties.get(code.id), config))
    for runtime in runtime_findings:
        if runtime.id not in linked_runtime and runtime.runtime is not None:
            issues.append(
                _runtime_only_issue(runtime, routes_by_id, host, assignment.penalties.get(runtime.id), config)
            )
    return sort_issues(issues)
