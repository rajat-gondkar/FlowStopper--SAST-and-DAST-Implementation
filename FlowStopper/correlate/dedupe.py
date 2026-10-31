"""Collapse duplicate findings (Owner: B, P2-B6 step 1).

Two engines can each report the same bug more than once - the same sink reached by two paths, or
the same parameter proven by two payloads. Grouping keys come straight from the spec:

- runtime: `(cwe family, route_id or path, param)`
- code:    `(cwe, file, function, sink line, source param)`

The representative is the highest-confidence member (ties broken by id, so the choice is stable),
and it is returned **unmodified** - nothing is rewritten, so a finding that reaches the correlator
is byte-identical to what the engine produced.
"""

from __future__ import annotations

from collections.abc import Sequence

from FlowStopper import cwe as cwe_mod
from FlowStopper.models import Finding


def runtime_key(f: Finding) -> tuple:
    rt = f.runtime
    if rt is None:
        return (cwe_mod.family_name(f.cwe), "", "")
    return (cwe_mod.family_name(f.cwe), rt.route_id or rt.path, (rt.param or "").lower())


def code_key(f: Finding) -> tuple:
    code = f.code
    taint = f.taint
    if code is None:
        return (f.cwe, "", "", 0, "")
    return (
        f.cwe,
        code.file,
        code.function or "",
        code.line_start,
        (taint.source_param if taint and taint.source_param else ""),
    )


def _best(group: Sequence[Finding]) -> Finding:
    return sorted(group, key=lambda f: (-f.confidence, f.id))[0]


def _dedupe(findings: Sequence[Finding], key) -> list[Finding]:
    groups: dict[tuple, list[Finding]] = {}
    for f in findings:
        groups.setdefault(key(f), []).append(f)
    return [_best(groups[k]) for k in sorted(groups, key=lambda t: tuple(str(x) for x in t))]


def dedupe_code(findings: Sequence[Finding]) -> list[Finding]:
    """One code finding per (cwe, file, function, sink line, source param)."""
    return _dedupe(findings, code_key)


def dedupe_runtime(findings: Sequence[Finding]) -> list[Finding]:
    """One runtime finding per (cwe family, route_id|path, param)."""
    return _dedupe(findings, runtime_key)
