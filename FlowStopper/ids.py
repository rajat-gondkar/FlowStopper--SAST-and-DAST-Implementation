"""Stable IDs (FlowStopper_BUILD_SPEC.md section 7, "Stable-ID rules"). SHARED, contract-v1.

Both developers must build IDs only through these helpers so SAST, DAST, the
correlator and storage agree byte-for-byte (FR-6 idempotency).

Encoding rules (docs/DECISIONS.md):
- parts are joined with "|"; None becomes ""; enums use their .value; ints use str();
- Finding IDs are the full sha1 hex digest (40 chars);
- Issue IDs are the first 16 hex chars of sha256;
- the CWE is used as given (no family canonicalisation);
- the payload is never part of an ID.
"""

from __future__ import annotations

import hashlib
from enum import Enum
from typing import Optional

from FlowStopper.models import Finding, Issue


def _join(parts: tuple[object, ...]) -> bytes:
    out = []
    for p in parts:
        if p is None:
            out.append("")
        elif isinstance(p, Enum):
            out.append(str(p.value))
        else:
            out.append(str(p))
    return "|".join(out).encode("utf-8")


def code_finding_id(engine: object, rule_id: str, cwe: int, file: str, function: Optional[str], line_start: int) -> str:
    """sha1(engine|rule_id|cwe|code.file|code.function|code.line_start)"""
    return hashlib.sha1(_join((engine, rule_id, cwe, file, function, line_start))).hexdigest()


def runtime_finding_id(
    engine: object, rule_id: str, cwe: int, method: str, route_id_or_path: str, param: Optional[str]
) -> str:
    """sha1(engine|rule_id|cwe|method|route_id_or_path|param)"""
    return hashlib.sha1(_join((engine, rule_id, cwe, method.upper(), route_id_or_path, param))).hexdigest()


def finding_id(f: Finding) -> str:
    """ID for a Finding: code rule when it has a code location, else the runtime rule."""
    if f.code is not None:
        return code_finding_id(f.engine, f.rule_id, f.cwe, f.code.file, f.code.function, f.code.line_start)
    if f.runtime is not None:
        rt = f.runtime
        return runtime_finding_id(f.engine, f.rule_id, f.cwe, rt.method, rt.route_id or rt.path, rt.param)
    raise ValueError(f"finding {f.rule_id!r} has neither a code nor a runtime location")


def code_issue_id(cwe: int, file: str, function: Optional[str], sink_line: int) -> str:
    """sha256(cwe|primary_code.file|primary_code.function|sink_line)[:16]"""
    return hashlib.sha256(_join((cwe, file, function, sink_line))).hexdigest()[:16]


def runtime_issue_id(cwe: int, route_id_or_host: str, param: Optional[str]) -> str:
    """sha256(cwe|route_id_or_host|param)[:16]. Host-wide findings pass the host (netloc)."""
    return hashlib.sha256(_join((cwe, route_id_or_host, param))).hexdigest()[:16]


def issue_id(issue: Issue, host: Optional[str] = None) -> str:
    """ID for an Issue built from its primary locations.

    Runtime-only issues use the route ID when known, else `host` (required for
    host-wide findings such as missing headers).
    """
    if issue.primary_code is not None:
        pc = issue.primary_code
        return code_issue_id(issue.cwe, pc.file, pc.function, pc.line_start)
    if issue.primary_runtime is not None:
        key = issue.primary_runtime.route_id or host
        if not key:
            raise ValueError("runtime-only issue without route_id needs the host")
        return runtime_issue_id(issue.cwe, key, issue.primary_runtime.param)
    raise ValueError("issue has neither primary_code nor primary_runtime")
