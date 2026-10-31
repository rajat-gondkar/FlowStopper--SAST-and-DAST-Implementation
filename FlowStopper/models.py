"""Shared data contracts (FlowStopper_BUILD_SPEC.md section 7).

SHARED file, frozen at tag `contract-v1`. After the tag, only additive,
backwards-compatible changes are allowed, and every change needs an entry in
docs/CONTRACT_CHANGES.md acknowledged by the other developer.

Content is exactly section 7 of the spec (only re-formatted for ruff).
"""

from __future__ import annotations

from enum import Enum
from typing import Literal, Optional

from pydantic import BaseModel, Field


class Engine(str, Enum):
    SAST = "sast"
    DAST = "dast"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Label(str, Enum):
    CONFIRMED = "confirmed"  # found by both SAST and DAST, linked
    CODE_ONLY = "code_only"  # SAST only, not proven at runtime
    RUNTIME_ONLY = "runtime_only"  # DAST only, no code location found


class ParamLocation(str, Enum):
    QUERY = "query"
    FORM = "form"
    JSON = "json"
    PATH = "path"
    HEADER = "header"
    COOKIE = "cookie"


class CodeLocation(BaseModel):
    file: str  # POSIX path relative to the source root
    line_start: int
    line_end: int
    function: Optional[str] = None  # qualified name of the enclosing function, e.g. "orders.get_orders"
    snippet: str = ""  # the offending lines (max 12 lines)


class TaintInfo(BaseModel):
    source_param: Optional[str] = None  # HTTP parameter name that feeds the sink, e.g. "id"
    source_kind: Optional[ParamLocation] = None
    source_location: Optional[CodeLocation] = None
    call_chain: list[str] = []  # qualnames: handler -> ... -> function containing the sink
    entry_routes: list[str] = []  # Route.id values from which this flow is reachable
    sanitizers_seen: list[str] = []


class RuntimeLocation(BaseModel):
    method: str
    url: str  # full URL requested
    path: str  # path only, no query string
    route_id: Optional[str] = None  # resolved Route.id if known
    param: Optional[str] = None
    param_location: Optional[ParamLocation] = None
    payload: Optional[str] = None
    proof: Literal["error", "echo", "differential", "marker", "header", "redirect", "file"] = "differential"
    request: str = ""  # raw HTTP request text (redacted)
    response_excerpt: str = ""  # max 2 KB
    evidence: str = ""  # one-line human explanation
    repro_curl: str = ""  # a curl command reproducing the finding


class Finding(BaseModel):
    id: str  # stable hash of (engine, rule_id, cwe, location key) - see FlowStopper/ids.py
    engine: Engine
    tool: str  # "FlowStopper-taint" | "FlowStopper-secrets" | "FlowStopper-dast"
    rule_id: str  # e.g. "py.sqli.concat.execute", "dast.sqli.error"
    cwe: int
    title: str
    severity: Severity
    confidence: float = Field(ge=0, le=1)
    code: Optional[CodeLocation] = None
    runtime: Optional[RuntimeLocation] = None
    taint: Optional[TaintInfo] = None
    suppressed: bool = False  # B-2: safe / unreachable
    suppress_reason: Optional[str] = None
    raw: dict = {}


class RouteParam(BaseModel):
    name: str
    location: ParamLocation
    required: bool = False


class Route(BaseModel):
    id: str  # f"{METHOD} {path_template}" e.g. "GET /api/orders"
    method: str
    path_template: str  # "/api/orders/<int:id>"
    path_regex: str  # anchored regex matching concrete URL paths
    handler: str  # qualified name
    file: str
    line_start: int
    line_end: int
    params: list[RouteParam] = []
    auth_required: bool = False
    reachable_functions: list[str] = []  # qualnames reachable from the handler (call depth <= 4)


class LinkReason(BaseModel):
    kind: Literal[
        "same_cwe",
        "route_chain_origin",
        "route_handler_span",
        "route_reachable",
        "same_param",
        "same_method",
        "auto_verified",
        "ambiguity_penalty",
    ]
    detail: str  # human-readable, e.g. "DAST param 'id' == SAST source param 'id'"
    weight: float


class Issue(BaseModel):
    id: str  # stable fingerprint, see section 7 stable-ID rules / FlowStopper/ids.py
    cwe: int
    title: str
    label: Label
    severity: Severity
    cvss: float
    risk: float  # 0-10, see P2-B6
    code_findings: list[Finding] = []
    runtime_findings: list[Finding] = []
    primary_code: Optional[CodeLocation] = None
    primary_runtime: Optional[RuntimeLocation] = None
    link_score: Optional[float] = None
    reasons: list[LinkReason] = []  # B-3
    verified_by: Optional[Literal["dast", "auto-verify"]] = None
    fix: Optional[str] = None  # B-4
    owasp_2025: Optional[str] = None
    first_seen_scan: Optional[str] = None
    last_seen_scan: Optional[str] = None


class SastResult(BaseModel):
    routes: list[Route]
    findings: list[Finding]
    stats: dict = {}


class DastResult(BaseModel):
    findings: list[Finding]
    stats: dict = {}
