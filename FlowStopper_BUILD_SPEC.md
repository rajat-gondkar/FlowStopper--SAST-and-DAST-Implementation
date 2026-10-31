# FlowStopper — SAST + DAST Correlation Engine
## Build Specification for the Coding Agents

> **Audience:** two coding agents (one per developer: **Dev A**, **Dev B**) working in parallel for ~16 hours.
> **Read this whole file once.** Then work only from your own phase tasks. This file is the single source of truth for scope, contracts, ownership and acceptance criteria.

---

## 0. How the agents must work

1. **Ownership is strict.** Each directory has one owner (section 6). Never edit the other developer's files. If you need a change in a shared contract (`models.py`, `cwe.py`), append an entry to `docs/CONTRACT_CHANGES.md` and get the other dev's acknowledgement before merging.
2. **Contracts freeze at the end of Phase 0** (tag `contract-v1`). After that, only additive, backwards-compatible changes are allowed.
3. **Work in vertical slices with tests.** Every task ends with passing tests (`make check` = ruff + pytest). Do not move on with failing tests.
4. **Track progress** in `docs/PROGRESS.md` (task ID, owner, status, notes). Update it at the end of every task.
5. **Commit small, commit often**, trunk-based: short-lived branches `a/<task-id>` and `b/<task-id>`, merge to `main` after `make check` passes.
6. **Never hardcode anything specific to a test app** (file names, URLs, line numbers, planted IDs). See rule R6.
7. **Determinism:** sorted outputs, stable IDs, seeded randomness where reproducibility matters (canaries use a per-scan seed recorded in the scan metadata).
8. **If a spec detail is ambiguous**, choose the simpler option, document the decision in `docs/DECISIONS.md` (one line), and continue. Do not block.

---

## 1. Product summary

**Goal:** a tool that scans an application's **source code (SAST)** and its **running instance (DAST)**, then **correlates** the two so every real vulnerability appears **once**, with the code line that causes it, the URL/parameter/payload that proves it, a risk score, and a fix suggestion.

**Pipeline**

```
source folder ─► [SAST: route map + call graph + taint + secrets] ─► sast findings + routes ─┐
                                                                                            ├─► normalize ─► CORRELATE ─► SQLite ─► API / CLI / HTML / SARIF
running app   ─► [DAST: seeded by route map + crawler + checks ]  ─► dast findings ─────────┘
```

**What is judged most: correlation quality.** Everything else exists to feed it accurate, well-structured data.

**Target application language:** Python (Flask primary; FastAPI and Django route extractors also required for generalisation to an unseen app).

---

## 2. Non-negotiable rules (hackathon compliance)

Violating any of these can disqualify the team. Agents must enforce them in code and tests, not only in docs.

| ID | Rule | How it is enforced |
|---|---|---|
| **R1** | **Original work.** Correlation logic, route mapper, taint engine, secrets detector, DAST engine and scoring are written from scratch for this event. No copied scanner code. | Code review; no vendored scanners. |
| **R2** | **Disclose every third-party component** (libraries, tools, datasets, AI coding assistants). | `THIRD_PARTY.md` maintained from Phase 0 (name, version, licence, how it is used). README states AI coding tools were used. |
| **R3** | **Scan only authorised targets.** DAST may only contact targets we are authorised to scan, running locally: the organisers' test app, our own mock apps, and third-party **benchmark** apps we run locally for evaluation (e.g. OWASP PyGoat). Any such host is added to the allow-list **via `ALLOWED_HOSTS` config only** — never hardcoded in `FlowStopper/`. | `FlowStopper/scope.py` allow-list guard enforced inside the HTTP client (section P0-B1). |
| **R4** | **No malicious code or harmful payloads.** Payloads are harmless canaries, arithmetic echoes and read-only file probes. No destructive, persistent or exfiltrating payloads. No DELETE/PUT by default. | Payload catalogue (Appendix B) is the only source of payloads; tests assert nothing outside it is sent. |
| **R5** | **Confidentiality.** Organisers' source code, answer key and data are used only for this hackathon and are never committed to a public repo or shared. | `.gitignore` excludes `target_src/`, `keys/`, `*.key.json`; README says so. |
| **R6** | **No overfitting.** No app-specific constants in `FlowStopper/`. The tool must work on an unseen second app. | `tests/test_no_overfit.py` greps `FlowStopper/` for strings taken from the local answer key (when present) and fails on a match. |
| **R7** | **Safe by construction.** SAST never imports or executes target code (parse only). Reports HTML-escape all evidence (payloads are XSS strings). Stored requests redact `Authorization`/`Cookie` values unless `--keep-secrets` is set. | Unit tests for each. |
| **R8** | **Only the organisers' app is scanned during evaluation**; our mock apps exist purely as development/regression fixtures and are clearly labelled as our own work. | README + `THIRD_PARTY.md` ("Own work: apps/mock_a, apps/mock_b"). |

---

## 3. Scope

### 3.1 Compulsory (all must be done)

| ID | Requirement | Primary owner | Phase |
|---|---|---|---|
| FR-1 | SAST scan: file, line, type, severity, snippet | A | 2 |
| FR-2 | DAST scan: URL, method, param, payload, evidence | B | 1–2 |
| FR-3 | Common finding format with CWE | Shared (A+B) | 0 |
| FR-4 | Route map (URL → handler function + line span) | A | 1 |
| FR-5 | Correlate (same CWE + DAST route handled by code holding the SAST finding) | B | 2 |
| FR-6 | Merge duplicates, idempotent re-scans | B | 2 |
| FR-7 | Labels: Confirmed / Code only / Runtime only | B | 2 |
| FR-8 | Issue detail for confirmed issues | B (data) + A (API) | 5 |
| FR-9 | Prioritised list (confirmed first, then risk) | B | 2 |
| FR-10 | CLI + API + short README | A | 5, 7 |

**Vulnerability types covered (all six):** SQL injection (CWE-89), XSS (CWE-79), command injection (CWE-78), path traversal (CWE-22), open redirect (CWE-601), hard-coded secrets (CWE-798, code only). Plus passive runtime checks (headers, cookies, CORS, verbose errors) for runtime-only findings.

### 3.2 Bonus items chosen (most aligned with the scoring targets)

| ID | Bonus | Why | Owner | Phase |
|---|---|---|---|---|
| **B-3** | Explain every link (reasons + weights) | Falls out of the scoring; supports "wrong links < 5%" reviews | B | 4 |
| **B-2** | Cut SAST noise (sanitised / unreachable → suppressed bucket) | Directly lowers "false alarms" | A | 4 |
| **B-1** | Auto-verify Code-only findings with a safe probe | Raises correct-link rate | B | 4 |
| **B-6** | SARIF 2.1.0 export + CI fail on confirmed high | Industry-standard format | B | 5 |
| **B-4** | Plain-English fix suggestion (templated per CWE) | Cheap, improves actionability | B | 5 |
| B-5 | Scan diff (new / fixed / open) | **Optional**, only if time remains in Phase 6 | B | 6 |

### 3.3 Out of scope

Automatic code fixing, login/user management, cloud deployment, polished UI (a clean server-rendered HTML report is enough), reachability-aware SCA.

---

## 4. Success targets (measured against the organisers' answer key)

| Metric | Good | Great | Definition |
|---|---|---|---|
| Code detection | > 60% | > 85% | planted code vulns found by SAST / planted vulns that have a code location |
| Runtime detection | > 50% | > 80% | planted runtime vulns found by DAST / planted vulns that have a runtime location |
| Correct links | > 50% | > 80% | planted pairs merged into one **Confirmed** issue / planted pairs (20) |
| Wrong links | < 20% | < 5% | Confirmed issues joining two different planted bugs / Confirmed issues |
| False alarms | < 30% | < 10% | reported (non-suppressed) issues overlapping a safe decoy / reported issues |
| Unseen app | > 40% | > 65% | correct-link rate on a second, unseen app |
| Run time | < 15 min | < 5 min | scan + correlate + report on the test app |

Planted counts on the real app: 36 total = 20 pairs + 10 code-only + 6 runtime-only, plus ~8 safe decoys.

---

## 5. Technology stack (all free / open source)

- **Python 3.11+**, standard-library `ast` for all code analysis, `sqlite3` for storage.
- Runtime dependencies (pin exact versions in `requirements.lock` at the end):
  `fastapi`, `uvicorn`, `pydantic>=2`, `httpx`, `jinja2`, `typer`, `beautifulsoup4`.
- Dev dependencies: `pytest`, `pytest-asyncio`, `ruff`.
- Mock apps (our own work) have separate requirements: `flask` (Mock A), `fastapi` + `uvicorn` (Mock B).
- Packaging: `pyproject.toml`, `Dockerfile`, `docker-compose.yml`, `Makefile`.
- No paid services, no API keys, no network access needed at run time other than the target app.

---

## 6. Repository layout and ownership

```
FlowStopper/
├── README.md                    (A drafts in P5, B reviews, finalised in P7)
├── THIRD_PARTY.md               (shared, from P0)
├── FlowStopper_BUILD_SPEC.md         (this file)
├── pyproject.toml  Makefile  Dockerfile  docker-compose.yml  .gitignore
├── docs/
│   ├── PROGRESS.md  DECISIONS.md  CONTRACT_CHANGES.md
│   ├── ARCHITECTURE.md  LIMITATIONS.md  metrics/            (P7)
├── fixtures/                    (shared, P0: hand-written sample JSON for every contract)
├── FlowStopper/
│   ├── models.py                SHARED  – pydantic contracts (frozen end of P0)
│   ├── cwe.py                   SHARED  – CWE catalogue, families, OWASP map, CVSS vectors
│   ├── config.py  storage.py    B
│   ├── scope.py                 B       – scope guard
│   ├── cvss.py                  B       – CVSS 3.1 calculator
│   ├── sast/                    A
│   │   ├── index.py             file discovery, parsing, symbol table
│   │   ├── routes/ (flask.py, fastapi.py, django.py, resolver.py)
│   │   ├── callgraph.py
│   │   ├── taint/ (engine.py, summaries.py, sources.py, sinks.py, sanitizers.py)
│   │   ├── secrets.py  templates.py  suppress.py  runner.py
│   ├── dast/                    B
│   │   ├── client.py  discovery.py  baseline.py  verify.py  runner.py
│   │   └── checks/ (sqli.py, xss.py, cmdi.py, traversal.py, redirect.py, passive.py)
│   ├── correlate/               B  (dedupe.py, matcher.py, scoring.py, issues.py, explain.py, autoverify.py)
│   ├── report/                  B  (html.py, sarif.py, fixes.py, templates/)
│   ├── api.py  cli.py  pipeline.py   A
│   └── evalkit/                 B  (keyschema.py, metrics.py, runner.py)
├── apps/
│   ├── mock_a/                  A   – Flask shop (development + regression fixture)
│   └── mock_b/                  B   – FastAPI shop (HELD-OUT, see P2-B6 and P6)
├── tests/                       each dev owns tests for their modules
├── target_src/   keys/          git-ignored: organisers' source and answer key (R5)
```

**Interface between the two developers (the only coupling):**

```python
# FlowStopper/sast/runner.py            (A)
def run_sast(source_root: Path, config: SastConfig) -> SastResult
#   SastResult: routes: list[Route], findings: list[Finding], stats: dict

# FlowStopper/dast/runner.py            (B)
async def run_dast(target_url: str, routes: list[Route], config: DastConfig) -> DastResult
#   DastResult: findings: list[Finding], stats: dict

# FlowStopper/correlate/engine.py       (B)
def correlate(sast: list[Finding], dast: list[Finding], routes: list[Route],
              config: CorrelateConfig) -> list[Issue]
```

Everything crosses these boundaries as the pydantic models below, serialisable to JSON.

---

## 7. Data contracts (`FlowStopper/models.py`) — frozen at end of Phase 0

```python
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
    id: str  # stable hash of (engine, rule_id, cwe, location key)
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
    id: str  # stable fingerprint, see section 9 (P2-B5)
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
```

**Stable-ID rules (needed for FR-6 idempotency):**
- `Finding.id = sha1(engine|rule_id|cwe|code.file|code.function|code.line_start)` for code findings; `sha1(engine|rule_id|cwe|method|route_id_or_path|param)` for runtime findings. The payload is **not** part of the ID.
- `Issue.id = sha256(cwe|primary_code.file|primary_code.function|sink_line)[:16]` when a code location exists, else `sha256(cwe|route_id_or_host|param)[:16]`. A Code-only issue that later becomes Confirmed keeps the same ID.

---

## 8. CWE catalogue (`FlowStopper/cwe.py`)

Shared; written in Phase 0. Contains, for each CWE: name, family set, OWASP Top 10:2025 category, CVSS 3.1 vector, fix-template key.

| CWE | Name | Family (match as "same type") | OWASP 2025* | CVSS 3.1 vector (assumes unauthenticated, network) |
|---|---|---|---|---|
| 89 | SQL Injection | {89} | A05 Injection | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H |
| 78 | OS Command Injection | {78, 77} | A05 Injection | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H |
| 79 | Cross-site Scripting | {79} | A05 Injection | AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N |
| 22 | Path Traversal | {22, 23, 36} | A01 Broken Access Control | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N |
| 601 | Open Redirect | {601} | A01 Broken Access Control | AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N |
| 798 | Hard-coded Credentials | {798, 259, 321} | A07 Authentication Failures | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N |
| 693 / 1021 | Missing security headers / clickjacking | own | A02 Security Misconfiguration | AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N |
| 1004 / 614 / 1275 | Cookie flags (HttpOnly / Secure / SameSite) | own | A02 Security Misconfiguration | AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N |
| 942 | Permissive CORS | {942} | A02 Security Misconfiguration | AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N |
| 209 / 489 / 215 | Verbose errors / debug mode | own | A02 / A10 | AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N |
| 200 / 497 | Information exposure (version banners) | own | A02 Security Misconfiguration | AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N |
| 548 | Directory listing | {548} | A02 Security Misconfiguration | AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N |

\*The OWASP mapping is a convenience label. Verify categories against https://owasp.org/Top10/2025/ before finalising the README.

Severity bucket from CVSS: ≥9.0 critical, 7.0–8.9 high, 4.0–6.9 medium, 0.1–3.9 low, 0 info.

---

# PART II — PHASED BUILD PLAN

Timeline is cumulative hours from kickoff. **Both developers work in parallel inside each phase; a phase ends only when both pass its exit criteria.**

| Phase | Hours | Theme |
|---|---|---|
| 0 | 0:00–1:00 | Foundations and frozen contracts (joint) |
| 1 | 1:00–4:00 | Core engines v0 (A: routes + call graph; B: DAST core) |
| 2 | 4:00–8:00 | Depth (A: taint + secrets; B: all checks + correlator v1) |
| 3 | 8:00–9:30 | Integration and baseline measurement (joint) |
| 4 | 9:30–12:30 | Accuracy tuning and chosen bonuses |
| 5 | 12:30–14:00 | Delivery surface: API, CLI, report, SARIF |
| 6 | 14:00–15:00 | Generalisation round on the held-out app |
| 7 | 15:00–16:00 | Release: docs, clean-clone test, freeze |

---

## PHASE 0 — Foundations (joint, 0:00–1:00)

**Goal:** a runnable skeleton, frozen contracts and fixtures so both tracks can proceed independently.

| Task | Owner | Description | Done when |
|---|---|---|---|
| P0-J1 | A | Scaffold repo: `pyproject.toml`, package layout (section 6), `Makefile` targets (`check`, `test`, `lint`, `demo`), ruff config, `.gitignore` (must include `target_src/`, `keys/`, `*.key.json`, `*.db`, `__pycache__/`). | `make check` runs green on empty tests |
| P0-J2 | A+B | Write `FlowStopper/models.py` exactly as section 7. Export JSON Schemas to `docs/schemas/`. | Both devs import models; `contract-v1` tag created |
| P0-J3 | B | Write `FlowStopper/cwe.py` from section 8 plus `fix` template keys. | `get_cwe(89).vector` works; unit test |
| P0-J4 | A+B | Hand-write `fixtures/`: `routes.json`, `sast_findings.json`, `dast_findings.json`, `answer_key.json`, `expected_issues.json`. Must contain: one clean pair, one code-only secret, one runtime-only header issue, one **ambiguous** case (two code findings, same CWE, same handler, different params), one decoy. | Both tracks can run against fixtures with no other code |
| P0-J5 | A+B | Read the organisers' app and answer key (local only). Record in a **git-ignored** `docs/target_notes.local.md`: framework, route style, helper layout, how it is started, planted-vuln locations, key format. | Notes written; app runs locally via its compose file |
| P0-B1 | B | `FlowStopper/scope.py`: allow-list guard. Allowed hosts come from `ALLOWED_HOSTS` (default `localhost,127.0.0.1,::1` plus compose service names given explicitly). Rules: refuse any other hostname **even if it resolves to a private IP**; re-check on every redirect hop; refuse non-http(s) schemes; an explicit `--allow-host` override must log a WARNING. | Unit tests: external host refused, redirect to external host refused, allow-listed host accepted |
| P0-J6 | A | `THIRD_PARTY.md` skeleton (name, version, licence, role, "own work" section). `docs/PROGRESS.md` created. | Files committed |

**Exit criteria (Phase 0):** `make check` green; models frozen; fixtures present; scope guard tested; target app runs locally.

---

## PHASE 1 — Core engines v0 (1:00–4:00)

### Dev A — code-side foundations

**P1-A1 · Source index (`sast/index.py`)** — 0:45
- Discover `*.py` under the source root (exclude `venv`, `.venv`, `site-packages`, `__pycache__`, `.git`, `node_modules`; skip files > 1 MB). Parse each with `ast.parse` (tolerate syntax errors: log and skip the file).
- Build a project symbol table: modules (dotted name from path), functions, methods, classes, with **qualified names**, file, `line_start`, `line_end` (use `end_lineno`), parameter names, decorators.
- Import resolution: `import x`, `from x import y as z`, relative imports, package `__init__` re-exports. Provide `resolve_call(node, module_ctx) -> Optional[qualname]`.
- **Never import or execute target code (R7).**

**P1-A2 · Route extractors (`sast/routes/`)** — 1:15
- **Flask:** `@app.route(path, methods=[...])`, `@bp.route`, `@app.get/post/put/delete/patch`, `app.add_url_rule`, `MethodView` classes, Blueprint `url_prefix` (set both in `Blueprint(...)` and in `register_blueprint(..., url_prefix=...)`), nested blueprints, application factories (`create_app`).
- **FastAPI:** `@app.get/post/...`, `APIRouter(prefix=...)`, `include_router(router, prefix=...)`, path/query/body parameters from function signatures (`Query`, `Path`, `Body`, pydantic models → field names as JSON params).
- **Django:** `urlpatterns` with `path()`, `re_path()`, `include()` (follow includes across files), function views and class-based views (`as_view()` → methods).
- Emit one `Route` per (method, path). `path_regex`: convert `<int:id>`, `<id>`, `<path:p>`, `{id}`, `{id:path}`, `(?P<id>...)` into anchored regexes (`[^/]+`, or `.+` for path converters), tolerate a trailing slash.
- **Parameters** read in the handler body, with locations: `request.args.get/[]` → query; `request.form` → form; `request.get_json()/request.json` → json (record top-level keys when statically visible); path converters → path; `request.headers`/`request.cookies` → header/cookie; FastAPI/Django equivalents.
- `auth_required = True` if the handler has a recognised decorator (`login_required`, `jwt_required`, `Depends(get_current_user)`, `permission_required`, …).

**P1-A3 · Call graph (`sast/callgraph.py`)** — 0:45
- Static, name-resolved call edges between project functions (functions, methods via `self.` and simple class instantiation tracking, module-qualified calls, imported names).
- For each route: `reachable_functions` = BFS from the handler, depth ≤ 4, cycle-safe.
- Unknown/dynamic calls are ignored (do not guess).

**P1-A4 · Mock A (`apps/mock_a/`)** — 0:30 (AI-generate quickly, then manually verify each planted bug works)
- A small Flask shop with SQLite, ~25 routes, blueprints with prefixes, helpers in separate modules, JSON and form bodies, Jinja templates. Planted bugs and decoys per **Appendix D** and a matching `apps/mock_a/answer_key.json` (schema: Appendix C). Runs via `docker compose -f apps/mock_a/docker-compose.yml up`.

**Phase 1 exit (A):** `FlowStopper sast <path>` writes `routes.json` for Mock A and for the real app; a unit test per route style; call-graph test shows a handler reaching a helper in another file.

### Dev B — runtime foundations

**P1-B1 · HTTP client (`dast/client.py`)** — 0:45
- Async `httpx.AsyncClient`, **every request goes through the scope guard**, redirects **not followed** by default (manual follow only within scope), cookie jar, timeouts (connect 3 s, total 10 s), concurrency limiter (default 20) and global request-rate cap, retry once on connection reset.
- Optional auth config: static headers/cookies, or a login step (`POST` credentials to a configured URL and keep the cookie jar).
- Records every exchange as `(request_text, response_status, headers, body_excerpt)` with redaction (R7). Body kept ≤ 64 KB in memory, ≤ 2 KB stored.
- Builds `repro_curl` strings.

**P1-B2 · Discovery (`dast/discovery.py`)** — 1:00
- **Seed from routes:** for each `Route`, generate concrete requests: substitute path params with sample values (`1`, `test`, `a.txt` by converter type), attach known query/form/json params with benign values.
- **Crawl** (same-origin only, depth ≤ 3, max 300 URLs): extract links, forms (action, method, input names, hidden fields), script `fetch(`/`axios` URL literals; read `/robots.txt`, `/sitemap.xml`, and `/openapi.json` / `/swagger.json` if present.
- Output `Endpoint` objects: `(method, url, route_id|None, params[name, location, sample value])`. Merge seeded and crawled endpoints; **seeded params always win**.

**P1-B3 · Baseline helpers (`dast/baseline.py`)** — 0:30
- For an endpoint+param: two baseline requests; response fingerprint = `(status, length bucket, normalised body hash, timing)`; mark the endpoint "unstable" if the two baselines differ (then require stricter evidence).
- Differential comparison helper `differs(a, b) -> bool` that ignores volatile content (timestamps, CSRF tokens, request IDs — normalise by regex).

**P1-B4 · First two checks: SQLi and XSS (`dast/checks/`)** — 1:15 (payload specs in Appendix B)
- Check interface: `async def run(ctx: CheckContext, endpoint: Endpoint, param: Param) -> list[Finding]`.
- Each active finding must carry `payload`, `proof`, `evidence`, `request`, `response_excerpt`, `repro_curl`.

**P1-B5 · Eval harness skeleton (`evalkit/`)** — 0:30
- `keyschema.py` (Appendix C), `metrics.py` implementing section 4 definitions, unit tests against `fixtures/`.

**Phase 1 exit (B):** `FlowStopper dast <url> --routes routes.json` finds SQLi and XSS on Mock A (or the real app) with full evidence; `FlowStopper eval` computes metrics on fixtures.

**Phase 1 sync checkpoint (4:00):** A's `routes.json` is consumed by B's discovery with no schema changes. If either side needs a change, use `docs/CONTRACT_CHANGES.md`.

---

## PHASE 2 — Depth (4:00–8:00)

### Dev A — taint analysis and secrets

**P2-A1 · Intraprocedural taint (`sast/taint/engine.py`)** — 1:15
- Abstract value: a set of `TaintLabel(param_name, location_kind, source_node)`; the empty set means untainted; a separate flag `is_constant_string` is tracked so parameterised SQL strings are recognised as safe.
- Walk each function body in statement order maintaining `env: dict[str, TaintValue]`. Handle: assignments (incl. tuple unpacking, augmented), `f"{x}"`, `+`, `%`, `.format()`, `.join()`, slicing, subscript/attribute of tainted values, container literals, comprehension passthrough, `str()/bytes()/.strip()/.lower()` etc. as propagators, `return`.
- **Branches:** join environments (union) after `if/else`, `try`, loops (one extra iteration for loops).
- Unknown external calls: propagate taint from any argument to the result (conservative), except calls listed as sanitisers.

**P2-A2 · Interprocedural summaries (`sast/taint/summaries.py`)** — 1:30
- For each project function compute a summary: `param_i → return`, `param_i → sink(cwe, location, rule)` (transitive). Iterate to a **fixpoint** over the call graph (cap 10 iterations, handle recursion).
- At a call site with tainted arguments, apply the callee summary: tainted return → taint the result; param→sink → emit a finding located **at the sink**, with `call_chain = [handler, ..., function_with_sink]`.
- Route handlers' request-derived values (see sources) seed the analysis; for each finding record `taint.source_param`, `source_kind` and `entry_routes` (every route whose `reachable_functions` includes the sink function **and** from whose handler the flow actually originates; handler-originated flows must be preferred over mere reachability).
- This is what enables cross-function **and cross-file** tracking and is the key input to correlation.

**P2-A3 · Sources, sinks, sanitisers (`sast/taint/sources.py|sinks.py|sanitizers.py`)** — 1:00
- **Sources:** Flask `request.args/form/values/json/data/cookies/headers/files/view_args` (+ `.get()`, `[]`, `getlist`); FastAPI handler parameters (`Query`, `Path`, `Body`, `Form`, `Header`, `Cookie`, plain typed params, pydantic model fields); Django `request.GET/POST/body/COOKIES/META/FILES` and URL kwargs.
- **Sinks** (which argument matters is part of the rule):

| CWE | Sink patterns | Vulnerable when |
|---|---|---|
| 89 | `.execute`, `.executemany`, `.executescript`, `.raw`, `.extra`, `sqlalchemy.text(...)`, `read_sql*` | **first argument (the SQL text)** is tainted / string-built (concat, f-string, `%`, `.format`, `.join`). A constant SQL string with tainted *bind parameters* is **safe** (decoy). |
| 78 | `os.system`, `os.popen`, `subprocess.*` (`run/call/check_call/check_output/Popen`), `commands.getoutput` | tainted command string with `shell=True` (or via `os.system/popen`). `subprocess` with a **list** argument and no `shell=True` is **safe** (decoy). |
| 22 | `open`, `Path(...)` read/write/open, `send_file`, `FileResponse`, `os.listdir`, `os.path.join(base, tainted)` flowing into those | tainted path reaches file access without a recognised containment check |
| 601 | `redirect`, `HttpResponseRedirect`, `RedirectResponse`, manual `Location` header | tainted URL without a recognised allow-list / same-site check |
| 79 | handler return value / `make_response` / `Response` / `HttpResponse` / `HTMLResponse` where the body is tainted and content-type is HTML (Flask returns `str` as HTML by default); `Markup(...)`, `mark_safe(...)`; `render_template(...)` where the template renders that variable with `|safe` or autoescape disabled (see P2-A5) | tainted data reaches an HTML response unescaped. `jsonify`, `JSONResponse`, `mimetype="application/json"`, `text/plain` are **safe** (decoy). |

- **Sanitisers** (neutralise taint for the listed CWEs): `int()/float()/bool()/uuid.UUID()` (all); `html.escape`, `markupsafe.escape`, `flask.escape`, `django.utils.html.escape`, `bleach.clean` (79); `shlex.quote` (78); `werkzeug.utils.secure_filename`, `os.path.basename` (22); `url_for` (601); `werkzeug.utils.safe_join` / `send_from_directory` (22).
- **Guard recognition (path-sensitive lite):** inside an `if` body (or after `if not guard: return/abort/raise`) a variable is considered sanitised for a CWE if the guard matches a known pattern: membership in a constant allow-list (`x in ALLOWED`), `x.startswith(base)` after `os.path.realpath/abspath`, `os.path.commonpath([...]) == base`, `Path(...).resolve().is_relative_to(base)`, `urlparse(x).netloc == ""` / `in ALLOWED_HOSTS`, `url_has_allowed_host_and_scheme`, `x.isdigit()/isalnum()`, `re.fullmatch(const_pattern, x)`. Record the guard in `taint.sanitizers_seen`.

**P2-A4 · Secrets detector (`sast/secrets.py`)** — 0:45 (CWE-798)
- Scan Python and config-like files (`.env`, `.ini`, `.cfg`, `.yaml/.yml`, `.json`, `.toml`, `Dockerfile`, compose `environment:`).
- Detect: assignments / dict literals / keyword args / config keys whose **name** matches `passw(or)?d|passwd|pwd|secret|api[_-]?key|token|auth|private[_-]?key|credential|access[_-]?key` with a **non-placeholder string literal** (length ≥ 6); well-known credential prefixes (`AKIA…`, `ghp_…`, `sk-…`, `-----BEGIN … PRIVATE KEY-----`); literal credential comparisons (`if password == "…"`); `app.config["SECRET_KEY"] = "<literal>"`; `jwt.encode(..., "<literal>")`; DSN strings with embedded credentials.
- Exclude: values read from `os.environ`/`getenv` (a literal **default** is reported at lower confidence), empty/placeholder values (`changeme`, `your_…`, `xxx`, `<...>`, `${...}`, `None`), vendored dirs. Entropy (Shannon ≥ 3.0 bits/char for ≥ 16-char values) boosts confidence; low entropy does not suppress a name match.

**P2-A5 · Template scan (`sast/templates.py`)** — 0:30
- Parse Jinja templates (regex-based tokeniser is sufficient): find `{{ var|safe }}`, `{% autoescape false %}`, `Markup` in templates. Link to Python via `render_template("name.html", key=value)` call sites so XSS findings point to the sink location with the right `source_param`.

**P2-A6 · SAST runner (`sast/runner.py`)** — 0:30
- Orchestrates index → routes → call graph → taint → secrets → templates → `SastResult`. Findings get stable IDs, snippets (offending lines ± 1), severity from CWE catalogue, confidence (taint with full chain 0.9, partial 0.7, name-only secret 0.7).
- CLI: `FlowStopper sast <path> -o sast.json`.

**Phase 2 exit (A):** on Mock A, code detection ≥ 85% with ≤ 1 false alarm among the decoys; cross-file helper bugs are found; every injection finding has `source_param` and `entry_routes`.

### Dev B — remaining checks, verification, correlator v1

**P2-B1 · Remaining active checks** — 1:15 (Appendix B)
- `cmdi.py`, `traversal.py`, `redirect.py`. Same interface and evidence requirements as P1-B4.

**P2-B2 · Passive and misconfiguration checks (`checks/passive.py`)** — 1:00
- Host-wide findings, reported **once per host** with the list of affected paths in `evidence`: security headers (CSP, clickjacking protection via `X-Frame-Options` or CSP `frame-ancestors`, `X-Content-Type-Options`, HSTS only on HTTPS, `Referrer-Policy`), cookie flags (`HttpOnly`, `Secure`, `SameSite`), permissive CORS (probe with `Origin: https://sdc-probe.invalid`), version banners (`Server`, `X-Powered-By`), verbose error pages / tracebacks / debug consoles (e.g. `/console`), exposed files from a **small fixed list** (`/.git/HEAD`, `/.env`, `/robots.txt` as info only), directory listing.
- These are `RUNTIME_ONLY` by nature (no code location).

**P2-B3 · Verification and dedupe of DAST findings (`dast/verify.py`)** — 0:45
- Every active hit is re-tested with a **second canary** and a **control request** (benign value). Report only if the second canary reproduces and the control does not. Collapse multiple payload hits for the same `(cwe, route_id|path, param)` into one `Finding` (keep the strongest proof, list other payloads in `raw`).

**P2-B4 · DAST runner (`dast/runner.py`)** — 0:45
- Build endpoints → for every endpoint/param run applicable checks concurrently under the global concurrency cap and a **time budget** (`--time-budget`, default 240 s; when exceeded, stop cleanly and record `stats.truncated=true`). Prioritise endpoints that appear in `routes.json` first.
- Method policy: GET/POST/HEAD/OPTIONS by default; PUT/PATCH only with `--allow-mutating`; DELETE never.
- CLI: `FlowStopper dast <url> --routes routes.json -o dast.json`.

**P2-B5 · Storage (`storage.py`)** — 0:30
- SQLite tables: `scans(id, started_at, finished_at, source_path, target_url, status, config_json, timings_json, seed)`, `findings(id, scan_id, engine, cwe, suppressed, json)`, `issues(id, cwe, json, first_seen_scan, last_seen_scan)`, `scan_issues(scan_id, issue_id, label, risk, json_snapshot)`. Upsert semantics on `issues.id` (FR-6).

**P2-B6 · Correlator v1 (`correlate/`)** — 2:00 (works against `fixtures/` first, then real data)

1. **Collapse duplicates** (`dedupe.py`): runtime findings by `(cwe_family, route_id|path, param)`; code findings by `(cwe, file, function, sink_line, source_param)`.
2. **Candidate generation** (`matcher.py`): for each runtime finding `r` and code finding `c` where `cwe_family(r) == cwe_family(c)` and `c` is not suppressed:
   - `route_match`:
     - `1.0` if `r.route_id ∈ c.taint.entry_routes` (flow originates at that route's handler),
     - `0.9` if `c.code.file`/line lies inside the route's handler span,
     - `0.8` if `c.code.function ∈ route.reachable_functions`,
     - else `0` → **not a candidate** (hard gate).
   - `param_match`: `1.0` if normalised names are equal (case-insensitive; strip `[]`; use last segment of dotted JSON paths); `0.5` if the SAST side has no `source_param`; `0.0` if both known and different.
   - `method_match`: `1.0` if `r.method ∈ route.method`, else `0`.
   - `specificity`: `1.0` if `c` has a full taint chain, `0.5` otherwise.
3. **Score** (`scoring.py`): `score = 0.50·route_match + 0.35·param_match + 0.10·method_match + 0.05·specificity`. Constants live in `CorrelateConfig` (`LINK_MIN=0.70`, `AMBIGUITY_MARGIN=0.10`) so the harness can tune them.
4. **Assignment** (`issues.py`): sort edges by score; **greedy one-to-one** matching (each code and runtime finding used at most once) accepting edges ≥ `LINK_MIN`. **Ambiguity rule:** if a runtime finding's best and second-best candidate scores differ by less than `AMBIGUITY_MARGIN` **and** `param_match` does not separate them, **do not link**; emit separate Code-only and Runtime-only issues and add an `ambiguity_penalty` reason. (Prefer a missed link over a wrong link.)
5. **Issue construction:** one `Issue` per linked pair; unlinked code findings → `CODE_ONLY`; unlinked runtime findings → `RUNTIME_ONLY`. Attach all merged evidence. Compute IDs per section 7. Label per FR-7.
6. **Risk score** (`cvss.py` + `scoring.py`): implement the CVSS 3.1 base-score formula from the vector. `risk = clamp(cvss × exploitability_factor, 0, 10)`, with `exploitability_factor` = `1.0` base, `×0.85` if the route requires auth, `×0.9` if the only proof is `differential`, `×0.6` for `CODE_ONLY` (unproven), `×0.9` for low-confidence runtime-only. **Sort:** Confirmed first, then `risk` desc, then severity, then CWE, then issue ID (deterministic).
7. **Idempotency:** running the pipeline twice on identical input yields identical issue IDs and counts (test required).

**Phase 2 exit (B):** correlator passes fixtures including the ambiguous case (must not produce a wrong link); idempotency test passes; DAST finds all five injection types and the passive findings on Mock A with ≥ 80% runtime detection.

**P2-B7 · Mock B (held-out) (`apps/mock_b/`)** — 0:45, last task of the phase; **Dev A must not read this directory until Phase 6**
- A FastAPI shop (~22 routes) written deliberately differently from Mock A: layered `routers/`, `services/`, `repositories/`; different naming conventions; `include_router` prefixes; pydantic JSON bodies; the same *kinds* of bugs (≥ 8 pairs covering all five injection CWEs, 3 code-only secrets, 3 runtime-only, ≥ 6 decoys) and `answer_key.json` in the Appendix C schema.

**Phase 2 sync checkpoint (8:00):** all contracts still valid; both runners produce real data.

---

## PHASE 3 — Integration and baseline (joint, 8:00–9:30)

| Task | Owner | Description | Done when |
|---|---|---|---|
| P3-A1 | A | `pipeline.py` + `FlowStopper scan --source <dir> --target <url> [--out dir]`: run SAST → DAST (seeded with routes) → correlate → store → write `issues.json`, `scan_meta.json` (timings per stage, seed, tool versions). | One command produces a prioritised issue list |
| P3-B1 | B | `FlowStopper eval --key keys/answer_key.json --scan <id>` prints the section 4 metrics table and writes `docs/metrics/<timestamp>.json`. Write a small **converter** from the organisers' key format into Appendix C once its format is known (`evalkit/convert_organiser_key.py`, git-ignored input). | Metrics table printed for the real app |
| P3-J1 | A+B | **Baseline run on the real app.** Save metrics as `docs/metrics/baseline.json`. | Baseline committed |
| P3-J2 | A+B | **Triage every miss and false alarm** into buckets: SAST miss / DAST miss / link miss / wrong link / decoy false alarm / suppression error. Write a ranked backlog `docs/BACKLOG.md` ordered by metric impact. | Backlog drives Phase 4 |

**Exit criteria:** end-to-end scan completes; metrics for all seven targets are computed and recorded.

---

## PHASE 4 — Accuracy tuning and bonuses (9:30–12:30)

**Rule:** tune only against the real app and Mock A. **Never** look at Mock B's failures yet.

### Dev A

| Task | Description |
|---|---|
| P4-A1 | Work the SAST backlog: missed bugs (new source/sink/propagator patterns — implemented as **generic rules**, never app-specific), and decoy false alarms (new sanitiser/guard patterns). Re-run the baseline after each batch; keep a before/after table in `docs/metrics/`. |
| P4-A2 | **B-2 noise cut (`sast/suppress.py`):** mark findings `suppressed=True` with a reason when (a) a recognised sanitiser/guard neutralises the flow (`sanitized:<name>`), (b) parameterised SQL / list-form subprocess etc. is detected, (c) no route can reach the function (`unreachable`; **not** applied to CWE-798). Suppressed findings are kept in the DB and shown in a collapsed section of the report but **never** in the main list and never counted as reported issues. |
| P4-A3 | SAST performance: cache parsed ASTs per run, avoid re-walking; target SAST ≤ 30 s on the real app. |

### Dev B

| Task | Description |
|---|---|
| P4-B1 | Work the DAST backlog: missed endpoints/params, weak evidence, extra payload variants (from Appendix B only). If the key contains stored XSS, add a **second-order pass**: after writes, re-fetch known pages and look for earlier canaries unescaped; report at the *writing* endpoint with the display URL in `evidence`. |
| P4-B2 | Correlator tuning with the harness: tune `LINK_MIN`, `AMBIGUITY_MARGIN`, weights; add test fixtures for every wrong link found. Target wrong links < 5%. |
| P4-B3 | **B-3 explanations (`correlate/explain.py`):** every linked issue carries `reasons: list[LinkReason]` with human-readable details (e.g. "DAST param `id` == SAST source param `id`", "flow originates at handler `orders.get_orders` for route `GET /api/orders`"). Always include `same_cwe`. |
| P4-B4 | **B-1 auto-verify (`correlate/autoverify.py`):** for each `CODE_ONLY` issue with `cwe ∈ {89, 78, 22, 601, 79}`, a known `entry_route` and `source_param`, run the matching check **only** against that route/param (choose method and body encoding from the route and param location). On success: add the runtime finding, set `verified_by="auto-verify"`, add an `auto_verified` reason, re-run linking for that pair and upgrade to `CONFIRMED`. Respect the global time budget (run last). |

**Exit criteria (Phase 4):** every PRD "Good" target met on the real app; "Great" targets attempted. Metrics table committed.

---

## PHASE 5 — Delivery surface (12:30–14:00)

### Dev A

**P5-A1 · API (`api.py`, FastAPI)** — FR-10
- `POST /scans` body `{source_path, target_url, options}` → `202 {scan_id, status}`; scan runs as a background task.
- `GET /scans/{id}` → status, per-stage timings, counts, `truncated` flag.
- `GET /issues?scan_id=&label=&cwe=&min_risk=&include_suppressed=` → prioritised list.
- `GET /issues/{id}` → full Issue (FR-8: URL, parameter, payload, file, line, snippet, CWE, severity, evidence, reasons, fix).
- `GET /scans/{id}/report` → HTML report; `GET /scans/{id}/sarif` → SARIF; `GET /health`.
- Idempotent: re-posting the same inputs updates the same issue IDs.

**P5-A2 · CLI (`cli.py`, Typer)**
- `FlowStopper sast`, `FlowStopper dast`, `FlowStopper correlate`, `FlowStopper scan`, `FlowStopper serve`, `FlowStopper eval`, `FlowStopper report`; `--fail-on confirmed:high` support (calls B's exit-code helper). Helpful `--help` text; non-zero exit codes on errors (distinct from the CI-gate code `2`).

**P5-A3 · Containers**
- `Dockerfile` (python:3.11-slim, non-root user), `docker-compose.yml` with a `FlowStopper` service, read-only mount of the source (`${TARGET_SRC}:/src:ro`), env `ALLOWED_HOSTS`, joining the target's compose network (`${TARGET_NETWORK}`), and a `make demo` that starts Mock A and scans it end-to-end with no dependency on the organisers' app.

### Dev B

**P5-B1 · HTML report (`report/html.py` + Jinja2)** — single self-contained page + per-issue detail pages
- Summary header (counts by label, scan time, targets), prioritised table (Confirmed first, then risk), issue detail view showing: label badge, risk/CVSS, **URL + method + parameter + payload + proof**, **file:line + highlighted snippet**, CWE + OWASP link, evidence, "why these were linked" (B-3), fix (B-4), and the `curl` reproduction. A collapsed "Suppressed (safe / unreachable)" section.
- **All dynamic text is HTML-escaped (R7)**; test with a finding whose evidence contains `<script>`.
- Plain CSS, no external assets (must work offline).

**P5-B2 · SARIF 2.1.0 export + CI gate (B-6) (`report/sarif.py`)**
- One `run` with `tool.driver.name = "FlowStopper"`, a `rules` entry per CWE, one `result` per issue: `ruleId`, `level` (critical/high → `error`, medium → `warning`, else `note`), `message`, `locations` (physicalLocation: relative `artifactLocation.uri`, `region.startLine/endLine`, snippet) for code, and for runtime evidence use `webRequest`/`webResponse` objects (fallback: `properties`). `partialFingerprints` = issue ID; `properties` = `{label, risk, cwe, owasp, url, param}`.
- `scan --fail-on confirmed:high` exits with code `2` if any Confirmed issue has severity ≥ high.
- Tests: structural validation of required SARIF keys; CI gate exit-code test.

**P5-B3 · Fix suggestions (B-4) (`report/fixes.py`)**
- A plain-English template per CWE, filled with the issue's function, parameter and file. Each suggestion has: what is wrong (one sentence), the minimal fix (one short code-style example specific to the pattern: parameterised query, `shlex`/list-form subprocess, `secure_filename` + base-directory check, allow-list redirect, escaping/autoescape, environment variable/secret manager), and one prevention tip. Templated and deterministic; no external services.

**Exit criteria (Phase 5):** from a clean shell, `FlowStopper scan ...` and `docker compose up` both work; API endpoints return correct data; HTML and SARIF produced; all tests green.

---

## PHASE 6 — Generalisation round (14:00–15:00)

| Task | Owner | Description |
|---|---|---|
| P6-J1 | A+B | **Unseal Mock B.** Run the full pipeline against it, run `FlowStopper eval` with its key. Record metrics as `docs/metrics/mock_b_first_run.json` **before** changing anything. |
| P6-J2 | A+B | Triage Mock B failures. Fix only **generic behaviours** (new framework idioms, missing sanitiser patterns, param-name normalisation, correlation edge cases). **No app-specific constants (R6).** |
| P6-J3 | A+B | Re-run the real app and Mock A after every change; **no regression** allowed on any target metric. |
| P6-B1 | B | *Optional (B-5):* `FlowStopper diff <scanA> <scanB>` → new / fixed / still-open issues by `Issue.id`; shown in the report if two scans exist. Only if all of the above is done. |

**Exit criteria:** unseen-app correct-link rate recorded and ≥ 40% (stretch ≥ 65%); real-app metrics unchanged or better.

---

## PHASE 7 — Release (15:00–16:00)

| Task | Owner | Description |
|---|---|---|
| P7-A1 | A | `README.md` (outline in Appendix E): setup, one-command demo, usage, safety notes, architecture summary, metrics table, how correlation works. Must be followable by a judge with Docker. |
| P7-A2 | A | `THIRD_PARTY.md` final: every dependency with exact version and licence (verify on PyPI), AI-assisted development statement, "own work" section (all of `FlowStopper/`, `apps/mock_a`, `apps/mock_b`). |
| P7-B1 | B | `docs/ARCHITECTURE.md` (diagram of the pipeline + correlation algorithm with the scoring formula), `docs/LIMITATIONS.md` (honest list: static name-resolution limits, no dynamic dispatch, blind injections not detected, etc.), final metrics tables in `docs/metrics/`. |
| P7-J1 | A+B | **Clean-clone test:** fresh machine/folder → clone → follow README exactly → `docker compose up` → scan the organisers' app → open the report. Fix anything that fails. Run `make check`. |
| P7-J2 | A+B | Generate `requirements.lock`; tag `v1.0`; **freeze at 15:45**, buffer for the last 15 minutes. Verify no organisers' source/key is in git history (`git log --stat` + grep). |

---

## 10. Cut list if the schedule slips (in this order)

1. P6-B1 (scan diff).
2. P5-B3 (fix suggestions) → shrink to one generic sentence per CWE.
3. P4-B4 (auto-verify).
4. P2-A5 (template scan) → keep only Python-side XSS detection.
5. Second-order XSS pass, Django route extractor depth (keep Flask + FastAPI first).

**Never cut:** FR-1 to FR-10, scope guard (R3), correlator ambiguity handling, idempotency, B-2 suppression, evaluation harness, README, `THIRD_PARTY.md`.

---

# APPENDICES

## Appendix A — Time budget per pipeline stage (target < 5 minutes on the test app)

| Stage | Budget |
|---|---|
| SAST (index, routes, taint, secrets) | ≤ 30 s |
| DAST (concurrency 20, time budget) | ≤ 3 min 30 s |
| Correlation + auto-verify | ≤ 30 s |
| Report generation | ≤ 5 s |

Record the real timings per stage in `scan_meta.json`.

## Appendix B — DAST check catalogue (the only payloads the tool may send — R4)

Notation: `RND` = random 6–8 character lowercase token from the per-scan seed; `A`,`B` = small random integers (e.g. 13 and 17) from the seed.

**SQL injection (CWE-89)** — for every string and numeric param
1. *Error-based:* append `'`, `"`, `')`, `'"` to the original value. Match any of: `sqlite3.OperationalError`, `SQLITE_ERROR`, `unrecognized token`, `near "`, `syntax error at or near`, `You have an error in your SQL syntax`, `psycopg2`, `pymysql`, `ORA-\d{5}`, `SQLSTATE`, `Unclosed quotation mark`, `OperationalError`, `ProgrammingError`. Must **not** appear in the baseline. Proof = `error`.
2. *Boolean differential:* string context `ORIG' AND 'RND'='RND` (true) vs `ORIG' AND 'RND'='RND2` (false); numeric context `ORIG AND 1=1` vs `ORIG AND 1=2`; also `ORIG' OR 'RND'='RND`. True-variant ≈ baseline **and** false-variant differs (status/length/hash after normalisation), consistent across two repeats. Proof = `differential`.
3. No time-based payloads by default (optional flag, off).
- Confidence: `error` 0.9; `differential` 0.8; both 0.95.

**Cross-site scripting (CWE-79)**
- Send `sdcRND<"'>` (and for attribute-context probes `sdcRND"onmouseover=x`). Response must be `Content-Type: text/html`. Report when the raw characters `<` and `"` or `'` are reflected **unencoded** after the canary. Classify context (HTML body / attribute / script) in `evidence`. Proof = `echo`.
- No JavaScript is executed by the scanner.

**Command injection (CWE-78)**
- Separators: `;`, `|`, `&&`, `$(...)`, backticks, newline. Payload example: `;echo sdcRND$((A*B))X`. Report when the response contains `sdcRND<A*B>X` (the evaluated result) — a pure reflection can only contain the unevaluated `$((A*B))`. Proof = `marker`.

**Path traversal (CWE-22)**
- `../../../../../../etc/passwd`, `....//....//....//etc/passwd`, `..%2f..%2f..%2f..%2fetc%2fpasswd`, absolute `/etc/passwd`. Report when the response matches `root:[x*!]*:0:0:`. Proof = `file`. Read-only, benign file only.

**Open redirect (CWE-601)**
- Values: `//sdcRND.invalid/`, `https://sdcRND.invalid/`, `/\sdcRND.invalid`, `///sdcRND.invalid`. **Do not follow redirects.** Report when the status is 3xx and the `Location` header's host is `sdcRND.invalid`. (`.invalid` is a reserved TLD, so no real domain is contacted.) Proof = `redirect`.

**Prioritised parameter names** (tested first, not exclusively): `next, url, redirect, return, returnTo, continue, dest, target, goto, file, path, filename, name, page, template, id, q, query, search, cmd, host, ip`.

**Passive checks:** see P2-B2. **Method policy:** see P2-B4.

## Appendix C — Answer-key schema (our own format; the organisers' key is converted into this)

```json
{
  "app": "shoplite-a",
  "language": "python",
  "vulns": [
    {"id": "V01", "cwe": 89, "kind": "pair",
     "code":    {"file": "blueprints/orders.py", "line_start": 80, "line_end": 95},
     "runtime": {"method": "GET", "path": "/api/orders", "param": "id"}},
    {"id": "V21", "cwe": 798, "kind": "code_only",
     "code": {"file": "config.py", "line_start": 7, "line_end": 7}},
    {"id": "V31", "cwe": 693, "kind": "runtime_only",
     "runtime": {"method": "GET", "path": "*", "param": null}}
  ],
  "decoys": [
    {"id": "D01", "cwe": 89, "file": "blueprints/products.py",
     "line_start": 40, "line_end": 46, "reason": "parameterised query"}
  ]
}
```

**Matching rules (`evalkit/metrics.py`):**
- *Code match:* same file (compare normalised relative paths), CWE in the same family, and the finding's line range overlaps `[line_start − 3, line_end + 3]`.
- *Runtime match:* CWE in the same family, method equal (or key method omitted), concrete path matches the key's path template (treat `<...>`/`{...}` as wildcards; `"*"` matches host-wide findings), and param equal when the key specifies one.
- *Correct link:* a pair's code match and runtime match live in the **same Confirmed issue**.
- *Wrong link:* a Confirmed issue whose code match and runtime match refer to **different** planted IDs (or one to a decoy).
- *False alarm:* a reported (non-suppressed) issue whose code location overlaps a decoy.
- Also report informational "unplanted" findings (not penalised by the PRD but useful for triage).

## Appendix D — Mock A specification (Flask shop, our own work)

Structure: `app.py` (factory), `config.py`, `db.py` (query helpers), `blueprints/{orders,products,users,files,admin}.py`, `utils/{shell,payments}.py`, `templates/`.

| ID | Kind | CWE | Where / how |
|---|---|---|---|
| M01 | pair | 89 | `GET /api/orders?id=` — handler calls `db.fetch_order(id)` in another module that builds SQL with an f-string (**cross-file**) |
| M02 | pair | 89 | `POST /login` form `username` concatenated into SQL |
| M03 | pair | 79 | `GET /search?q=` returns an f-string HTML page |
| M04 | pair | 79 | `GET /product/<id>?note=` rendered with `|safe` in a template |
| M05 | pair | 78 | `GET /api/ping?host=` → helper in `utils/shell.py` using `os.system` |
| M06 | pair | 78 | `POST /admin/backup` `name` → `subprocess.run(..., shell=True)` |
| M07 | pair | 22 | `GET /download?file=` → `open(os.path.join(BASE, file))` |
| M08 | pair | 22 | `GET /docs/<path:name>` → `send_file(...)` |
| M09 | pair | 601 | `GET /go?next=` → `redirect(next)` |
| M10 | pair | 601 | `POST /login?next=` post-login redirect |
| C01 | code_only | 798 | hard-coded `SECRET_KEY` in `config.py` |
| C02 | code_only | 798 | hard-coded DB password in `config.py` |
| C03 | code_only | 798 | hard-coded API token in `utils/payments.py` |
| R01 | runtime_only | 693/1021 | no CSP / `X-Content-Type-Options` / clickjacking protection (host-wide) |
| R02 | runtime_only | 1004/1275 | session cookie without `HttpOnly` / `SameSite` |
| R03 | runtime_only | 209/200 | `GET /api/crash` returns a verbose traceback; `Server` banner exposed |
| D01 | decoy | 89 | `GET /api/products?id=` parameterised query |
| D02 | decoy | 89 | SQL built with an `int()`-cast value |
| D03 | decoy | 79 | `html.escape(q)` before returning HTML |
| D04 | decoy | 78 | `subprocess.run([...], shell=False)` with user value as a list element |
| D05 | decoy | 22 | `secure_filename` + `send_from_directory` |
| D06 | decoy | 601 | redirect target checked against an allow-list |
| D07 | decoy | 79 | `jsonify({"echo": q})` (JSON response) |
| D08 | decoy | 798 | secret read from `os.environ` |

Answer key: `apps/mock_a/answer_key.json` (Appendix C). Mock A must run under Docker Compose and via `flask run`.

## Appendix E — README outline (judges follow this)

1. What it does (3 sentences) + one screenshot of the report.
2. **Quick start** — `docker compose up` / `make demo` (exact commands), expected output.
3. Scanning the organisers' app (compose network, `ALLOWED_HOSTS`, `--target`, `--source`).
4. **Safety:** scope guard, harmless payloads, parse-only SAST, what is never sent.
5. How it works: SAST (routes, call graph, taint, secrets), DAST (seeded discovery, checks, verification), **correlation** (gate → score → assignment → ambiguity rule → labels → risk), formula table.
6. Output formats: HTML report, API, CLI, SARIF, CI gate.
7. Results: metrics table (real app, Mock A, Mock B) with before/after history.
8. **Third-party components and AI usage** (link to `THIRD_PARTY.md`).
9. Limitations (link to `docs/LIMITATIONS.md`).

## Appendix F — Testing standards

- **Unit tests** for every module; **golden-file tests** for route extraction, taint findings, correlator output (fixtures).
- **Regression test** `tests/test_regression_mock_a.py`: runs the pipeline on Mock A and asserts metric floors (code detection ≥ 0.85, runtime detection ≥ 0.80, correct links ≥ 0.80, wrong links ≤ 0.05, false alarms ≤ 0.10).
- **Idempotency test:** scan twice, same issue IDs/count.
- **Scope-guard tests**, **HTML-escape test**, **no-overfit test (R6)**, **SARIF structure test**, **CI-gate exit-code test**.
- Lint/type hygiene: `ruff` clean; type hints on all public functions.

## Appendix G — Definition of done (whole project)

- [ ] FR-1 … FR-10 implemented and demonstrated on the real app.
- [ ] All six vulnerability types covered; passive runtime findings present.
- [ ] B-1, B-2, B-3, B-4, B-6 implemented (B-5 only if time).
- [ ] Targets in section 4 measured and recorded for the real app and Mock B.
- [ ] `make check` green; clean-clone test passed; one-command run works.
- [ ] README, `THIRD_PARTY.md`, `docs/ARCHITECTURE.md`, `docs/LIMITATIONS.md` complete.
- [ ] No organisers' source or key in git history (R5); no app-specific constants in `FlowStopper/` (R6); scope guard active (R3).
