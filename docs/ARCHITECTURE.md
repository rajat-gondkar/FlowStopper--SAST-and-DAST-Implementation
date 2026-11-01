# Architecture

Final for v1.0. Stage boundaries are the pydantic models in `FlowStopper/models.py` (frozen at
`contract-v1`). Every constant below is the value in the code (`FlowStopper/correlate/config.py`,
`FlowStopper/sast/config.py`, `FlowStopper/dast/config.py`).

## Pipeline

```
source folder ─► SAST ─────────────────────────────────────────────► routes + code findings ─┐
   file index → route extraction → call graph → taint (intra + summaries) → secrets → templates │
                                                                                               ├─► correlate ─► auto-verify ─► SQLite ─► HTML / SARIF / Markdown / API / CLI
running app ─► DAST ────────────────────────────────────────────────────► runtime findings ─┘
   scope-guarded client → login (optional) → discovery (route seeds + crawl) → passive → active checks → verify
```

| Stage | Entry point | Owner |
|---|---|---|
| SAST | `FlowStopper/sast/runner.py::run_sast(source_root, config) -> SastResult` | A |
| DAST | `FlowStopper/dast/runner.py::run_dast(target_url, routes, config) -> DastResult` (async) | B |
| Correlate | `FlowStopper/correlate/engine.py::correlate(sast, dast, routes, config) -> list[Issue]` | B |
| Auto-verify | `FlowStopper/correlate/autoverify.py::auto_verify(issues, routes, target_url, dast_config, ...)` | B |
| Store | `FlowStopper/storage.py::Storage` (SQLite, upsert on `issues.id`) | B |
| Pipeline | `FlowStopper/pipeline.py::run_pipeline(...)` and `FlowStopper scan` | A |
| Reports | `FlowStopper/report/{html,sarif,markdown,fixes,gate}.py` | B |
| API | `FlowStopper/api.py` (FastAPI) and `FlowStopper serve` | A |

## SAST (parse only, rule R7)

1. **Index** (`sast/index.py`):
   - finds `*.py` files, skipping vendor folders and files over 1 MB;
   - parses each with `ast`, and logs and skips any file with a syntax error;
   - builds a symbol table of modules, functions, methods and classes, with qualified names and line spans;
   - resolves imports: `import`, `from … import … as`, relative imports, `__init__` re-exports and star imports.

   A name that cannot be resolved statically becomes `None`. It is never guessed.
2. **Routes** (`sast/routes/`): one `Route` per (method, path), with an anchored `path_regex`, the parameters and their locations, and `auth_required`.
   - **Flask:** decorators, `add_url_rule`, `MethodView`, blueprint prefixes from both places they can be set, nested blueprints, factory functions, and routes registered on a function parameter (`def init(app): @app.route`).
   - **FastAPI:** `APIRouter`, `include_router` prefixes, and signature parameters including pydantic bodies.
   - **Django:** `path`, `re_path`, `include` and class-based views. This support is shallower.
3. **Call graph** (`sast/callgraph.py`):
   - name-resolved edges between project functions;
   - each route's `reachable_functions` is found by a cycle-safe breadth-first search from the handler, to depth 4.
4. **Taint** (`sast/taint/`):
   - **Inside each function:** a walk in statement order, where each value is a set of taint labels plus a "constant string" flag, so parameterised SQL is recognised as safe. Branches are joined by union, and loops run one extra iteration.
   - **Across functions:** a summary per function (parameter → return value, parameter → sink), iterated to a fixpoint (at most 10 passes) and applied at each call site.
   - **What a finding carries:** it is emitted at the **sink**, with `call_chain`, `source_param`, `source_kind` and `entry_routes`, so the handler a flow actually starts in comes first.
   - **Sources, sinks and sanitisers** follow the spec tables. Sinks also record which argument matters.
5. **Secrets** (`sast/secrets.py`):
   - name patterns and literal values in Python and config files, plus known credential prefixes and DSNs;
   - Shannon entropy only raises confidence;
   - values read from the environment are excluded.
6. **Templates** (`sast/templates.py`): `|safe`, `{% autoescape false %}` and `Markup`. These are linked back to `render_template` / `TemplateResponse` call sites, so the XSS finding sits at the Python sink.
7. **Suppression** (`sast/suppress.py`, B-2): findings are kept but marked `suppressed`, with a reason:
   - `sanitized:<name>` when a sanitiser or guard was seen;
   - `safe:sql-parameterised` or `safe:subprocess-list-no-shell` for safe forms of a sink;
   - `unreachable` when no route reaches the function. This one is never applied to CWE-798, and it is switched off when the project looks names up at run time.

## DAST

**Order and time budget.** Inside the DAST stage the order is fixed:
1. scope-check the target;
2. log in, if configured;
3. discover endpoints, seeded from the route map first, then from a crawl;
4. run the host-wide passive checks **once**;
5. run the active checks for each (endpoint, injectable parameter): route-map endpoints first, and Appendix B's priority parameter names first.

The `--time-budget` (default 240 s) governs **only the active phase**. Discovery and the passive pass run first and cannot be interrupted. When the budget runs out, the runner stops scheduling active checks and keeps everything already collected. It then sets `stats.truncated = true`, so total DAST time can exceed the budget by design (B-05).

**Checks.** All payloads come from spec Appendix B only (R4):

| Check | Proof |
|---|---|
| SQLi | a database error string (`error`), a true/false response difference (`differential`), or a repeatable 2xx/3xx → 5xx change on the quote payload (`status`) |
| XSS | the canary reflected unencoded in an HTML response (`echo`), including one probe to an unknown path |
| Command injection | the *evaluated* arithmetic marker (`marker`), or a repeatable response difference (`differential`) |
| Path traversal | `root:x:0:0:` in the response, raw or after HTML-entity decoding (`file`) |
| Open redirect | a 3xx whose `Location` host is the `.invalid` canary (`redirect`) |
| Passive | security headers, cookie flags, permissive CORS, verbose errors (also checked on GET routes that take no parameters), version banners, directory listing |

**Verify** (`dast/verify.py`): every active hit is re-tested with a second canary and a benign control. It is reported only if the second canary reproduces and the control does not. Hits for the same `(cwe, route|path, param)` collapse into one finding.

## Correlation (the judged core)

For a runtime finding `r` and a code finding `c` with `same_family(r.cwe, c.cwe)`, where `c` is not suppressed:

1. **Route gate (hard):** `route_match` is
   - `1.0` if `r.route_id ∈ c.taint.entry_routes` (the flow starts at that route's handler);
   - `0.9` if `c`'s file and line are inside the route handler's span;
   - `0.8` if `c.code.function ∈ route.reachable_functions`;
   - otherwise `0`, and the pair is **not a candidate**.
2. **Other signals:**
   - `param_match`: 1.0 when the normalised names are equal, 0.5 when the SAST parameter is unknown, 0.0 when both are known and different;
   - `method_match`: 1.0 when the methods agree, else 0;
   - `specificity`: 1.0 for a full taint chain, else 0.5.
3. **Score:** `0.50·route_match + 0.35·param_match + 0.10·method_match + 0.05·specificity`.
4. **Assignment:** edges are sorted by score and matched greedily **one-to-one**, accepting edges with a score of at least `link_min` = 0.70.
   - **Ambiguity rule:** if the best and second-best candidates differ by less than `ambiguity_margin` = 0.10, and the parameter does not separate them, **nothing is linked**. The pair becomes Code-only + Runtime-only, with an `ambiguity_penalty` reason.
5. **Labels:** a linked pair is Confirmed, an unlinked code finding is Code-only, and an unlinked runtime finding is Runtime-only. Every link carries its `reasons` with weights: `same_cwe`, the route kind, `same_param`, `same_method` (B-3).
6. **Auto-verify (B-1):**
   - **Eligible:** a Code-only issue with CWE 89, 78, 22, 601 or 79, plus a known entry route and source parameter.
   - **Probe:** it gets one targeted probe with the matching check, using the same login and scope as the DAST run.
   - **On success:** the issue is upgraded to Confirmed (`verified_by = "auto-verify"`). This step runs last, within its own budget (default 60 s).
7. **Risk:** `clamp(cvss × exploitability_factor, 0, 10)`, with factors ×0.85 for auth, ×0.9 for differential-only proof, ×0.6 for Code-only, and ×0.9 for low-confidence Runtime-only (below 0.7).
   - **Sort order:** Confirmed first, then risk (highest first), severity, CWE, id. The order is deterministic.
   - **CVSS** comes from the vector in `cwe.py`.
8. **Fix:** every issue gets a templated fix suggestion per CWE family (`report/fixes.py`, B-4).

Design principle: **prefer a missed link over a wrong one**. Wrong links are 0 on both
mock apps.

## Storage, API and reports

- **SQLite** (`storage.py`) has four tables: `scans`, `findings`, `issues` (upserted by issue id, so a re-scan updates the same issue) and `scan_issues` (what each scan reported).
  - A scan's row records its configuration (credentials redacted) and the folder its files were written to.
  - The API uses that folder to show a CLI-run scan's metadata and scores.
- **Reports:**
  - `report.html` is one self-contained page with no scripts. Jinja2 autoescape is always on, and hard-coded secrets are masked.
  - `issues.sarif` is SARIF 2.1.0.
  - `findings.md` is a Markdown findings list.
- **CI gate:** `--fail-on <label>:<severity>` exits 2.
- **Scores:**
  - `scan --key` writes `evaluation.json`, which fills the report's Evaluation tab.
  - `--unseen-from` fills its "Unseen app" row from a recorded first run.

## Determinism

- Sorted outputs.
- Stable ids from `ids.py`: sha1 for findings and sha256[:16] for issues, with no payload and no timestamp in either.
- Seeded canaries, with the seed recorded in `scan_meta.json`.
- Relative POSIX paths and LF line endings.

Two scans of identical input produce identical issue ids and counts. Timings and timestamps live
only in `scan_meta.json` and the store.
