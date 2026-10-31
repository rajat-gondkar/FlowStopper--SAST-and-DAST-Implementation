# Person 1 — Dev A task list (code-side + delivery surface)

You are **Person 1 / Dev A**. You did the repository initialisation, so most of Phase 0 is
already done (see the checkmarks). Work top to bottom. Every task ends with `make check` green
and a one-line update in [`PROGRESS.md`](PROGRESS.md). Branch per task `a/<task-id>`, merge to
`main` after check passes. **Never edit Dev B's files** (see [`PLAN.md`](PLAN.md) ownership);
**do not open `apps/mock_b/` until Phase 6.** **You (a human) perform all `git push`es and own the
GitHub remote — AI agents commit locally only and never push.**

Your ownership: `FlowStopper/sast/**`, `apps/mock_a/**`, `FlowStopper/cli.py`,
`FlowStopper/api.py`, `FlowStopper/pipeline.py`, and the repo scaffold/docs.

---

## Phase 0 — foundations (done during init)

- [x] **P0-J1** Scaffold: `pyproject.toml`, package layout, `Makefile` (`check/test/lint/fmt/demo`),
  ruff config, `.gitignore` (ignores `target_src/`, `keys/`, `*.key.json`, `*.db`, `__pycache__/`).
- [x] **P0-J2** `FlowStopper/models.py` exactly per spec §7; JSON Schemas exported to
  `docs/schemas/` by `scripts/export_schemas.py`. (Shared — written with B / signed off at freeze.)
- [x] **P0-J6** `THIRD_PARTY.md` skeleton + `docs/PROGRESS.md`.
- [x] Stable-ID helpers `FlowStopper/ids.py` (shared) and the fixtures generator.
- [ ] **P0-J5 (you + B, local only)** Read the organisers' app and answer key. Record in the
  **git-ignored** `docs/target_notes.local.md` (copy `docs/target_notes.template.md`): framework,
  route style, helper layout, how it starts, planted-vuln locations, key format. Do this as soon
  as the organisers release the app. **Nothing from this file may leak into `FlowStopper/` (R6).**
- [ ] **Confirm `contract-v1`** with B, then Person 1 tags it (`git tag contract-v1`).

## Phase 1 — code-side foundations (1:00–4:00)

- [ ] **P1-A1 · `sast/index.py`** — file discovery (skip `venv/.venv/site-packages/__pycache__/.git/node_modules`,
  skip >1 MB), `ast.parse` tolerating syntax errors (log + skip), project symbol table
  (modules/functions/methods/classes with **qualified names**, file, `line_start/end`, params,
  decorators), import resolution (`import`, `from..import..as`, relative, `__init__` re-exports),
  `resolve_call(node, module_ctx) -> Optional[qualname]`. **Never import/exec target code (R7).**
- [ ] **P1-A2 · `sast/routes/`** — Flask (`@app.route`/`@bp.route`/`@app.get…`, `add_url_rule`,
  `MethodView`, blueprint prefixes incl. `register_blueprint(url_prefix=)`, nested blueprints,
  `create_app`), FastAPI (`@app.get…`, `APIRouter(prefix=)`, `include_router(prefix=)`, params
  from signatures + pydantic models), Django (`urlpatterns`, `path/re_path/include`, CBVs).
  Emit one `Route` per (method, path); build anchored `path_regex`; read params with locations;
  set `auth_required` from recognised decorators. `resolver.py` holds template→regex + prefixing.
- [ ] **P1-A3 · `sast/callgraph.py`** — static name-resolved call edges; per route
  `reachable_functions` = BFS from handler, depth ≤ 4, cycle-safe; ignore dynamic calls.
- [ ] **P1-A4 · `apps/mock_a/`** — Flask shop, ~25 routes, blueprints w/ prefixes, helpers in
  separate modules, JSON + form bodies, Jinja templates. Plant the bugs/decoys in spec Appendix D
  and write `apps/mock_a/answer_key.json` (our schema, validate with `make validate-key
  KEY=apps/mock_a/answer_key.json`). Runs via `docker compose -f apps/mock_a/docker-compose.yml up`
  **and** `flask run`. AI-generate fast, then **manually verify each planted bug fires**.
- **Exit (A):** `FlowStopper sast <path>` writes `routes.json` for Mock A and the real app; a unit
  test per route style; a call-graph test shows a handler reaching a helper in another file.

## Phase 2 — taint & secrets (4:00–8:00)

- [ ] **P2-A1 · `sast/taint/engine.py`** — intraprocedural taint: taint-label sets + `is_constant_string`
  flag; statement-order walk with `env`; handle assignments/unpacking/augmented, f-strings, `+`,
  `%`, `.format`, `.join`, slicing/subscript/attr, containers, comprehensions, str propagators,
  `return`; branch join (union) for if/try/loops (one extra loop iteration); unknown calls
  propagate arg→result unless sanitiser.
- [ ] **P2-A2 · `sast/taint/summaries.py`** — per-function summaries (`param_i→return`,
  `param_i→sink`), fixpoint over the call graph (cap 10, recursion-safe); apply callee summaries at
  call sites; emit finding **at the sink** with `call_chain`; seed from request sources; record
  `taint.source_param/source_kind/entry_routes` (prefer handler-originated over mere reachability).
  This is the key input to correlation — get `source_param` and `entry_routes` right.
- [ ] **P2-A3 · `sources.py` / `sinks.py` / `sanitizers.py`** — exactly the tables in spec §P2-A3,
  including path-sensitive-lite guard recognition; record guards in `taint.sanitizers_seen`.
- [ ] **P2-A4 · `sast/secrets.py`** (CWE-798) — name-pattern + value-literal detection across
  `.py/.env/.ini/.cfg/.yaml/.json/.toml/Dockerfile`/compose; credential prefixes; `==` comparisons;
  `SECRET_KEY`/`jwt.encode`/DSN; exclude `os.environ`/placeholders; entropy boosts confidence.
- [ ] **P2-A5 · `sast/templates.py`** — Jinja tokeniser for `{{ var|safe }}`, `autoescape false`,
  `Markup`; link to Python via `render_template("name.html", key=value)`. *(Cut item #4 if slipping.)*
- [ ] **P2-A6 · `sast/runner.py`** — orchestrate index→routes→callgraph→taint→secrets→templates→
  `SastResult`; stable IDs via `ids.py`; snippets ±1 line; severity from `cwe.py`; confidence
  (full taint 0.9 / partial 0.7 / name-only secret 0.7). CLI `FlowStopper sast <path>` writes
  `sast.json` + `routes.json` (fill in `sast/commands.py`).
- **Exit (A):** on Mock A, code detection ≥ 85% with ≤ 1 decoy false alarm; cross-file helper bugs
  found; every injection finding has `source_param` and `entry_routes`.

## Phase 3 — integration (8:00–9:30, joint)

- [ ] **P3-A1 · `pipeline.py` + `scan`** — `FlowStopper scan --source <dir> --target <url> [--out dir]`:
  SAST → DAST (seeded with routes) → `correlate` → `storage` → write `issues.json` and
  `scan_meta.json` (per-stage timings, seed, tool versions). Flesh out `scan_command`.
- [ ] **P3-J2 (joint)** Triage every miss/false alarm into buckets; co-write `docs/BACKLOG.md`.

## Phase 4 — SAST accuracy & B-2 (9:30–12:30)

- [ ] **P4-A1** Work the SAST backlog as **generic rules** (new source/sink/propagator patterns;
  new sanitiser/guard patterns for decoys). Re-run baseline after each batch; keep a before/after
  table in `docs/metrics/`.
- [ ] **P4-A2 · `sast/suppress.py` (B-2)** — set `suppressed=True` + reason for sanitised/guarded
  flows (`sanitized:<name>`), parameterised SQL / list-form subprocess (`safe:<pattern>`), and
  unreachable functions (`unreachable`; **never for CWE-798**). Kept in DB, shown collapsed, never
  in the main list, never counted as reported.
- [ ] **P4-A3** SAST perf: cache parsed ASTs per run; target SAST ≤ 30 s on the real app.

## Phase 5 — delivery surface (12:30–14:00)

- [ ] **P5-A1 · `api.py` (FastAPI)** — `POST /scans` (202, background task), `GET /scans/{id}`,
  `GET /issues?scan_id&label&cwe&min_risk&include_suppressed`, `GET /issues/{id}` (full FR-8),
  `GET /scans/{id}/report`, `GET /scans/{id}/sarif`, `GET /health`. Idempotent re-posts. Bind
  `127.0.0.1` by default.
- [ ] **P5-A2 · `cli.py` polish** — helpful `--help`, `--fail-on confirmed:high` (calls B's
  exit-code helper), distinct non-zero exit codes (CI gate is `2`).
- [ ] **P5-A3 · containers** — `Dockerfile` (python:3.11-slim, non-root), `docker-compose.yml`
  (FlowStopper service, read-only source mount `${TARGET_SRC}:/src:ro`, `ALLOWED_HOSTS`, join
  `${TARGET_NETWORK}`), and `make demo` that starts Mock A and scans it end-to-end with no
  dependency on the organisers' app. (A root Dockerfile/compose skeleton already exists; extend it.)
- **Exit (A):** from a clean shell `FlowStopper scan …` and `docker compose up` both work; API
  returns correct data.

## Phase 6 — generalisation (14:00–15:00, joint)

- [ ] **P6-J1/J2/J3** Unseal Mock B; run full pipeline + `eval`; record first-run metrics *before*
  changes; fix only **generic** behaviours (R6); re-run real app + Mock A after each change — no
  regression allowed.

## Phase 7 — release (15:00–16:00)

- [ ] **P7-A1 · `README.md` final** — spec Appendix E outline; followable by a judge with Docker.
- [ ] **P7-A2 · `THIRD_PARTY.md` final** — every dep exact version + licence verified on PyPI; AI
  statement; "own work" section.
- [ ] **P7-J1/J2 (joint)** Clean-clone test; `requirements.lock`; tag `v1.0`; freeze 15:45; verify
  no organiser source/key in git history.

---

### FR coverage you own
FR-1 (SAST finding fields), FR-4 (route map), FR-8 API half, FR-10 (CLI + API + README).
