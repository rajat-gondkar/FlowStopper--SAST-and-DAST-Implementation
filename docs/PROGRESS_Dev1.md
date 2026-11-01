# Progress — Dev A (Person 1)

Dev A's progress. One line per task when it lands. Status: `[x]` done, `[~]` in progress, `[ ]` not
started. Dev B tracks their own in [`PROGRESS_Dev2.md`](PROGRESS_Dev2.md). Full task text:
[`PERSON_1_DEV_A.md`](PERSON_1_DEV_A.md). Decisions: [`DECISIONS_Dev1.md`](DECISIONS_Dev1.md).

## Phase 0 — foundations (Dev A share)
- [x] P0-J1 scaffold (pyproject, Makefile, ruff, .gitignore) — `make check` green, line-length 120.
- [x] P0-J2 models.py + JSON schemas (shared with B) — exact §7, drift test.
- [x] P0-J4 fixtures (shared with B) — `scripts/build_fixtures.py`.
- [x] ids.py stable-ID helpers (shared) — sha1 findings / sha256[:16] issues; payload-free.
- [x] P0-J6 THIRD_PARTY.md + progress skeleton.
- [ ] P0-J5 target notes (local, git-ignored) — when organisers release the app.

## Phase 1 — code-side foundations (COMPLETE)
- [x] P1-A1 `sast/index.py` — parse-only discovery + qualified-name symbol table + import resolution
  + `resolve_call`; 18 tests (`tests/test_sast_index.py`). Decisions A-01, A-02.
- [x] P1-A2 `sast/routes/` — Flask (full) + FastAPI + Django (shallow) + `resolver.py`/`common.py`;
  one Route per (method, path), params with locations, `auth_required`. Decisions A-03, A-04.
- [x] P1-A3 `sast/callgraph.py` — name-resolved edges; per-route `reachable_functions` (BFS depth ≤ 4,
  cycle-safe); cross-file handler→helper test. `tests/test_sast_callgraph.py`.
- [x] P1-A4 `apps/mock_a/` — Flask shop, 25 routes, Appendix-D bugs/decoys + `answer_key.json`
  (validates: 10 pairs + 3 code-only + 3 runtime-only + 8 decoys); every bug manually verified to
  fire, every decoy safe. `tests/test_mock_a.py`. Decision A-05.
- [x] `sast/runner.py` + `sast/commands.py` — `FlowStopper sast <path>` writes `routes.json`
  (Mock A 25 routes, bench app 12) + `sast.json` (findings arrive in Phase 2).
- **Exit (A) met:** correct `routes.json` for Mock A and the bench app; a unit test per route style;
  a call-graph test shows a handler reaching a helper in another file. `make check` green (146 tests).

## Phase 2 — taint & secrets (COMPLETE)
- [x] P2-A3 `sast/taint/{sources,sinks,sanitizers}.py` — the five spec sink rows with the argument
  that matters, Flask/Django/FastAPI sources, per-CWE sanitisers and the path-sensitive-lite guards.
  Decisions A-07, A-08, A-09, A-14, A-15, A-20, A-24.
- [x] P2-A1 `sast/taint/engine.py` — statement-order intraprocedural walk, per-CWE clearance, branch
  and loop joins, guard recognition. Decisions A-06, A-10, A-11, A-17.
- [x] P2-A2 `sast/taint/summaries.py` — parametric summaries to a fixpoint + the handler-rooted
  driver producing `source_param` / `entry_routes` / `call_chain`. Decisions A-12, A-13, A-16, A-22, A-23.
- [x] P2-A4 `sast/secrets.py` — CWE-798 name/prefix/comparison/DSN/config detectors, entropy boost,
  env-default exclusion; files selected by extension only (R6). Decision A-21.
- [x] P2-A5 `sast/templates.py` — `|safe`, `autoescape false`, `Markup(...)`; template resolved by
  path suffix and turned into the per-keyword CWE-79 sink. Decisions A-18, A-20.
- [x] P2-A6 `sast/runner.py` — index → routes → call graph → templates → taint → secrets →
  `SastResult`; stable ids, catalogue severities, snippets, counts-only stats. Decisions A-25, A-26.
- **Exit (A) met:** Mock A code detection **13/13** planted code vulns (floor 12), **0** decoy false
  alarms (ceiling 1), cross-file M01/M02/M05 all matched, every injection finding carrying
  `taint.source_param` and real `entry_routes`. `make check` green (229 tests).

## Phase 3+ — [x] pipeline/scan (P3-A1) · [x] API/CLI/containers (P5) · [ ] README/THIRD_PARTY (P7).
- [x] P3-A1 `pipeline.py` `run_pipeline` + `FlowStopper scan` — SAST → DAST (seeded with routes) →
  correlate → SQLite → `issues.json` + `scan_meta.json`. **Mock A live: 25 routes, 14 SAST + 19 DAST
  findings (634 requests, DAST 2.1 s, total 2.1 s), 21 issues (7 confirmed, 6 code-only, 8 runtime-only;
  1 suppressed); eval code 13/13, runtime 10/13, correct links 7/10, wrong links 0/7, false alarms
  1/21**, identical to the manual run; second scan gives identical issue ids. Decisions A-30..A-35.
  `make check` green (383 passed, 1 skipped).
- [x] P3-J1 baselines (run by Dev A) — `docs/metrics/baseline_mock_a.json` (code 13/13, runtime 10/13,
  links 7/10, wrong 0/7, false alarms 1/21) and `docs/metrics/baseline_bench.json` (code 3/4, runtime
  1/3, links 0/2, wrong 0/0, false alarms 0/9). The spec's `baseline.json` waits for the organisers'
  app (A-36). Triage handed to Dev B for `docs/BACKLOG.md` (P3-J2).

## Phase 4 (Dev A) — 2026-10-31, batch 1 (measured in `docs/metrics/phase4_dev_a.md`)
- [x] BACKLOG 12 — Mock A binds `HOST` (default `127.0.0.1`); Dockerfile/compose set `HOST=0.0.0.0` (A-37).
- [x] BACKLOG 9 — a response whose content type is set to JSON/plain text right after construction is
  safe (A-38); bench `app/app.py:185` CWE-79 gone, bench false alarms 0/9 → 0/8.
- [x] BACKLOG 11 splat — `render_template(t, **ctx)` resolves a single-assignment dict / `dict(...)` (A-39).
- [x] BACKLOG 11 `_is_abort` — only resolved abort/exit callees end a block (A-40).
- [x] BACKLOG 11 fixpoint cap — `compute_summaries` logs a WARNING when it hits the cap (A-41).
- [x] BACKLOG 11 receiver matching — checked, 0 path-access / `.raw`/`.extra` findings on both
  targets; left unchanged (A-42).
- [x] BACKLOG 10 — secrets in test code still reported, confidence capped at 0.5 (A-43).
- Batch-1 eval: Mock A 13/13 · 10/13 · 7/10 · 0/7 · 1/21 (unchanged); bench 3/4 · 1/3 · 0/2 · 0/0 ·
  0/8. `make check` green (427 passed, 1 skipped).

## Phase 4 (Dev A) — 2026-10-31, batch 2 (measured in `docs/metrics/phase4_dev_a.md`)
- [x] BACKLOG 8 (SAST half) — `request.url/path/full_path/base_url` are unnamed path sources (A-44);
  the `render_template_string` template source is a CWE-79 sink (A-45); request hooks such as
  `@app.errorhandler` are walked as code-only entry points (A-46). Bench VF02 now detected.
- [x] P4-A2 / BACKLOG 11 B-2 noise cut — `sast/suppress.py`: `sanitized:<names>`,
  `safe:sql-parameterised`, `safe:subprocess-*`, conservative `unreachable` (never CWE-798); a live
  finding drops suppressed duplicates at its site (A-47, A-48, A-49). New `SastResult.stats` ints:
  `reported_findings`, `suppressed_findings`, `suppressed_sanitized`, `suppressed_safe`,
  `suppressed_unreachable`, `request_hooks`, `unreachable_functions`.
- Batch-2 eval: Mock A 13/13 · 10/13 · 7/10 · 0/7 · 1/21 (unchanged, suppressed issues 1 → 5); bench
  4/4 · 1/3 · 0/2 · 0/0 · 0/9. `make check` green (455 passed, 1 skipped).

## Phase 4 (Dev A) — 2026-10-31, final (measured in `docs/metrics/phase4_dev_a.md`)
- [x] P4-A1 generic-rule backlog — before/after per batch in `docs/metrics/phase4_dev_a.md`; final
  run in `out/p4a_mock_a` / `out/p4a_bench` (BACKLOG 8 SAST half, 9, 10, 11, 12 above).
- [x] P4-A2 B-2 noise cut — `sanitized:`/`safe:`/`unreachable` suppression (batch 2, A-47..A-49).
- [x] P4-A3 performance — each file parsed once (new test); median `run_sast` Mock A 0.025 s, bench
  0.038 s, pydantic proxy 1.8 s (was 3.1 s), synthetic 200-route project 2.4 s; no optimisation needed (A-50).
- [x] BACKLOG 6 — Mock A key gaps (`POST /login` password, `GET /download` debug-page XSS) kept as
  known extras, `answer_key.json` unchanged (A-51).
- [x] BACKLOG 8 (SAST half) · [x] BACKLOG 9 · [x] BACKLOG 10 · [x] BACKLOG 11 · [x] BACKLOG 12 — see batches 1-2.
- Final eval: Mock A 13/13 · 10/13 · 7/10 · 0/7 · 1/21 (5 suppressed); bench 4/4 · 1/3 · 0/2 · 0/0 ·
  0/9 (1 suppressed). DAST numbers unchanged (Dev B's changes not in this checkout).
- [x] Review fixes — `unreachable` is switched off when the project looks names up at run time
  (`getattr` with a computed name, `globals()`/`vars()`, `__dict__`, ...) (A-52); the content-type
  lookahead uses the last straight-line write, so a later `text/html` override keeps the XSS (A-53).
  SAST output on Mock A and the bench unchanged.

## Phase 5 (Dev A) — 2026-11-01
- [x] P5-A3 containers + `make demo` — Dockerfile (python:3.11-slim, uid 10001, writable `/app/data`
  and `/app/out`, templates verified in the image), `docker-compose.yml` (read-only `/src`,
  `ALLOWED_HOSTS`, named volume for the store) + `docker-compose.target.yml` for `${TARGET_NETWORK}`,
  `make demo` / `make demo-down` (A-58, A-59, A-60). Live: `make demo` exit 0 over network
  `mock_a_default`, 25 routes, 18 SAST + 21 DAST findings, 18 issues (confirmed 9, code-only 4,
  runtime-only 5; 8 suppressed), `Report: …/out/demo/report.html`.
- [x] P5-A1 `api.py` + `FlowStopper serve` — all seven endpoints, 202 + background `run_pipeline`
  with a reserved scan id, R3 and source-path checks (400), no credential echo (A-61, A-62). Live in
  compose: `/health` ok, `POST /scans` (`/src`, `http://mock_a:5050`) 202 → `completed` in ~2 s with
  counts confirmed 9 / code-only 4 / runtime-only 5, `/report` 200 `text/html`, `/sarif` 200
  `application/sarif+json`, `example.com` refused with 400; plain `docker compose up` (no env) serves
  `/health` and keeps the store across restarts. `tests/test_api.py` (18 tests, 1 live).
- [x] P5-A2 CLI polish — `scan --fail-on` (Dev B's gate, exit 2), `report.html`/`issues.sarif`/
  `findings.md` next to `issues.json`, `scan --db`, help text, exit codes 0/1/2/64 (A-63, A-64; A-31
  replaced). Live (host Mock A): `scan … --out out/p5a --fail-on confirmed:high` exit 2 with all five
  files; eval code 13/13, runtime 11/13, links 8/10, wrong 0/8, false alarms 0/19 (same as before the
  change); `issues.json` issue ids, labels, severities, risks and link scores identical to the pre-change
  scan, only `response_excerpt` of debug-traceback pages differs (Werkzeug frame ids per process).
  `make check` green (590 passed, 2 skipped: the two live Mock A tests).

## Phase 6 (generalisation, both devs' areas, run by Dev A) — 2026-11-01
- [x] Round 1 — FastAPI pydantic body params seeded as JSON containers so `body.field` taints as JSON
  param `field` (A-65). Docker, before → after: Mock B code 10/13 → 12/13, links 6/10 → 7/10, wrong
  0/6 → 0/7, false alarms 0/17 → 0/18; Mock A and bench unchanged (identical issue sets). Triage and
  deferred items in [`metrics/phase6.md`](metrics/phase6.md). `make check` 699 passed, 2 skipped.
- [x] Round 2 — Starlette `TemplateResponse(name=..., context=...)` keyword form (A-67, B04) and a
  verbose-error GET on param-less routes (A-68, B33, DAST on Dev B's behalf). Docker, before → after:
  Mock B code 12/13 → 13/13, runtime 10/14 → 11/14, links 7/10 → 8/10, wrong 0/7 → 0/8, false alarms
  0/18 → 0/19; Mock A and bench unchanged (identical issue sets). `make check` 707 passed, 2 skipped.

## Third-party benchmark (we45 Vulnerable-Flask-App) — Dev A owned
- [x] Choose app + log (D-16); `make bench-fetch`/`make bench`; source-verified `answer_key.json`;
  scope via `ALLOWED_HOSTS` config only (R3); R6 guard extended to `bench/*/answer_key.json`;
  THIRD_PARTY credit. CC-01 ACKed by Dev B.
- [x] Second benchmark, OWASP Benchmark for Python (A-70): pinned clone, own Docker wrapper on :8110,
  key of 151 vulns + 215 decoys from the official CSV; first run frozen (all 0). Round 1 (A-71..A-73:
  Flask routes on a function parameter, traversal proof through HTML entities, `make_response` tuple
  body only, non-root bench container): code 0/127 → 51/127, runtime 0/151 → 28/151, links 0/127 →
  15/127, wrong 0/22, false alarms 0/5 → 68/739; Mock A, Mock B and we45 unchanged (identical issue
  sets). See [`metrics/bench_owasp-benchmark-python.md`](metrics/bench_owasp-benchmark-python.md).
  `make check` 711 passed, 2 skipped (the two live Mock A tests; 713 passed with Mock A up).

---
_Log_
- 2026-10-31 — Repo initialised (Phase 0 scaffold); contracts + fixtures + harness; `make check` green.
- 2026-10-31 — Benchmark target set to we45 Vulnerable-Flask-App (D-16, supersedes PyGoat D-15).
- 2026-10-31 — Push policy hard-blocked via the `block-git-writes` hook (D-17); Person 1 does all git.
- 2026-10-31 — **P1-A1 done**: `sast/index.py` (parse-only index + import resolution). `make check` green.
- 2026-10-31 — **P1-A2/A3/A4 done**: route extractors, static call graph, `FlowStopper sast` CLI, and
  the Mock A fixture with a validated answer key. `routes.json` correct for Mock A (25) and bench (12);
  every planted Mock A bug run and confirmed to fire; decoys confirmed safe. Phase 1 (Dev A) complete;
  `make check` green (146 tests).
- 2026-10-31 — Docs reorg: split per-developer `PROGRESS_Dev1/Dev2.md` and `DECISIONS_Dev1/Dev2.md`
  (ids `A-NN`/`B-NN`) to end merge conflicts; resolved a `B-01`/`B-02` collision (my SAST decisions →
  `A-01`/`A-02`; Dev B's → `B-01`/`B-02`). Shared Phase-0 decisions stay in `DECISIONS.md`.
- 2026-10-31 — **P2-A3 done**: source/sink/sanitiser tables (`taint/sources.py`, `sinks.py`,
  `sanitizers.py`) — the spec's five CWE rows with the argument that matters, the shell/list and
  constant-SQL/bind distinctions, every sanitiser and guard pattern. `make check` green.
- 2026-10-31 — **P2-A1 done**: `taint/engine.py` intraprocedural walk (f-strings, `+`/`%`/`.format`/
  `.join`, containers, propagators, branch/try/loop joins, per-CWE clearance, guard recognition).
- 2026-10-31 — **P2-A2 done**: `taint/summaries.py` parametric summaries to a fixpoint plus the
  handler-rooted driver; cross-file flows report at the sink with `[handler, …, helper]`,
  `source_param`, `source_kind` and `entry_routes`. 31 tests in `tests/test_sast_taint.py`.
- 2026-10-31 — **P2-A4 done**: `sast/secrets.py` CWE-798 detector (name, provider prefix, literal
  comparison, DSN, config key, env default) + config-file scan by extension; 26 tests. On Mock A it
  reports C01/C02/C03 and stays silent on the `os.environ` decoy D08.
- 2026-10-31 — **P2-A5 done**: `sast/templates.py` template scan (`|safe`, `autoescape false`,
  `Markup`) wired into the taint driver as a per-keyword CWE-79 sink (`py.xss.template.unescaped`);
  catches Mock A's M04 at the `render_template` call line. 11 tests.
- 2026-10-31 — **P2-A6 done**: `sast/runner.py` emits findings (stable `ids.py` ids, catalogue
  severities, ±1-line snippets, counts-only stats). **Mock A measured: 25 routes, 14 findings
  (11 taint + 3 secrets, 1 of them the template rule), code detection 13/13 planted code vulns,
  0 decoy false alarms, M01/M02/M05 matched, all 11 taint findings carrying `source_param` +
  `entry_routes`; D04 reported suppressed as `safe:subprocess-list-no-shell`.** Phase 2 (Dev A)
  complete; `make check` green (229 tests).
- 2026-10-31 — **Phase 2 (Dev A) integration pass**: checked the seams between P2-A1/A2/A3, P2-A4
  and P2-A5/A6 — rule ids and titles generated for all four taint rows in `fixtures/sast_findings.json`
  match the oracle exactly, signatures line up across the three features (`summaries.TemplateLookup`
  is `templates.TemplateLookup`, `summaries.SinkHit` is `engine.SinkReport`), findings come out
  sorted by `(file, line, cwe, rule_id, id)`, and `stats` stayed counts-only and idempotent (the
  same tree scanned at a second absolute path gives byte-identical findings and routes). One real
  duplicate found and removed: the non-Python file walk and the size-capped text read now live once
  in `sast/textfiles.py` (A-29). `make check` green (229 tests), Mock A still 25 routes / 14
  findings, accuracy gate 6 passed.
- 2026-10-31 — **P3-A1 done**: `FlowStopper scan` runs the whole pipeline in one command; on live Mock A
  it reproduces the manual sast→dast→correlate run exactly (21 issues, eval 13/13 · 10/13 · 7/10 ·
  0/7 · 1/21). 10 tests in `tests/test_pipeline.py` (1 live, skips when Mock A is down).
- 2026-10-31 — **P3-J1 done** (Dev A ran it; Dev B does P3-J2): baselines saved for Mock A and the bench
  app under per-target names; `baseline.json` reserved for the organisers' app (A-36).
- 2026-10-31 — **P3-J2 closed**: Dev B's `docs/BACKLOG.md` (Mock A items 1–6) plus a Dev A addendum
  (items 7–12: bench app results, DAST login support, VF02, the bench XSS false positive, secrets in
  test code, the Phase 2 review items, Mock A binding to 0.0.0.0) and a Phase 4 ownership split.
- 2026-11-01 — **Phase 4 follow-ups done** (before Phase 5): `scan --auth-config/--header/--cookie` and
  auto-verify after `correlate` (A-55); credential values kept out of `scan_meta.json` and the store
  (A-56); bench VF02 left unlinked by decision (A-57). One `scan` command now gives, on Mock A: code
  13/13, runtime 11/13, links 8/10, wrong 0/8, false alarms 0/19; on the bench, logged in: code 4/4,
  runtime 3/3, links 1/2, wrong 0/1, false alarms 0/11. `make check` 537 passed.
- 2026-10-31 — **Phase 4 (Dev A) done**: P4-A1/A2/A3 and BACKLOG 6, 8 (SAST half), 9-12 landed in
  three batches (A-37..A-51). Bench code detection 3/4 → 4/4, 0 wrong links on both targets, Mock A
  false alarms 1/21, pydantic proxy SAST 1.8 s.

## Phase 4 backlog (from the Phase 2 semantic review — all misses, never wrong answers)
Carry these into **P4-A1** (generic-rule backlog) / **P4-A2** (B-2 suppression):
- [x] **Template context splat invisible:** `sinks.template_context` skips `**kwargs`, so
  `render_template("p.html", **ctx)` with a tainted value yields no CWE-79. Resolve a splat of a
  local dict literal, or record it in `docs/LIMITATIONS.md` (Dev B finalises that file in P7-B1).
- [x] **Unreachable sinks are dropped, not suppressed:** the driver walks only route handlers, so a
  sink no route reaches emits nothing. P4-A2 needs those findings to *exist* and be marked
  `suppressed` with reason `unreachable` (never for CWE-798).
- [x] **`_is_abort` is too broad:** any unresolved `fail`/`exit`/`abort` leaf truncates the rest of
  the block, silently losing flows. Narrow to resolved framework/stdlib names, or drop `fail`.
- [x] **Fixpoint cap is silent:** `compute_summaries` stops at `fixpoint_max_iterations` with no log;
  a non-converged run shows only as `summary_iterations == 10` in stats. Log a warning.
- [x] **Receiver-based leaf matching is broad** (possible FP source): `PATH_ACCESS` fires on any
  tainted receiver's `.open()`/`.read_text()`/`.write_text()`, SQL on `.raw`/`.extra`. Needs a
  false-positive check against the real app in Phase 3/4.
- 2026-11-01 — **Phase 7 (release docs)**:
  - README rewritten to the spec's Appendix E outline, with report screenshots in `docs/img/`.
  - ARCHITECTURE and LIMITATIONS finalised, on Dev B's behalf.
  - THIRD_PARTY verified against the lock files.
  - Final Docker results written to `docs/metrics/final_mock_{a,b}.json`: Mock A 13/13 · 12/13 · 9/10 · 0/9 · 0/19;
    Mock B 13/13 · 11/14 · 8/10 · 0/8 · 0/19; unseen app 6/10 (first run).
  - Git history is clean of confidential files (R5).
  - Clean clone: `make setup && make check` green; `make demo` passes end to end. Decision A-74.
- 2026-11-01 — **Two new generic SAST rules (A-76, CC-02)**: CWE-502 insecure deserialization and CWE-489
  debug mode left on, with tests. Mock A and Mock B results unchanged (13/13 · 12/13 · 9/10 · 0 wrong · 0
  false alarms; 13/13 · 11/14 · 8/10 · 0 · 0), `make check` green (796 passed, 2 skipped). Dev B still
  owes the ACK for CC-02 and a look at the new `fixes.py` template.
- 2026-11-01 — **Post-release changes (A-75)**: time budgets removed everywhere (organisers: not needed);
  `make showcase APP=<folder> [TARGET=url] [KEY=file] [AUTH=file]` scans any folder, with no answer key
  needed. `make check` green (766 passed, 2 skipped). Showcase tested on a folder path, `--target`,
  `-MockA`, `stop` and the error paths.

