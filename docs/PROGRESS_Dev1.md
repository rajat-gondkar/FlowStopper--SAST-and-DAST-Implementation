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

## Phase 2 — taint & secrets (next)
- [ ] P2-A1 taint engine · P2-A2 summaries · P2-A3 sources/sinks/sanitizers · P2-A4 secrets
  · P2-A5 templates · P2-A6 SAST runner findings.

## Phase 3+ — [ ] pipeline/scan (P3-A1) · [ ] API/CLI/containers (P5) · [ ] README/THIRD_PARTY (P7).

## Third-party benchmark (we45 Vulnerable-Flask-App) — Dev A owned
- [x] Choose app + log (D-16); `make bench-fetch`/`make bench`; source-verified `answer_key.json`;
  scope via `ALLOWED_HOSTS` config only (R3); R6 guard extended to `bench/*/answer_key.json`;
  THIRD_PARTY credit. CC-01 ACKed by Dev B.

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
  (ids `A-NN`/`B-NN`) to end merge conflicts; resolved a `D-18`/`D-19` collision (my SAST decisions →
  `A-01`/`A-02`; Dev B's → `B-01`/`B-02`). Shared Phase-0 decisions stay in `DECISIONS.md`.
