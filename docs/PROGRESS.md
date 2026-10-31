# Progress

Update at the end of every task: tick the box, add a dated one-liner. Status keys: ✅ done ·
🚧 in progress · ⬜ not started. See [`PERSON_1_DEV_A.md`](PERSON_1_DEV_A.md) /
[`PERSON_2_DEV_B.md`](PERSON_2_DEV_B.md) for the full task text.

## Phase 0 — foundations

| Task | Owner | Status | Notes |
|---|---|---|---|
| P0-J1 scaffold (pyproject, Makefile, ruff, .gitignore) | A | ✅ | `make check` green on 3.12; line-length 120 |
| P0-J2 models.py + JSON schemas | A+B | ✅ | exact §7; `scripts/export_schemas.py` + drift test |
| P0-J3 cwe.py | B | ✅ | catalogue + families + precomputed CVSS base scores; OWASP 2025 verified |
| P0-J4 fixtures | A+B | ✅ | `scripts/build_fixtures.py`; clean pair, secret, header, ambiguous, decoy |
| ids.py stable-ID helpers (shared) | A+B | ✅ | sha1 findings / sha256[:16] issues; payload-free |
| evalkit/keyschema.py (shared) | B | ✅ | Appendix C as pydantic; `make validate-key` |
| P0-B1 scope.py | B | ⬜ | scaffolded with docstring; **implement + test first in Phase 1** |
| P0-J6 THIRD_PARTY.md + PROGRESS.md | A | ✅ | disclosure skeleton + AI statement |
| P0-J5 target notes (local) | A+B | ⬜ | do when organisers release the app; git-ignored |
| contract-v1 tag | A+B | ⬜ | tag after both sign off on models/ids |

**Init extras done:** README, SETUP, PLAN, per-person task lists, DECISIONS, CONTRACT_CHANGES,
ANSWER_KEY_FORMAT, ARCHITECTURE/LIMITATIONS skeletons, Dockerfile + compose, CI workflow,
lock files, `scripts/doctor.py`, Kiro steering. All module stubs created with owner + task tags.

## Phase 1 — core engines v0
| P1-A1 index | P1-A2 routes | P1-A3 callgraph | P1-A4 Mock A — A ⬜
| P1-B1 client | P1-B2 discovery | P1-B3 baseline | P1-B4 sqli+xss | P1-B5 metrics — B ⬜

## Phase 2 — depth
| P2-A1..A6 taint/secrets/templates/runner — A ⬜
| P2-B1..B7 checks/verify/storage/correlator/Mock B — B ⬜

## Phase 3 — integration ⬜  ·  ## Phase 4 — accuracy & bonuses ⬜
## Phase 5 — delivery surface ⬜  ·  ## Phase 6 — generalisation ⬜  ·  ## Phase 7 — release ⬜

## Third-party benchmark (we45 Vulnerable-Flask-App) — cross-phase

| Item | Owner | Status | Notes |
|---|---|---|---|
| Choose app + log (D-16) | A | ✅ | we45 Vulnerable-Flask-App, used with authors' permission (Flask = best fit); superseded PyGoat (D-15) |
| `make bench-fetch` (clone@pin + compose) | A | ✅ | `scripts/bench_fetch.sh`; src git-ignored, SHA-verified |
| Answer key (source-verified) | A | ✅ | `bench/vulnerable-flask-app/answer_key.json`: 2 pairs + 2 code-only + 1 runtime-only; validates |
| Scope via config (R3) + spec/README wording | A | ✅ | `ALLOWED_HOSTS` in `make bench`; no FlowStopper/ edits |
| `make bench` → `docs/metrics/bench_vulnerable-flask-app.json` | A | ✅ wiring | produces metrics once scan (P3-A1) + eval (P1-B5/P3-B1) land; not gating check |
| R6 guard extended to bench key | A | ✅ | `tests/test_no_overfit.py` globs `bench/*/answer_key.json` |
| Credit in THIRD_PARTY (outside own work) | A | ✅ | MIT + pinned commit |
| Dev B touch-points flagged | A→B | ⬜ ACK | `docs/CONTRACT_CHANGES.md` CC-01 (scope env, generic eval) |

---
_Log_
- 2026-10-31 — Repo initialised (Phase 0 scaffold). Contracts + fixtures + harness in place;
  `make check` green (38 tests). Ready for Person 2 to clone and for both to start Phase 1.
- 2026-10-31 — Added third-party benchmark target OWASP PyGoat (`make bench-fetch` / `make bench`,
  source-verified answer key, R3 scope-via-config, R6 guard extended, THIRD_PARTY credit). CC-01 awaits
  Dev B ACK. `make check` still green.
- 2026-10-31 — Policy: Kiro must NOT push to GitHub; Person 1 pushes manually (recorded in SETUP,
  PLAN, AGENTS, steering, per-person docs).
- 2026-10-31 — Benchmark target switched from PyGoat to the **we45 Vulnerable-Flask-App** (Flask, best
  framework fit; authors granted usage permission). D-16 supersedes D-15; bench dir, key, Compose,
  credit and all references updated. `make check` still green.
- 2026-10-31 — Push policy hardened into a **hard block**: a PreToolUse hook
  (`.kiro/hooks/block-git-writes.json` + `scripts/git_guard.py`) refuses any agent shell command that
  runs `git add`, `git commit` or `git push`. Person 1 still does all staging/committing/pushing.
