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

---
_Log_
- 2026-10-31 — Repo initialised (Phase 0 scaffold). Contracts + fixtures + harness in place;
  `make check` green (38 tests). Ready for Person 2 to clone and for both to start Phase 1.
