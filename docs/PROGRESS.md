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
| P0-B1 scope.py | B | ✅ | allow-list guard (R3): env `ALLOWED_HOSTS` override + `--allow-host` (WARNING); refuses non-http(s), no-host, unlisted hosts (never resolves DNS); IPv6/port/case/trailing-dot normalised; 23 tests |
| P0-J6 THIRD_PARTY.md + PROGRESS.md | A | ✅ | disclosure skeleton + AI statement |
| P0-J5 target notes (local) | A+B | ⬜ | do when organisers release the app; git-ignored |
| contract-v1 tag | A+B | 🚧 | **Dev B signed off 2026-10-31**: `models.py`/`cwe.py`/`ids.py`/`keyschema.py` final, no changes requested (all of Phase 1 built against them unchanged). Awaiting Person 1 to `git tag contract-v1`. |

**Init extras done:** README, SETUP, PLAN, per-person task lists, DECISIONS, CONTRACT_CHANGES,
ANSWER_KEY_FORMAT, ARCHITECTURE/LIMITATIONS skeletons, Dockerfile + compose, CI workflow,
lock files, `scripts/doctor.py`, Kiro steering. All module stubs created with owner + task tags.

## Phase 1 — core engines v0
| P1-A1 index | P1-A2 routes | P1-A3 callgraph | P1-A4 Mock A — A ⬜
| P1-B1 client ✅ | P1-B2 discovery ✅ | P1-B3 baseline ✅ | P1-B4 sqli+xss ✅ | P1-B5 metrics ✅ — B
  - P1-B1: `dast/client.py` async `DastClient` — every request + redirect hop scope-checked (R3),
    redirects not followed by default, Authorization/Cookie redaction (R7), 64 KB/2 KB body caps,
    cookie jar, timeouts, retry-once, `repro_curl`. 11 tests (offline via httpx MockTransport).
  - P1-B2: `dast/discovery.py` (+ `dast/types.py` Param/Endpoint) — seed concrete requests from the
    route map (path params sampled by converter) + same-origin crawl (links/forms/fetch/axios,
    robots/sitemap/openapi); merge seeded+crawled, seeded params win. 8 tests.
  - P1-B3: `dast/baseline.py` — `(status, normalised-length, body-hash)` fingerprint with volatile
    stripping (timestamps, UUID/CSRF/nonce, hex); `differs()`; stable/unstable baseline. 5 tests.
  - P1-B4: `dast/checks/{base,sqli,xss}.py` — check interface `run(ctx, endpoint, param)`; SQLi
    error-based + boolean-differential, reflected XSS; Appendix-B-only payloads with an R4
    provenance test; findings carry payload/proof/evidence/request/response_excerpt/repro_curl. 9 tests.
  - P1-B5: `evalkit/metrics.py` implements §4 metrics + Appendix C matching (code/runtime detection,
    correct/wrong links, false alarms); reproduces `fixtures/expected_metrics.json` exactly. `eval`
    CLI wired (`evalkit/runner.py` + `commands.py`): `FlowStopper eval --key … --issues …` prints the
    table and writes metrics JSON. 10 tests.
  - **Phase 1 (Dev B) complete.** `make check` green: 104 tests (was 38 at clone). Note P1-B4 ships
    the check *modules*; the `dast` runner/CLI that drives them end-to-end on a live app is P2-B4.

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
| Dev B touch-points flagged | A→B | ✅ ACK | `docs/CONTRACT_CHANGES.md` CC-01 ACKed by Dev B (scope honours `ALLOWED_HOSTS` via config only — R6; eval stays generic) |

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
- 2026-10-31 — Dev B: cloned and verified (`make setup && make check && make doctor` all green on
  WSL/Python 3.12). **P0-B1 `scope.py` implemented + tested** (R3 allow-list guard in `scope.py`
  honouring `ALLOWED_HOSTS` env parsed in `config.py`; `build_guard` applies env override + logs
  `--allow-host`). ACKed **CC-01** in `docs/CONTRACT_CHANGES.md`. `make check` green (61 tests, +23).
- 2026-10-31 — Dev B: **Phase 1 complete** — P1-B1 client, P1-B2 discovery (+`dast/types.py`),
  P1-B3 baseline, P1-B4 SQLi+XSS checks, P1-B5 eval metrics (+`eval` CLI). All offline-tested via
  httpx MockTransport; R3 enforced on every request, R4 payload-provenance test added, R7 redaction.
  Logged **D-19**. `make check` green (104 tests). Next for B: Phase 2 (P2-B1 remaining checks).
- 2026-10-31 — Dev B: **P0-J2 contract sign-off** — reviewed `models.py`, `cwe.py`, `ids.py`,
  `keyschema.py` and declared them **final, no changes requested** (Phase 1 built against them with
  zero contract edits; CC-01 ACKed). Person 1 may now `git tag contract-v1`. (Staging/commit/push of
  Phase 1 is a human action — the agent is hard-blocked from git writes.)
