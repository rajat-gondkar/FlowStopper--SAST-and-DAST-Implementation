# Progress

Update at the end of every task: tick the box, add a dated one-liner. Status keys: Γ£à done ┬╖
≡ƒÜº in progress ┬╖ Γ¼£ not started. See [`PERSON_1_DEV_A.md`](PERSON_1_DEV_A.md) /
[`PERSON_2_DEV_B.md`](PERSON_2_DEV_B.md) for the full task text.

## Phase 0 ΓÇö foundations

| Task | Owner | Status | Notes |
|---|---|---|---|
| P0-J1 scaffold (pyproject, Makefile, ruff, .gitignore) | A | Γ£à | `make check` green on 3.12; line-length 120 |
| P0-J2 models.py + JSON schemas | A+B | Γ£à | exact ┬º7; `scripts/export_schemas.py` + drift test |
| P0-J3 cwe.py | B | Γ£à | catalogue + families + precomputed CVSS base scores; OWASP 2025 verified |
| P0-J4 fixtures | A+B | Γ£à | `scripts/build_fixtures.py`; clean pair, secret, header, ambiguous, decoy |
| ids.py stable-ID helpers (shared) | A+B | Γ£à | sha1 findings / sha256[:16] issues; payload-free |
| evalkit/keyschema.py (shared) | B | Γ£à | Appendix C as pydantic; `make validate-key` |
| P0-B1 scope.py | B | Γ£à | allow-list guard (R3): env `ALLOWED_HOSTS` override + `--allow-host` (WARNING); refuses non-http(s), no-host, unlisted hosts (never resolves DNS); IPv6/port/case/trailing-dot normalised; 23 tests |
| P0-J6 THIRD_PARTY.md + PROGRESS.md | A | Γ£à | disclosure skeleton + AI statement |
| P0-J5 target notes (local) | A+B | Γ¼£ | do when organisers release the app; git-ignored |
| contract-v1 tag | A+B | ≡ƒÜº | **Dev B signed off 2026-10-31**: `models.py`/`cwe.py`/`ids.py`/`keyschema.py` final, no changes requested (all of Phase 1 built against them unchanged). Awaiting Person 1 to `git tag contract-v1`. |

**Init extras done:** README, SETUP, PLAN, per-person task lists, DECISIONS, CONTRACT_CHANGES,
ANSWER_KEY_FORMAT, ARCHITECTURE/LIMITATIONS skeletons, Dockerfile + compose, CI workflow,
lock files, `scripts/doctor.py`, Kiro steering. All module stubs created with owner + task tags.

## Phase 1 ΓÇö core engines v0
| P1-A1 index | P1-A2 routes | P1-A3 callgraph | P1-A4 Mock A ΓÇö A Γ¼£
| P1-B1 client Γ£à | P1-B2 discovery Γ£à | P1-B3 baseline Γ£à | P1-B4 sqli+xss Γ£à | P1-B5 metrics Γ£à ΓÇö B
  - P1-B1: `dast/client.py` async `DastClient` ΓÇö every request + redirect hop scope-checked (R3),
    redirects not followed by default, Authorization/Cookie redaction (R7), 64 KB/2 KB body caps,
    cookie jar, timeouts, retry-once, `repro_curl`. 11 tests (offline via httpx MockTransport).
  - P1-B2: `dast/discovery.py` (+ `dast/types.py` Param/Endpoint) ΓÇö seed concrete requests from the
    route map (path params sampled by converter) + same-origin crawl (links/forms/fetch/axios,
    robots/sitemap/openapi); merge seeded+crawled, seeded params win. 8 tests.
  - P1-B3: `dast/baseline.py` ΓÇö `(status, normalised-length, body-hash)` fingerprint with volatile
    stripping (timestamps, UUID/CSRF/nonce, hex); `differs()`; stable/unstable baseline. 5 tests.
  - P1-B4: `dast/checks/{base,sqli,xss}.py` ΓÇö check interface `run(ctx, endpoint, param)`; SQLi
    error-based + boolean-differential, reflected XSS; Appendix-B-only payloads with an R4
    provenance test; findings carry payload/proof/evidence/request/response_excerpt/repro_curl. 9 tests.
  - P1-B5: `evalkit/metrics.py` implements ┬º4 metrics + Appendix C matching (code/runtime detection,
    correct/wrong links, false alarms); reproduces `fixtures/expected_metrics.json` exactly. `eval`
    CLI wired (`evalkit/runner.py` + `commands.py`): `FlowStopper eval --key ΓÇª --issues ΓÇª` prints the
    table and writes metrics JSON. 10 tests.
  - **Phase 1 (Dev B) complete.** `make check` green: 104 tests (was 38 at clone). Note P1-B4 ships
    the check *modules*; the `dast` runner/CLI that drives them end-to-end on a live app is P2-B4.

## Phase 2 ΓÇö depth
| P2-A1..A6 taint/secrets/templates/runner ΓÇö A Γ¼£
| P2-B1 checks [done] | P2-B2 passive | P2-B3 verify | P2-B4 runner | P2-B5 storage | P2-B6 correlator | P2-B7 Mock B — B
  - P2-B1: `dast/checks/{cmdi,traversal,redirect}.py` — same `run(ctx, endpoint, param)` interface and
    evidence as sqli/xss. cmdi proves execution with an evaluated arithmetic marker
    (`echo <canary>$((A*B))X`) across the six Appendix B separators, so a plain reflection cannot
    trigger it; traversal is a read-only `/etc/passwd` probe requiring `root:[x*!]*:0:0:`, guarded by
    the baseline; redirect targets `<canary>.invalid` (reserved TLD) and is **never followed**.
    Added `build_raw_query_request()` so the pre-encoded `..%2f` variant is not double-encoded (B-03).
    13 tests incl. safe-look-alike decoys, an R4 payload-provenance assertion, a "canary host never
    contacted" assertion, and a double-encoding regression test.

## Phase 3 ΓÇö integration Γ¼£  ┬╖  ## Phase 4 ΓÇö accuracy & bonuses Γ¼£
## Phase 5 ΓÇö delivery surface Γ¼£  ┬╖  ## Phase 6 ΓÇö generalisation Γ¼£  ┬╖  ## Phase 7 ΓÇö release Γ¼£

## Third-party benchmark (we45 Vulnerable-Flask-App) ΓÇö cross-phase

| Item | Owner | Status | Notes |
|---|---|---|---|
| Choose app + log (D-16) | A | Γ£à | we45 Vulnerable-Flask-App, used with authors' permission (Flask = best fit); superseded PyGoat (D-15) |
| `make bench-fetch` (clone@pin + compose) | A | Γ£à | `scripts/bench_fetch.sh`; src git-ignored, SHA-verified |
| Answer key (source-verified) | A | Γ£à | `bench/vulnerable-flask-app/answer_key.json`: 2 pairs + 2 code-only + 1 runtime-only; validates |
| Scope via config (R3) + spec/README wording | A | Γ£à | `ALLOWED_HOSTS` in `make bench`; no FlowStopper/ edits |
| `make bench` ΓåÆ `docs/metrics/bench_vulnerable-flask-app.json` | A | Γ£à wiring | produces metrics once scan (P3-A1) + eval (P1-B5/P3-B1) land; not gating check |
| R6 guard extended to bench key | A | Γ£à | `tests/test_no_overfit.py` globs `bench/*/answer_key.json` |
| Credit in THIRD_PARTY (outside own work) | A | Γ£à | MIT + pinned commit |
| Dev B touch-points flagged | AΓåÆB | Γ£à ACK | `docs/CONTRACT_CHANGES.md` CC-01 ACKed by Dev B (scope honours `ALLOWED_HOSTS` via config only ΓÇö R6; eval stays generic) |

---
_Log_
- 2026-10-31 ΓÇö Repo initialised (Phase 0 scaffold). Contracts + fixtures + harness in place;
  `make check` green (38 tests). Ready for Person 2 to clone and for both to start Phase 1.
- 2026-10-31 ΓÇö Added third-party benchmark target OWASP PyGoat (`make bench-fetch` / `make bench`,
  source-verified answer key, R3 scope-via-config, R6 guard extended, THIRD_PARTY credit). CC-01 awaits
  Dev B ACK. `make check` still green.
- 2026-10-31 ΓÇö Policy: Kiro must NOT push to GitHub; Person 1 pushes manually (recorded in SETUP,
  PLAN, AGENTS, steering, per-person docs).
- 2026-10-31 ΓÇö Benchmark target switched from PyGoat to the **we45 Vulnerable-Flask-App** (Flask, best
  framework fit; authors granted usage permission). D-16 supersedes D-15; bench dir, key, Compose,
  credit and all references updated. `make check` still green.
- 2026-10-31 ΓÇö Push policy hardened into a **hard block**: a PreToolUse hook
  (`.kiro/hooks/block-git-writes.json` + `scripts/git_guard.py`) refuses any agent shell command that
  runs `git add`, `git commit` or `git push`. Person 1 still does all staging/committing/pushing.
- 2026-10-31 ΓÇö Dev B: cloned and verified (`make setup && make check && make doctor` all green on
  WSL/Python 3.12). **P0-B1 `scope.py` implemented + tested** (R3 allow-list guard in `scope.py`
  honouring `ALLOWED_HOSTS` env parsed in `config.py`; `build_guard` applies env override + logs
  `--allow-host`). ACKed **CC-01** in `docs/CONTRACT_CHANGES.md`. `make check` green (61 tests, +23).
- 2026-10-31 ΓÇö Dev B: **Phase 1 complete** ΓÇö P1-B1 client, P1-B2 discovery (+`dast/types.py`),
  P1-B3 baseline, P1-B4 SQLi+XSS checks, P1-B5 eval metrics (+`eval` CLI). All offline-tested via
  httpx MockTransport; R3 enforced on every request, R4 payload-provenance test added, R7 redaction.
  Logged **B-02**. `make check` green (104 tests). Next for B: Phase 2 (P2-B1 remaining checks).
- 2026-10-31 ΓÇö Dev B: **P0-J2 contract sign-off** ΓÇö reviewed `models.py`, `cwe.py`, `ids.py`,
  `keyschema.py` and declared them **final, no changes requested** (Phase 1 built against them with
  zero contract edits; CC-01 ACKed). Person 1 may now `git tag contract-v1`. (Staging/commit/push of
  Phase 1 is a human action ΓÇö the agent is hard-blocked from git writes.)
- 2026-10-31 - Dev B: **P2-B1 complete** - the three remaining active checks
  (`dast/checks/cmdi.py`, `traversal.py`, `redirect.py`), Appendix-B payloads only, plus
  `build_raw_query_request()` in `checks/base.py` so the pre-encoded `..%2f` traversal variant is sent
  faithfully instead of double-encoded (decision **B-03**). 13 new tests (safe-look-alike decoys, R4
  provenance, canary-host-never-contacted, no-double-encoding). Verified against Dev A's merged
  Phase 1: `make check` green (158 passed, 1 skipped - the bench-app route test self-skips until
  `make bench-fetch`). Also completed the docs-split follow-up: grepped for the old `D-18`/`D-19`
  ids - no code/test references existed - and repaired the provenance notes in `DECISIONS_Dev2.md`
  that a blind find/replace had mangled. Next for B: P2-B2 (passive/misconfiguration checks).
