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
| P2-B1 checks [done] | P2-B2 passive [done] | P2-B3 verify [done] | P2-B4 runner [done] | P2-B5 storage [done] | P2-B6 correlator [done] | P2-B7 Mock B [done] — B
  - **Phase 2 (Dev B) complete.** `make check` green: 287 passed, 1 skipped (bench-app route test
    self-skips until `make bench-fetch`). Decisions B-03..B-07.
  - P2-B1: `dast/checks/{cmdi,traversal,redirect}.py` — same `run(ctx, endpoint, param)` interface and
    evidence as sqli/xss. cmdi proves execution with an evaluated arithmetic marker
    (`echo <canary>$((A*B))X`) across the six Appendix B separators, so a plain reflection cannot
    trigger it; traversal is a read-only `/etc/passwd` probe requiring `root:[x*!]*:0:0:`, guarded by
    the baseline; redirect targets `<canary>.invalid` (reserved TLD) and is **never followed**.
    Added `build_raw_query_request()` so the pre-encoded `..%2f` variant is not double-encoded (B-03).
    13 tests incl. safe-look-alike decoys, an R4 payload-provenance assertion, a "canary host never
    contacted" assertion, and a double-encoding regression test.
  - P2-B2: `dast/checks/passive.py` - host-wide checks reported **once per host** with affected paths
    in `evidence` + `raw`: security headers (CSP, nosniff, Referrer-Policy, clickjacking via XFO or
    CSP frame-ancestors, HSTS on HTTPS only), cookie flags (HttpOnly/SameSite always, Secure only on
    HTTPS - B-04), permissive CORS (reflected or wildcard origin, probe `https://sdc-probe.invalid`),
    version banners, verbose errors + debug console, exposed files (`/.git/HEAD`, `/.env`,
    `/robots.txt` informational), directory listing. All RUNTIME_ONLY, no code location. Added
    `HttpExchange.set_cookies` because a dict collapses repeated `Set-Cookie` headers. 19 tests
    (sloppy vs hardened app, R4: the CORS Origin is the only injected value).
  - P2-B3: `dast/verify.py` - a hit is kept only if a **second canary** reproduces it and, where the
    proof is not canary-bound, a **benign control** does not show the signal (kills both flaky
    one-offs and pages that always contain the pattern). `collapse()` groups by
    `(cwe, route_id|path, param)`, keeps the strongest proof by rank and preserves the other payloads
    in `raw`. 13 tests.
  - P2-B4: `dast/runner.py` + `dast/commands.py` - `run_dast()` end to end: scope-check the target,
    discover, one passive pass, then every (endpoint, injectable param) under a concurrency cap and a
    **time budget** (`truncated` recorded, budget taken literally - B-05); routes-first ordering and
    Appendix B priority param names first; method policy GET/POST/HEAD/OPTIONS, PUT/PATCH only with
    `--allow-mutating`, **DELETE unreachable by configuration**. Per-unit derived RNG keeps payloads
    deterministic under concurrency. `FlowStopper dast <url> --routes routes.json -o dast.json` works.
    21 tests incl. a whole offline vulnerable app finding all five injection types, a decoy that stays
    quiet, and a runner-level R4 provenance check.
  - P2-B5: `storage.py` - SQLite `scans / findings / issues / scan_issues` exactly per spec; **upsert
    on `issues.id`** so a re-scan keeps `first_seen_scan` and advances `last_seen_scan` (FR-6), and a
    Code-only issue upgraded to Confirmed keeps its identity. Per-scan snapshots keep history honest.
    Prioritised queries (label/cwe/min_risk/include_suppressed) share one ordering helper with the
    correlator. 19 tests.
  - P2-B6: **the correlator** (`correlate/{dedupe,matcher,scoring,explain,issues,engine}.py` +
    `cvss.py`). Reproduces `fixtures/expected_issues.json` **exactly** - same ids, order, labels,
    risk and reason text - from the fixture SAST/DAST findings. Hard route gate (1.0 chain-origin /
    0.9 handler span / 0.8 reachable / 0 reject), param + method + specificity, greedy one-to-one
    assignment, ambiguity rule that refuses the tied link, labels, CVSS 3.1 risk factors and the
    deterministic sort. `cvss.py` reproduces every `cwe.BASE_SCORES` value. Idempotency and
    input-order independence tested. `FlowStopper correlate` CLI round-trips the golden fixture.
    32 + 27 tests.
  - P2-B7: `apps/mock_b/` **(HELD OUT - Dev A must not read it until Phase 6)** - shoplite-b, a
    FastAPI shop, 22 app routes, deliberately unlike Mock A (`routers/` -> `services/` ->
    `repositories/`, `include_router` prefixes, pydantic JSON bodies, different naming). 10 pairs
    across all five injection CWEs, 3 code-only secrets, 4 runtime-only, 8 decoys. `answer_key.json`
    is **generated** from source markers by `build_key.py` (line numbers cannot drift) and validates
    against the Appendix C schema. `selfcheck.py` proves all 16 planted bugs fire and all 8 decoys
    stay safe - it lives inside the sealed directory, not `tests/` (B-07).

## Phase 3 — integration
| P3-J1 baseline on the real app — A+B BLOCKED (no `target_src/` / `keys/` yet; not substituted)
| P3-J2 triage + ranked `docs/BACKLOG.md` [done on Mock A] — A+B
  - P3-J2: triaged a full live Mock A run into the spec's buckets — SAST miss 0, **DAST miss 3**,
    link miss 0, wrong link 0, decoy false alarm 1, suppression error 0 — and wrote
    `docs/BACKLOG.md` ranked by metric impact, with an owner and an evidence trail per item. No code
    changed (triage only). Key findings: (1) **path parameters are never tested** — `seed_endpoints`
    drops them when filling the URL, so `/docs/<path:name>`, `/api/orders/<id>` etc. get no checks at
    all (root cause of the M08 miss; a whole class of blind spot, worse on the real app);
    (2) cmdi only fires when the command's output is echoed, so `os.system` sinks are missed although
    the exit code visibly changes (M05); (3) error-based SQLi depends on the target leaking DB error
    text — the same scan with Flask debug off missed M02 entirely, which is the likely real-app
    configuration, so this is the top real-app risk despite zero Mock A impact; (4) the single false
    alarm is Appendix C's ±3 line fuzz letting decoy D01 swallow the genuine M02 finding at
    `db.py:29`, not a wrong detection; (5) M06 is genuinely blind (identical responses) and
    unfixable within R4, so it is an accepted limitation. Also flagged to Dev A that Mock A's key
    omits two genuine bugs (`POST /login` `password`, `/download` `file` reflection).
  - **Harness lesson:** the first triage run used Flask without `--debug`, which Mock A's README
    specifies; that hid two planted bugs and understated runtime detection (61.5% vs 76.9%) and
    correct links (60% vs 70%). Re-ran as documented before drawing any conclusion.
| P3-B1 eval on stored scans + organiser-key converter [done; real-app run pending] — B
  - P3-B1: `evalkit/runner.py` + `commands.py` — `FlowStopper eval --key <key> --scan <id|latest>`
    scores a stored scan's snapshot (or `--issues <file>`, which also reads the `scan_meta.json`
    beside it); the table now shows each §4 metric with its Good/Great target, a status and the run
    time; the report adds provenance (scan id, run time, truncation, issue counts, unplanted count).
    `evalkit/convert_organiser_key.py` converts an unknown-format key (CSV/JSON, column aliases,
    `--map` overrides) and validates it. Decision B-08. 32 new tests incl. one that drives Dev A's
    real pipeline then scores it with `--scan latest`.
  - **Live check on Mock A** (scratch copy outside the repo, real SAST + DAST + correlator + store):
    code detection 13/13 (100%, great), runtime detection 8/13 (61.5%, good), correct links 6/10
    (60%, good), wrong links 0/6 (great), false alarms 1/16 (6.2%, great), run time 4.9 s (great);
    1 unplanted issue. `--scan latest` and `--issues` gave identical metrics. Dev A's live
    integration test (normally self-skipped) also passed while Mock A was up. Not committed to
    `docs/metrics/`: the baseline is the joint P3-J1 task, against the real app.

## Phase 4 — accuracy & bonuses (Dev B)
| item 7 login [done] | item 1 path params | item 2 cmdi differential | item 3 SQLi status rule
| item 4 metrics precedence | item 5 traceback XSS | item 8 DAST half | P4-B3 explain | P4-B4 auto-verify

### item 7 - DAST login support (BACKLOG item 7, spec P1-B1) - **done**
`AuthConfig`/`LoginStep` in `dast/config.py`; `DastClient.authenticate()` runs the login before
discovery and copies a token from a response header or a JSON body field onto later requests;
`FlowStopper dast --auth-config FILE` (credentials in a file, never on the command line - B-09).
Found and fixed a second bug while proving it: a route that *reads* `Authorization` is listed by SAST
as having an `Authorization` **header param**, and `build_request` was filling it with a benign value,
clobbering the real token - the first authenticated bench run scored identically to no auth.

| Metric | bench before | bench after | Mock A before | Mock A after |
|---|---|---|---|---|
| Code detection | 3/4 75% | 3/4 75% | 13/13 100% | 13/13 100% |
| Runtime detection | 1/3 33.3% **below** | **2/3 66.7% good** | 10/13 76.9% | 10/13 76.9% |
| Correct links | 0/2 0% **below** | **1/2 50%** | 7/10 70% | 7/10 70% |
| Wrong links | 0/0 n/a | 0/1 0% great | 0/7 0% | 0/7 0% |
| False alarms | 0/9 0% | 0/10 0% | 1/21 4.8% | 1/21 4.8% |
| Unplanted | 4 | 5 | 5 | 5 |

VF01 (the SQLi behind the login) is now **Confirmed** with `proof=error`; it was Code-only before.
Mock A is unchanged, as expected - it has no authenticated routes. Matches the backlog's predicted
impact exactly (runtime 1/3 -> 2/3, links 0/2 -> 1/2). Correct links reads "below" at 50% because the
spec's target is strictly `>50%`. 19 new tests (`tests/test_dast_auth.py`), `make check` green:
**432 passed, 1 skipped** (was 414 + 2; the bench route test now runs because the source is fetched).

> **Needs Dev A:** `FlowStopper scan` (`pipeline.py`) has no way to pass auth config, so the bench
> numbers above were produced with the per-stage CLI (`sast` -> `dast --auth-config` -> `correlate` ->
> `eval`). The pipeline needs an equivalent option before `make bench` or a real-app scan can
> authenticate - already noted as the Dev A follow-up under backlog item 7.

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
  `make bench-fetch`). Also completed the docs-split follow-up: grepped for the old `B-01`/`B-02`
  ids - no code/test references existed - and repaired the provenance notes in `DECISIONS_Dev2.md`
  that a blind find/replace had mangled. Next for B: P2-B2 (passive/misconfiguration checks).
- 2026-10-31 - Dev B: **Phase 2 complete (P2-B1..B7)** - passive checks, verification/collapse, the
  DAST runner + `dast` CLI, SQLite storage, **the correlator** (reproduces
  `fixtures/expected_issues.json` exactly, with `cvss.py` reproducing every `cwe.BASE_SCORES` value),
  and the held-out Mock B (FastAPI, 22 routes, generated answer key, self-check green). Decisions
  **B-04..B-07**. `make check` green: **287 passed, 1 skipped** (was 158 at the start of the phase);
  the R6 no-overfit guard passes with Mock B's key included. Phase 2 exit criteria met: the
  correlator passes the fixtures including the ambiguous case with no wrong link, idempotency holds,
  and the DAST runner finds all five injection types plus passive findings on an offline app.
  Next for B: Phase 3 (P3-B1 `eval` on the real app) - blocked on Dev A's P3-A1 `scan` pipeline for
  end-to-end runs.
- 2026-10-31 - Dev B: **ratified two standing decisions** (both already implemented; no architecture
  or behaviour change). (1) **Mock B verification stays in `apps/mock_b/selfcheck.py`, outside
  `tests/`**, to preserve held-out isolation until Phase 6; run manually
  (`.venv/bin/python -m apps.mock_b.selfcheck`), with promotion into `tests/test_mock_b.py` deferred
  to new task **P6-B2** after unsealing. (2) **The 240 s DAST budget covers active checks only** -
  discovery and the passive pass run first and are unaffected; on expiry active checks stop
  gracefully, all collected findings (passive included) are preserved and `stats.truncated=true` is
  set, so total wall-clock may exceed 240 s - acceptable because the budget is our own operational
  limit, not a PRD requirement (the PRD run-time targets are spec §4). Documented in
  `DECISIONS_Dev2.md` (B-05, B-07), `LIMITATIONS.md`, `ARCHITECTURE.md`, `apps/mock_b/README.md` and
  `PERSON_2_DEV_B.md` (P6-B2). Code change limited to one `--time-budget` help string. Also fixed a
  **vacuous test**: `test_time_budget_truncates_cleanly` asserted `all(...)` over the findings, which
  passes on an empty list, so it would not have caught truncation discarding everything; it now
  asserts the passive findings are present, and a new unit test proves an expired deadline sends no
  payload at all. `make check` green: 290 passed, 1 skipped.
- 2026-10-31 - Dev B: **P3-B1 complete (real-app run pending)** - `eval --scan <id|latest>` scores
  stored scans from Dev A's P3-A1 pipeline, the §4 table shows targets/status/run time, and
  `convert_organiser_key.py` is ready for the organisers' key. Decision **B-08**. Verified live on Mock
  A: 100% code / 61.5% runtime detection, 6/10 correct links, 0 wrong links, 6.2% false alarms, 4.9 s.
  `make check` green: 414 passed, 2 skipped (both self-skip: Mock A not running, bench app not
  fetched). Blocked on the organisers' app/key for the actual real-app run (P3-J1).
- 2026-10-31 - Dev B: **P3-J2 complete** - triaged a live Mock A run (real SAST + DAST + correlator +
  store, `--debug` as Mock A documents) into the spec's buckets and wrote the ranked
  `docs/BACKLOG.md`. Measured: code detection 13/13 (100%), runtime detection 10/13 (76.9%), correct
  links 7/10 (70%), wrong links 0/7, false alarms 1/21 (4.8%), run time 4.7 s, 5 unplanted. Buckets:
  SAST miss 0, DAST miss 3, link miss 0, wrong link 0, decoy false alarm 1, suppression error 0 - so
  **DAST coverage, not correlation, is the bottleneck** (every pair with both halves found linked at
  score 1.0). Root causes confirmed by hand-probing, not inferred: path params are dropped by
  `seed_endpoints` so those endpoints are never tested; cmdi needs the command's output echoed;
  error-based SQLi needs the target to leak DB errors; the lone false alarm is a ±3-line fuzz
  collision with a true positive; M06 is blind and unfixable within R4. **No code changed** - P3-J2 is
  triage, and the fixes are Phase 4 items 1-5 in the backlog. `make check` still green: 414 passed,
  2 skipped. **P3-J1 remains blocked** on the organisers' app/key and was not substituted.
