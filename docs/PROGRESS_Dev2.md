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

### Phase 4 Dev B starting point (after Dev A P4 + item 7)
Fresh baseline on branch `b/p4-dast` off main `e68add6` (Dev A Phase 4 + item 7 merged), before any
Dev B Phase 4 item. Supersedes the Phase 3 and item 7 numbers above. Mock A on 127.0.0.1:5050 with
debug on (`PORT=5050 python app.py`); bench via `docker compose -p flowstopper-bench ... up --build -d`
on 127.0.0.1:8100, scanned with the per-stage CLI and `--auth-config` (login `POST /login`, JWT copied
from the `Authorization` response header; `dast: login ok`). Repeat recipe:
`out/wf/b-p4-dast/measure.md` (git-ignored).

| Metric | Mock A | Bench (authenticated) |
|---|---|---|
| Code detection | 13/13 100.0% great | 4/4 100.0% great |
| Runtime detection | 10/13 76.9% good | 2/3 66.7% good |
| Correct links | 7/10 70.0% good | 1/2 50.0% **below** (target >50%) |
| Wrong links | 0/7 0.0% great | 0/1 0.0% great |
| False alarms | 1/21 4.8% great | 0/10 0.0% great |
| Run time | 1.3 s great | n/a (per-stage CLI writes no scan_meta.json) |
| Unplanted (informational) | 5 | 4 |
| Issues (confirmed / code-only / runtime-only; suppressed) | 21 (7/6/8; 5) | 10 (1/6/3; 1) |

Mock A is unchanged from item 7. Bench code detection rose from 3/4 to 4/4 (Dev A's Phase 4 SAST
work); runtime, links and false alarms on the bench match item 7. Bench DAST: 7 findings from 18
endpoints, 508 requests.

- Item 1 done: `seed_endpoints` now attaches every single-token path segment (`<conv:name>` /
  `{name:conv}`, any position) as a PATH param with a from-the-end segment index; `build_request`
  injects into that segment (`quote(value, safe="")`), and the pre-encoded `..%2f` traversal form is
  spliced verbatim into a path segment as it already was into a query string (B-11). 10 new tests;
  `make check` 489 passed, 0 skipped. Files: `FlowStopper/dast/{types,discovery}.py`,
  `FlowStopper/dast/checks/{base,traversal}.py`, `tests/test_discovery.py`, `tests/test_checks_p2.py`.
  Mock A before/after: runtime 10/13 -> 10/13, links 7/10 -> 7/10, wrong 0/7 -> 0/7, false alarms
  1/21 -> 1/22, unplanted 5 -> 6, DAST findings 19 -> 20 (new: runtime-only XSS reflected in the
  Werkzeug debug traceback of `GET /docs/<path:name>`, item 5's target). M08 is still missed on
  :5050 for an environmental reason: the checkout is deep, so the 6-level Appendix B payload
  resolves to `/Users/etc/passwd` (500), and `%2Fetc%2Fpasswd` is merged by Werkzeug to
  `/docs/etc/passwd` (308). An unmodified copy of Mock A run from `/private/tmp` (port 5053,
  diagnostic only) gave runtime 11/13, links 8/10, wrong 0/8, false alarms 1/22, i.e. M08 detected and
  linked. Bench before/after: unchanged (code 4/4, runtime 2/3, links 1/2, wrong 0/1, false alarms
  0/10, unplanted 4); requests 508 -> 542.
- Item 2 done: the cmdi check gained a differential mode (`dast.cmdi.differential`, proof
  `differential`, confidence 0.7, B-12) for shell sinks that never echo output. It reuses the same six
  Appendix B payloads and reports only the shell-semantics split, comparing reflection-stripped
  fingerprints: `;`/`|`/newline agree with each other and differ from the stable baseline in body
  (same status), both `$(...)` and backtick match the baseline, the `;` result reproduces and a benign
  control matches the baseline (`&&` ignored). `verify.SELF_CONTROLLED_RULES` records that the control
  ran inside the check. 4 new tests; `make check` 493 passed, 0 skipped. Files:
  `FlowStopper/dast/checks/cmdi.py`, `FlowStopper/dast/verify.py`, `tests/test_checks_p2.py`.
  Mock A before/after: runtime 10/13 -> 11/13, links 7/10 -> 8/10, wrong 0/7 -> 0/8, false alarms
  1/22 -> 1/22, unplanted 6 -> 6, DAST findings 20 -> 21 (M05 `GET /api/ping` `host` now confirmed;
  no CWE-78 runtime finding at the `/api/diag` decoy). Bench before/after: unchanged (code 4/4,
  runtime 2/3, links 1/2, wrong 0/1, false alarms 0/10, unplanted 4); requests 542 -> 542.
- Item 3 done: SQLi status-transition rule `dast.sqli.status` (proof `error`, confidence 0.65, B-13)
  for targets that hide DB error text. Runs only after error-based and boolean both miss; fires when a
  stable 2xx/3xx baseline turns into a repeatable 5xx on `orig'` while `orig"`, the balanced
  `orig' AND 'RND'='RND` and a benign control stay below 500. `_error_based` now returns its per-suffix
  responses so `'`/`"` are not resent; `verify.CONTROL_SIGNALS` gained `dast.sqli.status` (status >= 500).
  5 new tests (unbalanced-quote app found; any-quote, `int()` and baseline-500 apps not; error string
  still wins at 0.9; R4 provenance incl. the new rule; verify confirm + control signal); `make check`
  498 passed, 0 skipped. Files: `FlowStopper/dast/checks/sqli.py`, `FlowStopper/dast/verify.py`,
  `tests/test_checks.py`, `tests/test_verify.py`. Hand-probe, Mock A debug off on :5052
  (`flask --app app run -p 5052`, unedited), `POST /login` with `password=test`: `username=test` 302,
  `test'` 500, `test"` 302, `test')` 500, `test'"` 500, `test' AND 'abc'='abc` 302,
  `test' AND 'abc'='abd` 302. Mock A **debug off** before/after: runtime 9/13 -> 10/13, links 7/10 ->
  8/10, wrong 0/7 -> 0/8, false alarms 1/16 -> 1/17, unplanted 1 -> 2, DAST findings 14 -> 16 (M02
  `POST /login` `username` now Confirmed via `dast.sqli.status`; the extra unplanted one is the
  genuine `password` SQLi already flagged as missing from Mock A's key in P3-J2; the `fetch_product`
  / `fetch_order_by_int` decoys stay quiet). :5052 stopped afterwards. Mock A **debug on** (:5050)
  before/after: unchanged (code 13/13, runtime 11/13, links 8/10, wrong 0/8, false alarms 1/22,
  unplanted 6, DAST findings 21; CWE-89 runtime findings still all `dast.sqli.error`). Bench
  before/after: unchanged (code 4/4, runtime 2/3, links 1/2, wrong 0/1, false alarms 0/10,
  unplanted 4); requests 542 -> 542.
- Item 4 done: eval exact-match precedence (B-14) in `evalkit/metrics.py`. A code finding that
  overlaps a planted vuln's **unfuzzed** range is no longer counted against a decoy it reaches only via
  the Appendix C ±3 fuzz; overlapping the decoy's own unfuzzed range is still a false alarm
  (pessimistic). The same `_decoy_hit` rule feeds the false-alarm count and the decoy ids in the
  wrong-link count, so they cannot disagree; detection matching and `LINE_FUZZ` unchanged, Mock A key
  untouched. 3 new tests (exact planted inside decoy fuzz -> not a false alarm; fuzz-only decoy overlap
  -> still one; planted + unfuzzed decoy overlap -> still one); golden `expected_metrics.json`
  reproduced; `make check` 501 passed, 0 skipped. Files: `FlowStopper/evalkit/metrics.py`,
  `tests/test_metrics.py`. Re-eval of the item 3 issues files (no rescan), Mock A before/after: false
  alarms 1/22 -> 0/22 (the Confirmed M02 SQLi at `db.py:29` inside D01's fuzz window [29, 38]); code
  13/13, runtime 11/13, links 8/10, wrong 0/8, unplanted 6 unchanged. Bench before/after: unchanged
  (code 4/4, runtime 2/3, links 1/2, wrong 0/1, false alarms 0/10, unplanted 4).
- Item 5 done: reflected XSS whose proving response is 5xx **and** matches `passive.ERROR_MARKERS` (a
  debug traceback) is returned suppressed (`suppress_reason="dast:debug-traceback-reflection"`,
  confidence 0.9 -> 0.5, evidence points at `dast.passive.verbose-error`); a clean reflection from the
  other probe still wins. Downstream: `matcher.generate_candidates` never links a suppressed runtime
  finding, and `issues.is_suppressed` now means "has findings and every code **and** runtime finding
  is suppressed" (B-15; a Confirmed issue always has an unsuppressed runtime finding). No Dev A change
  needed: pipeline, storage, eval and the correlate CLI already go through `is_suppressed`. 3 new tests
  + `test_is_suppressed_rule` extended; golden `expected_issues.json` reproduced; `make check` 504
  passed, 0 skipped. Files: `FlowStopper/dast/checks/xss.py`, `FlowStopper/correlate/{matcher,issues}.py`,
  `tests/test_checks.py`, `tests/test_metrics.py`, `tests/test_correlate.py`. Mock A before/after: code
  13/13, runtime 11/13, links 8/10, wrong 0/8 unchanged; false alarms 0/22 -> 0/19 (denominator is
  reported issues); unplanted 6 -> 3; suppressed 5 -> 8; DAST findings 21 -> 21. Three runtime-only
  XSS issues moved to the suppressed bucket, not the one planned: `GET /api/crash` `n`, `GET
  /docs/<path:name>` `name` (added by item 1) and `GET /download` `file`; hand-probed each with the
  body canary, all three are 500 Werkzeug traceback pages echoing it raw. The CWE-209
  `dast.passive.verbose-error` issue is still reported. Bench before/after: unchanged (code 4/4, runtime
  2/3, links 1/2, wrong 0/1, false alarms 0/10, unplanted 4, 1 suppressed); requests 542 -> 542.
- Item 8 (DAST half) done: new host-wide probe `xss.probe_unknown_path` (B-16) sends one GET to
  `{base}/{quote(sdcRND<"'>)}` (the Appendix B body canary as a non-existent path); on an HTML response
  echoing `canary<` raw it re-probes once with a fresh canary and reports `dast.xss.unknown_path`
  (CWE-79, GET, `route_id=None`, `param=None`, proof `echo`, confidence 0.8; the B-15 traceback rule
  suppresses a 5xx debug-page echo at 0.5). One request on a miss, two on a hit. `runner.run_dast` calls
  it once right after `passive.run` with `ctx.derive("xss-unknown-path")`, outside the time budget, adds
  it to the host-wide findings and records `stats["unknown_path_probe"]`. 6 new tests (4 in
  `test_checks.py`, 2 in `test_dast_runner.py`); runner-level R4 test unchanged and green; `make check`
  510 passed, 0 skipped. Files: `FlowStopper/dast/checks/xss.py`, `FlowStopper/dast/runner.py`,
  `tests/test_checks.py`, `tests/test_dast_runner.py`. Mock A before/after: unchanged (code 13/13,
  runtime 11/13, links 8/10, wrong 0/8, false alarms 0/19, unplanted 3, 8 suppressed, 21 DAST
  findings); its 404 page does not reflect the path, so no new finding. Bench before/after: runtime
  detection 2/3 -> 3/3 (VF02 runtime half found: `GET /sdcowserhq%3C%22%27%3E` echoed raw in a
  text/html 404); code 4/4, links 1/2, wrong 0/1 unchanged; false alarms 0/10 -> 0/11 (one more
  reported issue); unplanted 4; DAST findings 7 -> 8; requests 542 -> 544. VF02 stays runtime-only
  (see Needs Dev A).
- P4-B3 done: every Confirmed link is explained by exactly one `same_cwe`, one route-kind
  (`route_chain_origin` / `route_handler_span` / `route_reachable`), one `same_param` and one
  `same_method` reason, details name the route and parameter, and weights sum to `link_score` (B-17).
  `explain.py` no longer renders a bare `?` or `'None'` for a missing field (falls back to the runtime
  route id, `file:line`, or the word `unknown`); existing reason texts are byte-identical, so golden
  `expected_issues.json` is reproduced. New `explain.auto_verified_reason(...)` (kind `auto_verified`,
  weight 0.0) for P4-B4. New `tests/test_explain.py` (9 tests: the three route kinds, param unknown,
  param mismatch, method mismatch, missing fields, a fixture-wide invariant, the auto-verify helper);
  `make check` 519 passed, 0 skipped. Files: `FlowStopper/correlate/explain.py`, `tests/test_explain.py`.
  One-off invariant check on the existing `out/a/issues.json` (8 Confirmed) and `out/b/issues.json`
  (1 Confirmed): all pass. Mock A before/after: unchanged (explanation-only change, no rescan). Bench
  before/after: unchanged (no rescan).
- P4-B4 done: `correlate/autoverify.auto_verify(...)` re-tests each eligible Code-only issue (B-18:
  CWE 89/78/22/601/79, named source param, resolvable entry route with an allowed method, not
  suppressed, not ambiguity-penalised) with only the matching DAST check against only that
  (route, param), through the scope-guarded client (target checked first, R3) and the runner's
  verify + collapse; a hit is accepted only if the normal candidate + assignment pass links it to that
  code finding (route gate, `link_min`, ambiguity rule against every unsuppressed code finding, no
  runtime finding reused), then the issue becomes Confirmed with `verified_by="auto-verify"`, an
  `auto_verified` reason and the same issue id. Deadline checked before login and each probe
  (`stats["truncated"]`). `correlate` gained `--target`, `--auth-config`, `--autoverify-budget`
  (default 60 s) and `--seed`; without `--target` its output is byte-identical. `engine._confirmed_issue`
  -> `confirmed_issue` (alias kept). 10 new tests (`tests/test_autoverify.py`: upgrade, safe app,
  seven ineligible kinds with zero requests, non-Code-only untouched, expired deadline, out-of-scope
  ScopeError, R4 shapes, determinism, CLI byte-identical, CLI R3 refusal); golden
  `expected_issues.json` reproduced; `make check` 529 passed, 0 skipped. Files:
  `FlowStopper/correlate/{autoverify,engine,commands}.py`, `tests/test_autoverify.py`. Mock A (per-stage
  `sast` -> `dast` -> `correlate`, before = without `--target`, after = `--target
  http://127.0.0.1:5050`, same inputs): 2 eligible (M06 blind cmdi `POST /admin/backup` `name`, M08
  traversal `GET /docs/<path:name>` - the deep-checkout depth issue from item 1), 0 upgraded; issues
  files byte-identical; code 13/13, runtime 11/13, links 8/10, wrong 0/8, false alarms 0/19, unplanted 3
  before and after. Bench (authenticated, `--target http://127.0.0.1:8100 --auth-config
  out/b/auth.json`): 0 eligible (five CWE-798 secrets, the 404-handler XSS with no source param or
  entry route, one suppressed traversal), 0 upgraded; byte-identical; code 4/4, runtime 3/3, links 1/2,
  wrong 0/1, false alarms 0/11, unplanted 4 before and after. As predicted: items 1-3 already confirm
  every injectable Code-only issue these two apps have.
- Cross-item integration check (no code change): `make check` 529 passed, 0 skipped; every changed
  module imports cleanly on its own (no cycles). Fresh end-to-end re-measure matches the last row of
  each item: Mock A (`scan`) code 13/13, runtime 11/13, links 8/10, wrong 0/8, false alarms 0/19,
  unplanted 3, 8 suppressed, 21 DAST findings; bench (authenticated per-stage) code 4/4, runtime 3/3,
  links 1/2, wrong 0/1, false alarms 0/11, unplanted 4, 1 suppressed, 8 DAST findings, 544 requests.
  `correlate --target` gives byte-identical issues on both (Mock A 0 of 2 eligible upgraded, bench
  0 of 0). Item 5 suppression vs item 8 / P4-B4: suppressed runtime findings are never linked
  (matcher), never accepted by auto-verify, and lose dedupe/collapse to any unsuppressed finding on
  the same key (0.5 is the lowest runtime confidence). All 9 Confirmed links on the two apps pass the
  P4-B3 reason invariant.

### Needs Dev A

- **FYI (item 4, B-14):** eval now gives an exact planted-vuln match precedence over a ±3-line fuzzy
  decoy overlap, so Mock A false alarms drop 1/22 -> 0/22 with no scanner change. Numbers in
  `docs/metrics/phase4_dev_a.md` and earlier Mock A reports computed with the old rule are not directly
  comparable on the false-alarm row. No action needed; Mock A's key was not changed.
- Pipeline auth option for `FlowStopper scan` (see the item 7 note above) is still open.
- **Item 8 SAST half (bench VF02):** the SAST finding for the 404 handler has `entry_routes == []`
  (an error handler is not a route), so the correlator's hard route gate can never link it to the
  route-less `dast.xss.unknown_path` runtime finding. It stays runtime-only, which is preferred over a
  wrong link. Linking it needs Dev A to give error-handler findings some route/handler identity the
  correlator can match; no Dev B workaround beyond reporting the runtime half (B-16).
- **P4-B4 auto-verify in `scan` (B-18):** `pipeline.py` should call
  `await FlowStopper.correlate.autoverify.auto_verify(issues, routes, target_url, dast_config,
  deadline=<monotonic instant for the remaining budget>)` right after `correlate()` (same `DastConfig`,
  including the auth config once the pipeline has one) and store `result.issues` /
  `result.stats`, so `FlowStopper scan` auto-verifies. Workaround until then: per-stage CLI
  `correlate --sast ... --dast ... --target URL [--auth-config FILE]`.
- **Resolved by Dev A (A-55, A-56, A-57):** `scan` now takes `--auth-config/--header/--cookie` and calls
  `auto_verify` after `correlate` (on by default, `--no-autoverify`, `--autoverify-budget`); credential
  values are kept out of `scan_meta.json` and the store. Bench VF02 stays unlinked by decision (A-57).
  Also applied on Dev B's behalf: B-19 (seed-independent unknown-path finding id) and B-20 (`correlate
  --target` takes `--allow-host` / `--allow-mutating`). This file's emoji and dashes, which had been
  mis-decoded earlier (`Γ£à`, `ΓÇö`), were restored (43 lines, encoding only).

## Phase 5 — delivery surface 🚧 (Dev B, branch `b/p5`)
- Step 0 (interface for Dev A) done: `report/gate.py` complete (`GATE_EXIT_CODE = 2`,
  `parse_fail_on`, `gate_tripped`, suppressed issues never trip, B-21); minimal working
  `render_html` (Jinja2, autoescape on, `report/templates/report.html`), `to_sarif` (2.1.0 skeleton:
  one run, rule per CWE, result per reported issue) and `render_markdown`, all `(issues, meta=None)`.
  Names and signatures are frozen for Dev A's `api.py` / `pipeline.py`. 28 tests
  (`tests/test_report_gate.py`, `tests/test_report_api.py`); `make check` 564 passed, 1 skipped.
- P5-B1 done: `render_html` is one offline page (inline CSS, no scripts/fonts/images, light + dark via
  `prefers-color-scheme`): summary header (target, source, scan time, duration, label stat cards,
  severity bar), prioritised table, per-issue detail cards (label, risk/CVSS/link score, URL + method
  + param + payload + proof + evidence, curl, raw request/response, file:line + numbered snippet with
  the offending lines highlighted, source param + call chain, CWE + OWASP links, "why these were
  linked" with weights, fix, other merged findings) and a collapsed Suppressed section explaining every
  suppress_reason. Jinja2 autoescape, never `|safe` (R7); CWE-798-family snippet values masked (B-22);
  detail views are anchored sections of the same page (B-23). Shared helpers in `report/common.py`.
  32 tests (`tests/test_report_html.py`); `make check` 596 passed, 1 skipped.
- P5-B2 done: `to_sarif` emits SARIF 2.1.0, one run (`FlowStopper` driver + version), a rule per CWE
  (`security-severity`, OWASP tag), a result per reported issue with level by severity, relative
  `physicalLocation` (SRCROOT) + region/contextRegion snippets, `webRequest`/`webResponse` parsed from
  the stored exchange (unparseable parts fall back to `properties`), `partialFingerprints` = issue id
  and `properties` {label, risk, cwe, owasp, url, param, ...} (B-24). Validated once against the
  official OASIS 2.1.0 JSON schema: 0 errors on the fixtures and the last Mock A scan. 15 tests
  (`tests/test_report_sarif.py`); the CLI gate exit-code test lands with `report --fail-on` (step 5).
  `make check` 611 passed, 1 skipped.
- P5-B3 done: `report/fixes.fix_for(issue)` - one template per CWE family (sqli, cmdi, xss, traversal,
  redirect, secrets, headers, cookies, CORS, verbose errors, info exposure, directory listing) with
  per-CWE wording inside a family and a generic fallback; each is "What is wrong" (names the
  function/file:line or route and the parameter) + a short code example + one prevention tip;
  deterministic, no network. The correlator sets `Issue.fix` on every issue (`engine.with_fix`, so
  auto-verify upgrades keep it); reports fall back to `fix_for` for older issues.json files.
  `fixtures/expected_issues.json` regenerated with `make fixtures`: only the 9 `fix` fields changed
  (B-25; one-line change in `scripts/build_fixtures.py`). 37 tests (`tests/test_report_fixes.py`);
  `make check` 649 passed, 1 skipped.
- Step 4 done: `render_markdown` writes a readable findings list (D-03): header (target, source, scan,
  duration, counts), prioritised table linking to anchored per-issue sections (label, severity/risk/
  CVSS, CWE + OWASP, request/param/payload/proof/evidence, file:line + function + source param + call
  chain, numbered snippet with `>` on the offending lines, why linked, curl, fix) and the suppressed
  table with explained reasons. Prose is entity-escaped (no raw HTML from scan data), inline code and
  fences survive backticks, table cells escape `|`, secrets masked. 8 tests
  (`tests/test_report_markdown.py`); `make check` 657 passed, 1 skipped.
- Step 5 done: `FlowStopper report --issues issues.json [--meta scan_meta.json] [--html F] [--sarif F]
  [--md F] [--fail-on <label>:<severity>]` writes the requested formats (parent dirs created, UTF-8,
  SARIF pretty-printed, byte-identical across runs) and then applies the gate: exit 2 when tripped
  (listing the matching issues), 0 otherwise; every input error (missing `--issues`, nothing to do,
  bad gate spec, unreadable/invalid issues or meta) exits 1, never 2 (B-26). Added
  `gate.gate_matches` (additive; `gate_tripped` unchanged). 13 tests incl. the CLI gate exit-code test
  (`tests/test_report_cli.py`); `make check` 670 passed, 1 skipped.
- Live check (Mock A, debug on, :5050, `apps/mock_a` run with `~/fs-mocka/venv` - `~/mocka-venv` does
  not exist): `scan` -> 27 issues (8 confirmed, 5 code-only, 6 runtime-only reported; 8 suppressed),
  9.5 s, same buckets as the end of Phase 4; all 27 carry a `fix`. `report` wrote r.html / r.sarif /
  r.md; `--fail-on confirmed:high` exited 2. HTML checked by eye in light and dark (summary, table,
  details, raw exchange, suppressed bucket with reasons): no `<script>`/external refs, none of the 3
  hard-coded secret values appear in any format. SARIF: 0 errors against the official OASIS 2.1.0
  schema, 19 results (13 with code locations, 14 with webResponse). Found and fixed during the check:
  the live DAST client stores a body-only response excerpt, so SARIF now puts it in `webResponse.body`
  (+ a recorded `status`) instead of dropping to `properties`; evidence text no longer breaks
  mid-word. `make check` 671 passed, 1 skipped with Mock A stopped (672 passed, 0 skipped while it ran).

## Phase 6 — generalisation ⬜  ·  ## Phase 7 — release ⬜

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
  Logged **B-02**. `make check` green (104 tests). Next for B: Phase 2 (P2-B1 remaining checks).
- 2026-10-31 — Dev B: **P0-J2 contract sign-off** — reviewed `models.py`, `cwe.py`, `ids.py`,
  `keyschema.py` and declared them **final, no changes requested** (Phase 1 built against them with
  zero contract edits; CC-01 ACKed). Person 1 may now `git tag contract-v1`. (Staging/commit/push of
  Phase 1 is a human action — the agent is hard-blocked from git writes.)
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
