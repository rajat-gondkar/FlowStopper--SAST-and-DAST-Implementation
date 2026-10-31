# Decisions — Dev B (Person 2)

Dev B's own design decisions (ids `B-NN`, newest first). Joint/Phase-0 decisions are in the shared
[`DECISIONS.md`](DECISIONS.md); Dev A's are in [`DECISIONS_Dev1.md`](DECISIONS_Dev1.md). Using a `B-`
prefix keeps our ids from ever colliding with Dev A's `A-` ids.

> **Seeded by Person 1 during the per-dev docs split.** These are Dev B's two Phase-1 decisions, moved
> out of the old shared `DECISIONS.md` and renumbered from `B-01`/`B-02` (which had collided with
> Dev A's `B-01`/`B-02`). **Action for Dev B: done (2026-10-31)** — grepped
> `FlowStopper/` + `tests/` for `D-1[89]`: no code or test references existed (both decisions were
> only ever cited in the docs), so nothing needed renaming. The one remaining `DECISIONS D-12`
> citation in `correlate/issues.py` is correct: D-12 is a *shared* Phase-0 decision and still lives in
> [`DECISIONS.md`](DECISIONS.md).

- **B-09 (DAST authentication, P4-B1 / BACKLOG item 7):** (a) Spec P1-B1 asks for "static
  headers/cookies, or a login step". `AuthConfig` covers both, and the login step also handles a
  token returned in a **response header** (what the benchmark app does) or a JSON body field, copied
  onto later requests as a configurable header with an optional prefix. Cookie sessions need no
  configuration beyond the login step - the client's jar already keeps them. (b) Credentials are
  passed with `--auth-config FILE`, **not** inline flags: a password on the command line is visible
  in shell history and in the process list to every user on the machine. Only `--header`/`--cookie`
  (non-secret by convention) are inline. (c) The login runs **before discovery**, because a route
  behind a session answers 401/403 to everything, so discovery and every check would otherwise be
  probing the login wall rather than the app. (d) A failed login is **reported, not fatal**: it lands
  in `stats["auth"]` and logs a WARNING, because an unauthenticated scan still finds the public half
  of an app - but an out-of-scope login URL raises `ScopeError`, since that is a configuration error,
  not a login failure (R3). (e) The token is never stored in `AuthResult` or in the stats, only the
  name of the header it was placed in, and it is redacted from the stored request text and the repro
  curl (R7). (f) **`build_request` now leaves alone any header parameter whose name the client
  already sends.** A route that *reads* `Authorization` is reported by SAST as having an
  `Authorization` header parameter, and filling every non-injected parameter with a benign value was
  overwriting the real session token with `test` - so the first authenticated benchmark run scored
  *identically* to the unauthenticated one. Two regression tests cover it.
- **B-08 (eval on stored scans + the organiser-key converter, P3-B1):** (a) `eval --scan <id>` reads
  that scan's **snapshot** (`scan_issues`), not the latest state of each issue, so an old scan scores
  as it was reported; `--scan latest` picks the newest *completed* scan, and a failed or running scan
  is refused rather than scored as an empty result. Suppressed issues are included because
  detection counts suppressed findings and the false-alarm metric needs them present to exclude
  them. (b) **Run time** comes from the stored `timings.total` (or `scan_meta.json` beside an
  `--issues` file). **Truncation** is only in `scan_meta.json` — the store has no column for it and
  I did not add one, since that would change the P2-B5 schema for a display hint — so the report
  says `truncated: null` for `--scan` and the CLI prints "truncation unknown" rather than letting
  silence read as "not truncated". (c) Targets are graded with the spec's **strict** comparisons
  (`> 60%`, `< 20%`), so a value exactly on a line misses it; a metric with an empty denominator is
  `n/a`, because "0 wrong links of 0 Confirmed" would otherwise grade `great` for linking nothing.
  The "unseen app" target is not a separate row: it is the Correct links rate of a Mock B scan.
  (d) The written report carries only counts, rates, scan id and run time — never app paths or
  findings — so a report for the organisers' app can be committed (R5); its own path fields are
  made relative to the working directory so they carry no home-directory prefix. (e) The organiser
  key format is unknown (D-03), so the converter is **mapping-driven** (CSV/JSON, column aliases,
  `--map field=column` overrides) instead of guessed against one layout. Its alias list deliberately
  omits `kind` from the CWE candidates (in our own format it holds `pair`/`code_only`) and `planted`
  from the decoy candidates (`planted=yes` means the opposite), and it resolves columns from the
  union of all rows' keys: a first draft resolved from row 0 only and silently turned JSON decoys,
  which carried the marker only on later rows, into planted vulns.
- **B-07 (Mock B held-out hygiene, P2-B7)** — _(a) ratified 2026-10-31; keep as implemented_:
  (a) Mock B's verification lives in `apps/mock_b/selfcheck.py`, **not** under `tests/`, to preserve
  held-out isolation until Phase 6 — `make check` collects only `tests/`, and a test file there would
  expose the sealed contents to Dev A early. It asserts all 16 planted
  bugs fire *and* all 8 decoys stay safe, plus a baseline query, because the first draft "passed" its
  SQLi checks only because the schema was missing and every query raised `OperationalError`.
  **Run it manually** for now: `.venv/bin/python -m apps.mock_b.selfcheck` (documented in
  `apps/mock_b/README.md`). Accepted trade-off: it is not gated by `make check`, so it can rot
  silently; the mitigation is to run it whenever Mock B changes and at the Phase 6 unsealing.
  **Follow-up:** once Mock B is unsealed in Phase 6, promote the suitable checks into `tests/` so CI
  guards them — tracked as a Phase 6 item in `PERSON_2_DEV_B.md`. Until then, nothing about Mock B
  moves into `tests/`.
  (b) `answer_key.json` is **generated** from `# vuln:<id>` / `# decoy:<id>` markers next to the
  offending lines (`build_key.py`), so line numbers cannot drift from the code - a stale number
  silently converts a real detection into a miss. (c) Template XSS records the Python render call as
  its code location with the template named in `notes`, matching Dev A's Mock A convention (M04).
- **B-06 (correlator semantics, P2-B6):** choices forced by reproducing `expected_issues.json`.
  (a) **Specificity** is 1.0 only when the taint has *both* a call chain and a named source param,
  else 0.5 - that is what makes the two sibling report sinks score 0.80 and tie. (b) `link_score` is
  **derived from the sum of the reason weights** rather than computed separately, so the B-3
  explanation can never disagree with the score (`tests/test_fixtures.py` asserts they reconcile).
  (c) Specificity has no reason kind in the frozen contract, so it is folded into the route reason's
  weight and named in its text; a partial param match reuses the `same_param` kind with explanatory
  text for the same reason. (d) The ambiguity margin compares a **rounded** difference: in binary
  floats a genuine 0.10 gap (1.0 vs 0.9) computes as 0.0999...8 and would be misread as a tie,
  losing a legitimate link. (e) Issue titles are derived generically - the credential name for
  CWE-798 is parsed out of the SAST finding's own title, and host-wide runtime issues keep the
  check's wording plus "(host-wide)"; no app-specific strings enter `FlowStopper/` (R6).
- **B-05 (runner budget + determinism, P2-B4)** — _(a) ratified 2026-10-31; keep as implemented_:
  (a) The **240 s default budget covers the active checks only.** Discovery and the single host-wide
  passive pass run first and are deliberately not interruptible. The budget is taken **literally** —
  0 means no time is left, so the active phase is skipped rather than being clamped to a silent grace
  period. On expiry the runner stops active checks **gracefully** (checked before each unit and
  before each check within a unit), **preserves everything already collected** — passive findings and
  the active findings from units that finished or partly finished — and records
  `stats["truncated"] = True`. Consequence, accepted: **total scan wall-clock can exceed 240 s**
  (discovery + passive + the in-flight unit that is allowed to finish). That is fine because the
  budget is *our own* operational limit for bounding the active phase, **not** a PRD requirement; the
  PRD only sets the end-to-end run-time targets in spec §4 (&lt; 15 min good / &lt; 5 min great), which
  `scan_meta.json` reports per stage. Verified by
  `tests/test_dast_runner.py::test_time_budget_truncates_cleanly` (zero budget keeps the passive
  findings and flags truncation) and `::test_expired_deadline_stops_a_unit_before_it_sends_anything`
  (a spent deadline sends no payload at all).
  (b) Each (endpoint, param) unit derives its **own** RNG from `(seed, endpoint, param)`
  (`CheckContext.derive`), because a single shared RNG would make the recorded payloads depend on
  concurrent scheduling order - two runs of the same scan would differ (spec rule 7). (c) DELETE is
  removed from the allowed set unconditionally, so no configuration can reach it (R4).
- **B-04 (passive check precision, P2-B2):** (a) A missing `Secure` cookie flag and missing HSTS are
  reported **only over HTTPS** - on a plain-HTTP dev target every cookie would be flagged, which is
  noise rather than a finding. `HttpOnly` and `SameSite` are always reported. (b) `/robots.txt` is
  emitted at confidence 0.3 and labelled informational (spec lists it as info-only); `/.git/HEAD` and
  `/.env` are real findings at 0.9/0.8. (c) Host-wide findings are anchored to the `/` exchange with
  every affected path in `evidence` and `raw["affected_paths"]`, so they appear **once per host**.
  (d) Added `HttpExchange.set_cookies` (additive, my own file): `response_headers` is a plain dict and
  silently collapses repeated `Set-Cookie` headers, which would hide every cookie but the last.
- **B-03 (payload fidelity + evidence guards, P2-B1):** (a) Appendix B's pre-encoded traversal
  variant `..%2f..%2fetc%2fpasswd` cannot go through httpx's `params=`, which re-encodes the `%` and
  would send `..%252f` — the target would only ever see a literal `%2f`, testing nothing. Added
  `build_raw_query_request()` + `CheckContext.send(..., raw_query=True)` to splice an already-encoded
  payload into the query string verbatim; a test asserts no `%252f` ever leaves the tool. The variant
  is skipped for non-query params (form/json/path bodies would be re-encoded the same way).
  (b) **Traversal** consults the baseline and stays quiet when the benign page already matches
  `root:[x*!]*:0:0:` (attribution impossible) — same guard as the SQLi error check. **Command
  injection** needs no baseline: the proof is an arithmetic product of a per-scan random canary, so a
  pre-existing match is not credible and we save two requests per param. (c) Each check returns at
  most **one** finding per (endpoint, param) — the first payload that proves the bug wins; collapsing
  the remaining payload variants into `raw` is P2-B3's job, so nothing is lost.
- **B-02 (SQLi check, P1-B4)** _(formerly B-02)_: error-based evidence **short-circuits** the
  boolean-differential probe — when an error fires we report it at confidence 0.9 and skip the ~12
  extra differential requests, rather than running both to claim the spec's combined 0.95 (revisit in
  P4 tuning if the extra signal is worth the requests). The differential is also skipped when the
  baseline is *unstable* (can't trust the comparison), and error-based is skipped when the benign
  baseline page already contains a SQL-error string (can't attribute it). Payloads are exactly
  Appendix B; a test (`tests/test_checks.py::test_only_appendix_b_payloads_are_sent`) asserts nothing
  else is sent (R4).
- **B-01 (scope guard semantics, P0-B1)** _(formerly B-01)_: (a) `ALLOWED_HOSTS` env **replaces** the
  base allow-list rather than extending it (matches the `DastConfig.allowed_hosts` "env overrides"
  note and the SETUP/`make bench` usage, which list `localhost,127.0.0.1,::1` explicitly);
  `--allow-host` extras merge on top and log a WARNING. A stray empty/whitespace `ALLOWED_HOSTS=` is
  treated as unset (keeps the default) so it never refuses every target. (b) Matching is a pure string
  allow-list on the URL's parsed hostname — we **never resolve DNS** (R3), so an unlisted name is
  refused even if it would resolve to loopback/private. (c) IP *literals* are compared canonically via
  stdlib `ipaddress` (so `::1` == `0:0:0:0:0:0:0:1`), which resolves nothing; host names match exactly
  (no subdomain wildcards), case/port/trailing-dot normalised. Non-http(s) schemes and host-less URLs
  are refused.
