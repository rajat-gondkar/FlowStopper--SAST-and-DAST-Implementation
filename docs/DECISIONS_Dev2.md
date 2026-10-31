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

- **B-21 (CI gate semantics, P5-B2 / B-6):** `--fail-on` is `<label>:<severity>` with label in
  `confirmed | code_only | runtime_only | any` and a `Severity` value, case-insensitive, surrounding
  whitespace ignored; anything else (including the hyphenated `code-only`) is a `ValueError`, so a typo
  fails loudly instead of silently disabling the gate. The threshold is inclusive (`confirmed:high`
  trips on high and critical). Suppressed issues (`correlate.issues.is_suppressed`) never trip it,
  matching "reported issues" everywhere else. Exit code `GATE_EXIT_CODE = 2`. Interface for Dev A:
  `report/gate.py::parse_fail_on`, `gate_tripped`; report entry points `render_html`, `to_sarif`,
  `render_markdown`, all `(issues, meta=None)`, are not to be renamed.
- **B-20 (`correlate --target` scope options match `dast`):** `correlate --target` now takes
  `--allow-host` and `--allow-mutating` and passes them into the auto-verify `DastConfig`, so
  auto-verify allows exactly what the `dast` run allowed. Test:
  `tests/test_autoverify.py::test_cli_correlate_target_passes_allow_host_and_mutating`. Applied on Dev
  B's behalf (final-review note).
- **B-19 (unknown-path XSS finding id is seed-independent):** `probe_unknown_path` used the probed path,
  which holds the per-scan canary, in its finding id, so the id changed with `--seed` (FR-6). The id
  now uses a fixed key (`<unknown-path>`); the real path stays in `runtime.path`. Test:
  `tests/test_checks.py::test_unknown_path_finding_id_does_not_depend_on_the_seed`. Applied after the
  workflow's final review, on Dev B's behalf.
- **B-18 (auto-verify Code-only findings, P4-B4 / B-1):** (a) **Eligibility:** label Code-only, not
  suppressed, no `ambiguity_penalty` reason (re-linking a deliberately unlinked issue would bypass the
  ambiguity rule), exactly one code finding, CWE in {89, 78, 22, 601, 79}, a named
  `taint.source_param`, and a `taint.entry_routes` id present in the route map whose method the DAST
  method policy allows (DELETE never). The param is the seeded endpoint's param with the same
  normalised name (location from `taint.source_kind` when it disambiguates), else a new param at
  `source_kind` (default QUERY for GET/HEAD, FORM otherwise); a PATH name that owns no segment is
  skipped rather than rewriting the wrong segment. Anything else is never probed (zero requests).
  (b) **Probe:** only the matching check, only that (route, param), via the same scope-guarded
  `DastClient` (target scope-checked first, R3), Appendix B payloads (R4), the runner's second-canary
  + control verification and collapse, a per-issue RNG derived from (seed, issue id). Suppressed hits
  (e.g. B-15 traceback XSS) do not count. (c) **Re-link safety:** the new runtime finding must win the
  normal `generate_candidates` + `assign` pass against *every* unsuppressed code finding in the issue
  list (route gate, `link_min`, ambiguity rule), the winner must be this issue's code finding on this
  route, the runtime finding id must not already belong to another issue (one-to-one), and the rebuilt
  issue id must equal the Code-only id (storage identity). Otherwise the issue stays Code-only and is
  counted in `stats` - a missed link over a wrong one. Upgraded issues get `verified_by="auto-verify"`,
  the B-17 link reasons plus one `auto_verified` reason (weight 0), and the runtime finding carries
  `raw["auto_verify"]=True`. (d) **Budget:** runs after correlation; `deadline` is a monotonic instant
  checked before each probe (and before login), an expired budget sends nothing and sets
  `stats["truncated"]`. CLI default `--autoverify-budget 60`. (e) **Wiring:** `correlate --target URL
  [--auth-config FILE] [--seed N]`; without `--target` the command is byte-identical to before.
  `engine._confirmed_issue` renamed `confirmed_issue` (old name kept as an alias).
- **B-17 (link explanation completeness, P4-B3):** (a) Every Confirmed issue carries exactly one
  `same_cwe`, one route-kind, one `same_param` and one `same_method` reason; the route reason names the
  route id and the param reason names the DAST parameter; weights sum to `link_score`.
  `tests/test_explain.py` pins this for each route kind and over the fixture. (b) Missing fields never
  render as `?` or `'None'`: the route id falls back to the runtime finding's `route_id`, a missing
  function to `file:line`, anything else to the word `unknown`. Texts for fully populated links are
  unchanged (the golden fixture pins them). The partial-credit param text now also covers a DAST-side
  unknown name. (c) `auto_verified_reason(check_name, route_id, param, proof, payload)` returns a
  `LinkReason(kind="auto_verified", weight=0.0)` for P4-B4. Weight 0 because it records how the
  finding was confirmed rather than a link component, so the weight-sum invariant still holds.
- **B-16 (404 canary probe, Phase 4 item 8, DAST half):** (a) An error handler that echoes the
  request path is reachable from any unknown URL, not from a route parameter, so no per-parameter check
  can find it. `xss.probe_unknown_path` sends one GET whose path segment is the percent-encoded Appendix B
  body canary `sdcRND<"'>` (no new payload, R4; through the scope-guarded client, R3), and on an HTML
  response containing `canary<` raw re-probes once with a fresh canary. (b) The finding is
  `dast.xss.unknown_path`, CWE-79, GET, `route_id=None`, `param=None`, confidence 0.8 (below a
  parameter reflection's 0.9: the path is not a parameter the user controls in a form); a 5xx debug
  traceback echo is suppressed at 0.5 as in B-15. (c) It runs once per scan right after the passive
  pass, outside the time budget, and is counted with the host-wide findings
  (`stats["unknown_path_probe"]`). (d) It is reported **runtime-only**: the matching SAST finding (bench
  VF02) has no entry route, and the hard route gate is not relaxed for it (prefer a missed link over a
  wrong one). Bench runtime detection 2/3 -> 3/3; Mock A unchanged.
- **B-15 (traceback-XSS suppression, Phase 4 item 5):** (a) A canary echoed raw inside a 5xx debug
  traceback is a symptom of the verbose-error finding (`dast.passive.verbose-error`, CWE-209) that the
  passive pass already reports, not a separate XSS sink. When the proving response is >= 500 and
  matches `passive.ERROR_MARKERS`, `xss.run` returns the finding with `suppressed=True`,
  `suppress_reason="dast:debug-traceback-reflection"`, confidence 0.5 and an evidence note naming the
  verbose-error rule. It is kept, not dropped, so the evidence stays auditable. If the other Appendix B
  probe reflects in a non-error page, that unsuppressed finding wins (no new payloads). (b)
  `correlate.matcher.generate_candidates` skips suppressed runtime findings, as it already did for
  code. (c) `correlate.issues.is_suppressed` is extended, additively to D-12, to "the issue has findings
  and every code and runtime finding is suppressed", so a suppressed runtime-only issue sorts last and
  is not reported. A Confirmed issue always holds an unsuppressed runtime finding, so it cannot flip;
  the golden fixture is reproduced unchanged. (d) Mock A moved three runtime-only XSS issues
  (`/api/crash`, `/docs/<path:name>`, `/download`) to the suppressed bucket, all confirmed by hand as
  500 traceback pages. Unplanted 6 -> 3, false alarms 0/22 -> 0/19, other section-4 metrics
  unchanged; bench unchanged.
- **B-14 (eval: exact planted match beats fuzzy decoy overlap, Phase 4 item 4):** (a) Appendix C's
  ±3-line fuzz applies to decoys too, so a decoy's window can cover a genuine planted vuln a few lines
  away: Mock A decoy D01 (`db.py` 32-35, fuzzed [29, 38]) swallowed the Confirmed M02 SQLi at
  `db.py:29`, scoring one true positive as a false alarm as well. (b) Rule: a code finding counts
  against a decoy only if it fuzzy-matches the decoy **and** either overlaps the decoy's unfuzzed range
  or exactly matches no planted vuln (same file + CWE family, overlapping the planted range with no
  fuzz). Exact-vs-exact overlap stays a false alarm (pessimistic). (c) The same rule picks the decoy ids
  joined in the wrong-link count, so false alarms and wrong links never disagree. Detection matching,
  `LINE_FUZZ` and Mock A's answer key are unchanged. (d) **Changes reported numbers:** re-eval of the
  item 3 issues files gives Mock A false alarms 1/22 -> 0/22 (planned as 1/21 against the pre-item-3
  baseline; item 3 added one reported issue); bench unchanged; golden `fixtures/expected_metrics.json`
  still reproduced. Dev A FYI logged under "Needs Dev A" in `PROGRESS_Dev2.md`.
- **B-13 (SQLi status-transition rule, Phase 4 item 3):** (a) Error-based SQLi needs the target to
  leak DB error text; with Flask debug off Mock A's `POST /login` returns a bare 500 page and M02 was
  missed. We add `dast.sqli.status` as a **last resort**, run only after error-based and boolean
  differential both miss, using only Appendix B shapes already sent (`orig'`, `orig"`,
  `orig' AND 'RND'='RND`, the benign value; no timing, R4). (b) It fires only when the baseline is
  stable and every baseline response is 2xx/3xx, `orig'` is 5xx and a repeat is 5xx again, `orig"` is
  **not** 5xx (a handler that rejects any quote is not SQL-specific), the balanced
  `orig' AND 'RND'='RND` is **not** 5xx (rules out `int()`-style conversion of anything non-numeric),
  and a benign control sent afterwards is **not** 5xx. `_error_based` now also returns its per-suffix
  responses so the `'` and `"` requests are reused, not resent; the rule adds three requests.
  (c) Hand-probe on Mock A debug off (`flask --app app run -p 5052`, unedited), `POST /login`
  `password=test`: `username=test` 302, `test'` 500, `test"` 302, `test')` 500, `test'"` 500,
  `test' AND 'abc'='abc` 302, `test' AND 'abc'='abd` 302 - exactly the shape the rule needs.
  (d) Proof stays `error` (no new contract value) at **confidence 0.65** (error string 0.9, boolean
  0.8); the evidence says it is a status transition, not an error string. `verify.CONTROL_SIGNALS`
  gets `dast.sqli.status: status >= 500`, so the re-test's benign control must not be a 5xx.
  (e) Accepted residual risk: non-SQL code that treats only `'` as a quote (a hand-rolled tokenizer
  or expression evaluator) and crashes on an unbalanced one while tolerating `"` and balanced quotes
  would be reported as SQLi. A baseline that is 4xx (e.g. 401 on bad login)
  is not used, so such endpoints are still missed.
- **B-12 (differential command injection, Phase 4 item 2):** (a) Sinks like `os.system` run the
  shell but return only an exit code, so the evaluated-marker rule cannot see them. We add a
  differential mode that uses the **same six Appendix B payloads** (no new shapes, no timing, R4).
  (b) A plain "response differs from baseline" test was rejected: every payload contains a space and
  shell metacharacters, so any safe handler that validates input or reacts to odd values also differs.
  We require the **shell-semantics split** instead. `;`, `|` and newline make the injected `echo` the
  last command, so they must all give the same reflection-stripped response, and it must differ from
  the stable baseline in body but not status. `$(...)` and backticks only change the argument, so
  both must match the baseline. The `;` result must reproduce and a benign control must match the
  baseline. `&&` is ignored because its outcome depends on whether the first command passed.
  (c) Reflections of the payload and the original value are removed (raw, JSON-escaped, HTML-escaped,
  URL-quoted) before fingerprinting, so a page that only echoes the value never qualifies.
  (d) Confidence is **0.7** (marker stays 0.9): the evidence is inferred from response shape, and a
  filter that blocks `;`/`|`/newline but not `$`/backtick could in principle mimic it. A blind sink
  whose benign value already succeeds (same outcome as `echo`) is missed; we accept that.
  (e) `verify.SELF_CONTROLLED_RULES` marks the rule as carrying its own control, because the generic
  "benign value must not show the signal" control cannot discriminate a response difference.
- **B-11 (path-parameter injection, Phase 4 item 1):** (a) `seed_endpoints` used to drop PATH
  params, so a route like `/docs/<path:name>` was only ever requested with its benign sample. It now
  attaches one PATH `Param` per path segment that is **exactly one** `<...>`/`{...}` token, in any
  position (Flask name after the `:`, FastAPI name before it), valued with the converter sample.
  (b) `Param.segment` holds the segment index **counted from the end** (negative), so joining the
  template onto a base URL with its own path prefix does not shift it; `None` (crawled or hand-built
  params) keeps the old "last segment" behaviour. (c) A segment mixing a token with literal text
  (`<id>.json`) is **skipped**: replacing the whole segment would drop the literal and probe a
  different route, and splitting it is not worth the complexity yet. (d) Injected values are
  percent-encoded with `quote(value, safe="")`, so `/` inside a payload stays inside the one segment;
  the pre-encoded `..%2f` Appendix B form is spliced in verbatim (as B-03 already does for query
  strings) so the target sees `%2f`, not `%252f`. (e) `test_seed_endpoints_fills_path_and_keeps_query_params`
  asserted `param_names() == {"q"}`, which encoded the bug; it now expects `{"id", "q"}` with `id` at
  PATH, value `1`, segment `-1`. That is the fix, not a weakened test. (f) On Mock A at :5050 M08 is
  still missed because the deep checkout path puts `/etc/passwd` 7 levels up while Appendix B's
  deepest form climbs 6, and Werkzeug merges the `//` of the absolute form into a 308. Deeper
  payloads would break R4, so we accept the environment-dependent miss; the same unmodified app run
  from a shallow directory is detected and linked.
- **B-10 (provenance, Phase 4):** Dev B Phase 4 items 1-5, 8 (DAST), P4-B3, P4-B4 were run by an agent on Dev A's machine on Dev B's behalf.

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
