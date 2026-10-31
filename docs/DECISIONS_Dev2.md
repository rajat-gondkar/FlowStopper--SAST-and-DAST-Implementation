# Decisions — Dev B (Person 2)

Dev B's own design decisions (ids `B-NN`, newest first). Joint/Phase-0 decisions are in the shared
[`DECISIONS.md`](DECISIONS.md); Dev A's are in [`DECISIONS_Dev1.md`](DECISIONS_Dev1.md). Using a `B-`
prefix keeps our ids from ever colliding with Dev A's `A-` ids.

> **Seeded by Person 1 during the per-dev docs split.** These are Dev B's two Phase-1 decisions, moved
> out of the old shared `DECISIONS.md` and renumbered from `D-18`/`D-19` (which had collided with
> Dev A's `D-18`/`D-19`). **Action for Dev B: done (2026-10-31)** — grepped
> `FlowStopper/` + `tests/` for `D-1[89]`: no code or test references existed (both decisions were
> only ever cited in the docs), so nothing needed renaming. The one remaining `DECISIONS D-12`
> citation in `correlate/issues.py` is correct: D-12 is a *shared* Phase-0 decision and still lives in
> [`DECISIONS.md`](DECISIONS.md).

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
- **B-02 (SQLi check, P1-B4)** _(formerly D-19)_: error-based evidence **short-circuits** the
  boolean-differential probe — when an error fires we report it at confidence 0.9 and skip the ~12
  extra differential requests, rather than running both to claim the spec's combined 0.95 (revisit in
  P4 tuning if the extra signal is worth the requests). The differential is also skipped when the
  baseline is *unstable* (can't trust the comparison), and error-based is skipped when the benign
  baseline page already contains a SQL-error string (can't attribute it). Payloads are exactly
  Appendix B; a test (`tests/test_checks.py::test_only_appendix_b_payloads_are_sent`) asserts nothing
  else is sent (R4).
- **B-01 (scope guard semantics, P0-B1)** _(formerly D-18)_: (a) `ALLOWED_HOSTS` env **replaces** the
  base allow-list rather than extending it (matches the `DastConfig.allowed_hosts` "env overrides"
  note and the SETUP/`make bench` usage, which list `localhost,127.0.0.1,::1` explicitly);
  `--allow-host` extras merge on top and log a WARNING. A stray empty/whitespace `ALLOWED_HOSTS=` is
  treated as unset (keeps the default) so it never refuses every target. (b) Matching is a pure string
  allow-list on the URL's parsed hostname — we **never resolve DNS** (R3), so an unlisted name is
  refused even if it would resolve to loopback/private. (c) IP *literals* are compared canonically via
  stdlib `ipaddress` (so `::1` == `0:0:0:0:0:0:0:1`), which resolves nothing; host names match exactly
  (no subdomain wildcards), case/port/trailing-dot normalised. Non-http(s) schemes and host-less URLs
  are refused.
