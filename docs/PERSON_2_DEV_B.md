# Person 2 — Dev B task list (runtime + correlation + reports)

You are **Person 2 / Dev B**. Person 1 initialised and pushed the repo; start by cloning and
running it (see [`SETUP.md`](SETUP.md) → `make setup && make check && make doctor`). Then work
top to bottom. Every task ends with `make check` green and a one-line update in
[`PROGRESS.md`](PROGRESS.md). Branch per task `b/<task-id>`, merge to `main` after check passes.
**Never edit Dev A's files** (see [`PLAN.md`](PLAN.md) ownership). **All `git add` / `git commit` /
`git push` are human-only (Person 1 owns the remote) and hard-blocked for AI agents by the
`block-git-writes` hook; agents change files only.**

Your ownership: `FlowStopper/config.py`, `storage.py`, `scope.py`, `cvss.py`,
`FlowStopper/dast/**`, `FlowStopper/correlate/**`, `FlowStopper/report/**`,
`FlowStopper/evalkit/**` (except the shared `keyschema.py`), and `apps/mock_b/**` (held out).
You add CLI commands by filling in `dast/commands.py`, `correlate/commands.py`,
`report/commands.py`, `evalkit/commands.py` — **do not edit `cli.py`** (A owns it; it already
imports your command functions).

---

## Phase 0 — foundations (do right after cloning)

- [x] **P0-B1 · `scope.py`** scaffolded; **implement + unit-test it now** (first real code): allow-list
  from `ALLOWED_HOSTS` (default `localhost,127.0.0.1,::1` + explicit compose service names); refuse
  any other hostname **even if it resolves to a private IP**; re-check on every redirect hop; refuse
  non-http(s) schemes; `--allow-host` override logs a WARNING. Tests: external refused, redirect-to-
  external refused, allow-listed accepted. This is rule R3 and gates all of DAST.
- [x] **P0-J3 · `cwe.py`** written (shared) — confirm `get_cwe(89).vector` etc. work for your code.
- [x] **P0-J4 · fixtures** present — these are your correlator/eval oracle. Read
  [`../fixtures/README.md`](../fixtures/README.md).
- [x] **P0-J2 sign-off** — reviewed `models.py` / `cwe.py` / `ids.py` / `keyschema.py`; **Dev B
  declares them final (2026-10-31), no changes requested** — all of Phase 1 (incl. the eval metrics
  that reproduce `fixtures/expected_metrics.json`) was built against them unchanged. Awaiting Person 1
  to tag `contract-v1`.
  After the tag, only additive changes, logged in [`CONTRACT_CHANGES.md`](CONTRACT_CHANGES.md).
- [ ] **P0-J5 (you + A, local only)** help read the organisers' app/key into the git-ignored
  `docs/target_notes.local.md`.

## Phase 1 — runtime foundations (1:00–4:00)

- [ ] **P1-B1 · `dast/client.py`** — async `httpx.AsyncClient`; **every request goes through
  `scope.py`**; redirects **not** followed by default (manual, in-scope only); cookie jar; timeouts
  (connect 3 s / total 10 s); concurrency limiter (default 20) + global rate cap; retry once on
  reset. Optional auth (static headers/cookies or a login POST). Record every exchange with
  redaction (R7); body ≤ 64 KB memory / ≤ 2 KB stored; build `repro_curl`.
- [ ] **P1-B2 · `dast/discovery.py`** — seed concrete requests from each `Route` (sample path params
  by converter: `1`/`test`/`a.txt`; attach known params with benign values); crawl same-origin
  depth ≤ 3, ≤ 300 URLs (links, forms, `fetch`/`axios` literals; read `/robots.txt`, `/sitemap.xml`,
  `/openapi.json`); emit `Endpoint`s; merge seeded + crawled, **seeded params win**.
- [ ] **P1-B3 · `dast/baseline.py`** — two baseline requests → fingerprint `(status, length bucket,
  normalised body hash, timing)`; mark endpoint "unstable" if baselines differ; `differs(a,b)`
  ignoring volatile content (timestamps, CSRF tokens, request IDs via regex).
- [ ] **P1-B4 · `dast/checks/sqli.py` + `xss.py`** — check interface
  `async def run(ctx, endpoint, param) -> list[Finding]`; payloads **only** from spec Appendix B;
  each finding carries `payload/proof/evidence/request/response_excerpt/repro_curl`.
- [ ] **P1-B5 · `evalkit/metrics.py` + tests** — implement spec §4 definitions + Appendix C matching;
  must reproduce `fixtures/expected_metrics.json`. (`keyschema.py` already done + tested.)
- **Exit (B):** `FlowStopper dast <url> --routes routes.json` finds SQLi + XSS on Mock A (or the real
  app) with full evidence; `FlowStopper eval` computes metrics on fixtures.

## Phase 2 — checks, verify, storage, **correlator** (4:00–8:00)

- [ ] **P2-B1 · `checks/cmdi.py` / `traversal.py` / `redirect.py`** — same interface + evidence;
  payloads from Appendix B (cmdi arithmetic marker; traversal read-only `/etc/passwd`; redirect to
  `*.invalid`, **never follow**).
- [ ] **P2-B2 · `checks/passive.py`** — host-wide findings reported **once per host** with affected
  paths in `evidence`: security headers, cookie flags, permissive CORS (`Origin: https://sdc-probe.invalid`),
  version banners, verbose errors/debug, exposed files (`/.git/HEAD`, `/.env`, `/robots.txt` info-only),
  directory listing. All `RUNTIME_ONLY`.
- [ ] **P2-B3 · `dast/verify.py`** — re-test each hit with a **second canary** + a **control**; report
  only if the second canary reproduces and the control does not; collapse payload hits per
  `(cwe, route_id|path, param)` into one finding (strongest proof; others in `raw`).
- [ ] **P2-B4 · `dast/runner.py`** — build endpoints → run applicable checks concurrently under the
  concurrency cap + **time budget** (`--time-budget`, default 240 s; on exceed stop cleanly,
  `stats.truncated=true`); routes-first ordering. Method policy GET/POST/HEAD/OPTIONS; PUT/PATCH only
  `--allow-mutating`; **DELETE never**. CLI in `dast/commands.py`.
- [ ] **P2-B5 · `storage.py`** — SQLite `scans / findings / issues / scan_issues`; upsert on
  `issues.id` (FR-6).
- [ ] **P2-B6 · `correlate/**` (the judged core)** — build against fixtures first:
  1. `dedupe.py` collapse duplicates.
  2. `matcher.py` candidates with the **hard route gate** (route_match 1.0/0.9/0.8/0 as in spec) +
     param_match + method_match + specificity.
  3. `scoring.py` `score = 0.50·route + 0.35·param + 0.10·method + 0.05·specificity`; constants in
     `CorrelateConfig` (`link_min=0.70`, `ambiguity_margin=0.10`).
  4. `issues.py` greedy **one-to-one** assignment ≥ `link_min`; **ambiguity rule** (best vs 2nd <
     margin and param doesn't separate → do **not** link; emit separate + `ambiguity_penalty`).
     Prefer a missed link over a wrong link.
  5. Build one `Issue` per linked pair; unlinked code → `CODE_ONLY`, unlinked runtime →
     `RUNTIME_ONLY`; IDs per spec §7; labels per FR-7.
  6. Risk via `cvss.py` (implement CVSS 3.1 base formula — must reproduce `cwe.BASE_SCORES`) ×
     exploitability factor; deterministic sort (Confirmed first, then risk, severity, CWE, id).
  7. **Idempotency:** twice on identical input → identical IDs/counts (test required).
- [ ] **P2-B7 · `apps/mock_b/` (HELD OUT)** — FastAPI shop (~22 routes) deliberately different from
  Mock A (`routers/services/repositories/`, pydantic bodies, `include_router` prefixes); same *kinds*
  of bugs (≥8 pairs across all 5 injection CWEs, 3 code-only secrets, 3 runtime-only, ≥6 decoys) +
  `answer_key.json`. **A must not read this; keep it out of shared discussions until Phase 6.**
- **Exit (B):** correlator passes fixtures incl. the ambiguous case (no wrong link); idempotency
  passes; DAST hits all five injection types + passives on Mock A with ≥ 80% runtime detection.

## Phase 3 — integration (8:00–9:30, joint)

- [ ] **P3-B1 · `eval` on the real app** — `FlowStopper eval --key keys/answer_key.json --scan <id>`
  prints the §4 table and writes `docs/metrics/<ts>.json`. Write `evalkit/convert_organiser_key.py`
  (git-ignored input) to convert the organisers' key into our Appendix C format once it's known.
- [ ] **P3-J2 (joint)** triage into `docs/BACKLOG.md` ordered by metric impact.

## Phase 4 — DAST + correlator tuning & bonuses (9:30–12:30)

- [ ] **P4-B1** DAST backlog: missed endpoints/params, weak evidence, extra Appendix-B payload
  variants; add a **second-order XSS** pass if the key has stored XSS (re-fetch pages after writes,
  report at the writing endpoint). *(Cut item #5 if slipping.)*
- [ ] **P4-B2** Tune `link_min`/`ambiguity_margin`/weights with the harness; add a fixture for every
  wrong link found. Target wrong links < 5%.
- [ ] **P4-B3 · `correlate/explain.py` (B-3)** — every linked issue carries human-readable
  `reasons: list[LinkReason]`; always include `same_cwe`.
- [ ] **P4-B4 · `correlate/autoverify.py` (B-1)** — for each `CODE_ONLY` with `cwe∈{89,78,22,601,79}`,
  a known `entry_route` + `source_param`, run the matching check **only** against that route/param;
  on success add the runtime finding, `verified_by="auto-verify"`, re-link → `CONFIRMED`. Respect the
  time budget (run last). *(Cut item #3 if slipping.)*

## Phase 5 — reports (12:30–14:00)

- [ ] **P5-B1 · `report/html.py` + Jinja** — self-contained page + per-issue detail: label badge,
  risk/CVSS, URL+method+param+payload+proof, file:line+highlighted snippet, CWE+OWASP link, evidence,
  "why linked" (B-3), fix (B-4), `curl`; collapsed Suppressed section. **Escape all dynamic text
  (R7)** — test with evidence containing `<script>`. Plain CSS, offline.
- [ ] **P5-B2 · `report/sarif.py` (B-6)** — SARIF 2.1.0; one run, rule per CWE, result per issue;
  `level` by severity; code `physicalLocation`, runtime via `webRequest/webResponse` (fallback
  `properties`); `partialFingerprints`=issue id. `scan --fail-on confirmed:high` exits `2`. Tests:
  SARIF structure + CI-gate exit code.
- [ ] **P5-B3 · `report/fixes.py` (B-4)** — one plain-English template per CWE family filled with the
  issue's function/param/file: what's wrong, minimal fix example, one prevention tip. Deterministic.
  *(Cut item #2 if slipping → one generic sentence per CWE.)*

## Phase 6 — generalisation (14:00–15:00, joint)

- [ ] **P6-J1/J2/J3** unseal Mock B, run pipeline + eval, record first run before changes, fix only
  **generic** behaviours (R6), no regression on real app / Mock A.
- [ ] **P6-B1 · `diff` (B-5, OPTIONAL)** — `FlowStopper diff <scanA> <scanB>` → new/fixed/open by
  `Issue.id`; only if everything else is done. *(First on the cut list.)*

## Phase 7 — release (15:00–16:00)

- [ ] **P7-B1** `docs/ARCHITECTURE.md` (pipeline diagram + correlation algorithm & scoring formula),
  `docs/LIMITATIONS.md` (honest limits), final metrics tables in `docs/metrics/`.
- [ ] **P7-J1/J2 (joint)** clean-clone test; `requirements.lock`; tag `v1.0`; freeze; verify history.

---

### FR coverage you own
FR-2 (DAST), FR-5 (correlate), FR-6 (dedupe/idempotency), FR-7 (labels), FR-8 data, FR-9
(prioritised list). Bonuses B-1, B-2(*help*), B-3, B-4, B-6, and B-5 if time.
