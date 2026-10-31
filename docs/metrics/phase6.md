# Phase 6 — generalisation rounds on Mock B (P6-J2, P6-J3)

Mock B (`apps/mock_b`, key `apps/mock_b/answer_key.json`) is the held-out FastAPI app. Its first run,
before any change, is frozen in [`mock_b_first_run.json`](mock_b_first_run.json). Each round has a
small fixed goal, applies only generic fixes (R6), and re-measures all three targets **in Docker**
(the deep host path hides path traversal, see the round 1 brief), before and after, with:

```bash
FlowStopper scan --source <src> --target <url> [--auth-config out/b/auth.json] --out out/p6rN_<name>_<before|after>
FlowStopper eval --key <key> --issues out/p6rN_<name>_<before|after>/issues.json --out out/p6rN_<name>_<before|after>/metrics.json
```

Targets: Mock B `apps/mock_b` on `:8090`; Mock A `apps/mock_a` on `:5050`; bench
`bench/vulnerable-flask-app/src` on `:8100`, scanned authenticated with `out/b/auth.json`.

## Round 1 — 2026-11-01

Goal: Mock B correct links ≥ 7/10 with no metric worse on any target and 0 wrong links. **Met.**

`python -m apps.mock_b.selfcheck`: all planted bugs fire and all decoys are safe (26 routes mounted).

### Triage of every Mock B miss (round 1 before)

Root causes were confirmed by probing synthetic FastAPI trees with `run_sast`, by `curl` against the
Docker app, and by reading the scanner code.

| Item | Bucket | Root cause | Owner area | Status |
| --- | --- | --- | --- | --- |
| B02 SQLi, `POST /accounts/signin` `handle` (pair, runtime found) | SAST miss → link miss | A pydantic-typed handler param was expanded into JSON route params, but the taint seed matched only declared names, so the param itself was untainted and `body.field` reached the sink clean. | SAST (`sast/taint/sources.py`, `summaries.py`, `routes/fastapi.py`) | **Fixed** (A-65): now Confirmed |
| B06 cmdi, `POST /ops/archive` `tag` (pair) | SAST miss + DAST miss | SAST: same root cause as B02 (fixed, now Code only). DAST: blind. The `;echo` output is appended to a log file by the command's own redirect, and the response returns only the first `echo`. Only timing/out-of-band payloads could prove it, and R4 forbids them. | SAST (fixed) / DAST | SAST half **fixed**; DAST half **deferred, out of reach under R4** |
| B04 template XSS, `GET /catalogue/detail/{sku}` `label` (pair, runtime found) | SAST miss → link miss | `sinks.template_name` does not read Starlette's keyword form `TemplateResponse(request=..., name="x.html", context={...})`: `name` is not in `TEMPLATE_NAME_KEYWORDS`, so no template is resolved and no sink fires. The positional form already works. Adding `name` globally would break Flask `render_template("x.html", name=v)` (where `name` is a variable), so it must be specific to `TemplateResponse`. | SAST (`sast/taint/sinks.py`) | **Deferred** (round 2 candidate #1: cheap, +1 link, +1 code) |
| B10 open redirect after sign-in, `POST /accounts/signin` `onward` (pair, code found) | DAST miss | The redirect only happens with valid credentials in the JSON body. Without valid credentials the route returns 401 before the redirect (checked with `curl`), and the scan had no credentials to send. A fix would let an auth-config login step supply the sibling body fields when the fuzzer probes that same login route. | DAST (`dast/runner.py`, auth) | **Deferred** (medium; needs a generic "login route" rule) |
| B32 session cookie flags, `POST /accounts/signin` (runtime only) | DAST miss | Same as B10: the cookie is set only on a successful sign-in. The passive cookie check reads only the sampled GET responses, never a login response. | DAST (`dast/checks/passive.py`) | **Deferred** (run cookie checks on the login response) |
| B33 verbose error, `GET /ops/boom` (runtime only) | DAST miss | Passive sampling requests only the first 5 GET paths alphabetically (`SAMPLE_PATHS = 5`), and `/ops/boom` takes no params, so no active check requests it either. The random 404 probe does not reach the exception handler. Confirmed by `curl`: the page returns `Traceback (most recent call last)`, which `ERROR_MARKERS` matches. | DAST (`dast/checks/passive.py`) | **Deferred** (round 2 candidate #2: also check param-less GET routes for error markers) |
| 2 unplanted secrets in `apps/mock_b/selfcheck.py` | none (informational) | The selfcheck script inside the app tree holds the demo credentials as literals. They are real literals, are not decoys, and are not counted as false alarms. | SAST | **No action** (A-66) |
| Wrong links | none | 0 before, 0 after. | — | — |
| False alarms | none | 0 before, 0 after (no decoy reported). | — | — |
| Suppression errors | none | All 8 decoys suppressed or not reported; new suppressed `safe:sql-parameterised` finding on the parameterised password query (correct). | — | — |

Ranked by cost per safe correct link: B02 (done) → B04 → B10 → B06 (blocked by R4).

### Before / after (Docker, same environment)

| Target | Metric | Round 1 before | Round 1 after |
| --- | --- | --- | --- |
| Mock B | Code detection | 10/13 | **12/13** |
| Mock B | Runtime detection | 10/14 | 10/14 |
| Mock B | Correct links | 6/10 | **7/10** |
| Mock B | Wrong links | 0/6 | 0/7 |
| Mock B | False alarms | 0/17 | 0/18 |
| Mock A | Code detection | 13/13 | 13/13 |
| Mock A | Runtime detection | 12/13 | 12/13 |
| Mock A | Correct links | 9/10 | 9/10 |
| Mock A | Wrong links | 0/9 | 0/9 |
| Mock A | False alarms | 0/19 | 0/19 |
| Bench | Code detection | 4/4 | 4/4 |
| Bench | Runtime detection | 3/3 | 3/3 |
| Bench | Correct links | 1/2 | 1/2 |
| Bench | Wrong links | 0/1 | 0/1 |
| Bench | False alarms | 0/11 | 0/11 |

Mock A and bench issue sets (id, label, CWE) are identical before and after. Mock B: the B02
Runtime-only issue became Confirmed, B06 appeared as Code only, and one new suppressed issue appeared.

### Fixes

- A-65 · FastAPI pydantic body params are seeded as JSON containers, so `body.field` is the JSON param
  `field` (`sast/routes/fastapi.py`, `sast/taint/sources.py`, `sast/taint/summaries.py`; tests in
  `tests/test_sast_taint.py`).

### Deferred (round 2 starts here)

1. B04: Starlette `TemplateResponse(name=..., context=...)` keyword form (SAST, cheap, +1 link).
2. B33: error-marker check on param-less GET routes beyond the 5 passive samples (DAST, runtime only).
3. B10 + B32: probe the auth-config login route with the configured credentials, and run the cookie
   checks on the login response (DAST, medium).
4. B06 runtime half: blind command injection, out of reach under R4 (no timing payloads).
