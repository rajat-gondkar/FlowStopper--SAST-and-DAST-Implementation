# Backlog — ranked by metric impact (P3-J2 triage)

Every miss, wrong link and false alarm from a full pipeline run, sorted into the spec's buckets and
ranked by what fixing it is worth. This drives Phase 4; nothing here was fixed during triage.

> **Measured on Mock A, not the organisers' app.** `target_src/` and `keys/` are still empty, so the
> real-app baseline (**P3-J1**, `docs/metrics/baseline.json`) has not been produced and this is not a
> substitute for it. The spec allows Phase 4 tuning against Mock A, so these numbers are a legitimate
> starting point — but every impact estimate below is *expected*, and must be re-measured on the real
> app once it lands. Items are marked where the real app is expected to behave differently.

## The run these numbers come from

Real SAST + real DAST + real correlator + real store, against a live Mock A (scratch copy outside the
repo), `--seed 0`. Mock A was run **with `--debug`**, which is what its README and `app.py` specify.

> That flag matters more than it looks. On a first pass without it, Flask returned a generic 500 and
> two planted bugs became invisible: the SQL error text M02 relies on, and the traceback R03 relies
> on. Runtime detection read 61.5% and correct links 60%. The scanner had not changed — the harness
> was misconfigured. **See item 3: on the real app, debug will probably be off, so the honest
> expectation is closer to the lower numbers.**

| Metric | Result | Good | Great | Status |
|---|---|---|---|---|
| Code detection | 13/13 — 100% | >60% | >85% | **great** |
| Runtime detection | 10/13 — 76.9% | >50% | >80% | good |
| Correct links | 7/10 — 70% | >50% | >80% | good |
| Wrong links | 0/7 — 0% | <20% | <5% | **great** |
| False alarms | 1/21 — 4.8% | <30% | <10% | **great** |
| Run time | 4.7 s | <15 min | <5 min | **great** |

Unplanted (informational, not penalised): **5**.

## Triage buckets (spec P3-J2)

| Bucket | Count | Items |
|---|---|---|
| SAST miss | **0** | — every planted code location was found |
| DAST miss | **3** | M05, M06 (command injection), M08 (path traversal) |
| Link miss | **0** | all 3 unlinked pairs are downstream of the DAST misses |
| Wrong link | **0** | — |
| Decoy false alarm | **1** | D01 — a line-fuzz collision with a genuine finding, see item 4 |
| Suppression error | **0** | D04 correctly suppressed as `safe:subprocess-list-no-shell` |

**The correlator is not the bottleneck.** Every pair whose two halves were both found got linked, at
score 1.0, with zero wrong links. All three link misses are missing *runtime* halves. So Phase 4
effort belongs in DAST coverage, not in correlation tuning — `link_min` and `ambiguity_margin` have
nothing to prove here yet (revisit when the real app produces genuine ambiguity).

---

## 1. Path parameters are never tested — Owner: **B** · cost: small · P4-B1

**Fixes M08** (path traversal via `/docs/<path:name>`) and opens a whole untested class.

Root cause: `discovery.seed_endpoints` fills path parameters into the concrete URL and then **drops
them**, so they are never offered to the checks. Evidence from the run's discovery dump:

```
GET /docs/a.txt        src=seed  params=[]        <- name: gone, nothing to inject
GET /api/orders/1      src=seed  params=[]        <- order_id: gone
GET /product/test      src=seed  params=[('note', ...)]   <- note kept, id dropped
```

`injectable_params()` therefore returns nothing for those endpoints and **no check runs at all** on
them. The bug is not in the traversal check or the payloads — both work. Verified by hand:

```
GET /docs/..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd   ->  200, body contains root:x:0:0:
```

and httpx preserves that encoding (`/docs/..%2F..%2F..%2Fetc%2Fpasswd` arrives intact), so the
existing `build_request` PATH handling already sends the right bytes. Attaching path params is the
whole fix.

- Expected impact: runtime detection 10/13 → **11/13 (84.6%, crosses into "great")**; correct links
  7/10 → **8/10 (80%)**.
- **Real app: likely worth more than on Mock A.** REST paths (`/api/orders/<id>`) are the norm there,
  and right now every one of them is a blind spot.
- Also fix while in there: `build_request` substitutes only the **last** path segment, so a template
  like `/api/<tenant>/orders/<id>` can only ever be injected at `id`. And httpx *normalises* raw dot
  segments (`/docs/../../x` → `/x`), so the percent-encoded form is the only viable one — keep it.

## 2. Command injection is only detected when the command's output is echoed — Owner: **B** · cost: medium · P4-B1

**Fixes M05** (`/api/ping`). Not M06 — see "accepted limitations".

Root cause: `checks/cmdi.py` reports only when the **evaluated** marker `<canary><A*B>X` appears in
the response body. `os.system` returns an exit status and sends the command's stdout to the server's
console, so the marker can never appear, even though injection succeeds. The response does change,
though — it leaks the exit code:

```
GET /api/ping?host=test                        ->  {"exit": 512, "host": "test"}
GET /api/ping?host=test;echo sdcx$((13*17))X   ->  {"exit": 0,   "host": "..."}     <- command ran
```

Proposal: add a **differential** mode to the cmdi check, mirroring the SQLi one — same Appendix B
payloads (R4 unaffected: this changes the detection rule, not what is sent), requiring a stable,
repeatable difference from baseline with a clean control, reported at lower confidence (~0.7) than a
marker hit (0.9) because a response difference is weaker evidence that a shell ran.

- Expected impact: +1 runtime, +1 link. With item 1: runtime **12/13 (92.3%)**, links **9/10 (90%)** —
  both "great".

## 3. SQL injection detection leans on the app leaking DB errors — Owner: **B** · cost: small-medium · P4-B1

**Mock A impact today: zero.** Ranked third anyway because it is the item most likely to decide the
real-app score.

Evidence, from running the same scan twice: with `--debug` off, M02 (`POST /login`, `username`) was
missed completely; with it on, it was caught by `proof=error` matching `sqlite3.OperationalError` in
the body. So that detection depends on the target echoing its database error text — which a
production-configured app will not do. The boolean-differential fallback did not rescue it either:
a failed login redirects identically whether the injected condition is true or false, so the
false-variant never differed.

Proposal: add a **status-transition** rule — baseline is 2xx/3xx, the quote payload yields 5xx,
repeatable across two attempts, and the benign control stays clean → report at lower confidence
(~0.6–0.7, `proof=error`). A 500 alone is not proof of SQLi, which is exactly why it needs the
repeat-and-control discipline already in `verify.py` and a lower confidence than an error-string
match.

- Expected impact on Mock A: **0** (already caught via error text). On the organisers' app: this is
  plausibly the difference between finding and missing most SQLi. Validate the rule when implementing
  it — the hypothesis that a quote payload reliably 500s with debug off still needs confirming.

## 4. A planted true positive is counted as a decoy false alarm — Owner: **B** (notify **A**) · cost: small · P4-B2

The single false alarm is not a wrong detection. Appendix C applies ±3 lines of fuzz to the **key's**
decoy range, so D01 (`db.py:32-35`, "parameterised query") expands to `[29, 38]` — which swallows
`db.py:29`, the genuine **M02** SQL injection in `db.find_user`. The offending issue is *Confirmed*
and matches M02 exactly, so it is simultaneously scored as a true positive and a false alarm.

Proposal: in `evalkit/metrics.py`, an exact planted-vuln match takes precedence over a fuzzy decoy
overlap — an issue that matches a planted vuln is not also a false alarm.

- Expected impact: false alarms 4.8% → **0%** (already "great", so this is about reporting honestly
  rather than chasing a target).
- Needs a `DECISIONS_Dev2.md` entry and Dev A's awareness, because it changes reported numbers.
- **Explicitly not doing:** moving Mock A's decoy or narrowing its line range to dodge the overlap.
  That is fitting the fixture to the metric, and it would hide the same collision on the real key.

## 5. XSS reported on debug traceback pages — Owner: **B** · cost: small · P4-B1

`GET /api/crash?n=` reflects `n` unescaped inside the 500 debug traceback, so the XSS check fires.
The reflection is real, but it is a symptom of the verbose-error issue (R03) that we already report
separately, so it reads as duplicate noise in the issue list.

Proposal: when the proving response is a 5xx carrying a debug-traceback marker, suppress the XSS
finding (or drop its confidence) and let the verbose-error finding stand.

- Expected impact: unplanted 5 → 4. **No metric change** — unplanted findings are not penalised; this
  is purely report quality for the judges.

## 6. Mock A's answer key looks incomplete — Owner: **A** · cost: small · P3/P4

Two of the five "unplanted" findings look like genuine planted-quality bugs that the key does not
list, which makes our reported detection rates slightly pessimistic:

- `POST /login`, param **`password`** — `find_user(username, password)` concatenates *both* values
  into the SQL, so the password is a second injection point at the same sink as M02. Confirmed by
  `proof=error`.
- `GET /download`, param **`file`** — the filename is reflected unescaped into an HTML response
  (separate from the M07 traversal at the same endpoint).

Either add them to `apps/mock_a/answer_key.json` or record here why they are deliberately out, so the
Phase 6/7 numbers stay honest. The other three unplanted findings are debug-mode artefacts and
correct: `/console` debug console (CWE-489), the version banner (CWE-497), and the `/api/crash`
reflection from item 5.

---

## Accepted limitations (no action planned)

**M06 — blind command injection at `POST /admin/backup`.** `subprocess.run(..., shell=True)` discards
the command's output and the handler always answers `{"status": "ok"}`:

```
name=test                      ->  {"status": "ok"}
name=t;echo sdcx$((13*17))X    ->  {"status": "ok"}      <- byte-identical
```

There is no non-timing signal, and a timing probe would need a `sleep` payload, which is **not in
Appendix B** — sending one would break R4, and `tests/test_checks_p2.py` asserts we do not. So this
stays undetected by design. It caps runtime detection at **12/13** on Mock A even with items 1 and 2
done. Recorded in `docs/LIMITATIONS.md`.

## If every actionable item lands

| Metric | Now | Items 1+2 | Items 1+2+4 |
|---|---|---|---|
| Runtime detection | 76.9% | 92.3% **great** | 92.3% **great** |
| Correct links | 70% | 90% **great** | 90% **great** |
| False alarms | 4.8% | 4.8% | **0%** |
| Code detection | 100% | 100% | 100% |
| Wrong links | 0% | 0% | 0% |

Items 1, 2 and 4 are all small-to-medium and all in Dev B's files. Item 3 shows no Mock A gain but is
the one to prioritise for the real app.

## Still to do before Phase 4 is grounded

- **P3-J1 baseline on the organisers' app** — blocked on `target_src/` + `keys/`. Everything needed is
  in place: convert the key, `FlowStopper scan`, then
  `FlowStopper eval --key keys/answer_key.json --scan latest --out docs/metrics/baseline.json`.
- **P0-J5 target notes** (`docs/target_notes.local.md`, git-ignored) — joint, once the app is released.
- Re-run this triage against the real app and re-rank; the ordering above assumes Mock A's shape.

---

## Addendum (Dev A): bench app run + Dev A items

The items above come from Mock A. The bench app (we45 Vulnerable-Flask-App, third-party, written by
neither of us) was scanned as part of P3-J1 (`docs/metrics/baseline_bench.json`). It scores lower and
is the better guide to how we'll do on an app we didn't write:

| Metric | Bench app | Status |
|---|---|---|
| Code detection | 3/4 (75%) | good |
| Runtime detection | 1/3 (33.3%) | **below** |
| Correct links | 0/2 (0%) | **below** |
| Wrong links | 0/0 | n/a |
| False alarms | 0/9 (0%) | great |

Per-item: VF01 SQLi code OK / runtime **miss**; VF02 404-page XSS code **miss** / runtime **miss**;
VF03, VF04 secrets OK; VF05 missing CSP OK.

## 7. DAST has no login support — Owner: **B** · cost: medium · P4-B1 · **rank first for the real app**

**Fixes the bench SQLi (VF01) runtime miss.** `POST /search` needs a JWT; without one every request gets
`{"Error": "Not Authenticated!"}`, so no check ever reaches the vulnerable code. SAST found the bug
correctly (`app/app.py:265`, `source_param=search`, `entry_routes=["POST /search"]`), so the pair
should link as soon as DAST can authenticate.

`FlowStopper/dast/config.py` has no auth fields at all, but spec P1-B1 asks for "static
headers/cookies, or a login step (POST credentials to a configured URL and keep the cookie jar)". For
the bench app the login returns the token in a response **header** (`Authorization`), not a cookie,
so the login step also needs a way to copy a response header onto later requests.

- Expected impact on the bench app: runtime 1/3 → 2/3, links 0/2 → 1/2.
- **Real app:** if its interesting routes are behind a login, this item decides most of the
  runtime and link scores. Rank it above item 1 there.
- Dev A follow-up: once the config exists, `FlowStopper scan` needs options to pass it through
  (P5-A2 CLI polish, or earlier if the real app needs it).

## 8. VF02: XSS in the 404 handler is missed by both sides — Owner: A + B · cost: medium · P4

The handler builds HTML with `'%s' % request.url` and passes it to `render_template_string`.
- **SAST (A):** `request.url` is not a taint source and `render_template_string` is not a sink. Both
  are generic Flask facts (not app-specific), so adding them is a fair P4-A1 rule.
- **DAST (B):** it only probes known routes. Reflection on an *unknown* path needs one extra request
  to a non-existent path carrying the canary, which fits the existing XSS payloads.
- The key marks this item as uncertain. Low priority unless the real app's 404 page reflects input.

## 9. SAST false positive: response content type set after construction — Owner: **A** · cost: small · P4-A1

Bench app `app/app.py:185` is reported as XSS:

```python
resp = Response(json.dumps({"Authenticated": True, "User": username}))
...
resp.mimetype = "application/json"  # line 189: makes the response JSON, not HTML
return resp
```

The XSS rule judges the response only at construction and doesn't see the later `resp.mimetype =` /
`resp.content_type =` / `resp.headers["Content-Type"] =` assignment. Generic fix: track those writes
on the response variable before it is returned. Not counted as a false alarm (no decoy there), but it
is reported noise, and the pattern is common in real apps.

## 10. Secrets in test code and seed data — Owner: **A** · cost: small · P4-A1 (decision)

Two "unplanted" bench findings: a seeded default login (`user.password = 'admin123'`, `app/app.py:63`)
and a credential dict in the app's own test file (`tests/e2e_zap.py:15`). Both are real hard-coded
credentials, so neither is a wrong detection. Decide whether files under `tests/` / `test_*.py` are
reported at lower confidence or not at all. Record the choice as a Dev A decision.

## 11. Remaining SAST items from the Phase 2 review — Owner: **A** · P4-A1 / P4-A2

Recorded in `docs/PROGRESS_Dev1.md` ("Phase 4 backlog"). None changes a current metric; all are
misses, never wrong answers:
- `render_template("x.html", **ctx)` (context splat) is not seen as a template sink.
- Sinks that no route can reach are dropped instead of being reported as `suppressed: unreachable`
  (needed by P4-A2, B-2 noise cut).
- `_is_abort` treats any unresolved `fail`/`exit`/`abort` call as ending the block.
- The fixpoint cap (10 rounds) is reached silently; log a warning.
- Receiver-based sink matching (`.open()`, `.read_text()`, `.raw`, `.extra`) is broad; check it for
  false positives on the real app.

## 12. Mock A listens on every network interface in debug mode — Owner: **A** · cost: small · now

`python app.py` runs `app.run(host="0.0.0.0", debug=True)`. That puts the Werkzeug debug console
(PIN-protected, but a code-execution console) on the local network, not just this laptop. Fix: default
to `127.0.0.1` and let the Dockerfile set `0.0.0.0` through an env var. This changes no scanner result.

## Answer to item 6 (Dev A)

Agreed that the key is missing the `password` injection point at `POST /login` and the reflection at
`GET /download`. Dev A will decide in P4 whether to add them as planted entries (which changes the
totals) or to list them as known extras, and will record the choice.

## Ownership summary for Phase 4

- **Dev B:** items 7, 1, 2, 3, 4, 5, plus the DAST half of 8.
- **Dev A:** items 9, 10, 11, 12, the SAST half of 8, plus the answer to item 6.
