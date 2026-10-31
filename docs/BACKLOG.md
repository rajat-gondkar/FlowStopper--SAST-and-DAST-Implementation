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
