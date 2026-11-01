# FlowStopper: slide-by-slide content for the presentation

Each slide below has:
- **Title**: the slide heading.
- **On the slide**: the text or table to put on it (keep it short on the slide itself).
- **Visual**: a suggested picture, diagram or layout.
- **Say**: speaker notes (not on the slide).

Status markers used throughout, so the deck can colour-code them:

| Marker | Meaning |
|---|---|
| ✅ | Required by the problem statement, **done** |
| ⭐ | Bonus item, **done** |
| ➕ | Extra we added beyond what was asked |
| ⏸️ | Optional, **not done** (and why) |

The problem statement and its requirement IDs (FR-1…FR-10, R1…R8, B-1…B-6) come from
`FlowStopper_BUILD_SPEC.md`, sections 1 to 4.

**Suggested deck (24 slides, about 12–15 minutes):**

| # | Section | Slide |
|---|---|---|
| 1 | Intro | Title |
| 2 | Intro | The problem |
| 3 | Intro | What was asked (one-line goal) |
| 4 | Requirements | Compulsory requirements FR-1…FR-10 |
| 5 | Requirements | Vulnerability types required |
| 6 | Requirements | Bonus items B-1…B-6 |
| 7 | Requirements | Compliance rules R1…R8 |
| 8 | Requirements | Success targets |
| 9 | Solution | Architecture overview |
| 10 | Solution | SAST: the code scanner |
| 11 | Solution | Taint analysis in one picture |
| 12 | Solution | DAST: the runtime scanner |
| 13 | Solution | Safe payloads and proof |
| 14 | Solution | Correlation: the core |
| 15 | Solution | Correlation worked example |
| 16 | Solution | Labels, risk score, prioritised list |
| 17 | Solution | Auto-verify and noise cut (bonuses) |
| 18 | Solution | Outputs: report, SARIF, API, CLI, CI gate |
| 19 | Solution | Extras beyond the brief |
| 20 | Decisions | Key design decisions |
| 21 | Results | Mock A results |
| 22 | Results | Mock B (held-out) results + unseen-app score |
| 23 | Wrap-up | Limitations and what we'd do next |
| 24 | Wrap-up | Summary scorecard + demo / thank you |

---

## Section 1: Introduction

### Slide 1: Title

**On the slide**
- **FlowStopper**
- *SAST + DAST correlation engine for Python web apps*
- "Every real vulnerability, once: the code line that causes it and the request that proves it."
- Team name, member names, date.

**Visual:** logo or a simple icon of two streams (code / running app) merging into one.

**Say:** "FlowStopper scans an app's source code and the running app, and joins the two so a
developer gets one list of proven problems, each pinned to the exact line of code."

---

### Slide 2: The problem

**On the slide**

| | Code scanner (SAST) | Runtime scanner (DAST) |
|---|---|---|
| Reads | source code | the running website |
| Good at | the exact line | proving the bug is real |
| Bad at | many false alarms | no idea where in the code |

- Two tools → two long lists that don't agree → developers ignore both.
- **Missing piece: proof that a code finding and a runtime finding are the same bug.**

**Visual:** two lists side by side with question marks between them.

**Say:** "The value isn't in either list alone; it's in the link between them."

---

### Slide 3: What was asked

**On the slide**
> Build a tool that scans an app's **source code (SAST)** and its **running instance (DAST)**, then
> **correlates** the two so every real vulnerability appears **once**, with the **code line** that
> causes it, the **URL / parameter / payload** that proves it, a **risk score**, and a **fix
> suggestion**.

- Target language: **Python**. Flask primary; **FastAPI and Django** also required (to work on an
  unseen app).
- **What is judged most: correlation quality.**

**Visual:** the five outputs as icons: code line · request · risk score · fix · one list.

**Say:** "This is the brief in one sentence. The rest of the deck maps each part of it to what we built."

---

## Section 2: Requirements (what was asked) and our coverage

### Slide 4: Compulsory requirements, FR-1 to FR-10

**On the slide**

| ID | Requirement | Status | Where / how |
|---|---|---|---|
| FR-1 | SAST: file, line, type, severity, snippet | ✅ | `run_sast()`; every finding has file, line span, CWE, severity, snippet |
| FR-2 | DAST: URL, method, param, payload, evidence | ✅ | `run_dast()`; every finding has full request, payload, response excerpt, evidence, `curl` repro |
| FR-3 | Common finding format with CWE | ✅ | One `Finding` model (`models.py`) for both engines; CWE catalogue `cwe.py` |
| FR-4 | Route map (URL → handler function + line span) | ✅ | `extract_routes()` for Flask, FastAPI, Django |
| FR-5 | Correlate (same CWE + DAST route handled by the code holding the SAST finding) | ✅ | `correlate()`: CWE family + hard route gate + score |
| FR-6 | Merge duplicates, idempotent re-scans | ✅ | `dedupe_*()`; stable IDs (`ids.py`); same input → byte-identical output |
| FR-7 | Labels: Confirmed / Code only / Runtime only | ✅ | Every issue carries exactly one label |
| FR-8 | Issue detail for confirmed issues | ✅ | HTML report detail view + `GET /issues/{id}` |
| FR-9 | Prioritised list (Confirmed first, then risk) | ✅ | `sort_issues()`: label, then risk 0–10 |
| FR-10 | CLI + API + short README | ✅ | 7 CLI commands, FastAPI REST API, README |

**Headline:** **10 / 10 compulsory requirements done.**

**Visual:** a checklist with ten green ticks.

**Say:** "Every compulsory item is done and tested; about 800 automated tests run offline."

---

### Slide 5: Vulnerability types required

**On the slide**

| Required type | CWE | Code side (SAST) | Runtime side (DAST) | Status |
|---|---|---|---|---|
| SQL injection | 89 | ✅ taint to `execute()` etc. | ✅ error-based + true/false differential | ✅ |
| Cross-site scripting | 79 | ✅ HTML responses, `Markup`, templates `|safe` | ✅ unescaped canary reflection | ✅ |
| Command injection | 78 | ✅ `os.system`, `subprocess(shell=True)` | ✅ arithmetic marker + differential | ✅ |
| Path traversal | 22 | ✅ `open`, `send_file`, `Path.read_*` | ✅ read-only `/etc/passwd` probe | ✅ |
| Open redirect | 601 | ✅ `redirect()`, `Location` header | ✅ `.invalid` canary in `Location` | ✅ |
| Hard-coded secrets | 798 | ✅ names, key prefixes, entropy, config files | code only (by design) | ✅ |
| Passive runtime checks | 693, 1021, 1004, 614, 1275, 942, 209, 497, 538, 548 | — | ✅ headers, cookies, CORS, verbose errors, banners, exposed files, listings | ✅ |
| **Insecure deserialization** | 502 | ➕ `pickle`/`marshal`/unsafe `yaml` of request data | code only | ➕ |
| **Debug mode left on** | 489 | ➕ `app.run(debug=True)`, `FastAPI(debug=True)`, settings | ➕ debug console probe | ➕ |

**Headline:** **all 6 required types + passive checks, plus 2 extra types.**

**Visual:** a grid of bug-type tiles, green for required, blue for extras.

---

### Slide 6: Bonus items

**On the slide**

| ID | Bonus | Status | What we built |
|---|---|---|---|
| B-1 | Auto-verify Code-only findings with a safe probe | ⭐ Done | `auto_verify()` sends one targeted check per eligible issue; upgrades to Confirmed when proven |
| B-2 | Cut SAST noise (sanitised / unreachable → suppressed bucket) | ⭐ Done | Findings kept but marked `suppressed` with a reason (`safe:sql-parameterised`, `sanitized:html.escape`, `unreachable`); own report tab |
| B-3 | Explain every link (reasons + weights) | ⭐ Done | `link_reasons()`: every Confirmed issue lists each reason and its weight |
| B-4 | Plain-English fix suggestion per CWE | ⭐ Done | `fix_for()`: what is wrong / minimal fix with code / prevention |
| B-6 | SARIF 2.1.0 export + CI fail on Confirmed high | ⭐ Done | `to_sarif()` (validated against the OASIS schema); `scan --fail-on confirmed:high` → exit code 2 |
| B-5 | Scan diff (new / fixed / still open) | ⏸️ Not done | Optional, only if time remained. The groundwork is there: stable issue IDs and `first_seen_scan` / `last_seen_scan` in the database |

**Headline:** **5 of the 5 chosen bonuses done; the optional 6th (scan diff) left out.**

**Visual:** five gold stars and one grey star.

**Say:** "B-5 was explicitly marked optional in the plan. Because IDs are stable, it would be a
small addition."

---

### Slide 7: Compliance rules R1 to R8 (non-negotiable)

**On the slide**

| Rule | Meaning | Status | How we enforce it |
|---|---|---|---|
| R1 | Original work, no copied scanner code | ✅ | All engines written from scratch |
| R2 | Disclose every third-party component and AI tool | ✅ | `THIRD_PARTY.md` (versions, licences, AI-assistant statement) |
| R3 | Scan only authorised targets | ✅ | `scope.py` guard inside the HTTP client: every request and redirect hop checked against `ALLOWED_HOSTS`; no DNS used to decide |
| R4 | No harmful payloads | ✅ | Fixed payload catalogue only; a test asserts nothing else is sent; no time-based, destructive or exfiltrating payloads; no `DELETE` ever |
| R5 | Confidentiality of the organisers' code and key | ✅ | `target_src/`, `keys/`, `*.key.json` git-ignored; git history checked clean |
| R6 | No overfitting | ✅ | `tests/test_no_overfit.py` fails if any answer-key string appears in the tool; all fixes are generic rules |
| R7 | Safe by construction | ✅ | SAST parses only (`ast`), never imports/runs; reports HTML-escaped, no scripts; auth headers/cookies redacted; secret values masked |
| R8 | Only the organisers' app scanned in evaluation | ✅ | Mock apps clearly labelled as our own fixtures |

**Headline:** **8 / 8 rules, enforced by code and tests, not just documents.**

**Visual:** a shield icon with eight ticks.

---

### Slide 8: Success targets

**On the slide**

| Metric | Good | Great | Mock A | Mock B (held out) |
|---|---|---|---|---|
| Code detection | > 60% | > 85% | **100%** great | **100%** great |
| Runtime detection | > 50% | > 80% | **92%** great | **79%** good |
| Correct links | > 50% | > 80% | **90%** great | **80%** good |
| Wrong links | < 20% | < 5% | **0%** great | **0%** great |
| False alarms | < 30% | < 10% | **0%** great | **0%** great |
| Unseen app (correct links) | > 40% | > 65% | — | **60%** good (first run) |
| Run time | < 15 min | < 5 min | **~2 s** great | **~2 s** great |

**Visual:** a traffic-light table (green = great, yellow-green = good).

**Say:** "Measured against our own answer keys, in Docker. Not the organisers' score, but the same
metric definitions."

---

## Section 3: How it works (features)

### Slide 9: Architecture overview

**On the slide**
```
source code ──► SAST ──► routes + code findings ─┐
                  │ routes seed DAST             ├─► CORRELATE ─► AUTO-VERIFY ─► SQLite ─► HTML · SARIF · Markdown · API
running app ──► DAST ──► runtime findings ───────┘
```
- One command: `FlowStopper scan --source <folder> --target <url>`
- Entry point: `run_pipeline()` → `run_sast()` → `run_dast()` → `correlate()` → `auto_verify()` → store → reports

**Visual:** the pipeline as a left-to-right flow diagram with the five stage boxes.

**Say:** "SAST's route map is handed to DAST, so DAST tests every endpoint the code defines, not
just the ones a crawler happens to find."

---

### Slide 10: SAST, the code scanner

**On the slide**

| Step | Function | What it does |
|---|---|---|
| Index | `build_index()` | Parses every `.py` file (never runs it) and resolves imports |
| Routes | `extract_routes()` | Flask (blueprints, prefixes, factories, `MethodView`), FastAPI (`APIRouter`, `include_router`, pydantic bodies), Django (`path`, `re_path`, `include`, class views) |
| Call graph | `build_call_graph()` | Who calls whom; which functions each route reaches (depth 4) |
| Templates | `scan_templates()` | Jinja variables printed unescaped (`|safe`, `autoescape false`) |
| Taint | `analyse_taint()` | Follows user input from source to sink across functions |
| Secrets | `scan_secrets()` | Passwords and keys by name, known prefixes, entropy, config files |
| Debug mode | `scan_misconfig()` | `debug=True` left on |

**Visual:** a stacked list of the seven steps with small icons.

---

### Slide 11: Taint analysis in one picture

**On the slide**
```
request.args.get("id")   ──►   q = "SELECT … " + id   ──►   cur.execute(q)
      SOURCE                     (data flows)                   SINK  → CWE-89
```
- **Source**: where user input enters (`request.args`, form, JSON, path params, cookies).
- **Sink**: a dangerous call (`execute`, `subprocess(shell=True)`, `open`, `redirect`).
- **Sanitiser**: makes data safe *for one bug type* (`html.escape` → XSS only; `int()` → all).
- **Function summaries** solved to a fixpoint → finds bugs several helper calls deep.
- Safe flows are **kept but suppressed** with a reason (bonus B-2).

**Visual:** an arrow from a "user input" icon through code boxes to a red "danger" box; a green
"sanitiser" box breaking a second arrow.

---

### Slide 12: DAST, the runtime scanner

**On the slide**

| Step | Function | What it does |
|---|---|---|
| Scope guard | `ScopeGuard.check()` | Only allow-listed hosts; every request and redirect hop |
| Login (optional) | `authenticate()` | Form/JSON login or fixed headers/cookies; session reused |
| Discover | `discover()` | Seeded from SAST routes **plus** a same-site crawl |
| Passive checks | `passive.run()` | Headers, cookies, CORS, verbose errors, banners, exposed files |
| Active checks | `_scan_param()` | SQLi, XSS, command injection, traversal, redirect on every (URL, parameter) |
| Verify | `verify_findings()` | Re-test with a **second canary + a harmless control**; keep only if it reproduces |

**Visual:** a magnifying glass over a browser window, with the six steps listed.

---

### Slide 13: Safe payloads and proof

**On the slide**

| Check | Payload (example) | Proof we accept |
|---|---|---|
| SQL injection | `'` … / `' AND 'x'='x` vs `' AND 'x'='y` | DB error text, or true/false answers differ |
| XSS | `sdcRND<"'>` | Canary comes back **unescaped** in HTML |
| Command injection | `;echo sdcRND$((A*B))X` | The **computed** number appears (a plain echo can't fake it) |
| Path traversal | `../../../../../../etc/passwd` | `root:x:0:0:` in the response (read-only) |
| Open redirect | `//sdcRND.invalid/` | `Location` points at it; redirect **not followed**; `.invalid` can't resolve |

- No time-based, destructive or exfiltrating payloads. `DELETE` never sent.
- Every hit re-tested with a different canary + a control value before it counts.

**Visual:** a table with a lock icon.

**Say:** "We trade some coverage for safety: a bug we can't prove with a harmless payload stays
Code only; we never fake a confirmation."

---

### Slide 14: Correlation, the core

**On the slide**

A code finding and a runtime finding become **one Confirmed issue** only if **all four** hold:
1. **Same bug family** (e.g. CWE-22/23/36 are all path traversal).
2. **Route gate (hard):** the URL belongs to the route where the taint flow starts (1.0), whose
   handler contains the line (0.9), or that reaches the function (0.8). No shared route → **never linked**.
3. **Score ≥ 0.70**, where
   `score = 0.50·route + 0.35·parameter + 0.10·method + 0.05·specificity`
4. **Ambiguity rule:** two candidates within **0.10** that the parameter can't separate → **link nothing**.

Then: **one-to-one assignment**, best pairs first.

**Visual:** a funnel with four filters; candidate pairs in at the top, Confirmed issues out at the bottom.

**Say:** "Our principle: **a missed link is better than a wrong link.** That's why wrong links are 0."

---

### Slide 15: Correlation worked example

**On the slide**

| | Code (SAST) | Runtime (DAST) |
|---|---|---|
| Finding | `redirect(next_url)` in handler `go`, source param `next` | `GET /go?next=//abc.invalid/` → `302 Location: //abc.invalid/` |
| Route | `GET /go` | `GET /go` |

| Reason | Weight |
|---|---|
| Same family (open redirect) | gate |
| Flow starts in the handler of `GET /go` (+ specificity) | 0.55 |
| Parameter `next` = `next` | 0.35 |
| Method `GET` = `GET` | 0.10 |
| **Link score** | **1.00 → Confirmed** |

**Visual:** two cards (code card, request card) joined by a line labelled "1.00".

**Say:** "These exact reasons and weights are shown in the report for every Confirmed issue (bonus B-3)."

---

### Slide 16: Labels, risk score, prioritised list

**On the slide**

| Label | Meaning |
|---|---|
| **Confirmed** | In the code and proven at runtime, linked. Fix first. |
| **Code only** | In the code, not proven at runtime |
| **Runtime only** | Seen at runtime, no code line (often server settings) |

- **Risk (0–10)** = CVSS 3.1 base score × factors:
  - Code only × 0.6 · needs login × 0.85 · proof only a response difference × 0.9 · weak runtime-only × 0.9
- Example: SQL injection Confirmed **9.8** vs the same bug Code only **5.88**.
- List order: Confirmed first, then risk (FR-9).
- CVSS and OWASP Top 10 2025 category attached to every issue.

**Visual:** three coloured label chips and a sorted list mock-up.

---

### Slide 17: Auto-verify and noise cut (bonuses B-1, B-2)

**On the slide**

**Auto-verify (B-1)**
- After correlation, each eligible Code-only issue gets **one** targeted check on its exact route and
  parameter.
- If proven → upgraded to Confirmed, marked `verified_by: auto-verify`.
- Same safe payloads, same scope guard.

**Noise cut (B-2)**
- Safe flows are **not deleted**; they're marked suppressed with a reason:
  - `safe:sql-parameterised`: bind parameters, constant SQL
  - `safe:subprocess-list-no-shell`: list form, no shell
  - `sanitized:html.escape`: sanitiser on the path
  - `unreachable`: no route can call it (never for secrets)
- Hidden from the main list, visible in the report's **Suppressed** tab.

**Visual:** left half "upgrade arrow Code only → Confirmed"; right half "bin with a reason label".

---

### Slide 18: Outputs

**On the slide**

| Output | Detail |
|---|---|
| **HTML report** | One offline page. Tabs: Overview, Issues, Evaluation, Schema and method, Suppressed. Each issue: request, payload, evidence, code line, *why linked*, fix, `curl` repro |
| **REST API** | `POST /scans`, `GET /scans/{id}`, `GET /issues?label=&cwe=&min_risk=`, `/report`, `/sarif`, `/docs`; binds to 127.0.0.1 |
| **SARIF 2.1.0** | For GitHub code scanning; schema-validated |
| **Markdown** | `findings.md` readable list |
| **CLI** | `sast`, `dast`, `correlate`, `scan`, `eval`, `report`, `serve` |
| **CI gate** | `--fail-on confirmed:high` → exit 2; exit codes 0 ok · 1 error · 2 gate · 64 usage |
| **Storage** | SQLite: scans, findings, issues; stable IDs across scans |

**Visual:** screenshots `docs/img/report-overview.png` and `docs/img/report-evaluation.png`.

---

### Slide 19: Extras beyond the brief

**On the slide**
- ➕ **Login support**: form/JSON login or fixed headers/cookies, reused by DAST and auto-verify.
- ➕ **Two extra bug types**: insecure deserialization (CWE-502) and debug mode left on (CWE-489).
- ➕ **Evaluation harness**: `FlowStopper eval` scores a scan against an answer key; scores shown in
  the report's Evaluation tab.
- ➕ **One-command demo**: `make demo` (Docker only) and `make showcase APP=<folder>` (any folder,
  starts the app, scans, starts the API, prints every link).
- ➕ **Docker packaging**: non-root image, read-only source mount, joins the target's network.
- ➕ **Determinism**: same input → byte-identical `issues.json` (seeded canaries, sorted output).
- ➕ **Secret masking** in all reports; credentials never stored.
- ➕ **Our own CVSS 3.1 calculator**, tested against the catalogue scores.

**Visual:** a grid of eight small feature cards.

---

## Section 4: Decisions we took

### Slide 20: Key design decisions

**On the slide**

| Decision | Why |
|---|---|
| **Route gate is hard**: no shared route, no link, whatever the score | Prevents linking two different bugs of the same type |
| **Ambiguity rule**: close candidates → link nothing | A wrong link costs more than a missed one |
| **Parse-only SAST** (Python `ast`, no imports) | Safety rule R7; never runs untrusted code |
| **Sanitisers clear per bug type** (`html.escape` ≠ SQL-safe) | Avoids hiding real SQLi behind an HTML escape |
| **Suppress, don't delete** | Judges and developers can see *why* we stayed quiet |
| **Sinks matched by resolved name first** (a project function called `execute` is not a sink) | Fewer false alarms |
| **SAST routes seed DAST** | DAST tests endpoints a crawler would never find |
| **Every DAST hit re-tested** (second canary + control) | Removes flukes and reflections |
| **Only harmless payloads; no time-based** | Rule R4; blind bugs stay honestly Code only |
| **Mock B sealed until the end**; unseen score = its **first** run | Honest generalisation number (no tuning on the test) |
| **Measure in Docker** | A deep laptop path hid a path-traversal proof |
| **No time budget** (organisers confirmed not needed) | Full coverage; each request still has a 3 s / 10 s timeout |
| **Stable IDs from content, not line numbers or time** | Idempotent re-scans; issues keep identity |
| **Exit code 2 only for the CI gate; 64 for usage errors** | CI can tell "found high issues" from "bad command" |

**Visual:** two-column table; maybe icons per row.

**Say:** "Almost every decision trades a little coverage for zero wrong links and full safety."

---

## Section 5: Results

### Slide 21: Mock A results (Flask, the development app)

**On the slide**

| Metric | Result | Target (good / great) | Status |
|---|---|---|---|
| Code detection | **13 / 13 (100%)** | > 60% / > 85% | great |
| Runtime detection | **12 / 13 (92%)** | > 50% / > 80% | great |
| Correct links | **9 / 10 (90%)** | > 50% / > 80% | great |
| Wrong links | **0 / 9 (0%)** | < 20% / < 5% | great |
| False alarms | **0 / 20 (0%)** | < 30% / < 10% | great |
| Run time | **~2 s** (≈720 requests) | < 15 min / < 5 min | great |

- 25 routes, 19 code findings, 22 runtime findings → 20 issues (9 Confirmed).
- The one missed link: a **blind command injection** (`shell=True`, output thrown away). No safe
  payload can show it; it is reported honestly as Code only.

**Visual:** six green gauges or a bar chart against the target lines.

---

### Slide 22: Mock B results (FastAPI, held out) and the unseen-app score

**On the slide**

| Metric | First run (unseen) | Final | Target (good / great) |
|---|---|---|---|
| Code detection | 10 / 13 | **13 / 13 (100%)** | > 60% / > 85% |
| Runtime detection | 10 / 14 | **11 / 14 (79%)** | > 50% / > 80% |
| Correct links | **6 / 10 (60%)** | **8 / 10 (80%)** | > 50% / > 80% |
| Wrong links | 0 / 6 | **0 / 8 (0%)** | < 20% / < 5% |
| False alarms | 0 / 17 | **0 / 19 (0%)** | < 30% / < 10% |

- **Unseen-app score: 60% (good; target > 40%)**. We count the *first* run, before any tuning.
- Two rounds of **generic** fixes took it to 80% (pydantic request bodies; Starlette
  `TemplateResponse` keyword form; error check on parameter-less routes), with **no regression on Mock A**.
- Remaining misses: a redirect and a cookie flag that only appear after a *successful* login, and one
  blind command injection.

**Visual:** a before/after bar chart (first run vs final), with a marker at 40% and 65% for the
unseen-app target.

**Say:** "Mock B was built by us but kept sealed while we developed. Different framework, different
code style. 60% on its very first run is our honest generalisation number."

---

## Section 6: Wrap-up

### Slide 23: Limitations and what we'd do next

**On the slide**

| Limitation | Effect | Next step |
|---|---|---|
| Names must resolve statically (`getattr(obj, name)()` not followed) | Some dynamic flows missed | Constant-folding of names |
| No header / cookie injection in DAST | Bugs fed only by headers/cookies not proven | Add header and cookie as injectable locations |
| Blind bugs can't be proven with safe payloads | Stay Code only | Allowed out-of-band markers, if rules permit |
| Behaviour only after a successful login on the same request | Not reached | Use login credentials as the baseline when fuzzing the login route |
| Route-less bugs (e.g. in a 404 handler) | Reported, but never linked | A route-less correlation rule |
| Taint through dict/list keys is shallow | Some flows missed | Key-sensitive container tracking |
| Django support shallower (no DRF routers) | Fewer routes on DRF apps | DRF viewset/router extractor |
| Traversal proof limited to six `../` steps | App must run from a shallow folder | Run in Docker (as we do) |
| Scan diff (B-5) not built | No new/fixed view | Small: IDs and first/last-seen already stored |

**Visual:** a two-column "today → next" layout.

**Say:** "Every limitation is a deliberate safety or precision trade-off, documented in
`docs/LIMITATIONS.md`."

---

### Slide 24: Summary scorecard + demo

**On the slide**

| Area | Score |
|---|---|
| Compulsory requirements (FR-1…FR-10) | **10 / 10 ✅** |
| Required vulnerability types | **6 / 6 ✅** + passive checks + 2 extra types |
| Chosen bonuses (B-1, B-2, B-3, B-4, B-6) | **5 / 5 ⭐** (optional B-5 not done) |
| Compliance rules (R1…R8) | **8 / 8 ✅**, enforced by tests |
| Wrong links on every measured app | **0** |
| Unseen-app correct links | **60%** (target > 40%) |
| Automated tests | **~800**, all offline |

- Live demo: `make showcase APP=-MockA` → open the report → one Confirmed issue → `curl` repro.
- Thank you / questions.

**Visual:** a big scorecard; a QR code or link to the repository.

---

## Appendix: material for backup slides (optional)

**A. Folder map**

| Folder | Contents |
|---|---|
| `FlowStopper/sast/` | index, routes, call graph, taint, secrets, debug-mode checks |
| `FlowStopper/dast/` | client, discovery, checks, verify |
| `FlowStopper/correlate/` | matcher, scoring, assignment, explanations, auto-verify |
| `FlowStopper/report/` | HTML, SARIF, Markdown, fixes, CI gate |
| `FlowStopper/scope.py` | allow-list guard |
| `FlowStopper/api.py`, `cli.py`, `pipeline.py` | API, CLI, the end-to-end scan |
| `apps/mock_a`, `apps/mock_b` | our own vulnerable test apps with answer keys |

**B. Tech stack:** Python 3.11+, standard-library `ast` and `sqlite3`, FastAPI + uvicorn (API),
httpx (HTTP client), pydantic v2 (models), Jinja2 (report), typer (CLI), pytest + ruff (tests, lint),
Docker Compose. No paid services, no AI calls at run time.

**C. Out of scope (as stated in the brief):** automatic code fixing, login/user management, cloud
deployment, a polished UI, reachability-aware dependency scanning (SCA).

**D. Demo checklist:** Docker running · `make setup` done · `make showcase APP=-MockA` once
beforehand · browser tab on the report · terminal ready for the `curl` repro.
