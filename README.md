# FlowStopper: SAST + DAST correlation engine

## What we built, in brief

FlowStopper scans a Python web app's **source code** (SAST) and its **running instance** (DAST), then
**correlates** the two, so each real vulnerability appears **once**. That one entry carries:
- the code line that causes it;
- the URL, parameter and payload that prove it;
- a risk score;
- a fix suggestion.

It supports **Flask, FastAPI and Django**, covers SQL injection, XSS, command injection, path traversal,
open redirect and hard-coded secrets (plus insecure deserialization, debug mode and passive
misconfiguration checks), and delivers the results as an HTML report, a REST API, SARIF, Markdown and
a CLI with a CI gate.

**Headline results** (our own answer keys, measured in Docker, details in [section 4](#4-results)):

| | Code detection | Runtime detection | Correct links | Wrong links | False alarms |
|---|---|---|---|---|---|
| Mock A (Flask) | 100% | 92% | 90% | **0** | **0** |
| Mock B (FastAPI, held out) | 100% | 79% | 80% | **0** | **0** |

**Unseen-app score: 60%** correct links on Mock B's first run (target: >40% good, >65% great).
All 10 compulsory requirements, all 6 required vulnerability types, 5 of the 6 bonus items and all 8
compliance rules are covered (section 2).

![Report overview](docs/img/report-overview.png)

**Contents**
1. [The problem statement](#1-the-problem-statement)
2. [How we tackled the PRD, item by item](#2-how-we-tackled-the-prd-item-by-item)
3. [Key decisions](#3-key-decisions)
4. [Results](#4-results)
5. [Quick start](#5-quick-start)
6. [Scanning the organisers' app](#6-scanning-the-organisers-app)
7. [How it works](#7-how-it-works)
8. [Output formats](#8-output-formats)
9. [Safety](#9-safety)
10. [Third-party components and AI usage](#10-third-party-components-and-ai-usage)
11. [Limitations](#11-limitations)
12. [Repository layout](#12-repository-layout)

---

## 1. The problem statement

The brief (our working copy is [`FlowStopper_BUILD_SPEC.md`](FlowStopper_BUILD_SPEC.md), sections 1–4):

> Build a tool that scans an application's **source code (SAST)** and its **running instance
> (DAST)**, then **correlates** the two so every real vulnerability appears **once**, with the code
> line that causes it, the URL/parameter/payload that proves it, a risk score, and a fix suggestion.

- **Target language:** Python. Flask is primary; FastAPI and Django route extraction are also
  required, so the tool generalises to an unseen app.
- **What is judged most:** correlation quality.
- **The PRD is made of:**
  - **10 compulsory functional requirements** (FR-1 to FR-10);
  - **6 required vulnerability types** plus passive runtime checks;
  - **bonus items** (B-1 to B-6);
  - **8 non-negotiable compliance rules** (R1 to R8);
  - **success targets** for detection, linking, false alarms, the unseen app and run time.
- **Out of scope:** automatic code fixing, login/user management, cloud deployment, a polished UI,
  reachability-aware dependency scanning.

**Why it matters.** A code scanner finds the exact line but raises many false alarms. A runtime
scanner proves a bug is real but cannot say where in the code it lives. Two disagreeing lists get
ignored. FlowStopper's job is to prove that a code finding and a runtime finding are the **same bug**.

---

## 2. How we tackled the PRD, item by item

Legend: ✅ done · ⭐ bonus done · ➕ beyond the brief · ⏸️ not done.

### 2.1 Compulsory functional requirements (10 / 10)

| ID | Requirement | Status | How we did it |
|---|---|---|---|
| **FR-1** | SAST scan: file, line, type, severity, snippet | ✅ | `run_sast()` (`sast/runner.py`) parses every `.py` file with Python's `ast` module and runs taint analysis, a secrets detector, a template scan and a debug-mode check. Every finding has file, line span, function, CWE, severity (from CVSS) and a snippet. |
| **FR-2** | DAST scan: URL, method, param, payload, evidence | ✅ | `run_dast()` (`dast/runner.py`) discovers endpoints, runs passive and active checks, and re-verifies each hit. Every finding stores the full request, payload, response excerpt, evidence text, proof type and a `curl` repro. |
| **FR-3** | Common finding format with CWE | ✅ | One pydantic `Finding` model (`models.py`) for both engines; a shared CWE catalogue (`cwe.py`) gives each CWE its family, OWASP Top 10:2025 category and CVSS 3.1 vector. |
| **FR-4** | Route map (URL → handler function + line span) | ✅ | `extract_routes()` (`sast/routes/`) for **Flask** (blueprints, prefixes, app factories, `MethodView`, `add_url_rule`, routes registered inside functions), **FastAPI** (`APIRouter`, `include_router`, pydantic bodies) and **Django** (`path`, `re_path`, `include`, class-based views). Each route has method, path template, parameters, handler and line span. |
| **FR-5** | Correlate: same CWE + the DAST route is handled by the code holding the SAST finding | ✅ | `correlate()` (`correlate/engine.py`): same CWE family, a **hard route gate** backed by the call graph, a weighted score, one-to-one assignment and an ambiguity rule (section 7). |
| **FR-6** | Merge duplicates, idempotent re-scans | ✅ | `dedupe_code()` / `dedupe_runtime()` merge duplicates. Issue IDs are hashed from content (`ids.py`), never from line numbers or time, so a re-scan updates the same rows in SQLite. The same input produces a byte-identical `issues.json`. |
| **FR-7** | Labels: Confirmed / Code only / Runtime only | ✅ | Every issue gets exactly one label; definitions are in the report. |
| **FR-8** | Issue detail for Confirmed issues | ✅ | The HTML report's detail view shows the request and payload, evidence, code line, *why it was linked*, the fix and a `curl` repro; `GET /issues/{id}` returns the same data as JSON. |
| **FR-9** | Prioritised list (Confirmed first, then risk) | ✅ | `sort_issues()`: label first, then a 0–10 risk score = CVSS × exploitability factors. |
| **FR-10** | CLI + API + short README | ✅ | CLI with 7 commands (`sast`, `dast`, `correlate`, `scan`, `eval`, `report`, `serve`); a FastAPI REST API (`api.py`); this README. |

### 2.2 Required vulnerability types (6 / 6, plus extras)

| Type | CWE | Code side (SAST) | Runtime side (DAST) | Status |
|---|---|---|---|---|
| SQL injection | 89 | request data reaching `execute()`, `raw()`, `text()`, `read_sql` | error-based + true/false differential | ✅ |
| Cross-site scripting | 79 | HTML responses, `Markup`/`mark_safe`, templates with `|safe` or autoescape off | canary reflected unescaped in HTML | ✅ |
| Command injection | 78 | `os.system`, `os.popen`, `subprocess(..., shell=True)` | evaluated arithmetic marker + shell-semantics differential | ✅ |
| Path traversal | 22 | `open`, `send_file`, `FileResponse`, `Path.read_*`/`write_*`, `os.listdir` | read-only `/etc/passwd` probe | ✅ |
| Open redirect | 601 | `redirect()`, `RedirectResponse`, manual `Location` header | `.invalid` canary in the `Location` header | ✅ |
| Hard-coded secrets | 798 | names (`password`, `secret_key`…), provider prefixes (`AKIA`, `ghp_`, `sk_live_`…), DSNs with passwords, entropy, config files | code only by nature | ✅ |
| Passive runtime checks | 693, 1021, 1004, 614, 1275, 942, 209, 497, 538, 548 | — | security headers, cookie flags, CORS, verbose errors, version banners, exposed files, directory listings | ✅ |
| Insecure deserialization | 502 | `pickle`/`marshal`/`dill`/unsafe `yaml` loads of request data | none (no safe runtime proof) | ➕ |
| Debug mode left on | 489 | `app.run(debug=True)`, `FastAPI(debug=True)`, `DEBUG = True` in settings | debug-console probe | ➕ |

### 2.3 Bonus items (5 / 6)

| ID | Bonus | Status | How we did it |
|---|---|---|---|
| **B-1** | Auto-verify Code-only findings with a safe probe | ⭐ | `auto_verify()` (`correlate/autoverify.py`) sends **one** matching check to each eligible issue's exact route and parameter; when it proves the bug the issue becomes Confirmed with `verified_by: auto-verify`. |
| **B-2** | Cut SAST noise (sanitised / unreachable → suppressed) | ⭐ | Safe flows are kept but marked suppressed with a reason: `safe:sql-parameterised`, `safe:subprocess-list-no-shell`, `safe:yaml-safe-loader`, `sanitized:<names>`, `unreachable` (never for secrets). They are hidden from the list and shown in the report's *Suppressed* tab. |
| **B-3** | Explain every link (reasons + weights) | ⭐ | `link_reasons()` (`correlate/explain.py`): every Confirmed issue lists each reason (`same_cwe`, route evidence, `same_param`, `same_method`…) with its weight. |
| **B-4** | Plain-English fix suggestion per CWE | ⭐ | `fix_for()` (`report/fixes.py`): *what is wrong / minimal fix with code / prevention*, filled from the issue's own parameter and location. |
| **B-6** | SARIF 2.1.0 + CI fail on Confirmed high | ⭐ | `to_sarif()` (validated against the OASIS schema); `scan --fail-on confirmed:high` exits with code **2**. |
| B-5 | Scan diff (new / fixed / still open) | ⏸️ | Marked optional in the plan and not built. The groundwork exists: stable issue IDs and `first_seen_scan` / `last_seen_scan` in the database. |

### 2.4 Compliance rules (8 / 8, enforced by code and tests)

| Rule | Requirement | How we enforce it |
|---|---|---|
| **R1** | Original work | Correlation, route mapper, taint engine, secrets detector, DAST engine and scoring written from scratch; no vendored scanners. |
| **R2** | Disclose every third-party component | [`THIRD_PARTY.md`](THIRD_PARTY.md): every library with exact version and licence, tools, and the AI-assistant statement. |
| **R3** | Scan only authorised targets | `scope.py` guard inside the HTTP client checks **every** request and redirect hop against `ALLOWED_HOSTS` (default `localhost,127.0.0.1,::1`). It never uses DNS to decide. Hosts come from configuration only. |
| **R4** | No harmful payloads | Payloads only from the fixed catalogue (spec Appendix B): canaries, arithmetic echoes, a read-only file probe. A test asserts nothing else is sent. No time-based payloads, `DELETE` never sent, `PUT`/`PATCH` only with `--allow-mutating`. |
| **R5** | Confidentiality | `target_src/`, `keys/`, `*.key.json` are git-ignored; the git history was checked clean. |
| **R6** | No overfitting | `tests/test_no_overfit.py` fails the build if any answer-key string appears in `FlowStopper/`. Every fix is a generic rule. Mock B was kept sealed during development. |
| **R7** | Safe by construction | SAST parses only (never imports or runs target code). Reports are HTML-escaped with no scripts. `Authorization`/`Cookie` values are redacted, login credentials never stored, secret values masked. |
| **R8** | Only the organisers' app scanned in evaluation | The mock apps are labelled as our own development fixtures. |

### 2.5 Success targets

| Metric | Good | Great | Mock A | Mock B |
|---|---|---|---|---|
| Code detection | >60% | >85% | **100%** great | **100%** great |
| Runtime detection | >50% | >80% | **92%** great | **79%** good |
| Correct links | >50% | >80% | **90%** great | **80%** good |
| Wrong links | <20% | <5% | **0%** great | **0%** great |
| False alarms | <30% | <10% | **0%** great | **0%** great |
| Unseen app | >40% | >65% | — | **60%** good (first run) |
| Run time | <15 min | <5 min | **~1–3 s** great | **~1–3 s** great |

### 2.6 Beyond the brief

- ➕ **Login support** (`--auth-config`): a form or JSON login, or fixed headers/cookies; the session or
  token is reused by DAST and auto-verify.
- ➕ **Evaluation harness** (`FlowStopper eval`, `scan --key`): scores a scan against an answer key and
  shows the scores in the report's Evaluation tab.
- ➕ **One-command runs:** `make demo` (Docker only) and `make showcase APP=<folder>`, which scans any
  folder, starts the API and prints every link.
- ➕ **Docker packaging:** non-root image, read-only source mount, joins the target's compose network.
- ➕ **Our own CVSS 3.1 calculator** (`cvss.py`), tested against the catalogue scores.
- ➕ **Determinism:** seeded canaries, sorted output, stable IDs; two scans give identical results.

---

## 3. Key decisions

The full log is in `docs/DECISIONS.md`, `docs/DECISIONS_Dev1.md` and `docs/DECISIONS_Dev2.md`. The ones
that shape the tool:

| Decision | Why |
|---|---|
| **"A missed link is better than a wrong link."** | A wrong link sends a developer to the wrong line. Every correlation rule below follows from this. |
| **The route gate is hard.** No shared route → never linked, whatever the score. | Prevents joining two different bugs of the same type. |
| **Ambiguity rule.** Two candidates within 0.10 that the parameter cannot separate → link nothing. | Same reason. Result: 0 wrong links on every target we measured. |
| **SAST's route map seeds DAST.** | DAST tests endpoints a crawler would never find, and the route IDs make correlation exact. |
| **Parse-only SAST** with Python's `ast`. | Rule R7: untrusted code is never imported or run. |
| **Name resolution never guesses.** Sinks match the resolved dotted name first, the attribute name second; a project function called `execute` is not a sink. | Fewer false alarms. |
| **Sanitisers clear per bug type.** `html.escape` makes data safe for HTML, not SQL; `int()` clears all. | A real SQL injection is not hidden behind an HTML escape. |
| **Suppress, don't delete.** Safe flows stay in the data with a reason. | Reviewers can see why the tool stayed quiet (bonus B-2). |
| **Every DAST hit is re-tested** with a second canary and a harmless control. | Removes flukes and plain reflections. |
| **Only harmless payloads, no time-based ones.** | Rule R4. Blind bugs stay honestly Code only rather than being guessed. |
| **Mock B sealed until the generalisation round; the unseen score is its first run.** | An honest generalisation number, not a tuned one. |
| **Measure in Docker.** | A deep laptop path hid a path-traversal proof (six `../` steps). |
| **No time budget.** | Confirmed unnecessary by the organisers; each request still has a 3 s connect and 10 s total timeout. |
| **Stable IDs from content.** | Idempotent re-scans (FR-6) and a basis for a future scan diff. |
| **Exit code 2 only for the CI gate, 64 for usage errors.** | CI can tell "high issues found" from "bad command". |
| **New behaviour only as generic rules.** | Rule R6, enforced by a test. |

---

## 4. Results

These are our own measurements against our own answer keys, not an official score. Both mock apps
ran in Docker. The raw numbers are in `docs/metrics/final_mock_a.json` and
`docs/metrics/final_mock_b.json`.

| Target | Code detection | Runtime detection | Correct links | Wrong links | False alarms | Run time |
|---|---|---|---|---|---|---|
| Mock A (our Flask fixture) | 13/13 (100%) | 12/13 (92%) | 9/10 (90%) | 0/9 | 0/19 | 1.3 s |
| **Mock B (held out, FastAPI)** | 13/13 (100%) | 11/14 (79%) | 8/10 (80%) | 0/8 | 0/19 | 1.5 s |

After the debug-mode rule (decision A-76) Mock A reports one more true Code-only issue
(`app.run(..., debug=True)` in its entry point), so its false alarms read 0/20; every other number is
unchanged.

**Unseen app** (target >40% good, >65% great): **60%** (6/10). This is Mock B's correct-link rate at
its **first run**, before the tool was ever tuned on it. Two later rounds of generic fixes took Mock B
to 80%. Those later numbers are a tuned result and are not counted as "unseen".

How the results developed:

| Stage | Mock A links | Mock B links | Notes |
|---|---|---|---|
| Phase 3 baseline | 7/10 | (sealed) | `docs/metrics/baseline_mock_a.json` |
| Phase 4 | 8/10 | (sealed) | DAST path-parameter injection, command-injection differential, decoy-overlap fix in the scorer |
| Phase 6 first run on Mock B | 9/10 (Docker) | **6/10** | `docs/metrics/mock_b_first_run.json`, frozen |
| Phase 6 rounds 1–2 | 9/10 | 8/10 | FastAPI pydantic bodies, Starlette `TemplateResponse` keywords, error check on parameter-less routes (`docs/metrics/phase6.md`) |

Reading the results:
- **Wrong links are 0 on both apps**, and no decoy raised a false alarm.
- Mock A's missed link is a blind command injection (`shell=True` with the output thrown away); no
  safe payload can show it, so it is reported as Code only.
- Mock B's misses are a redirect and a cookie flag that only appear after a *successful* login, and one
  blind command injection.
- On a laptop run, as opposed to Docker, Mock A's runtime detection is 11/13, because the deep checkout
  path puts `/etc/passwd` out of reach of the payload's six `../` steps. Docker runs from `/app`.

---

## 5. Quick start

You need **Docker** (Docker Desktop or Colima) and **make**. Python is not required for the demo.

```bash
git clone <this-repo> FlowStopper && cd FlowStopper
make demo          # builds the images, starts Mock A, scans it end to end, prints the report path
open out/demo/report.html
make demo-down     # stop Mock A
```

Expected output: 25 routes and 19–20 reported issues, 9 of them Confirmed. One runtime-only host-wide
finding can differ between runs. The run ends with a line like
`Report: /…/FlowStopper/out/demo/report.html`.

> **Colima users:** by default Colima shares only your home directory with containers. Clone the repo
> somewhere under `~`. A clone in `/tmp` fails with `Permission denied: '/app/out/demo'`, because the
> container cannot write to the output folder.

**With Python 3.11+** (for the CLI, the API and the showcase command):

```bash
make setup                     # .venv with the pinned dependencies (requirements-dev.lock)
make check                     # lint + tests (about 800 tests, all offline)
make showcase APP=mock_b       # start a demo target, scan, score, start the API, print every link
make showcase-stop             # stop the target and the API
```

`make showcase APP=…` accepts `mock_a`, `mock_b` or the path of any folder that holds an app's source
(see section 6). It prints:
- the report URL and its Evaluation tab;
- the API links: issues, scan status and SARIF;
- the scores, when an answer key exists.

---

## 6. Scanning the organisers' app

The organisers' source and answer key are confidential and **never committed** (rule R5).
`target_src/` and `keys/` are git-ignored. No answer key is needed to scan: it is only used to score.

**Quickest way: point the showcase command at the folder.** The folder can be anywhere.

```bash
# the app is already running on a local port
make showcase APP=~/Desktop/their_app TARGET=http://127.0.0.1:5000

# the folder has a docker-compose file: it is started and its published port is found automatically
make showcase APP=~/Desktop/their_app

# only if you have a key, or the app needs a login
make showcase APP=~/Desktop/their_app TARGET=http://127.0.0.1:5000 KEY=keys/answer_key.json AUTH=keys/login.json
make showcase-stop             # stop what it started
```

This scans the folder's source (parsed, never run) and the running app, writes the report, and prints
the report and API links. Without `KEY` there are no scores and the Evaluation tab says so. The same
works for the demo apps: `make showcase APP=-MockA`.

The manual commands:

```bash
mkdir -p target_src keys
cp -R /path/to/their_app/* target_src/
```

**From the host** (the app published on a local port):

```bash
export ALLOWED_HOSTS=localhost,127.0.0.1,::1
.venv/bin/FlowStopper scan --source target_src --target http://127.0.0.1:<port> --out out/target
open out/target/report.html
```

**In Docker**, on the app's own compose network (`docker network ls` shows its name):

```bash
export TARGET_SRC=./target_src TARGET_NETWORK=<their_network> ALLOWED_HOSTS=localhost,127.0.0.1,::1,<service>
docker compose -f docker-compose.yml -f docker-compose.target.yml run --rm --user "$(id -u):$(id -g)" \
  -e FLOWSTOPPER_DB=/app/out/target/.flowstopper/scans.db \
  flowstopper scan --source /src --target http://<service>:<port> --out /app/out/target
```

Useful options on `scan`:

| Option | What it does |
|---|---|
| `--auth-config login.json` | Log in first (static headers/cookies, or a login request whose session or token is reused). Keep the file git-ignored, e.g. in `keys/`. |
| `--fail-on confirmed:high` | CI gate: exit code 2 if a Confirmed issue is high or critical |
| `--key keys/answer_key.json` | Score the scan against an answer key (our format: `docs/ANSWER_KEY_FORMAT.md`); the scores appear on the report's Evaluation tab |
| `--allow-host <name>` | Add one extra allowed host (logs a WARNING) |
| `--allow-mutating` | Also send PUT/PATCH (never DELETE) |

Outputs go into `--out`:
- `issues.json`;
- `scan_meta.json` (per-stage timings, seed, tool versions);
- `report.html`;
- `issues.sarif`;
- `findings.md`;
- `evaluation.json`, when `--key` is given.

---

## 7. How it works

```
source ─► SAST: file index → routes → call graph → templates → taint (+ summaries) → secrets → debug mode ─┐
                                                                                                          ├─► correlate ─► auto-verify ─► SQLite ─► HTML / SARIF / Markdown / API
running app ─► DAST: scope-guarded client → login → discovery (seeded by routes + crawl) → checks → verify ─┘
```

The entry point is `run_pipeline()` in `FlowStopper/pipeline.py`: `run_sast()` → `run_dast()` →
`correlate()` → `auto_verify()` → store → reports.

- **SAST:**
  - Route extraction for Flask, FastAPI and Django (section 2.1, FR-4).
  - A name-resolved call graph: which functions each route can reach.
  - Taint analysis inside each function, with per-function summaries solved to a fixpoint across the
    call graph. A finding is reported at the sink, with the HTTP parameter that feeds it
    (`source_param`) and the routes it can be reached from (`entry_routes`).
  - Sanitisers and guard checks mark safe flows as *suppressed* instead of dropping them.
  - A hard-coded-secrets detector, a Jinja template scan (`|safe`, `autoescape false`), and a check for
    debug mode left on.
  - Insecure deserialization (`pickle`, `marshal`, unsafe `yaml` loads of request data) is a taint sink
    too. It is always Code only, because a safe runtime proof does not exist.
- **DAST:**
  - Endpoints are seeded from the route map, plus a same-origin crawl.
  - Active checks for SQLi, XSS, command injection, path traversal and open redirect.
  - Every hit is re-tested with a second canary plus a benign control, and is reported only if it
    reproduces.
  - Passive checks for headers, cookies, CORS, verbose errors, version banners and exposed files.
  - An optional login step.
- **Correlation**, the core: a code finding and a runtime finding become one **Confirmed** issue only
  when all of the following hold:
  1. **Same CWE family** (e.g. 22/23/36 are one family).
  2. **Route gate (hard):** the runtime finding's route is where the taint flow starts (1.0), the code
     line is inside that route's handler (0.9), or the code's function is reachable from the handler
     (0.8). Otherwise they are never linked.
  3. **Score** = `0.50·route + 0.35·param + 0.10·method + 0.05·specificity`. Param is 1.0 when the
     names match, 0.5 when SAST does not know the parameter, and 0 when they differ.
  4. **One-to-one assignment** of the best pairs scoring at least `0.70`.
  5. **Ambiguity rule:** if two candidates score within `0.10` of each other and the parameter cannot
     tell them apart, **nothing is linked**.
  6. **Labels:** Confirmed / Code only / Runtime only.
  7. **Risk** = CVSS 3.1 base × exploitability factors (×0.85 auth, ×0.9 differential-only proof,
     ×0.6 code only, ×0.9 low-confidence runtime only).

  Each link carries its reasons and their weights, shown in the report. **Auto-verify** then probes
  each eligible Code-only issue once more with the matching check and upgrades it if the probe proves
  it.

Details: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

---

## 8. Output formats

| Output | Where |
|---|---|
| **HTML report** | `out/<dir>/report.html`: one offline page with tabs for Overview, Issues (proof first: request and payload, evidence, code line, why it was linked, fix, `curl` repro), Evaluation, Schema and method, and Suppressed |
| **API** | `FlowStopper serve` (or `docker compose up`) on `http://127.0.0.1:8000`: `POST /scans` (202, runs in the background), `GET /scans/{id}`, `GET /issues?scan_id=&label=&cwe=&min_risk=&include_suppressed=`, `GET /issues/{id}`, `GET /scans/{id}/report`, `GET /scans/{id}/sarif`, `GET /health`, interactive docs at `/docs` |
| **SARIF 2.1.0** | `issues.sarif`, for code-scanning tools; validated against the official OASIS schema |
| **Markdown** | `findings.md`, a readable findings list |
| **CLI** | `FlowStopper sast` / `dast` / `correlate` / `scan` / `eval` / `report` / `serve`; `--help` on each |
| **CI gate** | `scan --fail-on confirmed:high` exits **2** when tripped. Exit codes: 0 ok, 1 error, 2 gate, 64 usage error. |

![Evaluation tab](docs/img/report-evaluation.png)

---

## 9. Safety

- **Scope guard (R3):** DAST contacts only hosts in `ALLOWED_HOSTS` (default `localhost,127.0.0.1,::1`).
  - Any other hostname is refused even if it resolves to a private IP. The guard never resolves DNS.
  - It re-checks every redirect hop and refuses non-http(s) schemes.
  - `--allow-host` adds a host and logs a WARNING.
  - Hosts are set by configuration only, never hard-coded in the tool.
- **Harmless payloads only (R4):**
  - Every payload comes from the fixed catalogue in spec Appendix B: canaries, arithmetic echoes, and
    one read-only `/etc/passwd` probe. A test asserts that nothing else is sent.
  - There are no time-based, destructive or exfiltrating payloads.
  - DELETE is never sent; PUT and PATCH only with `--allow-mutating`.
- **Parse-only SAST (R7):** source is read with Python's `ast` module, never imported or executed.
- **Report hygiene (R7):**
  - All evidence is HTML-escaped, and the report has no scripts and no external assets.
  - `Authorization` and `Cookie` values are redacted unless `--keep-secrets` is set.
  - Login credentials never reach `scan_meta.json` or the database.
  - Hard-coded secrets are masked in the reports.
- **The API binds to 127.0.0.1 by default.** In Docker it is published on `127.0.0.1:8000` only.

---

## 10. Third-party components and AI usage

Every library, with its exact version and licence, and our use of AI coding assistants are disclosed in
[`THIRD_PARTY.md`](THIRD_PARTY.md) (rule R2). FlowStopper itself makes no AI calls at run time. Our own
work: the whole `FlowStopper/` package, the two mock apps (`apps/mock_a`, `apps/mock_b`), and all
fixtures, tests and scripts.

---

## 11. Limitations

Honest list: [`docs/LIMITATIONS.md`](docs/LIMITATIONS.md). In short:
- names must resolve statically (no `getattr` dispatch);
- no header/cookie injection in DAST;
- blind injections cannot be proven within the safe-payload rules;
- behaviour that only appears after a *successful* login on the request being tested is not reached;
- findings with no route (e.g. in error handlers) are never linked;
- taint through dict and list keys is shallow;
- Django support is shallower than Flask and FastAPI (no DRF routers);
- the scan diff bonus (B-5) is not built.

---

## 12. Repository layout

| Path | What it holds |
|---|---|
| `FlowStopper/` | the tool (`sast/`, `dast/`, `correlate/`, `report/`, `evalkit/`, `pipeline.py`, `api.py`, `cli.py`) |
| `apps/mock_a`, `apps/mock_b` | our own vulnerable fixture apps, with answer keys |
| `fixtures/` | contract fixtures |
| `docs/` | spec, plan, decisions, metrics, architecture, limitations |
| `tests/` | test suite (about 800 tests, all offline) |
| `scripts/` | tooling (`showcase.sh` and helpers) |

The build plan is in [`docs/PLAN.md`](docs/PLAN.md). Decisions are in `docs/DECISIONS*.md`.
