# FlowStopper — SAST + DAST correlation engine

FlowStopper scans a Python web app's **source code** (SAST) and its **running instance**
(DAST), then **correlates** the two so each real vulnerability appears once: the code line
that causes it, the URL/parameter/payload that proves it, a risk score, and a fix suggestion.

> **Status:** Phase 0 scaffold. Contracts, fixtures, CWE catalogue, CLI skeleton and the test
> harness are in place; the engines are being implemented in later phases. See
> [`docs/PLAN.md`](docs/PLAN.md) for the full phased plan and
> [`docs/PROGRESS.md`](docs/PROGRESS.md) for live status.

## What it does

- **SAST:** route map (Flask / FastAPI / Django), call graph, interprocedural taint analysis,
  hard-coded secrets. Parse-only — it never imports or runs the target (rule R7).
- **DAST:** scope-guarded crawler seeded by the route map; safe, non-destructive checks for
  SQLi, XSS, command injection, path traversal, open redirect, plus passive misconfiguration
  checks (headers, cookies, CORS, verbose errors).
- **Correlate:** links a code finding to a runtime finding when they share a CWE family and the
  runtime route is handled by the code holding the finding. Emits one prioritised issue list
  labelled Confirmed / Code-only / Runtime-only, with an explanation of every link.

## Quick start (developers)

Requires **Python 3.11+** (3.12 recommended) and **git**. Docker is needed later for the mock
apps and the one-command demo.

```bash
git clone <your-repo-url> FlowStopper && cd FlowStopper
make setup     # create .venv, install pinned deps, install the package (editable)
make check     # ruff + pytest — must be green
make doctor    # verify your machine has everything (ports, docker, lock drift, R5 hygiene)
```

`make help` lists every target. If you do not have `make`, read it for the exact commands;
each target is a one- or two-line shell sequence.

New here? Read [`docs/SETUP.md`](docs/SETUP.md) first (it covers the two-person workflow and
how to bring in the organisers' app safely), then your task list:
[`docs/PERSON_1_DEV_A.md`](docs/PERSON_1_DEV_A.md) or
[`docs/PERSON_2_DEV_B.md`](docs/PERSON_2_DEV_B.md).

## Usage (as the engines land)

```bash
FlowStopper sast  <source_dir> -o sast.json --routes-out routes.json
FlowStopper dast  <target_url> --routes routes.json -o dast.json
FlowStopper correlate --sast sast.json --dast dast.json -o issues.json
FlowStopper scan  --source <source_dir> --target <target_url> --out out/   # full pipeline
FlowStopper serve                                                          # HTTP API
FlowStopper eval  --key keys/answer_key.json --issues out/issues.json      # metrics
FlowStopper report --issues out/issues.json -f html -o report.html
```

`FlowStopper --help` (or `python -m FlowStopper --help`) documents every command.

## Safety (rules R3, R4, R7)

- **Scope guard:** DAST only contacts allow-listed hosts (`ALLOWED_HOSTS`, default
  `localhost,127.0.0.1,::1`). Any other hostname is refused even if it resolves to a private
  IP; the guard re-checks on every redirect hop and refuses non-http(s) schemes. Locally run
  targets — the organisers' app, our mock apps, and third-party **benchmark** apps (e.g. the we45
  Vulnerable-Flask-App) — are allow-listed through `ALLOWED_HOSTS` config, never hardcoded (rule R3).
- **Harmless payloads only:** canaries, arithmetic echoes and a read-only `/etc/passwd` probe,
  taken solely from the payload catalogue (spec Appendix B). No destructive, persistent or
  exfiltrating payloads; no DELETE, and no PUT/PATCH unless `--allow-mutating` is passed.
- **Parse-only SAST:** source is analysed with Python's `ast`, never imported or executed.
- **Report hygiene:** all evidence is HTML-escaped; stored requests redact `Authorization` and
  `Cookie` unless `--keep-secrets` is set.

## Confidentiality (rule R5)

The organisers' source code and answer key are used only for this hackathon and are **never**
committed. `.gitignore` excludes `target_src/`, `keys/`, `*.key.json` and
`docs/target_notes.local.md`. Put the organisers' app in `target_src/` and their (converted)
answer key in `keys/answer_key.json` locally; see [`docs/SETUP.md`](docs/SETUP.md).

## Benchmarking against a third-party app

To measure generalisation on a real, independently written app, we scan the **we45
Vulnerable-Flask-App** (Flask — our best-fit framework) locally, with the authors' permission. Its
source is **not vendored** — it is cloned at a pinned commit into a git-ignored
`bench/vulnerable-flask-app/src/` and run via Docker Compose:

```bash
make bench-fetch     # clone the Flask app @ pinned commit (git-ignored) and start it via Docker Compose
make bench           # full pipeline + eval -> docs/metrics/bench_vulnerable-flask-app.json (not part of make check)
make bench-down      # stop it
```

Our hand-written, source-verified answer key is `bench/vulnerable-flask-app/answer_key.json`; details
and caveats (Python 2.7 app; JWT-gated endpoints) are in
[`bench/vulnerable-flask-app/README.md`](bench/vulnerable-flask-app/README.md). Choice and pinned
commit: [`docs/DECISIONS.md`](docs/DECISIONS.md) D-16; credit: [`THIRD_PARTY.md`](THIRD_PARTY.md).

## How correlation works

Gate → score → assignment → ambiguity rule → labels → risk. The full formula and the scoring
weights are in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Third-party components & AI usage

See [`THIRD_PARTY.md`](THIRD_PARTY.md). AI coding assistants were used to build this project
(disclosed per rule R2). Limitations are tracked in [`docs/LIMITATIONS.md`](docs/LIMITATIONS.md).

## Repository layout

`FlowStopper/` the tool · `apps/` our own mock apps · `fixtures/` contract fixtures ·
`docs/` plan & design · `tests/` test suite · `scripts/` dev tooling. Ownership and the full
tree are in [`docs/PLAN.md`](docs/PLAN.md) §6.
