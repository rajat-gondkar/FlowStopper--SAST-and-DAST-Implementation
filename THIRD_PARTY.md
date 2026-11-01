# Third-party components & AI usage

Rule R2 requires us to disclose every third-party component (libraries, tools, datasets,
AI coding assistants). This file is kept current from Phase 0 onward. Versions are the exact
pins in `requirements.lock` (runtime) and `requirements-dev.lock` (runtime + dev); regenerate
with `make lock` and update this table in the same commit.

## AI-assisted development

This project was built with the help of AI coding assistants (large-language-model pair
programmers inside the editor). AI was used to scaffold the repository, draft module code,
write tests and documentation, and review diffs. All design decisions, the correlation
algorithm, the taint engine, the DAST checks and the scoring were specified by the team and
reviewed by the team; no third-party scanner code was copied (rule R1).

## Runtime dependencies (`requirements.lock`)

Direct dependencies declared in `pyproject.toml`:

| Package | Version | Licence | How we use it |
|---|---|---|---|
| fastapi | 0.162.0 | MIT | HTTP API (`FlowStopper serve`, `FlowStopper/api.py`) |
| uvicorn | 0.54.0 | BSD-3-Clause | ASGI server that runs the API |
| pydantic | 2.14.2 | MIT | All data contracts (`FlowStopper/models.py`) and config |
| httpx | 0.28.1 | BSD-3-Clause | Async HTTP client for the DAST engine |
| jinja2 | 3.1.6 | BSD-3-Clause | HTML report templates |
| typer | 0.27.3 | MIT | Command-line interface (`FlowStopper/cli.py`) |
| beautifulsoup4 | 4.15.0 | MIT | Parse HTML during DAST crawl/discovery |

Transitive runtime dependencies (installed automatically, pinned in `requirements.lock`):

| Package | Version | Licence |
|---|---|---|
| annotated-doc | 0.0.5 | MIT |
| annotated-types | 0.8.0 | MIT |
| anyio | 4.15.1 | MIT |
| certifi | 2026.10.23 | MPL-2.0 |
| click | 8.5.0 | BSD-3-Clause |
| h11 | 0.16.0 | MIT |
| httpcore | 1.0.9 | BSD-3-Clause |
| idna | 3.20 | BSD-3-Clause |
| markdown-it-py | 4.2.0 | MIT |
| MarkupSafe | 3.0.4 | BSD-3-Clause |
| mdurl | 0.1.2 | MIT |
| opentelemetry-api | 1.45.2 | Apache-2.0 |
| pydantic-core | 2.50.2 | MIT |
| Pygments | 2.21.0 | BSD-2-Clause |
| rich | 15.0.0 | MIT |
| shellingham | 1.5.4 | ISC |
| soupsieve | 3.0.4 | MIT |
| starlette | 1.10.0 | BSD-3-Clause |
| typing-inspection | 0.4.4 | MIT |
| typing-extensions | 4.16.0 | PSF-2.0 |

## Development-only dependencies (`requirements-dev.lock`)

| Package | Version | Licence | How we use it |
|---|---|---|---|
| pytest | 9.2.0 | MIT | Test runner |
| pytest-asyncio | 1.4.1 | Apache-2.0 | Async test support (DAST) |
| ruff | 0.17.3 | MIT | Linter + formatter |
| iniconfig | 2.3.1 | MIT | (pytest transitive) |
| pluggy | 1.7.0 | MIT | (pytest transitive) |
| packaging | 26.3 | Apache-2.0 OR BSD-2-Clause | (pytest transitive) |

## Standard library only (no third-party package)

Core analysis uses the Python standard library: `ast` (all SAST parsing — rule R7, parse only),
`sqlite3` (storage), `hashlib` (stable IDs), `re`, `urllib`, `html`, `json`, `pathlib`.

## Third-party benchmark targets (development/evaluation only — NOT our work)

Used only as **scan targets** to measure generalisation to a real, independently written app. Their
source is **not vendored**: `scripts/bench_fetch.sh` clones each at a pinned commit into a git-ignored
`bench/<app>/src/` and runs it locally via Docker Compose (see `docs/DECISIONS.md` D-16). We ship only
our own answer key, Compose wrapper and README for them.

| App | Pinned commit | Licence / permission | Role |
|---|---|---|---|
| [we45 Vulnerable-Flask-App](https://github.com/we45/Vulnerable-Flask-App) | `b6a4f97afd466e83e1f60781494252dec1c37039` | No licence file; **used with the authors' (we45) explicit permission** for this event | Third-party Flask benchmark target (intentionally vulnerable) |
| [OWASP Benchmark for Python](https://github.com/OWASP-Benchmark/BenchmarkPython) | `f1291485808b66e20ddb6b01b10dc71b3df8c8ba` | GNU GPL v3.0 (`GPL-3.0-only`); cloned locally and scanned only, never modified or redistributed | Third-party Flask benchmark target (OWASP test suite); key transcribed from its official `expectedresults-0.1.csv` (`docs/DECISIONS_Dev1.md` A-70) |

The OWASP Benchmark for Python is © the OWASP Benchmark project and its authors, licensed under the
GPL v3.0. We only clone it into the git-ignored `bench/owasp-benchmark-python/src/` and run it in a
local container built by our own `Dockerfile`; we ship none of its code. Our files for it
(`bench/owasp-benchmark-python/{answer_key.json,build_key.py,Dockerfile,.dockerignore,docker-compose.yml,README.md}`)
are our work.

The we45 app is © its authors; it carries no licence file, so we use it **only under the permission the
authors (we45) granted us** for this event, and we neither modify nor redistribute it. Our own files
for it (`bench/vulnerable-flask-app/answer_key.json`, `bench/vulnerable-flask-app/docker-compose.yml`,
`bench/vulnerable-flask-app/README.md`) are our work and are listed under "own work" below.

## Own work (not third-party)

Written from scratch by the team for this event (rule R1, R8):

- The whole `FlowStopper/` package: route mapper, call graph, taint engine, secrets detector,
  DAST engine and checks, **correlation engine**, scoring/CVSS, reports, eval harness.
- `apps/mock_a/` (Flask shop) and `apps/mock_b/` (FastAPI shop) — our own development and
  regression fixtures, clearly labelled as our own work. They are **not** the evaluation
  target; only the organisers' app is scanned during evaluation (rule R8).
- Our files under `bench/<app>/` (answer keys, compose overrides, READMEs) — but **not** the
  benchmark apps' own source, which is third-party (see the section above) and never committed.
- All fixtures, tests, scripts and documentation.

> Verify every licence and version against PyPI before the final submission (task P7-A2).
