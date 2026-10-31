# Benchmark target: OWASP PyGoat

A third-party, intentionally vulnerable **Django** app used only as a **scan target** to measure how
well FlowStopper generalises to a real app we did not write. It is **not** part of our product and is
**not vendored**.

- Upstream: https://github.com/adeyosemanputra/pygoat
- Pinned: tag `v2.0.1`, commit `c11e8429349cc05ff38564d3bf7ef09fb2411874`
- Licence: MIT (© its authors). We neither modify nor redistribute it. See `../../THIRD_PARTY.md`.
- Why PyGoat / why v2.0.1 (not v3.x): `../../docs/DECISIONS.md` D-15.

## Files here (our own work)

| File | What it is |
|---|---|
| `answer_key.json` | hand-written, source-verified key in our Appendix C schema (`../../docs/ANSWER_KEY_FORMAT.md`) |
| `compose.override.yml` | our Compose override: publish on `127.0.0.1:${BENCH_PORT:-8100}` + network alias `pygoat` |
| `README.md` | this file |
| `src/` | the cloned app — **git-ignored, never committed** |
| `out/` | scan outputs — git-ignored |

## Run

```bash
make bench-fetch          # clone @ pinned commit into src/ (git-ignored) and start via Docker Compose
make bench                # full pipeline + FlowStopper eval -> ../../docs/metrics/bench_pygoat.json
make bench-down           # stop
```

`make bench` allow-lists the target **via config only** (`ALLOWED_HOSTS`, rule R3); it never edits
`FlowStopper/`. The app is reachable at `http://127.0.0.1:8100` (override `BENCH_PORT` to change).

## Keyed vulnerabilities (verified against the pinned source)

| ID | CWE | Kind | Where |
|---|---|---|---|
| PG01 | 89 | pair | `introduction/views.py` `sql_lab` — `raw()` with concatenated `name`/`pass` → `POST /sql_lab` |
| PG02 | 89 | pair | `introduction/views.py` `injection_sql_lab` — same `raw()` pattern → `POST /injection_sql_lab` |
| PG03 | 79 | pair | `introduction/views.py` `xss_lab` — GET `q` rendered via a `|safe` template → `GET /xssL` |
| PG04 | 78 | pair | `introduction/views.py` `cmd_lab` — `subprocess.Popen(shell=True)` on formatted `domain` → `POST /cmd_lab` |
| PG05 | 798 | code_only | `pygoat/settings.py:24` hard-coded `SECRET_KEY` |
| PG06 | 489 | runtime_only | `DEBUG = True` → verbose error pages (host-wide) — *runtime manifestation marked uncertain* |
| PG07 | 693 | runtime_only | missing `Content-Security-Policy` header (host-wide) — *runtime manifestation marked uncertain* |

Conservative by design (prefer fewer correct entries over guesses). Not keyed: PyGoat's `eval()` lab
(CWE-95, outside our six types), SSRF/XXE/insecure-deserialisation labs (outside our types), and the
partial XSS filters in `xss_lab2`/`xss_lab3` (bypassable but not cleanly classifiable — left out
rather than guessed).

## Caveats that affect measured metrics (not the key's correctness)

- **Auth:** every lab view checks `request.user.is_authenticated`, so DAST must register/log in to
  reach the runtime side. Without DAST auth config, the pairs are detected code-only. Configure the
  DAST login step (P1-B1) to exercise the runtime side.
- **CSRF:** `sql_lab` is not `@csrf_exempt` (needs a CSRF token on POST); `injection_sql_lab` and
  `cmd_lab` are `@csrf_exempt`.
- **Django is our shallowest extractor** (cut-list item), so code detection here is an honest
  lower-bound signal, which is exactly the point of a generalisation benchmark.
- `make bench` produces `docs/metrics/bench_pygoat.json` once the pipeline (P3-A1) and eval
  (P1-B5/P3-B1) are implemented; before then it prints guidance and writes nothing.
