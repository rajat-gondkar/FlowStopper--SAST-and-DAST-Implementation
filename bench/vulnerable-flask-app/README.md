# Benchmark target: we45 Vulnerable-Flask-App

A third-party, intentionally vulnerable **Flask** app used only as a **scan target** to measure how
well FlowStopper generalises to a real app we did not write. It is **not** part of our product and is
**not vendored**. Flask is our primary framework, so this is our best-fit generalisation target.

- Upstream: https://github.com/we45/Vulnerable-Flask-App
- Pinned: commit `b6a4f97afd466e83e1f60781494252dec1c37039` (master; the repo has no release tags)
- Usage: **open source; the authors (we45) granted us permission to use it for this event.** The repo
  carries no licence file, so permission is by the authors' grant — see `../../docs/DECISIONS.md` D-15
  and `../../THIRD_PARTY.md`. We neither modify nor redistribute it.

## Files here (our own work)

| File | What it is |
|---|---|
| `answer_key.json` | hand-written, source-verified key in our Appendix C schema (`../../docs/ANSWER_KEY_FORMAT.md`) |
| `docker-compose.yml` | our Compose wrapper: builds the app's cloned Dockerfile, publishes `127.0.0.1:${BENCH_PORT:-8100}` |
| `README.md` | this file |
| `src/` | the cloned app — **git-ignored, never committed** |
| `out/` | scan outputs — git-ignored |

## Run

```bash
make bench-fetch          # clone @ pinned commit into src/ (git-ignored) and start via Docker Compose
make bench                # full pipeline + FlowStopper eval -> ../../docs/metrics/bench_vulnerable-flask-app.json
make bench-down           # stop
```

`make bench` allow-lists the target **via config only** (`ALLOWED_HOSTS`, rule R3); it never edits
`FlowStopper/`. The app is reachable at `http://127.0.0.1:8100` (container port 5050; override
`BENCH_PORT`).

## Keyed vulnerabilities (verified against the pinned source, `app/app.py`)

| ID | CWE | Kind | Where |
|---|---|---|---|
| VF01 | 89 | pair | `search_customer` — `request.json['search']` %-formatted into SQL run by `db.engine.execute` (L261/265) → `POST /search` |
| VF02 | 79 | pair | `pnf` 404 handler — `render_template_string('%s' % request.url)` reflects the URL unescaped (L114) → `GET *` |
| VF03 | 798 | code_only | `app.secret_key = '...'` literal (L28) |
| VF04 | 798 | code_only | `app.config['SECRET_KEY_HMAC'] = 'secret'` JWT signing key (L26; also L27 `_HMAC_2`) |
| VF05 | 693 | runtime_only | missing `Content-Security-Policy` header (host-wide) |

Conservative by design (prefer fewer correct entries over guesses). **Not keyed** (outside our six
detection types): insecure JWT verification (`verify=False`, CWE-347), `yaml.load` deserialisation
(CWE-502), the docx/XXE uploader (CWE-611), IDOR on `/get/<id>` (access control), and sensitive-data
exposure (CCNs). The file-upload paths use `werkzeug.secure_filename`, which our taint engine treats
as a path-traversal sanitiser — correctly **not** a traversal finding.

## Caveats that affect measured metrics (not the key's correctness)

- **Python 2.7 app.** The upstream Dockerfile is `python:2.7.14-jessie`. `app/app.py` is still
  Python-3-**parseable** (function-style `print`, `except … as e`), so our parse-only SAST (R7) reads
  it fine. The Docker **build** uses old/py2 wheels and archived apt repos, so `make bench-fetch` may
  need network access and can be brittle on modern hosts; this affects only the DAST (running) side,
  not SAST.
- **Auth:** the data endpoints (incl. `/search`) require a JWT. Get one with
  `POST /login {"username":"admin","password":"admin123"}` (seeded user) → token in the `Authorization`
  response header → send it as `Authorization` on later requests. Configure the DAST login step
  (P1-B1) or the pairs detect code-only.
- **JSON APIs:** most endpoints return `application/json`; the HTML reflections (XSS) are on the 404
  page and the `/search` error path, so the reflected-XSS finding (VF02) is realistically a **DAST**
  (runtime) detection — SAST is unlikely to link it (see VF02 notes).
- `make bench` produces the metrics file once the pipeline (P3-A1) and eval (P1-B5/P3-B1) are
  implemented; before then it prints guidance and writes nothing.
