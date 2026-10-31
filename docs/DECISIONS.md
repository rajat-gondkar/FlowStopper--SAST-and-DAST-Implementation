# Decisions

One line per decision (spec rule: when a detail is ambiguous, pick the simpler option, record it,
continue). Newest first.

<<<<<<< HEAD
- **D-19 (SAST name resolution never guesses):** `resolve_call` / `ProjectIndex.canonical` return a
  project qualname, an external dotted name (`os.system`, `flask.request.args.get`) or `builtins.<name>`,
  and **None** for local variables (unless the call graph supplies a tracked instance type), computed
  callees (`getattr(...)()`, `f()()`), and names that point into the project but are defined nowhere.
  Imports inside `except ImportError:` never shadow the `try:` import; a bare name that is not
  defined, imported or builtin is attributed to the module's single external star import.
- **D-18 (SAST module names + absolute-import fallback):** module name = dotted path relative to the
  source root (`pkg/__init__.py` → `pkg`; `pkg.py` loses to `pkg/__init__.py`, as in Python); when the
  root itself has an `__init__.py` and an identifier name, that name prefixes every module. An absolute
  import resolves as written first; if that is not a project module it is retried relative to the
  importing file's package chain, closest first (apps started from their own directory import siblings
  as top-level names). Standard-library names (`sys.stdlib_module_names`) never take that fallback.

=======
- **D-19 (SQLi check, P1-B4):** error-based evidence **short-circuits** the boolean-differential
  probe — when an error fires we report it at confidence 0.9 and skip the ~12 extra differential
  requests, rather than running both to claim the spec's combined 0.95 (revisit in P4 tuning if the
  extra signal is worth the requests). The differential is also skipped when the baseline is
  *unstable* (can't trust the comparison), and error-based is skipped when the benign baseline page
  already contains a SQL-error string (can't attribute it). Payloads are exactly Appendix B; a test
  (`tests/test_checks.py::test_only_appendix_b_payloads_are_sent`) asserts nothing else is sent (R4).
- **D-18 (scope guard semantics, P0-B1):** (a) `ALLOWED_HOSTS` env **replaces** the base allow-list
  rather than extending it (matches the `DastConfig.allowed_hosts` "env overrides" note and the
  SETUP/`make bench` usage, which list `localhost,127.0.0.1,::1` explicitly); `--allow-host` extras
  merge on top and log a WARNING. A stray empty/whitespace `ALLOWED_HOSTS=` is treated as unset (keeps
  the default) so it never refuses every target. (b) Matching is a pure string allow-list on the URL's
  parsed hostname — we **never resolve DNS** (R3), so an unlisted name is refused even if it would
  resolve to loopback/private. (c) IP *literals* are compared canonically via stdlib `ipaddress`
  (so `::1` == `0:0:0:0:0:0:0:1`), which resolves nothing; host names match exactly (no subdomain
  wildcards), case/port/trailing-dot normalised. Non-http(s) schemes and host-less URLs are refused.
>>>>>>> b/phase-1
- **D-17 (git writes hard-blocked for the agent):** the no-auto-push rule is now enforced
  mechanically, not just documented. A PreToolUse hook (`.kiro/hooks/block-git-writes.json`, matcher
  `bash`) runs `scripts/git_guard.py`, which exits 2 (block) on any agent shell command that invokes
  `git add`, `git commit` or `git push` (handles chained commands and `-C`/`-c` forms; command-position
  anchored so quoted mentions like `grep "git push"` are allowed). Other git commands (status, diff,
  log, clone, checkout, merge, tag, rev-parse, check-ignore) stay allowed. Person 1 does all staging,
  committing and pushing. Active from the next session start.
- **D-16 (benchmark app switched to the Flask app):** replaced PyGoat (D-15) with the **we45
  Vulnerable-Flask-App** (`we45/Vulnerable-Flask-App`), pinned at commit
  `b6a4f97afd466e83e1f60781494252dec1c37039` (master; no tags). The authors (we45) **granted us
  permission** to use it for this event; the repo ships no licence file, so use is by that grant
  (recorded in `THIRD_PARTY.md`). Chosen because **Flask is our primary / best-fit framework** — the
  earlier licence blocker in D-15 is resolved by the permission. Trade-offs, documented and accepted:
  it is a Python 2.7 app (the source is still py3-**parseable**, so parse-only SAST works; the Docker
  build uses old wheels and can be brittle on modern hosts — affects only the DAST side), and most
  endpoints are JSON APIs behind JWT auth (`admin`/`admin123`), so the reflected-XSS finding is
  realistically a runtime detection. Not vendored (cloned into git-ignored
  `bench/vulnerable-flask-app/src/`); scope via `ALLOWED_HOSTS` config only (R3); `make bench` never
  gates `make check`. Mock A and Mock B are unchanged.
- **D-15 (third-party benchmark app — SUPERSEDED by D-16):** chose **OWASP PyGoat**
  (`adeyosemanputra/pygoat`) pinned at tag **`v2.0.1`** (`c11e8429349cc05ff38564d3bf7ef09fb2411874`),
  MIT. Evaluated the candidates:
  *we45/Vulnerable-Flask-App* is Flask (best framework fit) but has **no licence** (all-rights-
  reserved) → fails the permissive-licence requirement; *DVPWA* is aiohttp and *DSVW* is stdlib
  `http.server` → neither is supported by our route extractors; *PyGoat* is Django + MIT + Docker
  Compose + maintained. Picked PyGoat on licence + runnability; accepted the trade-off that Django is
  our shallowest extractor (cut-list), which makes it an honest generalisation signal. Pinned **v2.0.1
  not v3.x**: v3 runs traefik + per-lab Docker-in-Docker containers (mounts the docker socket) and the
  vulnerable code is not all in the Django source our SAST reads — a poor static-analysis target.
  Not vendored (cloned at the pin into git-ignored `bench/pygoat/src/`). Scope via `ALLOWED_HOSTS`
  config only (R3); no FlowStopper/ edits. `make bench` is never gated by `make check`.
- **D-14 (Python):** Require 3.11+; version pins were resolved on Python 3.12 (no 3.11 on the init
  machine). `.python-version` = 3.12. Lock files note the resolver version.
- **D-13 (lint):** ruff line-length 120; `E501` ignored because `ruff format` owns wrapping and we
  allow long string literals (payloads, evidence). Keeps the catalogue/fixtures readable.
- **D-12 (suppressed issues):** "suppressed" is derived, not a new model field — an issue with no
  runtime findings whose code findings are all `suppressed=True`. Helper `is_suppressed(issue)` in
  `correlate/issues.py`; such issues sort last and never count as reported (B-2).
- **D-11 (engine entry points):** `run_sast`→`sast/runner.py`, `run_dast`→`dast/runner.py`,
  `correlate`→`correlate/engine.py` (per the spec §6 interface box). Stubs raise `NotImplementedError`.
- **D-10 (config args):** the three interface functions take `config=None` and build a default
  config when omitted. Additive vs the spec signature; keeps call sites simple.
- **D-09 (OWASP 2025 map):** verified categories against the official 2025 mapped-CWE lists
  (owasp.org/Top10/2025). Where the spec's convenience label differed, the official mapping wins:
  **200, 497, 538, 548, 1275 → A01** (spec table said A02). 614/1004/942/489/215/693/1021 → A02;
  209 → A10; injection → A05; hard-coded secrets kept at **A07** (re-verify 321 vs A04 in P7).
- **D-08 (CVSS):** CVSS 3.1 vectors stored in `cwe.py` with the `CVSS:3.1/` prefix and a precomputed
  base score + severity bucket, so SAST can set severity without importing `cvss.py`. B's `cvss.py`
  must reproduce `cwe.BASE_SCORES` (test required in P2-B6).
- **D-07 (CLI registry):** `cli.py` (A) only imports and registers commands; each command body lives
  in the owner's package (`*/commands.py`). So Dev B adds commands without touching `cli.py`.
- **D-06 (config layout):** engine configs live with their engines — `sast/config.py` (A),
  `dast/config.py` (B), `correlate/config.py` (B); `FlowStopper/config.py` (B) holds global/env.
- **D-05 (CWE families):** each row of spec §8 is one family; rows marked "own" form a family of the
  CWEs listed (e.g. {693,1021}). `cwe.family_name()` returns a stable key used by dedupe/matching.
- **D-04 (ports):** Mock A dev port 5050, Mock B 8090, API 8000 (macOS reserves 5000 for AirPlay).
- **D-03 (answer key):** the organisers prescribe no key format (judges verify by reading our
  output), so our Appendix C schema is canonical for every key, and the organisers' key is
  transcribed/converted into it (`evalkit/convert_organiser_key.py`, Phase 3). We also export a
  Markdown findings list (`report/markdown.py`) to make manual verification easy — any clear layout
  is fine.
- **D-02 (spec file):** renamed `FlowStopper Build Plan.md` → `FlowStopper_BUILD_SPEC.md` (the name
  the spec's own layout uses; no spaces).
- **D-01 (naming):** package directory and CLI are both `FlowStopper` (matching the spec's casing);
  `python -m FlowStopper` works too. Distribution name on PyPI-style metadata is lowercase
  `flowstopper`.
