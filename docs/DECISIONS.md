# Decisions

One line per decision (spec rule: when a detail is ambiguous, pick the simpler option, record it,
continue). Newest first.

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
