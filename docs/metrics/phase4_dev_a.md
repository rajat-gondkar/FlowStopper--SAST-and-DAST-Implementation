# Phase 4 (Dev A) — SAST tuning before/after

Spec P4-A1 asks for a before/after measurement of each batch of SAST rule changes. "Phase 3" is the
P3-J1 baseline (`baseline_mock_a.json`, `baseline_bench.json`, scans in `out/baseline_*`). Each batch
column is a fresh live `FlowStopper scan` + `FlowStopper eval` of the same targets (outputs in
`out/p4a_*`, git-ignored). Dev B's DAST/correlator changes are not in these runs, so DAST numbers
should not move.

## Mock A (`apps/mock_a`, key `apps/mock_a/answer_key.json`)

| Metric | Phase 3 (before) | Batch 1 | Batch 2 | Final |
| --- | --- | --- | --- | --- |
| Code detection | 13/13 | 13/13 | 13/13 | 13/13 |
| Runtime detection | 10/13 | 10/13 | 10/13 | 10/13 |
| Correct links | 7/10 | 7/10 | 7/10 | 7/10 |
| Wrong links | 0/7 | 0/7 | 0/7 | 0/7 |
| False alarms | 1/21 | 1/21 | 1/21 | 1/21 |
| Unplanted (informational) | 5 | 5 | 5 | 5 |
| Reported issues | 21 | 21 | 21 | 21 |
| Suppressed issues | 1 | 1 | 5 | 5 |
| SAST findings (live / suppressed) | 13 / 1 | 13 / 1 | 13 / 5 | 13 / 5 |
| DAST findings (requests) | 19 (634) | 19 (634) | 19 (634) | 19 (634) |
| SAST time | 0.039 s | 0.027 s | 0.029 s | 0.029 s |

## Bench (`bench/vulnerable-flask-app/src`, key `bench/vulnerable-flask-app/answer_key.json`)

| Metric | Phase 3 (before) | Batch 1 | Batch 2 | Final |
| --- | --- | --- | --- | --- |
| Code detection | 3/4 | 3/4 | 4/4 | 4/4 |
| Runtime detection | 1/3 | 1/3 | 1/3 | 1/3 |
| Correct links | 0/2 | 0/2 | 0/2 | 0/2 |
| Wrong links | 0/0 | 0/0 | 0/0 | 0/0 |
| False alarms | 0/9 | 0/8 | 0/9 | 0/9 |
| Unplanted (informational) | 4 | 3 | 3 | 3 |
| Reported issues | 9 | 8 | 9 | 9 |
| Suppressed issues | 0 | 0 | 1 | 1 |
| SAST findings (live / suppressed) | 7 / 0 | 6 / 0 | 7 / 1 | 7 / 1 |
| DAST findings (requests) | 5 (454) | 5 (454) | 5 (454) | 5 (454) |
| SAST time | 0.049 s | 0.034 s | 0.036 s | 0.043 s |

## SAST timings (P4-A3)

`run_sast` only (no DAST), median of 3 runs with `time.perf_counter`, `SastConfig(exclude_dirs=["__pycache__"])`,
on this machine after batches 1 and 2. "Planning" is the measurement taken before any Phase 4 change.

| Target | Functions | Routes | Findings (suppressed) | Summary passes | Planning | Final |
| --- | --- | --- | --- | --- | --- | --- |
| Mock A (`apps/mock_a`) | 35 | 25 | 18 (5) | 2 | 0.04 s | 0.025 s |
| Bench (`bench/vulnerable-flask-app/src`) | 19 | 12 | 8 (1) | 2 | 0.06 s | 0.038 s |
| Pydantic proxy (`.venv/.../site-packages/pydantic`, 105 files) | 1798 | 0 | 0 (0) | 3 | 3.1 s | 1.8 s |
| Synthetic Flask project (200 generated modules) | 800 | 200 | 400 (200) | 2 | — | 2.4 s |

The synthetic project gives each module a route, a chained cross-module SQL helper (200 live
findings) and an uncalled `os.system` helper, so the request-hook and `unreachable` passes run at
scale (200 unreachable functions, 200 suppressed `unreachable` findings). Every Python file is parsed
exactly once (`tests/test_sast_runner.py::test_run_sast_parses_each_python_file_once`). No target got
slower, so no optimisation was made (A-50).

## What changed and why

Batch 1 (A-37 to A-43):

- **Bench SAST findings 7 → 6, reported issues 9 → 8, unplanted 4 → 3, false-alarm denominator
  9 → 8**: the CWE-79 at `app/app.py:185` is gone. The handler builds `Response(json.dumps(...))`
  and sets `resp.mimetype = 'application/json'` a few lines later, which A-38 now treats like a safe
  response wrapper (BACKLOG 9). That finding matched nothing in the key, so no detection number moves.
- **Bench secret at `tests/e2e_zap.py:15`: confidence 0.7 → 0.5** (A-43, BACKLOG 10). Still reported,
  so the counts are unchanged.
- **Mock A: no number moves.** The splat (A-39), `_is_abort` (A-40) and fixpoint-warning (A-41)
  changes have no matching code shape in Mock A, and the host binding (A-37) touches only
  `app.py`'s `__main__` line, which has no key entry. The one false alarm is BACKLOG 4 (Dev B's
  evalkit fix) and is not a SAST issue.
- **Receiver-based leaf matching (A-42)**: checked, zero `py.traversal.path-access` and zero
  `.raw`/`.extra` SQL findings on both targets, so nothing changed.
- SAST/total time differences are run-to-run noise at this scale.

Batch 2 (A-44 to A-49):

- **Bench code detection 3/4 → 4/4, reported issues 8 → 9, SAST live findings 6 → 7**: VF02 (the
  404 handler `pnf` building a template with `% request.url` and passing it to
  `render_template_string`) is now a live CWE-79 at `app/app.py:114`. Three rules make it: the
  request URL is a source (A-44), the template source of `render_template_string` is a sink (A-45),
  and `@app.errorhandler` functions are walked as code-only entry points (A-46). It has
  `entry_routes == []` and `source_param None`, so the correlator cannot link it, and it adds no
  false alarm (0/9).
- **Bench suppressed issues 0 → 1**: the CWE-22 in `yaml_hammer` (`app/app.py:326`) now exists as a
  suppressed `sanitized:werkzeug.utils.secure_filename` finding (A-47). Before, a sanitised flow
  produced nothing. It matches no key entry.
- **Mock A suppressed issues 1 → 5, SAST suppressed findings 1 → 5**: the decoys that used to be
  silent now carry suppressed findings with their reason: D03 `greet` (`sanitized:html.escape`),
  D06 `safe_redirect` (`sanitized:guard:allow-list`), D01 `fetch_product` (`safe:sql-parameterised`)
  and D02 `fetch_order_by_int` (`sanitized:builtins.int`); D04 `safe_ping` keeps
  `safe:subprocess-list-no-shell`. Live findings, links and false alarms do not move, and no planted
  bug is suppressed.
- **`unreachable`: 0 findings on both targets.** Mock A has one unreachable function
  (`utils.payments.charge`, no taint sink); the bench app has none (A-48).
- DAST numbers are unchanged on both targets, as expected.

Final (A-50, A-51), the spec's P4-A1 "after" run (`out/p4a_mock_a`, `out/p4a_bench`):

- **No number moves against Batch 2.** Batch 3 adds only the parse-once test, the timings above and
  the Mock A key decision; it changes no SAST rule. SAST time differences are run-to-run noise.
- **Overall Phase 3 → Final**: bench code detection 3/4 → 4/4 (batch 2, VF02), bench unplanted 4 → 3
  (batch 1, `app/app.py:185`), suppressed issues Mock A 1 → 5 and bench 0 → 1 (batch 2, B-2
  reasons). Wrong links stay 0 on both targets, Mock A false alarms stay 1/21.
- **Mock A key gaps (A-51, BACKLOG 6)**: `POST /login` `password` and `GET /download` "XSS" stay
  known extras; `apps/mock_a/answer_key.json` is not edited.
- **DAST numbers did not move** (runtime detection, DAST findings and request counts are identical
  in every column), because Dev B's DAST/correlator changes are not in this checkout.
