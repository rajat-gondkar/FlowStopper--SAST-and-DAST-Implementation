# Metrics

Section 4 metrics written by `FlowStopper eval`. One file per run.

| File | Target | What it is |
|---|---|---|
| `baseline_mock_a.json` | Mock A (our own Flask fixture) | Phase 3 baseline, before any Phase 4 tuning |
| `baseline_bench.json` | we45 Vulnerable-Flask-App (third-party benchmark) | Phase 3 baseline, before any Phase 4 tuning |
| `baseline.json` | **organisers' app** | **Not created yet.** The spec's P3-J1 baseline. It is written only when the organisers' app (`target_src/`) and key (`keys/`) are available. Do not fill it from another target. |

Mock B is never scanned before Phase 6 (held-out test), so it has no baseline here.

## Phase 3 baselines (2026-10-31, before tuning)

| Metric | Mock A | Bench app |
|---|---|---|
| Code detection | 13/13 (100%) | 3/4 (75%) |
| Runtime detection | 10/13 (76.9%) | 1/3 (33.3%) |
| Correct links | 7/10 (70%) | 0/2 (0%) |
| Wrong links | 0/7 (0%) | 0/0 |
| False alarms | 1/21 (4.8%) | 0/9 (0%) |
| Run time | 2.1 s | 2.1 s |

How they were produced (Mock A run with Flask on port 5050; bench app via
`docker compose -f bench/vulnerable-flask-app/docker-compose.yml up --build` on port 8100):

```bash
FlowStopper scan --source apps/mock_a --target http://127.0.0.1:5050 --out out/baseline_mock_a
FlowStopper eval --key apps/mock_a/answer_key.json --issues out/baseline_mock_a/issues.json --out docs/metrics/baseline_mock_a.json

FlowStopper scan --source bench/vulnerable-flask-app/src --target http://127.0.0.1:8100 --out out/baseline_bench
FlowStopper eval --key bench/vulnerable-flask-app/answer_key.json --issues out/baseline_bench/issues.json --out docs/metrics/baseline_bench.json
```

The triage of every miss and false alarm goes in `docs/BACKLOG.md` (P3-J2).
