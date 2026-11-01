# Metrics

Section 4 metrics written by `FlowStopper eval` or `FlowStopper scan --key`, one file per run. These
are our own development measurements against our own answer keys, not an official score.

## Final results (v1.0, 2026-11-01)

Both mock apps ran in Docker on the final `main`. The `final_*.json` files are the `eval` outputs.

| Target | Code | Runtime | Correct links | Wrong links | False alarms | Run time | File |
|---|---|---|---|---|---|---|---|
| Mock A (our Flask fixture) | 13/13 | 12/13 | 9/10 | 0/9 | 0/19 | 1.3 s | `final_mock_a.json` |
| Mock B (held out, FastAPI) | 13/13 | 11/14 | 8/10 | 0/8 | 0/19 | 1.5 s | `final_mock_b.json` |

**Unseen app** (spec: >40% good, >65% great): **6/10 = 60%**. This is Mock B's correct-link rate at
its first run, before any tuning on it (`mock_b_first_run.json`). The 8/10 above came after two
rounds of generic fixes based on Mock B's misses, so it does not count as unseen.

## Files

| File | Target | What it is |
|---|---|---|
| `final_mock_a.json`, `final_mock_b.json` | Mock A, Mock B | v1.0 results (table above) |
| `baseline_mock_a.json` | Mock A | Phase 3 baseline, before any Phase 4 tuning |
| `phase4_dev_a.md` | Mock A | Phase 4 SAST before/after table |
| `mock_b_first_run.json` | Mock B | **Phase 6 first run, frozen.** The unseen-app score. Never overwrite |
| `phase6.md` | Mock B, Mock A | Phase 6 rounds 1–2: triage, before/after, fixes, deferred list |
| `baseline.json` | **organisers' app** | **Not created yet.** The spec's P3-J1 baseline is written only when the organisers' app (`target_src/`) and key (`keys/`) are available. Do not fill it from another target |

## Reproduce

```bash
make showcase APP=mock_a     # or mock_b: starts the target in Docker, scans and scores it
```

The same steps by hand:

```bash
FlowStopper scan --source <src> --target http://127.0.0.1:<port> --out out/<name> --key <answer_key.json>
```

| Target | Source | Port | Key |
|---|---|---|---|
| Mock A | `apps/mock_a` | 5050 | `apps/mock_a/answer_key.json` |
| Mock B | `apps/mock_b` | 8090 | `apps/mock_b/answer_key.json` |

Run the targets in Docker. On a laptop, a deep checkout path can hide a path-traversal bug (see
`docs/LIMITATIONS.md`). The triage behind each round of fixes is in `docs/BACKLOG.md` and `phase6.md`.
