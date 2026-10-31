# Contract changes

The shared contracts — `FlowStopper/models.py`, `FlowStopper/cwe.py`, `FlowStopper/ids.py`,
`FlowStopper/evalkit/keyschema.py` — **freeze at tag `contract-v1`** (end of Phase 0). After the
tag, only **additive, backwards-compatible** changes are allowed, and each one needs:

1. an entry in this file (date, author, what & why, affected files),
2. the other developer's **ACK** before merge,
3. regenerated schemas (`make schemas`) and fixtures if affected (`make fixtures`), committed together.

Breaking changes (renames, removals, type changes, stricter validation) are **not** allowed after
the freeze without an explicit joint decision recorded here.

## Template

```
### CC-NN — <short title>
- Date / Author:
- Files:
- Change (additive?):
- Why:
- Impact on fixtures/schemas:
- ACK by <other dev>:
```

## Log

### CC-01 — Third-party benchmark target (we45 Vulnerable-Flask-App): Dev B touch-points (no contract change)
- Date / Author: 2026-10-31 / Dev A (Person 1)
- Files: none of Dev B's files were edited. This entry flags two Dev-B-owned couplings the benchmark
  relies on, for ACK — no change to any frozen contract (`models.py`/`cwe.py`/`ids.py`/`keyschema.py`).
- Context: added `make bench-fetch` / `make bench` + `bench/vulnerable-flask-app/` (answer key, Compose wrapper).
  All new code is Dev-A-owned (Makefile, `scripts/bench_fetch.sh`, `scripts/bench.sh`) plus an additive
  one-line widening of the shared R6 guard `tests/test_no_overfit.py` (now also globs
  `bench/*/answer_key.json`).
- Ask of Dev B (ownership: `scope.py`, `config.py`, `evalkit/metrics.py`) — **no edits requested now**,
  just confirm these behave generically when you implement them:
  1. **Scope (R3):** `scope.py`/`config.py` must honor the `ALLOWED_HOSTS` env var and merge in extra
     hosts (already your P0-B1 plan). `make bench` passes `ALLOWED_HOSTS=localhost,127.0.0.1,::1,flaskapp`
     (`flaskapp` is the compose service alias) so the benchmark host is allow-listed **via config only**
     — please do not hardcode any bench host in `FlowStopper/` (R6). No new field required
     (`DastConfig.allowed_hosts` already covers it).
  2. **Eval/metrics:** `make bench` calls `FlowStopper eval --key bench/vulnerable-flask-app/answer_key.json
     --issues … --out docs/metrics/bench_vulnerable-flask-app.json`. `evalkit/metrics.py` must stay
     **generic over any Appendix-C key** (no app-specific logic). The bench key uses only existing
     schema fields.
- Impact on fixtures/schemas: none.
- ACK by Dev B: **ACKed — Dev B, 2026-10-31.** Confirmed, no frozen-contract change. (1) Scope is
  honoured via config only: `scope.py` reads the allow-list from `ALLOWED_HOSTS` (parsed in
  `config.py`, default `localhost,127.0.0.1,::1`) and `build_guard()` merges `--allow-host` extras,
  so `make bench`'s `ALLOWED_HOSTS=…,flaskapp` allow-lists the benchmark host with **no bench host
  hardcoded in `FlowStopper/`** (R6; `tests/test_no_overfit.py` passes). `DastConfig.allowed_hosts`
  already covers it — no new field. (2) `evalkit/metrics.py` will implement the generic Appendix-C
  matching rules only (no app-specific logic); the bench key uses existing schema fields. Delivered
  as part of P0-B1.

_(Contracts not yet frozen; once `contract-v1` is tagged, add further entries above.)_
