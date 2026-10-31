# FlowStopper — master plan & orchestration

This is the *how we actually run the build* layer on top of
[`../FlowStopper_BUILD_SPEC.md`](../FlowStopper_BUILD_SPEC.md), which stays the single source of
truth for scope, contracts and acceptance criteria. Read the spec once; then work from your own
per-person task list:

- **Person 1 = Dev A** → [`PERSON_1_DEV_A.md`](PERSON_1_DEV_A.md)
- **Person 2 = Dev B** → [`PERSON_2_DEV_B.md`](PERSON_2_DEV_B.md)

Person 1 owns repository initialisation (this scaffold) and pushes first; Person 2 clones and
starts from Phase 1. [`SETUP.md`](SETUP.md) is the clone-and-run guide.

## Ownership (strict — never edit the other dev's files)

| Area | Path | Owner |
|---|---|---|
| Shared contracts | `FlowStopper/models.py`, `FlowStopper/cwe.py`, `FlowStopper/ids.py`, `FlowStopper/evalkit/keyschema.py` | **Shared** (frozen at `contract-v1`) |
| SAST | `FlowStopper/sast/**` | A |
| Mock A | `apps/mock_a/**` | A |
| CLI / API / pipeline | `FlowStopper/cli.py`, `FlowStopper/api.py`, `FlowStopper/pipeline.py` | A |
| Global/storage/scope/cvss | `FlowStopper/config.py`, `storage.py`, `scope.py`, `cvss.py` | B |
| DAST | `FlowStopper/dast/**` | B |
| Correlate | `FlowStopper/correlate/**` | B |
| Report | `FlowStopper/report/**` | B |
| Eval harness | `FlowStopper/evalkit/**` (except keyschema, shared) | B |
| Mock B (held out) | `apps/mock_b/**` | B — **A must not read until Phase 6** |
| Docs / scaffold | `pyproject.toml`, `Makefile`, `README.md`, `THIRD_PARTY.md`, `docs/**`, `scripts/**` | A drafts, both maintain |

Each dev owns the tests for their own modules under `tests/`. Shared-contract changes go
through [`CONTRACT_CHANGES.md`](CONTRACT_CHANGES.md) with the other dev's acknowledgement.

The command registry `FlowStopper/cli.py` (A) only *imports and registers* each command; the
command body lives in the owner's package (`dast/commands.py`, `correlate/commands.py`,
`report/commands.py`, `evalkit/commands.py` are B's). So B never edits `cli.py`.

## Cross-developer interface (the only coupling)

```python
FlowStopper/sast/runner.py      def run_sast(source_root, config=None) -> SastResult   # A
FlowStopper/dast/runner.py      async def run_dast(target_url, routes, config=None) -> DastResult  # B
FlowStopper/correlate/engine.py def correlate(sast, dast, routes, config=None) -> list[Issue]      # B
```

Everything crosses as the pydantic models in `FlowStopper/models.py`, serialisable to JSON.
The hand-written `fixtures/` are the shared oracle: B's correlator and eval must reproduce
`fixtures/expected_issues.json` / `expected_metrics.json` from the other fixture files **before**
either engine produces real data. See [`../fixtures/README.md`](../fixtures/README.md).

## Phases (both devs work in parallel; a phase ends when both pass its exit criteria)

| Phase | Hours | A | B | Joint exit |
|---|---|---|---|---|
| 0 | 0–1 | scaffold, models, routes-ready | scope guard, cwe help, fixtures | `make check` green, contracts frozen |
| 1 | 1–4 | index, routes, call graph, Mock A | HTTP client, discovery, baseline, SQLi+XSS, eval skeleton | A's `routes.json` consumed by B |
| 2 | 4–8 | taint, secrets, templates, SAST runner | remaining checks, verify, storage, **correlator v1**, Mock B | runners produce real data; correlator passes fixtures |
| 3 | 8–9.5 | `pipeline.py` + `scan` | `eval` on real app | baseline metrics recorded |
| 4 | 9.5–12.5 | SAST backlog, B-2 suppression, perf | DAST backlog, B-3 explain, B-1 auto-verify, tuning | "Good" targets met |
| 5 | 12.5–14 | API, CLI polish, containers | HTML, SARIF+CI gate, fixes | clean run + Docker up |
| 6 | 14–15 | (joint) unseal Mock B, fix generic behaviours only | generalisation ≥ 40% link rate, no regression |
| 7 | 15–16 | README, THIRD_PARTY final | ARCHITECTURE, LIMITATIONS, metrics | clean-clone test, tag `v1.0` |

## Success targets (section 4 of the spec)

Code detection >60/85% · Runtime detection >50/80% · Correct links >50/80% · Wrong links
<20/5% · False alarms <30/10% · Unseen app >40/65% · Run time <15/5 min. Prefer a **missed
link over a wrong link** everywhere.

## Non-negotiable rules (R1–R8)

Original work, disclose third parties (`THIRD_PARTY.md`), scan only authorised targets (scope
guard), harmless payloads only, confidentiality (`.gitignore`), no overfitting
(`tests/test_no_overfit.py`), safe-by-construction (parse-only SAST, escaped reports), only the
organisers' app is scanned in evaluation. Full text: spec §2. These are enforced by tests, not
just docs.

## Cut list if the schedule slips

P6-B1 diff → P5-B3 fixes (shrink) → P4-B4 auto-verify → P2-A5 template scan → second-order XSS /
Django depth. **Never cut:** FR-1…FR-10, scope guard, ambiguity handling, idempotency, B-2
suppression, eval harness, README, THIRD_PARTY.

## Git workflow

Trunk-based. Short-lived branches `a/<task-id>` and `b/<task-id>`; merge to `main` only after
`make check` passes. Commit small and often. Tag `contract-v1` once both devs confirm the
contracts; tag `v1.0` at release and freeze. Details and the two-person bootstrap are in
[`SETUP.md`](SETUP.md).
