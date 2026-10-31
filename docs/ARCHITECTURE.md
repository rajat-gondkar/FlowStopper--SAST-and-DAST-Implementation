# Architecture

> Skeleton seeded in Phase 0; finalised by Dev B in Phase 7 (P7-B1) with the pipeline diagram and
> the real tuned constants. The scoring formula below is the contract the correlator implements.

## Pipeline

```
source folder ─► SAST ─► routes + sast findings ─┐
   index → routes → call graph → taint → secrets   │
                                                    ├─► normalize ─► CORRELATE ─► SQLite ─► API / CLI / HTML / SARIF / Markdown
running app  ─► DAST ─► dast findings ─────────────┘
   scope-guarded client → discovery (seeded by routes + crawl) → baseline → checks → verify
```

Stage boundaries are the pydantic models in `FlowStopper/models.py`. Entry points:
`sast.runner.run_sast` (A), `dast.runner.run_dast` (B), `correlate.engine.correlate` (B), tied
together by `pipeline.py` (A).

**DAST ordering and budget scope.** Inside the DAST stage the order is fixed: scope-check the target,
discover endpoints (route-map seeded, then crawl), run the host-wide passive checks **once**, then
run the active checks per (endpoint, injectable parameter) — route-map endpoints first, Appendix B
priority parameter names first. The `--time-budget` (default 240 s) governs **only that last, active
phase**: discovery and the passive pass run first and are not interruptible. On expiry the runner
stops scheduling active checks, keeps everything already collected (passive findings included) and
sets `stats.truncated = true`, so total DAST wall-clock can exceed the budget by design (see
`docs/LIMITATIONS.md` and decision B-05).

## Correlation algorithm (the judged core)

For a runtime finding `r` and a code finding `c` with `same_family(r.cwe, c.cwe)` and `c` not
suppressed:

1. **Route gate (hard):** `route_match` =
   - `1.0` if `r.route_id ∈ c.taint.entry_routes` (flow originates at that route's handler),
   - `0.9` if `c`'s file/line is inside the route handler's span,
   - `0.8` if `c.code.function ∈ route.reachable_functions`,
   - else `0` → **not a candidate**.
2. **Other signals:** `param_match` (1.0 equal normalised names / 0.5 SAST param unknown / 0.0 both
   known & different), `method_match` (1.0 if methods agree else 0), `specificity` (1.0 full taint
   chain else 0.5).
3. **Score:** `0.50·route_match + 0.35·param_match + 0.10·method_match + 0.05·specificity`.
4. **Assignment:** sort edges by score; greedy **one-to-one** accepting edges ≥ `link_min` (0.70).
   **Ambiguity rule:** if best and second-best differ by < `ambiguity_margin` (0.10) and param does
   not separate them → **do not link** (emit Code-only + Runtime-only, add `ambiguity_penalty`).
5. **Labels:** linked → Confirmed; unlinked code → Code-only; unlinked runtime → Runtime-only.
6. **Risk:** `clamp(cvss × exploitability_factor, 0, 10)`; factors ×0.85 auth, ×0.9 differential-only,
   ×0.6 code-only, ×0.9 low-confidence runtime-only. Sort: Confirmed first, then risk↓, severity,
   CWE, id (deterministic). CVSS base from the vector in `cwe.py`.

Design principle: **prefer a missed link over a wrong link** (the "wrong links < 5%" target).

## Determinism (spec rule 7)

Sorted outputs, stable IDs (`ids.py`), seeded canaries (per-scan seed recorded in `scan_meta.json`),
normalised relative POSIX paths, LF line endings. Two scans of identical input produce identical
issue IDs and counts.
