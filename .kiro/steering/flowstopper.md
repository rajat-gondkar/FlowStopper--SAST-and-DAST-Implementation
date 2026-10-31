# FlowStopper project rules (always-on steering)

This workspace builds **FlowStopper**, a SAST + DAST correlation engine, by two developers in
parallel. Authoritative docs: `FlowStopper_BUILD_SPEC.md` (source of truth), `docs/PLAN.md`,
`AGENTS.md`, and the per-person task lists `docs/PERSON_1_DEV_A.md` / `docs/PERSON_2_DEV_B.md`.

## Always
- Confirm whether you are acting as **Dev A** or **Dev B**, and work only from that task list.
- **Edit only your owner's files** (ownership table in `docs/PLAN.md`). Shared contracts
  (`FlowStopper/models.py`, `cwe.py`, `ids.py`, `evalkit/keyschema.py`) are frozen at `contract-v1`:
  additive changes only, via `docs/CONTRACT_CHANGES.md` with the other dev's ACK.
- Run `make check` (ruff + pytest) after changes; keep it green before merging. Then update
  `docs/PROGRESS.md` and log decisions in `docs/DECISIONS.md`.
- Regenerate, don't hand-edit, generated files: `make fixtures`, `make schemas`.

## Never
- **Never** edit `apps/mock_b/` as Dev A before Phase 6 (held-out test).
- **Never** commit `target_src/`, `keys/`, `*.key.json`, or `docs/target_notes.local.md` (rule R5).
- **Never** put app-specific constants (file names, URLs, planted IDs) in `FlowStopper/` (rule R6);
  write generic rules. `tests/test_no_overfit.py` enforces this.
- **Never** add DAST payloads outside spec Appendix B (R4), bypass `scope.py` (R3), or import/execute
  target source in SAST (R7).

## Compliance (R1–R8) is enforced by tests
Don't weaken a test to pass. Correctness > speed. Prefer a missed correlation link over a wrong one.

## House style
Python 3.11+, type hints on public functions, ruff clean (line-length 120). Pydantic models cross
stage boundaries. Deterministic output: sorted lists, stable IDs via `FlowStopper/ids.py`, seeded
randomness. Commit small; branches `a/<task-id>` / `b/<task-id>`.
