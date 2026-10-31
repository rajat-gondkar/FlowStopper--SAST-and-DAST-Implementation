# AGENTS.md — guidance for AI coding agents on this repo

Both developers drive AI coding agents. This file is the contract for any agent working here. (Use
of AI tools is disclosed in `THIRD_PARTY.md`, rule R2.)

## Before you touch anything
1. Read `FlowStopper_BUILD_SPEC.md` once (the single source of truth), then `docs/PLAN.md`.
2. Work **only** from your developer's task list: `docs/PERSON_1_DEV_A.md` (Dev A) or
   `docs/PERSON_2_DEV_B.md` (Dev B). Confirm which developer you are before editing.

## Hard rules
- **Ownership is strict.** Edit only your developer's files (ownership table in `docs/PLAN.md`).
  Shared files (`models.py`, `cwe.py`, `ids.py`, `evalkit/keyschema.py`) are frozen at `contract-v1`;
  changes are additive only and go through `docs/CONTRACT_CHANGES.md` with the other dev's ACK.
- **Dev A must not read `apps/mock_b/`** until Phase 6 (held-out generalisation test).
- **Every task ends green:** run `make check` (ruff + pytest). Never merge or move on with a failing
  check. Then update `docs/PROGRESS.md` (one line) and log any judgement call in `docs/DECISIONS.md`.
- **Compliance rules R1–R8 are enforced by tests, not just docs** (see spec §2). Don't weaken a test
  to make it pass. In particular:
  - R3 scope guard: every DAST request goes through `scope.py`.
  - R4 payloads: only those in spec Appendix B; tests assert nothing else is sent.
  - R5: never commit `target_src/`, `keys/`, `*.key.json`, or `docs/target_notes.local.md`.
  - R6 no overfitting: **no app-specific constants in `FlowStopper/`** — `tests/test_no_overfit.py`
    greps for answer-key strings. Implement new behaviour as **generic rules**.
  - R7: SAST parses, never imports/executes target code; reports HTML-escape all evidence.
- **Determinism:** sorted outputs, stable IDs via `ids.py`, seeded randomness. Don't introduce
  nondeterministic ordering or timestamps into IDs or sorted lists.
- **Never stage, commit, or push.** `git add`, `git commit` and `git push` are **hard-blocked** for the
  agent by the `block-git-writes` PreToolUse hook (`.kiro/hooks/block-git-writes.json` →
  `scripts/git_guard.py`, exit 2). Make file changes only and report what you changed; Person 1 (a
  human) does all staging, committing and pushing. Other git commands (status, diff, log, clone,
  checkout, merge) are fine.

## Conventions
- Python 3.11+; type hints on public functions; `ruff` clean (line-length 120, `make fmt` to autofix).
- Pydantic models for anything crossing a stage boundary; serialise with `model_dump(mode="json")`.
- CLI: add a command by writing its function in **your** package's `commands.py`; `cli.py` (Dev A)
  registers it. Don't edit `cli.py` if you're Dev B.
- Tests live in `tests/`, each dev owns their modules'. Golden-file tests for routes/taint/correlator
  use `fixtures/` — regenerate with `make fixtures` / `make schemas`, never hand-edit the JSON.
- Commit small, trunk-based, branch `a/<task-id>` or `b/<task-id>`.

## The answer key is free-form
The organisers prescribe no key/report format (judges verify by reading). We use our own schema
(`docs/ANSWER_KEY_FORMAT.md`) and also emit a Markdown findings list. Any clear layout is acceptable;
don't over-engineer formatting.

## When a spec detail is ambiguous
Pick the simpler option, add one line to `docs/DECISIONS.md`, and continue. Don't block.
