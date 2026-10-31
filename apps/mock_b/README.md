# shoplite-b (Mock B) — held-out fixture app

**Our own work** (rule R8). A deliberately vulnerable FastAPI shop used as FlowStopper's
**generalisation test**.

> **HELD OUT.** Dev A must not read this directory until **Phase 6**. Mock B answers one question
> honestly: does the scanner work on an app it was never tuned against? Looking at it early (or
> tuning against its failures before Phase 6) destroys that signal — and the unseen-app metric is
> a scored target (spec §4).

## Why it looks nothing like Mock A

Mock A is Flask with blueprints and helper modules. Mock B is deliberately different in every
dimension a scanner might accidentally depend on:

| | Mock A | Mock B |
|---|---|---|
| Framework | Flask | **FastAPI** |
| Routing | `@bp.route`, blueprints | **`APIRouter` + `include_router` prefixes** |
| Layout | blueprints + `utils/` | **`routers/` → `services/` → `repositories/`** |
| Request data | query + form | **pydantic JSON bodies**, query, path converters |
| Templates | `render_template` | **`Jinja2Templates.TemplateResponse`** |
| Naming | `get_orders`, `file` | `list_items`, `fragment`, `onward`, `doc` |

Injection sinks sit one or two layers below the route handler, so finding them requires following
cross-module calls rather than matching a pattern inside a handler.

## Run it

```bash
docker compose -f apps/mock_b/docker-compose.yml up        # http://127.0.0.1:8090
# or, in the dev venv:
.venv/bin/python -m uvicorn apps.mock_b.main:app --port 8090
```

## Verify the planted bugs still fire

**Run this manually whenever Mock B changes, and again at the Phase 6 unsealing:**

```bash
.venv/bin/python -m apps.mock_b.selfcheck
```

It asserts all 16 planted bugs fire **and** all 8 decoys stay safe (plus a baseline query, so a
broken fixture cannot pass by making every query raise). Exit code is non-zero if anything fails.

This lives here rather than under `tests/` on purpose (decision **B-07**): `make check` collects only
`tests/`, so a test file there would expose the held-out contents to Dev A before Phase 6. The
trade-off is explicit — **it is not gated by `make check`, so it can rot silently**; running it on
every change to this directory is the mitigation. A planted bug that quietly stopped working would
make the Phase 6 generalisation score a lie.

**After Phase 6 unsealing:** promote the suitable checks into `tests/` (e.g. `tests/test_mock_b.py`)
so CI guards them like Mock A's, and keep this script only for whatever does not belong in the test
suite. Tracked as a Phase 6 item in [`../../docs/PERSON_2_DEV_B.md`](../../docs/PERSON_2_DEV_B.md).
Nothing about Mock B moves into `tests/` before then.

## Answer key

`answer_key.json` (our Appendix C schema) is **generated, not hand-written** — every planted bug
carries a `# vuln:<id>` / `# decoy:<id>` marker next to the offending line and the key is built
from those, so line numbers cannot drift:

```bash
.venv/bin/python -m apps.mock_b.build_key
make validate-key KEY=apps/mock_b/answer_key.json
```

Contents: **10 pairs** (two each for CWE-89, 79, 78, 22, 601), **3 code-only** secrets (CWE-798),
**4 runtime-only** (missing headers, cookie flags, verbose errors, version banner) and
**8 decoys** (safe look-alikes that must not be reported).

Credentials for the authenticated paths: `avery` / `pepper-ridge`.
