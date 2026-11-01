# Target app notes — TEMPLATE

Copy this to `docs/target_notes.local.md` (git-ignored, rule R5) and fill it in locally once the
organisers release their app. **Never commit the filled-in copy.** Nothing here may be hardcoded
into `FlowStopper/` — it informs *generic* rules only (rule R6).

> This template is safe to commit; it contains no organiser data.

## App basics
- Framework / version:
- How to start it (compose file, command, port):
- Base URL used for DAST:
- Auth (any login? endpoint, sample creds provided by organisers?):

## Route style
- Decorators / registration pattern (`@app.route`, `APIRouter`, `urlpatterns`, blueprints?):
- URL prefixes (blueprint/router) and where they're set:
- Path-param converter style (`<int:id>`, `{id}`, `(?P<id>…)`):
- Where request params are read (args/form/json/headers/cookies):

## Code layout
- Package/module layout, where helpers live (cross-file flows to expect):
- DB access layer (raw sqlite? ORM? query helpers?):
- Templating (Jinja? `|safe` usage?):

## Planted vulnerabilities (from the organisers' key)
- Count by kind (pairs / code-only / runtime-only / decoys):
- Key format the organisers gave us (so we can write the converter):
- Anything unusual (blind injection, stored XSS, non-standard sinks):

## Scanning notes
- `ALLOWED_HOSTS` value needed (compose service name?):
- How long a full scan took:
- Endpoints that are slow / unstable (need stricter evidence):
