# Decisions — Dev A (Person 1)

Dev A's own design decisions (ids `A-NN`, newest first). Joint/Phase-0 decisions are in the shared
[`DECISIONS.md`](DECISIONS.md); Dev B's are in [`DECISIONS_Dev2.md`](DECISIONS_Dev2.md). Using an
`A-` prefix keeps our ids from ever colliding with Dev B's `B-` ids.

- **A-05 (Mock A serves real files)** _(formerly D-22)_: `apps/mock_a` creates `data/` and
  `docs_store/` (with a benign `welcome.txt`) at startup via `ensure_dirs()`, so the path-traversal
  bugs (M07/M08) actually reach files at runtime. Both dirs are git-ignored (`apps/*/data/`,
  `apps/*/docs_store/`); `shop.db` is seeded on startup and git-ignored (`*.db`). Verified manually:
  every planted bug fires and every decoy stays safe (SQLi error on `/api/orders?id=1'`, reflected and
  `|safe` XSS echo, `/etc/passwd` via `/download` and `/docs`, open redirects, 302s; decoys return
  escaped/JSON/404/allow-listed).
- **A-04 (XSS-via-template key location)** _(formerly D-21)_: the M04 answer-key code location points
  at the `render_template(...)` call site (`blueprints/users.py`), not the template line, because our
  pipeline reports the XSS at the handler sink with `source_param` and links it to the route there;
  the template `{{ note|safe }}` (templates/product.html) is the reason it is unescaped.
- **A-03 (route output conventions)** _(formerly D-20)_: `path_regex` is anchored and tolerates a
  trailing slash (`^...(/)?$`); `path_template` carries no trailing slash (root is `/`). Blueprint /
  router prefix composition follows each framework: Flask `register_blueprint(url_prefix=)` replaces
  the blueprint's own prefix (else the own prefix is used), nested blueprints compose; FastAPI
  `include_router(prefix=)` composes additively with the router's own `prefix`; Django roots are the
  `urlpatterns` modules not pulled in by another `include()`. One `Route` is emitted per (method,
  path); unresolved/dynamic registrations are skipped, never guessed.
- **A-02 (SAST name resolution never guesses)** _(formerly B-02)_: `resolve_call` /
  `ProjectIndex.canonical` return a project qualname, an external dotted name (`os.system`,
  `flask.request.args.get`) or `builtins.<name>`, and **None** for local variables (unless the call
  graph supplies a tracked instance type), computed callees (`getattr(...)()`, `f()()`), and names
  that point into the project but are defined nowhere. Imports inside `except ImportError:` never
  shadow the `try:` import; a bare name that is not defined, imported or builtin is attributed to the
  module's single external star import.
- **A-01 (SAST module names + absolute-import fallback)** _(formerly B-01)_: module name = dotted path
  relative to the source root (`pkg/__init__.py` → `pkg`; `pkg.py` loses to `pkg/__init__.py`, as in
  Python); when the root itself has an `__init__.py` and an identifier name, that name prefixes every
  module. An absolute import resolves as written first; if that is not a project module it is retried
  relative to the importing file's package chain, closest first (apps started from their own directory
  import siblings as top-level names). Standard-library names (`sys.stdlib_module_names`) never take
  that fallback.
