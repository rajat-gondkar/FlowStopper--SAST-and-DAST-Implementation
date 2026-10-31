# Decisions — Dev A (Person 1)

Dev A's own design decisions (ids `A-NN`, newest first). Joint/Phase-0 decisions are in the shared
[`DECISIONS.md`](DECISIONS.md); Dev B's are in [`DECISIONS_Dev2.md`](DECISIONS_Dev2.md). Using an
`A-` prefix keeps our ids from ever colliding with Dev B's `B-` ids.
- **A-54 (two more run-time lookup idioms turn `unreachable` off)**: `inspect.getmembers(...)`
  registries and a lookup function passed as a value (e.g. `functools.reduce(getattr, parts, mod)`)
  can reach any function, so they now count as a run-time lookup like A-52. Both were confirmed to
  leave route-reachable sinks wrongly marked `unreachable` before. Tests added in
  `tests/test_sast_suppress.py::REFERENCED`.
- **A-53 (last content-type write decides, A-38 follow-up)**: the lookahead after `resp = Response(...)`
  now scans the whole straight-line range and keeps the verdict of the last `mimetype`/`content_type`/
  `headers["Content-Type"]` write, so a later override to `text/html` keeps the CWE-79. A call on
  `resp.headers` (`.set/.update/...`), a write to `resp.headers` itself or to a computed header key, a
  compound statement that mentions the response's content type or headers, or a returned
  `(resp, status, headers)` tuple with non-constant extras all mean "not safe". Review finding; the
  bench false positive at `app/app.py:185` stays fixed.
- **A-52 (dynamic name lookup switches `unreachable` off, A-48 follow-up)**: when any module calls
  `getattr`/`attrgetter`/`methodcaller`/`eval`/`exec` with a non-constant name argument, calls
  `globals()`/`locals()`/`vars()`, or reads `__dict__`, `unreachable_functions` returns nothing for the
  project: a computed name such as `"cmd_" + action` can reach any function, and doubt means
  reachable. The simpler project-wide bail-out was chosen over per-module or name-prefix matching.
  Mock A and the bench are unaffected (0 `unreachable` findings before and after). Review finding.
- **A-51 (Mock A key gaps are known extras, key unchanged)**: `POST /login` `password` shares the
  M02 sink and produces a single SAST finding, so a second planted pair would be structurally
  unlinkable under one-to-one matching. The `GET /download` "XSS" is a reflection inside Werkzeug's
  debug traceback, the same artefact as BACKLOG 5 (Dev B's). Both stay unplanted extras and
  `apps/mock_a/answer_key.json` is not edited (BACKLOG 6).
- **A-50 (P4-A3 performance: parse once, no optimisation needed)**: only `index.py::parse_source`
  calls `ast.parse`; routes, call graph, taint, secrets and snippets reuse `ModuleInfo.tree`/`.lines`,
  now asserted by `test_run_sast_parses_each_python_file_once`. Median `run_sast` after batches 1-2:
  Mock A 0.025 s (planning 0.04 s), bench 0.038 s (0.06 s), pydantic proxy 105 files / 1798
  functions 1.8 s (3.1 s), a synthetic 200-route project 2.4 s. Nothing regressed, so no code was
  optimised.

- **A-49 (sanitised/safe findings come from the engine)**: the engine already knows the clearance at
  the sink, so `_FunctionWalk._sink_report` emits the suppressed `sanitized:`/`safe:` reports itself,
  and `_SummaryHook` turns a callee hit whose caller labels were all cleared into a suppressed one.
  `suppress.py` holds only the reason strings, the request-hook test and the reachability test.
  `analyse_taint` therefore returns suppressed findings too; existing tests whose intent is "nothing
  reported" now filter `not f.suppressed` and also assert the suppressed reasons.
- **A-48 (conservative `unreachable`)**: no project routes → nothing is unreachable. A candidate is a
  module-level, undecorated, non-dunder function that is not a method and whose name never appears in
  the project as a value reference, a name-like string (also a dotted/colon path such as
  `"pkg.tasks.run"`, which goes slightly beyond the plan), the leaf of a call that does not resolve
  to a project function or class, or the leaf of any call the call graph does not see (module or
  class level, lambdas, decorators, defaults). Every other function plus every route handler is a
  root; a BFS with no depth cap removes reached candidates. Only an unreachable function's *own*
  sinks are emitted (suppressed, `entry_routes` empty, confidence 0.7); a `safe:`/`sanitized:` reason
  wins, and CWE-798 is never suppressed. Doubt always means reachable: a wrong `unreachable` would
  hide a real bug. Mock A: 1 unreachable function (no sinks), bench: 0.
- **A-47 (B-2 reasons and precedence)**: reasons are `sanitized:<names>` (sorted sanitiser/guard names
  of the cleared labels joined with `+`, e.g. `sanitized:html.escape`, `sanitized:guard:allow-list`),
  `safe:sql-parameterised` (constant SQL text, request data only in bind arguments), the unchanged
  `safe:subprocess-list-no-shell` / `safe:subprocess-no-shell`, and `unreachable`. A clearance with
  no sanitiser name (the request URL and CWE-601) reports nothing. A live finding at a sink site
  `(file, function, line, cwe)` drops every suppressed finding at that site, and a live and a
  suppressed finding are never merged. Dev B's `dedupe.code_key` keeps the highest-confidence
  finding per site and source parameter, so a suppressed duplicate could otherwise replace a live
  one and lose a link.
- **A-46 (request hooks are code-only entry points)**: functions decorated with a leaf in
  `errorhandler`, `app_errorhandler`, `before_request`, `before_app_request`, `after_request`,
  `after_app_request`, `teardown_request`, `teardown_app_request`, `before_first_request`,
  `exception_handler` or `middleware` (and not route handlers) are walked like handlers with an
  empty seed env. Their findings get `entry_routes == []`, confidence 0.7 and no reachability
  fallback, so a helper shared with a route never borrows that route's id. No route ids are invented.
- **A-45 (`render_template_string` template source is a CWE-79 sink)**: new `SinkSpec`
  `TEMPLATE_STRING` (arg 0 / keyword `source`), rule id `py.xss.<built>.template-string`. It sits in
  `SINKS`, so `sink_at` wins over the template-render barrier for that callee; its keyword arguments
  stay escaped template variables and report nothing (bench VF02).
- **A-44 (request URL attributes are sources)**: `request.url`, `request.path`, `request.full_path`
  and `request.base_url` are request data with `param_name=None` and location `path`. No pseudo
  name is invented, because a name like "path" could match an unrelated DAST parameter and make a
  wrong link. CWE-601 is cleared from the start: `redirect(request.url)` is the redirect-to-self idiom.
- **A-43 (secrets in test code are capped, not dropped)**: a CWE-798 hit in a file under a `tests/`
  or `test/` directory, or named `test_*.py`, `*_test.py` or `conftest.py`, keeps being reported but
  its confidence is capped at `SastConfig.secret_test_confidence` (0.5). Test credentials can still be
  real, so hiding them would be a silent miss; the cap ranks them below app secrets. Seed data in app
  code (`user.password = '...'`) is unchanged (BACKLOG 10).
- **A-42 (receiver-based leaf matching left as is)**: `run_sast` on Mock A and the bench app reports
  zero `py.traversal.path-access` findings and zero SQL findings on a `.raw`/`.extra` leaf, so there
  is no observed false positive to fix. `PATH_ACCESS` and `SQL_EXECUTE.leaf_methods` stay unchanged.
- **A-41 (fixpoint cap logs a warning)**: `compute_summaries` logs one WARNING on
  `FlowStopper.sast.taint.summaries` when `fixpoint_max_iterations` passes run without a pass that
  changed nothing, naming the cap and the function count. Before, a non-converged run was visible
  only as `summary_iterations` in stats.
- **A-40 (`_is_abort` resolves the callee)**: a call ends a block only when it resolves to
  `flask.abort`, `flask.helpers.abort`, `werkzeug.exceptions.abort`, `sys.exit`, `builtins.exit`,
  `builtins.quit`, `os._exit` or `os.abort`. `fail` is dropped and unresolved leaves (`obj.abort()`)
  no longer cut the rest of the block, which used to hide real flows.
- **A-39 (template `**ctx` splat)**: `render_template(t, **ctx)` contributes template variables when
  the splat is an inline dict literal, or a local assigned exactly once (one entry in
  `FunctionInfo.assignments`) to a dict literal or a bare `dict(k=v, ...)` call. The values are
  evaluated with the env at the render call; anything else (reassigned, mutated, from a call) stays a
  miss rather than a guess.
- **A-38 (content type set after construction)**: `resp = Response(...)` / `make_response(...)` is
  treated like a safe response wrapper when the following statements of the *same* block set
  `resp.mimetype`, `resp.content_type` or `resp.headers["Content-Type"]` to a constant
  `application/json` or `text/plain` before any reassignment of `resp`, return, raise or compound
  statement. Other plain assignments and expression statements are skipped. A write inside a branch
  may not run, so that case stays a CWE-79 finding (BACKLOG 9, bench `app/app.py:185`).
- **A-37 (Mock A binds 127.0.0.1 by default)**: `apps/mock_a/app.py` reads the bind address from
  `HOST` (default `127.0.0.1`); the Dockerfile and compose file set `HOST=0.0.0.0` so the container
  is still reachable through its `127.0.0.1:5050` port mapping. A debug-mode app with planted bugs
  should not listen on every interface of a developer machine (BACKLOG 12).
- **A-36 (Phase 3 baselines are named per target)**: the spec's `docs/metrics/baseline.json` is the
  organisers'-app baseline, and that app is not available yet. So the P3-J1 runs are saved as
  `baseline_mock_a.json` and `baseline_bench.json`, and `baseline.json` stays unused until the real
  app arrives. Mock A was scanned unmodified, so its baseline shows the state before Phase 4 fixes.
  `docs/metrics/README.md` lists which file is which.
- **A-35 (unique scan ids; meta before "completed")**: `Storage.make_scan_id` hashes a
  seconds-precision timestamp, so two scans of the same source and target in one second would share
  and overwrite one `scans` row. `run_pipeline` now passes an explicit `scan_id` and adds a `#n`
  suffix to the hashed material while that id already exists (no change to Dev B's `storage.py`).
  `scan_meta.json` is written inside the guarded block, before `finish_scan(completed)`, and
  `start_scan` errors become `PipelineError("store")`, so the store and the CLI exit code always agree.
- **A-34 (`--seed` on `scan`, default 0)**: `DastConfig.seed` is the per-scan seed and defaults to
  `None`, which the checks already treat as 0. `scan` exposes `--seed` (default 0, same as `dast`)
  and the pipeline resolves `None` to 0 before running, so the seed in `scan_meta.json`, the DB row
  and the DAST stats is the value actually used.
- **A-33 (stage failures and the scan row)**: `run_pipeline` raises `PipelineError(stage, ...)` for a
  bad source dir (before anything is stored), a scope-guard refusal (`ScopeError` from `run_dast`,
  which checks before any connection) or any exception inside a stage; the scan row is then
  finished as `failed` with the timings so far, and `scan` exits 1. Exit 2 stays reserved for the CI
  gate. The target is not pre-checked before SAST, so the R3 WARNING for `--allow-host` is logged
  once, by `run_dast`'s own guard; the cost is a few seconds of SAST before a refusal.
- **A-32 (storage location)**: `Storage`'s default path (`.flowstopper/scans.db`, git-ignored),
  not a DB per `--out`. Simpler, and it gives the P5 API, `eval --scan` and FR-6 upserts one shared
  store across scans. `run_pipeline(db_path=...)` overrides it (tests use `tmp_path`).
- **A-31 (`--fail-on` is a no-op until P5)**: the CI gate (exit code 2) is Dev B's P5-B2 helper in
  `report/sarif.py`, which is still a stub, so `scan --fail-on` logs a WARNING ("not implemented
  until P5") and is ignored. P5-A2 wires it to B's helper; no gate logic lives in `pipeline.py`.
- **A-30 (`run_pipeline` contract)**: a sync function `run_pipeline(source, target, out_dir, *,
  sast_config, dast_config, correlate_config, db_path) -> PipelineResult` that drives `run_dast`
  with `asyncio.run`, so the P5 API must call it from a worker thread (FastAPI runs a sync
  background task in its thread pool). `issues.json` is exactly what `correlate` returns (same
  serialisation as `FlowStopper correlate`, suppressed issues included, `first/last_seen_scan`
  left unset) so it holds no scan id, timestamp or timing; all run data goes to `scan_meta.json`
  (scan id, start/finish, seed, `truncated`, per-stage `timings_s`, tool versions, counts, configs,
  SAST/DAST stats) and the DB.
- **A-29 (one text-file policy for the non-Python scanners)**: the secrets scan (P2-A4) and the
  template scan (P2-A5) were each walking the tree and reading files themselves, so `exclude_dirs`
  and `max_text_file_bytes` were honoured by two copies of the same code that could drift apart.
  Both now call `sast/textfiles.py` (`text_files` for extension-based discovery in relative-POSIX
  order, `read_text` for the size cap and the UTF-8 decode), and the runner reads a secret's
  snippet lines through the same function instead of its own `errors="replace"` reader — a file a
  scanner refused can no longer be quoted back in a snippet. Selection stays by extension, with
  `extra_names` for the one conventional extension-less name the secrets scan needs (R6).
- **A-28 (Phase-2 config fields + one call graph)**: `SastConfig` gained `template_extensions`,
  `secret_file_extensions`, `secret_min_length`, `secret_entropy_bits`, `secret_entropy_min_length`,
  `taint_loop_iterations` and `max_text_file_bytes` (additive, Dev A's file); `annotate_reachable`
  gained a keyword-only `graph=` so the runner builds the call graph once and shares it with the
  taint driver, and `callgraph.local_types` became public because the engine must resolve call sites
  exactly as the graph does.
- **A-27 (how the Mock A gate counts)**: detection assigns each planted id a *distinct* finding, so
  one finding cannot answer for two keyed lines that sit within the Appendix C ±3 slack (C01/C02 are
  three lines apart); a decoy false alarm is measured against the decoy's own line range, because the
  ±3 slack belongs to the code-match rule — a true positive a few lines above a decoy is not noise.
- **A-26 (stats carry counts only)**: `compute_summaries` / `analyse_taint` take an optional
  `TaintStats` out-parameter so `SastResult.stats` can report `functions_analysed` and
  `summary_iterations`; no timing or timestamp ever enters `stats`, so two scans of one tree
  serialise byte-for-byte (FR-6, asserted for Mock A and a synthetic tree).
- **A-25 (snippet shape)**: a finding's snippet quotes the offending lines ±1 (capped at the 12 lines
  `models.CodeLocation` documents) while `taint.source_location` quotes just the source line, as the
  `fixtures/sast_findings.json` oracle does. Python text comes from the already-parsed index,
  config/template text is re-read from disk; a secret's literal reaches `raw` only redacted.
- **A-24 (guard precision)**: `x.startswith(base)` clears CWE-22 only when the path is normalised
  (`realpath`/`abspath`/`normpath`, `Path(...).resolve()`) or the base is a constant — the spec says
  "after realpath/abspath" without saying how to tell. Membership in a constant allow-list clears
  *every* CWE (the value is pinned to a known set); every other guard clears only the CWE the spec
  lists. Guard labels surface in `taint.sanitizers_seen` as `guard:<label>`.
- **A-23 (what keeps the sanitiser decoys quiet)**: a summary stores the parameter *labels* that
  reached a sink rather than bare parameter indices, so an `int()` applied inside the callee carries
  its clearance back onto the caller's request label (D02 stays silent); `send_from_directory` is a
  sanitiser whose *result* is a barrier, without which the handler return read as XSS (D05).
- **A-22 (the driver is handler-rooted)**: only route handlers are walked, and a callee's own request
  reads are forwarded through its summary with the chain extended, so a helper that reads
  `request.args` itself is still reported as `[handler, …, helper]`. A chain never revisits a
  function, which is what makes recursion terminate.
- **A-21 (secrets rule ids and filters)**: a Name/Attribute assignment emits `…assign`, while a
  subscript config write, a dict-literal key and a call keyword emit `…config`; a provider prefix or
  an embedded DSN credential overrides the shape (`…prefix` / `…dsn`, 0.9). `jwt.encode(payload,
  "literal")` is reported under `…assign` with the name `jwt.encode()`. An `os.getenv` literal
  default is reported at 0.5 only when the name matches the credential pattern (an empty default
  never). `author`/`authors`/`authored` is stripped before the name match (the spec's pattern
  contains `auth`), and a credential-free URL, a filesystem path or a SQL statement suppresses a
  name match but never a prefix/DSN hit.
- **A-20 (rule-id shape)**: the string-building kind belongs to the rule id only for the `sqli` and
  `xss` families (the agreed oracle has `py.sqli.fstring.execute` but plain `py.cmdi.subprocess`),
  and `tainted` is the kind when a raw request value reaches a sink unbuilt. The template row carries
  the fixed id `py.xss.template.unescaped` (`sinks.FIXED_RULE_IDS`): how the Python string was built
  says nothing about a template sink — the template's own escaping does.
- **A-19 (the gate test owns the match rule)**: `tests/test_sast_accuracy_mock_a.py` implements the
  Appendix C code match itself (normalised POSIX path equality, `cwe.same_family`, line-range overlap
  with `[line_start−3, line_end+3]`) instead of importing Dev B's private
  `evalkit/metrics.py::_code_matches`, which wants `Issue` objects Phase 2 does not produce yet.
- **A-18 (template scan runs before taint)**: the CWE-79 template rule needs the unescaped-variable
  map to decide whether a render call's keyword argument is a sink, so `scan_templates` runs before
  `analyse_taint` (the spec's prose order is descriptive, not a dependency). A template-only problem
  (a `|safe` with no tainted value) produces **no** finding — the finding belongs at the Python sink
  (consistent with A-04). Template names resolve by POSIX path suffix, shortest match first.
- **A-17 (branch and loop joins)**: `if/else` analyses both arms from the entry environment and unions
  after; `try` unions body + handlers + `orelse`, then `finally`; `for`/`while` re-analyse the body
  `taint_loop_iterations` (2) times, so taint created late in a loop is still seen. Findings are
  de-duplicated within a walk by `(file, line, rule, labels)`.
- **A-16 (two-phase interprocedural analysis)**: phase 1 computes *parametric* summaries for every
  project function to a fixpoint (`fixpoint_max_iterations` = 10, reverse-topological, cycle-safe,
  monotone); phase 2 walks each handler with a *seeded* environment and applies callee summaries at
  call sites, which is where findings, `call_chain`, `source_param` and `entry_routes` are produced.
- **A-15 (container sources refine on member access)**: a whole-container read (`request.args`,
  `request.get_json()`) carries `param_name=None`; `value["key"]` / `value.attr` refines it to that
  member. An unrefined container keeps `param_name=None` and confidence 0.7 (the shape the oracle's
  `py.sqli.concat.execute` entry already encodes). A FastAPI pydantic body parameter is *not* seeded
  as a container, because `Route.params` carries the model's expanded field names, not the parameter.
- **A-14 (handler parameters are seeded from `Route.params`)**: any handler signature parameter whose
  name appears in the route's params becomes a source with that `ParamLocation`, which covers Flask
  `<path:name>` converters (M08), FastAPI `Query/Path/Body/Form` markers and Django URL kwargs for
  free and keeps P1-A2 the single source of truth for parameters.
- **A-13 (`entry_routes` = the flow's origin)**: the routes whose handler is `call_chain[0]`, sorted;
  a handler registered for two methods yields both route ids (the engine does not branch on
  `request.method`). Reachability (`route.reachable_functions`) is used only when a flow has no
  handler origin, and then confidence drops to 0.7.
- **A-12 (one finding per sink line, earliest-read source wins)**: `ids.code_finding_id` hashes
  `(engine, rule_id, cwe, file, function, line_start)`, so two findings at one sink line would
  collide; when several labels reach a sink the label with the smallest `(source line, param_name)`
  becomes `source_param` and every contributing name is listed, sorted, in `raw["source_params"]`
  (Mock A's M02 picks `username`, read one line before `password`).
- **A-11 (guards are unsound in the safe direction)**: `if <guard>:` clears inside the body, and
  `if <negated guard>: return/raise/abort/continue` clears on the fall-through path; the names a
  guard constrains are the `ast.Name` ids in the test, expanded transitively through a `derived_from`
  map recorded on assignments (`host = urlparse(target).netloc` ⇒ `host` ← `target`); in a `BoolOp`
  **any** recognised operand clears. This is what makes decoy D06 safe — a missed finding is
  preferred over a wrong one.
- **A-10 (XSS fires on any 79-tainted handler return)**: except behind a recognised safe wrapper
  (`jsonify`, `JSONResponse`, `Response(..., mimetype/content_type` of `application/json` or
  `text/plain`), which is decoy D07. `html_markup` (a constant part of the string contained `<…>`)
  only selects wording, so a bare `return q` is still caught.
- **A-09 (sink results are taint barriers)**: `open`, `.execute*`, `send_file`, `os.listdir`,
  `subprocess.*`, `os.system`, `redirect` and `render_template` return a handle, rows or a response —
  not the request string. Marking their results untainted stops cascades such as `return fh.read()`
  after `open(tainted)` being reported as XSS.
- **A-08 (sinks match the dotted name first, the attribute leaf second)**: `resolve_call` returns
  `None` for `conn.execute(...)` by design (A-02), yet the CWE-89 row has to catch it, so a leaf-name
  table (`execute`, `executemany`, `executescript`, `raw`, `extra`, `read_sql*`, …) backs every row;
  leaf matching is skipped when the callee resolves to a project symbol, so a project function called
  `execute` stays a call. The false-positive risk is contained by "first argument tainted **and**
  string-built".
- **A-07 (sanitisers clear per CWE, not globally)**: a label carries `cleared: frozenset[int]`, so
  `html.escape(x)` clears `{79}` and leaves 89/78/22/601 tainted while `int(x)` clears all. Without
  this one sanitiser would hide unrelated flows through the same variable.
- **A-06 (taint value shape)**: `TaintValue(labels, is_constant_string, built, html_markup)` with
  `TaintLabel(kind, file, line, function, param_name, location_kind, cleared, sanitizers)`. The
  spec's `source_node` is stored as its `(file, line, function)` projection so labels stay hashable,
  comparable and deterministic — and that projection is exactly what `TaintInfo.source_location`
  needs. `is_constant_string` is what makes a constant SQL string with tainted binds read as safe.
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
- **A-02 (SAST name resolution never guesses)** _(formerly D-19)_: `resolve_call` /
  `ProjectIndex.canonical` return a project qualname, an external dotted name (`os.system`,
  `flask.request.args.get`) or `builtins.<name>`, and **None** for local variables (unless the call
  graph supplies a tracked instance type), computed callees (`getattr(...)()`, `f()()`), and names
  that point into the project but are defined nowhere. Imports inside `except ImportError:` never
  shadow the `try:` import; a bare name that is not defined, imported or builtin is attributed to the
  module's single external star import.
- **A-01 (SAST module names + absolute-import fallback)** _(formerly D-18)_: module name = dotted path
  relative to the source root (`pkg/__init__.py` → `pkg`; `pkg.py` loses to `pkg/__init__.py`, as in
  Python); when the root itself has an `__init__.py` and an identifier name, that name prefixes every
  module. An absolute import resolves as written first; if that is not a project module it is retried
  relative to the importing file's package chain, closest first (apps started from their own directory
  import siblings as top-level names). Standard-library names (`sys.stdlib_module_names`) never take
  that fallback.
