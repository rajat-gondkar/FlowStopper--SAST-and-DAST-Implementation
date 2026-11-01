# Limitations

This is an honest list, final for v1.0. Each item says what we found on our own targets.

## SAST (static analysis)

- **Names must resolve statically.**
  - There is no dynamic dispatch, `getattr`-based routing or run-time metaprogramming. A call we cannot resolve is ignored, never guessed.
  - Flows through a registry such as `HANDLERS[name](x)` are missed.
- **Bounded interprocedural analysis.** The call graph is searched to depth 4, the summary fixpoint stops at 10 passes, and loops get one extra iteration. Very deep flows can escape.
- **Taint through containers is shallow.**
  - Values written into a dict or list, or into a `ConfigParser`, and then read back are not tracked by key, so such flows can be missed.
- **No constant folding.** A branch that is always false (e.g. `if 7 * 18 + n > 200:` with a known `n`) is still analysed, which can cause false alarms.
- **Project functions are never trusted as sanitisers by name.** A home-made HTML encoder does not clear taint, which can cause false alarms in apps that use one.
- **Parse-only (R7).** We never import or run the target, so anything decided only at run time (routes built from config, SQL built from external data) may not be visible.
- **Frameworks.**
  - Flask and FastAPI are first-class.
  - Django support covers `path`, `re_path`, `include` and class-based views; it does not yet understand DRF viewsets and routers.
- **Route-less findings are never linked.**
  - A bug inside an error handler (e.g. a 404 page that reflects the URL) is found by SAST, but it has no route, so the route gate cannot link it to the DAST finding (A-57).
  - Both halves are reported separately.
- **Routes registered through an unresolvable call.** When a blueprint is passed into a route-registration function through a call we cannot resolve (e.g. `importlib`), its routes are mounted at the root. Their real prefix is lost, so those links are missed rather than made wrongly.

## DAST (dynamic analysis)

- **Query, form, JSON and path parameters only.**
  - Headers and cookies are not injected, so a bug fed only by a header or cookie is never proven at runtime.
- **Safe payloads only (R4).**
  - There are no time-based payloads, so **blind** injections cannot be proven. Examples: a command whose output is discarded, or a file that is opened but never read.
  - Path traversal is proven only by reading `/etc/passwd`. So existence checks and write-only file access are invisible, as are paths that need more than six `../` steps from the app's working directory.
  - DELETE is never sent; PUT and PATCH are sent only with `--allow-mutating`.
- **Values are mutated, names are not.** When an app uses a parameter's *name* as the attack value, DAST cannot test it.
- **Login.**
  - One configured login (static headers/cookies, or a login request) is applied to the whole scan.
  - Behaviour that appears only after a *successful* login on the same request that is being tested is not reached. An example is a redirect or cookie set by the login route itself.
- **Crawl bounds.** The crawl stays on the same origin, goes at most 3 levels deep, follows at most 300 URLs, and runs under a time budget. Deep or JavaScript-rendered apps may be under-covered. The route map seeds most endpoints anyway.
- **The time budget bounds the active checks, not the whole scan.**
  - `--time-budget` (default 240 s) applies only to the per-parameter active checks. Discovery and the one-off host-wide passive pass run before it, so **total DAST time can exceed the budget**.
  - When it expires we keep every finding collected so far and set `stats.truncated = true`, so a truncated scan is visible, not silently partial.
- **The `Secure` cookie flag is checked only over HTTPS**, so plain-HTTP targets never report it.

## Correlation

- **Conservative by design.**
  - The ambiguity rule drops uncertain links: we prefer a miss over a wrong link. That can lower the correct-link rate on genuinely ambiguous handlers.
  - Wrong links are 0 on both mock apps.
- **A code location is needed to confirm.** A runtime finding with no reachable code stays Runtime-only.

## Measurements

- **All scores are against our own answer keys.**
  - Mock A and Mock B are our own apps. We tuned on Mock B after its first run, so its unseen-app score is the first run's 6/10, not the later 8/10.
  - Neither is the organisers' score.
- **Environment matters for path traversal.** Running an app from a deep directory can hide a traversal bug that the same app in Docker exposes, because of the six-step payload limit. We measure in Docker.

## Scope

Out of scope (spec §3.3): automatic code fixing, login/user management, cloud deployment, and
reachability-aware SCA.
