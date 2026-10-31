# Limitations

> Honest list, seeded in Phase 0; Dev B completes it in Phase 7 (P7-B1) once real behaviour is known.
> Being upfront here is part of the submission.

## SAST (static analysis)
- **Name-resolution only.** No dynamic dispatch, no `getattr`/reflection, no runtime metaprogramming;
  calls we can't resolve statically are ignored (not guessed), so some cross-function flows are missed.
- **Bounded interprocedural analysis.** Call-graph BFS depth ≤ 4; summary fixpoint capped at 10
  iterations; loops analysed with one extra iteration. Very deep or highly dynamic flows can escape.
- **Parse-only (R7).** We never import or execute the target, so anything decided purely at runtime
  (config-driven routes, dynamically built SQL from external data) may not be visible.
- **Frameworks.** Flask + FastAPI are first-class; Django extraction is shallower (cut-list item).

## DAST (dynamic analysis)
- **No blind/second-order by default.** Time-based SQLi is off by default; stored/second-order XSS
  only if explicitly enabled (P4-B1). Evidence-free vulnerabilities are not reported.
- **Crawl bounds.** Same-origin, depth ≤ 3, ≤ 300 URLs, under a time budget — deep or JS-rendered
  apps may be under-covered.
- **Safe payloads only (R4).** Harmless canaries/echoes/read-only probes; no destructive payloads and
  no DELETE (no PUT/PATCH without `--allow-mutating`), so some classes stay out of reach by design.

## Correlation
- **Conservative by design.** The ambiguity rule drops uncertain links (prefers a miss over a wrong
  link), which can lower the correct-link rate on genuinely ambiguous handlers.
- **Needs a code location to confirm.** Runtime-only findings with no reachable code stay Runtime-only.

## Scope
- Out of scope (spec §3.3): automatic code fixing, login/user management, cloud deployment, polished
  UI, reachability-aware SCA.
