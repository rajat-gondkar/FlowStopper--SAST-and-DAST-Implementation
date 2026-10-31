# Contract changes

The shared contracts — `FlowStopper/models.py`, `FlowStopper/cwe.py`, `FlowStopper/ids.py`,
`FlowStopper/evalkit/keyschema.py` — **freeze at tag `contract-v1`** (end of Phase 0). After the
tag, only **additive, backwards-compatible** changes are allowed, and each one needs:

1. an entry in this file (date, author, what & why, affected files),
2. the other developer's **ACK** before merge,
3. regenerated schemas (`make schemas`) and fixtures if affected (`make fixtures`), committed together.

Breaking changes (renames, removals, type changes, stricter validation) are **not** allowed after
the freeze without an explicit joint decision recorded here.

## Template

```
### CC-NN — <short title>
- Date / Author:
- Files:
- Change (additive?):
- Why:
- Impact on fixtures/schemas:
- ACK by <other dev>:
```

## Log

_(none yet — contracts not yet frozen. Add entries below once `contract-v1` is tagged.)_
