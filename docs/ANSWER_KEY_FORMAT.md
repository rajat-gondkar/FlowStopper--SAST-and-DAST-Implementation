# Answer-key format (our own format)

The organisers do **not** prescribe a key format — their judges verify findings by reading our
output. So we define one format and use it for **every** key: our mock apps' keys, the fixture
key, and the organisers' key (transcribed/converted into this shape locally, in `keys/`, never
committed — rule R5).

The schema is enforced by `FlowStopper/evalkit/keyschema.py` (pydantic, `extra="forbid"`). Validate
any key with:

```bash
make validate-key KEY=apps/mock_a/answer_key.json
# or: python -m FlowStopper.evalkit.keyschema path/to/key.json
```

JSON Schema is exported to `docs/schemas/answer_key.schema.json`.

## Shape

```json
{
  "schema_version": "1",
  "app": "shoplite-a",
  "language": "python",
  "framework": "flask",            // optional, informative
  "base_url": "http://localhost:5050",  // optional, informative

  "vulns": [
    // kind "pair" -> has BOTH code and runtime (a planted bug detectable both ways)
    {"id": "V01", "cwe": 89, "kind": "pair",
     "code":    {"file": "blueprints/orders.py", "line_start": 80, "line_end": 95,
                 "function": "orders.get_orders"},   // function optional, informative
     "runtime": {"method": "GET", "path": "/api/orders", "param": "id"}},

    // kind "code_only" -> code only (e.g. a hard-coded secret)
    {"id": "V21", "cwe": 798, "kind": "code_only",
     "code": {"file": "config.py", "line_start": 7, "line_end": 7}},

    // kind "runtime_only" -> runtime only (e.g. a missing header, host-wide)
    {"id": "V31", "cwe": 693, "kind": "runtime_only",
     "runtime": {"method": "GET", "path": "*", "param": null}}
  ],

  "decoys": [
    // safe look-alikes that must NOT be reported as real (false-alarm metric)
    {"id": "D01", "cwe": 89, "file": "blueprints/products.py",
     "line_start": 40, "line_end": 46, "reason": "parameterised query"}
  ]
}
```

## Field rules (validated)

- `kind` ↔ locations: `pair` needs **both** `code` and `runtime`; `code_only` needs `code` only;
  `runtime_only` needs `runtime` only. Mismatches are rejected.
- `code.file` is a **relative POSIX path** from the scanned source root (no leading `/`, no `\`).
- `code.line_end >= code.line_start` (both ≥ 1).
- `runtime.path` starts with `/` **or** is `"*"` (host-wide). `runtime.method` omitted/null = any
  method (normalised to upper-case otherwise). `runtime.param` null = not parameter-specific.
- `id`s are unique across `vulns` + `decoys`.
- Unknown fields are rejected (keeps keys honest).

## How the key is used (matching rules — `evalkit/metrics.py`, spec Appendix C)

- **Code match:** same file (normalised relative path), CWE in the same family, finding line range
  overlaps `[line_start − 3, line_end + 3]`.
- **Runtime match:** same CWE family, method equal (or key method omitted), concrete path matches the
  key's template (`<…>`/`{…}` are wildcards; `"*"` matches host-wide findings), param equal when
  specified.
- **Correct link:** a `pair`'s code match and runtime match live in the **same Confirmed issue**.
- **Wrong link:** a Confirmed issue whose code and runtime matches refer to **different** planted IDs
  (or one to a decoy).
- **False alarm:** a reported (non-suppressed) issue whose code location overlaps a decoy.

## Converting the organisers' key (Phase 3)

`FlowStopper/evalkit/convert_organiser_key.py` converts their key into this schema. Their format is
not known in advance, so the converter is **mapping-driven**: it reads CSV, or JSON (a list, or an
object holding a list under `vulns`/`vulnerabilities`/`findings`/`items`/`entries`, plus an optional
`decoys` list), finds each field through common column names, and validates the result before
writing it.

```bash
# keep BOTH files under the git-ignored keys/ (rule R5); the converter warns otherwise
python -m FlowStopper.evalkit.convert_organiser_key keys/organisers_raw.csv -o keys/answer_key.json \
    --app organisers-app --strip-prefix app
# a column it did not recognise: name it explicitly instead of editing code
python -m FlowStopper.evalkit.convert_organiser_key keys/raw.json --map cwe=VulnClass --map file=Src
make validate-key KEY=keys/answer_key.json
```

What it normalises: CWE from `89`, `CWE-89` or a type name (`SQL Injection`, `XSS`, ...); code
location from separate file/line columns or one `path/file.py:80-95` value (Windows separators and a
`--strip-prefix` source root removed); runtime path from a path column or a full URL (query dropped;
`*`/`any`/`all` → host-wide); `kind` from which locations are present; rows whose status column says
`decoy`/`safe`/`false positive` (or a truthy `is_decoy`) become decoys. An unreadable CWE or a file
without a line number is an error naming the row, never a silent skip.

The counts to expect on the real app (spec §4): 36 planted = 20 pairs + 10 code-only + 6
runtime-only, plus ~8 safe decoys. Check the converter's summary line against those.

## Scoring a scan

```bash
FlowStopper eval --key keys/answer_key.json --scan latest          # newest completed scan in the store
FlowStopper eval --key keys/answer_key.json --scan <scan-id>       # a specific scan (see `scan` output)
FlowStopper eval --key keys/answer_key.json --issues out/issues.json   # a file; reads scan_meta.json beside it
```

The table shows each §4 metric with its Good/Great target and a status (`great`/`good`/`below`, or
`n/a` when the denominator is 0 — e.g. no Confirmed issues, so the wrong-link rate means nothing).
The report is written to `docs/metrics/<timestamp>.json` unless `--out` is given. It contains counts,
rates, the scan id and run time only — no file paths, routes or findings from the scanned app — so a
report for the organisers' app is safe to commit.
