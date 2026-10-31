"""Convert an organisers' answer key into our Appendix C format (Owner: B, P3-B1).

The organisers' key format is not known in advance (DECISIONS D-03), so this converter is
**mapping-driven** rather than written against one layout: it reads rows from a CSV file or JSON
(a list of objects, or an object holding a list under "vulns"/"vulnerabilities"/"findings"/"items"),
finds each field through a list of common column names, and normalises the values. When the real
key arrives, point any mismatched field at the right column with `--map field=column` instead of
editing code.

    python -m FlowStopper.evalkit.convert_organiser_key keys/raw_key.csv -o keys/answer_key.json
    python -m FlowStopper.evalkit.convert_organiser_key keys/raw.json --map cwe=VulnClass --app target-app

Normalisation:
- CWE from `89`, `CWE-89` or a type name (`SQL Injection`, `XSS`, ...); unknown -> the row is rejected.
- code location from separate file/line columns or one `path/to/file.py:80-95` value; Windows
  separators and an absolute source-root prefix (`--strip-prefix`) are removed.
- runtime from method/path/param columns, or a full URL (query string dropped); `*`/`any`/`all`
  becomes the host-wide wildcard.
- kind = pair / code_only / runtime_only from which locations are present, unless a type column
  says the row is a decoy (safe / false positive), in which case it becomes a decoy entry.

The output is validated against `keyschema.AnswerKey` before it is written. The input and output
are the organisers' confidential material (rule R5): keep both under the git-ignored `keys/`
directory - the converter warns if the output path would not be ignored. Nothing app-specific lives
in this file (rule R6); every value comes from the input.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Optional
from urllib.parse import urlsplit

from pydantic import ValidationError

from FlowStopper.evalkit.keyschema import AnswerKey

# Field -> candidate column names, compared case-insensitively with spaces/dashes/underscores removed.
DEFAULT_ALIASES: dict[str, tuple[str, ...]] = {
    "id": ("id", "vulnid", "vuln", "ref", "reference", "key", "number", "no"),
    # "kind" is deliberately absent: in our own format it holds pair/code_only, not a CWE.
    "cwe": ("cwe", "cweid", "type", "vulntype", "vulnerability", "category", "class"),
    # "planted" is deliberately absent: planted=yes means the opposite of a decoy.
    "kind": ("kind", "status", "label", "expected", "verdict", "isdecoy", "decoy"),
    "file": ("file", "filename", "filepath", "sourcefile", "source", "codefile", "location"),
    "line_start": ("linestart", "startline", "line", "lineno", "linenumber", "from"),
    "line_end": ("lineend", "endline", "to"),
    "function": ("function", "func", "method_name", "handler", "symbol"),
    "method": ("httpmethod", "method", "verb"),
    "path": ("path", "route", "endpoint", "urlpath", "url", "uri"),
    "param": ("param", "parameter", "paramname", "input", "field", "argument"),
    "title": ("title", "name", "summary", "description"),
    "notes": ("notes", "note", "comment", "comments", "details", "reason"),
}

# Vulnerability names -> CWE. Generic vocabulary only (no app data, rule R6).
TYPE_NAMES: dict[str, int] = {
    "sqlinjection": 89,
    "sqli": 89,
    "sql": 89,
    "crosssitescripting": 79,
    "xss": 79,
    "reflectedxss": 79,
    "storedxss": 79,
    "commandinjection": 78,
    "oscommandinjection": 78,
    "cmdi": 78,
    "rce": 78,
    "pathtraversal": 22,
    "directorytraversal": 22,
    "traversal": 22,
    "lfi": 22,
    "openredirect": 601,
    "redirect": 601,
    "unvalidatedredirect": 601,
    "hardcodedsecret": 798,
    "hardcodedcredentials": 798,
    "hardcodedpassword": 259,
    "hardcodedkey": 321,
    "secret": 798,
    "missingsecurityheaders": 693,
    "securityheaders": 693,
    "clickjacking": 1021,
    "cookiehttponly": 1004,
    "cookiesecure": 614,
    "cookiesamesite": 1275,
    "insecurecookie": 1004,
    "cors": 942,
    "permissivecors": 942,
    "verboseerror": 209,
    "stacktrace": 209,
    "debugmode": 489,
    "informationdisclosure": 200,
    "versionbanner": 497,
    "directorylisting": 548,
}
DECOY_WORDS = {"decoy", "safe", "falsepositive", "fp", "notvulnerable", "benign"}
# A boolean column (is_decoy / decoy) marks a decoy with a truthy value instead of a word.
BOOLEAN_DECOY_COLUMNS = {"isdecoy", "decoy"}
TRUTHY = {"true", "yes", "y", "1"}
WILDCARD_PATHS = {"*", "any", "all", "hostwide", "global", "site", "sitewide"}
_LOCATION = re.compile(r"^(?P<file>.+?):(?P<start>\d+)(?:\s*[-:]\s*(?P<end>\d+))?$")
_RANGE = re.compile(r"^\s*(?P<start>\d+)(?:\s*[-:,]\s*(?P<end>\d+))?\s*$")
_CWE = re.compile(r"(?i)^\s*(?:cwe)?[\s-]*(\d+)\s*$")


class ConvertError(ValueError):
    """A row could not be converted; carries the row number for a useful message."""


def _norm(name: str) -> str:
    return re.sub(r"[\s_\-]+", "", name).lower()


# --------------------------------------------------------------------------- reading
def read_rows(path: Path) -> list[dict[str, str]]:
    """Rows from a CSV file or a JSON document, with every value as a string."""
    text = path.read_text(encoding="utf-8-sig")
    if path.suffix.lower() == ".csv":
        return [{k: (v or "") for k, v in row.items() if k is not None} for row in csv.DictReader(text.splitlines())]
    data = json.loads(text)
    if isinstance(data, Mapping):
        for container in ("vulns", "vulnerabilities", "findings", "items", "entries"):
            if isinstance(data.get(container), list):
                rows = list(data[container])
                rows += [dict(d, kind="decoy") for d in data.get("decoys", []) if isinstance(d, Mapping)]
                data = rows
                break
        else:
            raise ConvertError("JSON object has no list under vulns/vulnerabilities/findings/items/entries")
    if not isinstance(data, list):
        raise ConvertError("expected a JSON list of entries")
    out: list[dict[str, str]] = []
    for item in data:
        if not isinstance(item, Mapping):
            raise ConvertError("every JSON entry must be an object")
        out.append(
            {
                str(k): "" if v is None else (json.dumps(v) if isinstance(v, (dict, list)) else str(v))
                for k, v in item.items()
            }
        )
    return out


def resolve_columns(headers: Iterable[str], overrides: Mapping[str, str]) -> dict[str, str]:
    """Map each of our fields onto an input column (explicit overrides win, then the aliases)."""
    present = {_norm(h): h for h in headers}
    mapping: dict[str, str] = {}
    for field, column in overrides.items():
        if field not in DEFAULT_ALIASES:
            raise ConvertError(f"--map: unknown field {field!r} (known: {', '.join(sorted(DEFAULT_ALIASES))})")
        if _norm(column) not in present:
            raise ConvertError(f"--map {field}={column}: no such column (have: {', '.join(sorted(headers))})")
        mapping[field] = present[_norm(column)]
    used = set(mapping.values())
    for field, aliases in DEFAULT_ALIASES.items():
        if field in mapping:
            continue
        for alias in aliases:
            column = present.get(_norm(alias))
            if column and column not in used:
                mapping[field] = column
                used.add(column)
                break
    return mapping


# --------------------------------------------------------------------------- value normalisation
def parse_cwe(value: str) -> Optional[int]:
    m = _CWE.match(value or "")
    if m:
        return int(m.group(1))
    return TYPE_NAMES.get(_norm(value or ""))


def normalise_file(value: str, strip_prefix: Optional[str]) -> str:
    path = (value or "").strip().replace("\\", "/")
    if strip_prefix:
        prefix = strip_prefix.replace("\\", "/").rstrip("/") + "/"
        if path.startswith(prefix):
            path = path[len(prefix) :]
    while path.startswith("./"):
        path = path[2:]
    return path.lstrip("/")


def parse_lines(start: str, end: str) -> tuple[Optional[int], Optional[int]]:
    """`80` / `80-95` in the start column, or separate start + end columns."""
    m = _RANGE.match(start or "")
    if not m:
        return None, None
    lo = int(m.group("start"))
    hi = int(m.group("end")) if m.group("end") else None
    if hi is None:
        m_end = _RANGE.match(end or "")
        hi = int(m_end.group("start")) if m_end else lo
    return lo, max(lo, hi)


def normalise_path(value: str) -> Optional[str]:
    raw = (value or "").strip()
    if not raw:
        return None
    if _norm(raw) in WILDCARD_PATHS:
        return "*"
    if "://" in raw:
        raw = urlsplit(raw).path or "/"
    raw = raw.split("?", 1)[0].split("#", 1)[0]
    return raw if raw.startswith("/") else "/" + raw


def _is_decoy(value: str, column: Optional[str]) -> bool:
    word = _norm(value or "")
    if word in DECOY_WORDS:
        return True
    return bool(column) and _norm(column) in BOOLEAN_DECOY_COLUMNS and word in TRUTHY


# --------------------------------------------------------------------------- conversion
def convert_rows(
    rows: list[dict[str, str]],
    *,
    app: str,
    overrides: Optional[Mapping[str, str]] = None,
    strip_prefix: Optional[str] = None,
    framework: Optional[str] = None,
    base_url: Optional[str] = None,
) -> dict:
    """Turn input rows into an Appendix C key dict (not yet validated)."""
    if not rows:
        raise ConvertError("the input has no rows")
    # Union of every row's keys, in first-seen order: JSON entries need not share one shape, and
    # resolving from row 0 alone would silently drop a field (e.g. the decoy marker) that only
    # later rows carry - turning a decoy into a planted vuln.
    headers = list(dict.fromkeys(name for row in rows for name in row))
    columns = resolve_columns(headers, overrides or {})
    if "cwe" not in columns:
        raise ConvertError("no CWE/type column found; name it with --map cwe=<column>")

    def get(row: dict[str, str], field: str) -> str:
        column = columns.get(field)
        return (row.get(column) or "").strip() if column else ""

    vulns: list[dict] = []
    decoys: list[dict] = []
    for number, row in enumerate(rows, start=1):
        where = f"row {number}"
        cwe = parse_cwe(get(row, "cwe"))
        if cwe is None:
            raise ConvertError(f"{where}: cannot read a CWE from {get(row, 'cwe')!r} (use --map cwe=<column>)")
        entry_id = get(row, "id") or f"K{number:02d}"

        file_value = get(row, "file")
        start_value, end_value = get(row, "line_start"), get(row, "line_end")
        loc = _LOCATION.match(file_value) if file_value else None
        if loc and not start_value:  # one combined "file.py:80-95" value
            file_value, start_value, end_value = loc.group("file"), loc.group("start"), loc.group("end") or ""
        code: Optional[dict] = None
        if file_value:
            lo, hi = parse_lines(start_value, end_value)
            if lo is None:
                raise ConvertError(f"{where}: file {file_value!r} has no readable line number")
            code = {"file": normalise_file(file_value, strip_prefix), "line_start": lo, "line_end": hi}
            if get(row, "function"):
                code["function"] = get(row, "function")

        if _is_decoy(get(row, "kind"), columns.get("kind")):
            if code is None:
                raise ConvertError(f"{where}: a decoy needs a code location")
            decoys.append(
                {
                    "id": entry_id,
                    "cwe": cwe,
                    "file": code["file"],
                    "line_start": code["line_start"],
                    "line_end": code["line_end"],
                    "reason": get(row, "notes") or get(row, "title") or "safe look-alike (organisers' key)",
                }
            )
            continue

        path = normalise_path(get(row, "path"))
        runtime: Optional[dict] = None
        if path:
            runtime = {"method": (get(row, "method") or None), "path": path, "param": get(row, "param") or None}
        if code is None and runtime is None:
            raise ConvertError(f"{where}: needs a code location, a runtime path, or both")
        kind = "pair" if code and runtime else "code_only" if code else "runtime_only"

        entry: dict = {"id": entry_id, "cwe": cwe, "kind": kind}
        if code:
            entry["code"] = code
        if runtime:
            entry["runtime"] = runtime
        for field in ("title", "notes"):
            if get(row, field):
                entry[field] = get(row, field)
        vulns.append(entry)

    key: dict = {"schema_version": "1", "app": app, "language": "python", "vulns": vulns, "decoys": decoys}
    if framework:
        key["framework"] = framework
    if base_url:
        key["base_url"] = base_url
    return key


def is_git_ignored_path(path: Path) -> bool:
    """R5 guard mirroring the .gitignore rules for confidential keys: `keys/` (a directory of that name
    anywhere in the path) or a `*.key.json` file name."""
    return "keys" in path.parts[:-1] or path.name.endswith(".key.json")


def convert_file(
    input_path: Path,
    *,
    app: str,
    overrides: Optional[Mapping[str, str]] = None,
    strip_prefix: Optional[str] = None,
    framework: Optional[str] = None,
    base_url: Optional[str] = None,
) -> AnswerKey:
    """Read, convert and validate. Raises ConvertError or pydantic.ValidationError."""
    key = convert_rows(
        read_rows(input_path),
        app=app,
        overrides=overrides,
        strip_prefix=strip_prefix,
        framework=framework,
        base_url=base_url,
    )
    return AnswerKey.model_validate(key)


# --------------------------------------------------------------------------- CLI
def _parse_map(values: list[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for item in values:
        field, sep, column = item.partition("=")
        if not sep or not field.strip() or not column.strip():
            raise ConvertError(f"--map expects field=column, got {item!r}")
        out[field.strip()] = column.strip()
    return out


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m FlowStopper.evalkit.convert_organiser_key",
        description="Convert an organisers' answer key (CSV/JSON) into our Appendix C format.",
    )
    parser.add_argument("input", type=Path, help="organisers' key (keep it under the git-ignored keys/)")
    parser.add_argument("-o", "--out", type=Path, default=Path("keys") / "answer_key.json", help="output key")
    parser.add_argument("--app", default="organisers-app", help="app name recorded in the key")
    parser.add_argument("--map", action="append", default=[], metavar="FIELD=COLUMN", help="override a column")
    parser.add_argument("--strip-prefix", help="source-root prefix to remove from file paths")
    parser.add_argument("--framework", help="informative: flask / fastapi / django")
    parser.add_argument("--base-url", help="informative: where the app ran")
    args = parser.parse_args(argv)

    try:
        key = convert_file(
            args.input,
            app=args.app,
            overrides=_parse_map(args.map),
            strip_prefix=args.strip_prefix,
            framework=args.framework,
            base_url=args.base_url,
        )
    except (OSError, ConvertError, json.JSONDecodeError) as exc:
        print(f"convert: {exc}", file=sys.stderr)
        return 1
    except ValidationError as exc:
        print(f"convert: the converted key does not validate:\n{exc}", file=sys.stderr)
        return 1

    if not is_git_ignored_path(args.out):
        print(
            f"convert: WARNING - {args.out} is not under keys/ or named *.key.json, so git may track it. "
            "The organisers' key is confidential (rule R5).",
            file=sys.stderr,
        )
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(key.model_dump(mode="json", exclude_none=True), indent=2) + "\n", encoding="utf-8")
    counts = {k: len(key.by_kind(k)) for k in ("pair", "code_only", "runtime_only")}
    print(f"convert: wrote {args.out}: {counts} decoys={len(key.decoys)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
