"""Generate apps/mock_b/answer_key.json from the `# vuln:` / `# decoy:` markers in the source.

Line numbers in an answer key have to be right - the eval harness matches a finding to a planted
bug by file and line overlap, so a stale number silently turns a real detection into a miss. Rather
than maintain them by hand, every planted bug carries a marker comment next to the offending line
and this script reads them back out. Regenerate (never hand-edit the JSON) with:

    .venv/bin/python -m apps.mock_b.build_key
    make validate-key KEY=apps/mock_b/answer_key.json

Markers ending in `entry` mark the *route* that reaches a bug (used only for the notes), not the
code location. Jinja templates carry markers too, but the code location follows Mock A's
convention: it points at the Python render call, with the template named in the notes.
"""

from __future__ import annotations

import ast
import json
import re
from pathlib import Path

APP_DIR = Path(__file__).resolve().parent
MARKER = re.compile(r"#\s*(vuln|decoy):([A-Z]\d+)(?P<entry>\s+entry)?", re.IGNORECASE)

# cwe / kind / runtime(method, path, param) / title / notes per planted bug.
VULNS: dict[str, dict] = {
    "B01": {
        "cwe": 89,
        "kind": "pair",
        "runtime": ("GET", "/catalogue/items", "fragment"),
        "title": "SQL injection in the catalogue search (fragment interpolated into SQL one layer down)",
        "notes": "router routers/catalogue.py:list_items passes the query value to "
        "repositories.catalogue_repo.search_items, which builds the statement with an f-string (cross-module).",
    },
    "B02": {
        "cwe": 89,
        "kind": "pair",
        "runtime": ("POST", "/accounts/signin", "handle"),
        "title": "SQL injection in sign-in (JSON body handle concatenated into SQL)",
        "notes": "pydantic body field `handle` reaches repositories.account_repo.authenticate, which concatenates "
        "it into the statement. JSON body parameter, not a form field.",
    },
    "B03": {
        "cwe": 79,
        "kind": "pair",
        "runtime": ("GET", "/catalogue/lookup", "term"),
        "title": "Reflected XSS in the catalogue lookup (term pasted into an HTMLResponse)",
        "notes": "the term is interpolated into markup returned as HTMLResponse, so the raw characters survive.",
    },
    "B04": {
        "cwe": 79,
        "kind": "pair",
        "runtime": ("GET", "/catalogue/detail/{sku}", "label"),
        "title": "Template XSS: label rendered with |safe in detail.html",
        "notes": "TemplateResponse('detail.html', label=...) where the template renders {{ label|safe }} "
        "(templates/detail.html). Code location points at the Python render call, as in Mock A's M04.",
    },
    "B05": {
        "cwe": 78,
        "kind": "pair",
        "runtime": ("GET", "/ops/diagnose", "endpoint"),
        "title": "Command injection in the diagnostics endpoint (os.system)",
        "notes": "routers/ops.py:diagnose calls services.net.probe_endpoint, which passes the value to os.system "
        "inside an f-string (cross-module).",
    },
    "B06": {
        "cwe": 78,
        "kind": "pair",
        "runtime": ("POST", "/ops/archive", "tag"),
        "title": "Command injection in the archive endpoint (subprocess shell=True)",
        "notes": "JSON body field `tag` reaches services.archive.snapshot, which runs a shell command string.",
    },
    "B07": {
        "cwe": 22,
        "kind": "pair",
        "runtime": ("GET", "/assets/fetch", "doc"),
        "title": "Path traversal in the asset reader (os.path.join + open, no containment check)",
        "notes": "an absolute payload also works because os.path.join discards the base when the second part "
        "is absolute.",
    },
    "B08": {
        "cwe": 22,
        "kind": "pair",
        "runtime": ("GET", "/assets/raw/{name}", "name"),
        "title": "Path traversal in the raw asset route (path converter into FileResponse)",
        "notes": "the {name:path} converter keeps separators, so an encoded traversal reaches FileResponse.",
    },
    "B09": {
        "cwe": 601,
        "kind": "pair",
        "runtime": ("GET", "/accounts/bounce", "onward"),
        "title": "Open redirect in the bounce endpoint (unvalidated RedirectResponse target)",
        "notes": "no allow-list; protocol-relative and absolute off-site targets are both honoured.",
    },
    "B10": {
        "cwe": 601,
        "kind": "pair",
        "runtime": ("POST", "/accounts/signin", "onward"),
        "title": "Open redirect after sign-in (post-authentication onward target)",
        "notes": "same route as B02 but a different parameter: the redirect is only reachable with valid "
        "credentials (avery / pepper-ridge).",
    },
    "B21": {
        "cwe": 798,
        "kind": "code_only",
        "title": "Hard-coded session signing secret",
        "notes": "literal assigned to SIGNING_SECRET in config.py.",
    },
    "B22": {
        "cwe": 798,
        "kind": "code_only",
        "title": "Hard-coded warehouse database password",
        "notes": "literal password, also embedded in the DSN string on the following line.",
    },
    "B23": {
        "cwe": 798,
        "kind": "code_only",
        "title": "Hard-coded vendor pricing feed token",
        "notes": "literal token in the pricing service, used to build an Authorization header.",
    },
    "B31": {
        "cwe": 693,
        "kind": "runtime_only",
        "runtime": ("GET", "*", None),
        "title": "Missing security headers on every response (no CSP, X-Frame-Options, nosniff, Referrer-Policy)",
        "notes": "host-wide: the app sets no security headers anywhere.",
    },
    "B32": {
        "cwe": 1004,
        "kind": "runtime_only",
        "runtime": ("POST", "/accounts/signin", None),
        "title": "Session cookie set without HttpOnly, Secure or SameSite",
        "notes": "set on the sign-in response; needs valid credentials (avery / pepper-ridge) to observe.",
    },
    "B33": {
        "cwe": 209,
        "kind": "runtime_only",
        "runtime": ("GET", "/ops/boom", None),
        "title": "Verbose error page returns a full Python traceback",
        "notes": "the global exception handler renders traceback.format_exception to the client.",
    },
    "B34": {
        "cwe": 497,
        "kind": "runtime_only",
        "runtime": ("GET", "*", None),
        "title": "Server banner discloses the application version",
        "notes": "host-wide: a middleware stamps a versioned Server header on every response.",
    },
}

DECOYS: dict[str, dict] = {
    "D01": {"cwe": 89, "reason": "parameterised query with a bound placeholder"},
    "D02": {"cwe": 89, "reason": "value cast to int before use in SQL"},
    "D03": {"cwe": 79, "reason": "html.escape before returning HTML"},
    "D04": {"cwe": 78, "reason": "subprocess argument vector with shell=False"},
    "D05": {"cwe": 22, "reason": "os.path.basename plus a resolved-root containment check"},
    "D06": {"cwe": 601, "reason": "redirect target checked against an allow-list"},
    "D07": {"cwe": 79, "reason": "value reflected as JSON, not HTML"},
    "D08": {"cwe": 798, "reason": "credential read from os.environ"},
}


def module_name(rel_path: Path) -> str:
    parts = list(rel_path.with_suffix("").parts)
    if parts and parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def enclosing_functions(source: str, module: str) -> list[tuple[int, int, str]]:
    """(start, end, qualified name) for every function/method, innermost last."""
    out: list[tuple[int, int, str]] = []

    def walk(node: ast.AST, prefix: str) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                name = f"{prefix}.{child.name}" if prefix else child.name
                out.append((child.lineno, getattr(child, "end_lineno", child.lineno), name))
                walk(child, name)
            elif isinstance(child, ast.ClassDef):
                walk(child, f"{prefix}.{child.name}" if prefix else child.name)

    walk(ast.parse(source), module)
    return out


def scan() -> tuple[dict[str, dict], dict[str, dict], dict[str, list[str]]]:
    """Find every marker. Returns (code locations, entry notes, duplicates)."""
    locations: dict[str, dict] = {}
    entries: dict[str, dict] = {}
    seen: dict[str, list[str]] = {}

    for path in sorted(APP_DIR.rglob("*.py")):
        rel = path.relative_to(APP_DIR)
        if rel.name in ("build_key.py", "selfcheck.py"):
            continue
        source = path.read_text(encoding="utf-8")
        lines = source.splitlines()
        functions = enclosing_functions(source, module_name(rel))

        for index, line in enumerate(lines, start=1):
            match = MARKER.search(line)
            if not match:
                continue
            marker_id = match.group(2).upper()
            target = min(index + 1, len(lines))
            record = {
                "file": rel.as_posix(),
                "line_start": target,
                "line_end": min(target + 1, len(lines)),
            }
            enclosing = [name for start, end, name in functions if start <= target <= end]
            if enclosing:
                record["function"] = enclosing[-1]

            if match.group("entry"):
                entries[marker_id] = record
            else:
                seen.setdefault(marker_id, []).append(f"{rel.as_posix()}:{index}")
                locations[marker_id] = record
    return locations, entries, seen


def build() -> dict:
    locations, entries, seen = scan()

    duplicates = {k: v for k, v in seen.items() if len(v) > 1}
    if duplicates:
        raise SystemExit(f"duplicate markers for {duplicates}")

    vulns: list[dict] = []
    for vuln_id, meta in VULNS.items():
        entry: dict = {"id": vuln_id, "cwe": meta["cwe"], "kind": meta["kind"], "title": meta["title"]}
        notes = meta.get("notes", "")

        if meta["kind"] in ("pair", "code_only"):
            if vuln_id not in locations:
                raise SystemExit(f"{vuln_id}: no `# vuln:{vuln_id}` marker found in the source")
            entry["code"] = locations[vuln_id]
        if meta["kind"] in ("pair", "runtime_only"):
            method, path, param = meta["runtime"]
            entry["runtime"] = {"method": method, "path": path, "param": param}
        if vuln_id in entries:
            where = entries[vuln_id]
            notes = f"{notes} Route entry: {where['file']}:{where['line_start']}.".strip()
        entry["notes"] = notes
        vulns.append(entry)

    decoys: list[dict] = []
    for decoy_id, meta in DECOYS.items():
        if decoy_id not in locations:
            raise SystemExit(f"{decoy_id}: no `# decoy:{decoy_id}` marker found in the source")
        where = locations[decoy_id]
        decoys.append(
            {
                "id": decoy_id,
                "cwe": meta["cwe"],
                "file": where["file"],
                "line_start": where["line_start"],
                "line_end": where["line_end"],
                "reason": meta["reason"],
            }
        )

    return {
        "schema_version": "1",
        "app": "shoplite-b",
        "language": "python",
        "framework": "fastapi",
        "base_url": "http://127.0.0.1:8090",
        "vulns": vulns,
        "decoys": decoys,
    }


def main() -> int:
    key = build()
    out = APP_DIR / "answer_key.json"
    out.write_text(json.dumps(key, indent=2) + "\n", encoding="utf-8")
    kinds: dict[str, int] = {}
    for vuln in key["vulns"]:
        kinds[vuln["kind"]] = kinds.get(vuln["kind"], 0) + 1
    cwes = sorted({v["cwe"] for v in key["vulns"] if v["kind"] == "pair"})
    print(f"wrote {out.relative_to(APP_DIR.parents[1])}")
    print(f"  {kinds} decoys={len(key['decoys'])}")
    print(f"  pair CWEs: {cwes}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
