"""Build bench/owasp-benchmark-python/answer_key.json from the app's OFFICIAL solution.

Our own helper script (not upstream code). It transcribes, it does not judge:
- vulnerable/safe comes only from upstream `expectedresults-0.1.csv` (OWASP's expected results);
- the request recipe (inputs per test) comes from upstream `data/benchmark-crawler-http.xml`;
- code locations are read from the pinned clone in ./src with `ast.parse` (parse only, never imported).

Only the six in-scope CSV categories are keyed (decision A-70). Every entry is verified against the
pinned source; any mismatch aborts instead of writing a guess:
- the module defines `<Test>_post` under a POST `@app.route` whose path names the test;
- the category's sink call is present inside that function (and, for securecookie, the `secure=`
  flag agrees with the CSV verdict);
- `<Test>_get` is on GET at the same path. runtime.method is null (any method) when its body is just
  `return <Test>_post()`, else POST (GET renders the form page).

Usage (after `scripts/bench_fetch.sh clone owasp-benchmark-python`):
    .venv/bin/python bench/owasp-benchmark-python/build_key.py
"""

from __future__ import annotations

import ast
import csv
import json
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

HERE = Path(__file__).resolve().parent
SRC = HERE / "src"
OUT = HERE / "answer_key.json"
SHA = "f1291485808b66e20ddb6b01b10dc71b3df8c8ba"
BLOB = f"https://github.com/OWASP-Benchmark/BenchmarkPython/blob/{SHA}"
CSV_NAME = "expectedresults-0.1.csv"
XML_NAME = "data/benchmark-crawler-http.xml"

# CSV category -> (CWE, kind, label, sink call names that must appear in the POST handler)
SCOPE: dict[str, tuple[int, str, str, set[str]]] = {
    "sqli": (89, "pair", "SQL injection", {"execute"}),
    "xss": (79, "pair", "Reflected XSS", set()),  # sink = the handler's returned HTML (checked below)
    "cmdi": (78, "pair", "OS command injection", {"subprocess.run", "os.system"}),
    "pathtraver": (22, "pair", "Path traversal", {"open", "exists", "read_text"}),
    "redirect": (601, "pair", "Open redirect", {"redirect"}),
    "securecookie": (614, "runtime_only", "Cookie set without the Secure flag", {"set_cookie"}),
}


def _fail(msg: str) -> None:
    sys.exit(f"build_key: {msg}")


def _calls(node: ast.Call, names: set[str]) -> bool:
    """True when the call's dotted name equals, or ends with '.' + one of names."""
    func = ast.unparse(node.func)
    return any(func == n or func.endswith("." + n) for n in names)


def _crawler_inputs() -> dict[str, list[tuple[str, str]]]:
    root = ET.parse(SRC / XML_NAME).getroot()
    out: dict[str, list[tuple[str, str]]] = {}
    for test in root.iter("benchmarkTest"):
        out[test.get("tcName", "")] = [(el.tag, el.get("name", "")) for el in test]
    return out


def _route(fn: ast.FunctionDef) -> tuple[str, list[str]]:
    for dec in fn.decorator_list:
        if isinstance(dec, ast.Call) and ast.unparse(dec.func) == "app.route" and dec.args:
            path = ast.literal_eval(dec.args[0])
            methods = ["GET"]
            for kw in dec.keywords:
                if kw.arg == "methods":
                    methods = [m.upper() for m in ast.literal_eval(kw.value)]
            return path, methods
    _fail(f"{fn.name}: no @app.route decorator")
    raise AssertionError


def _get_delegates(tree: ast.Module, name: str, path: str) -> bool:
    """True when `<name>_get` (GET on the same path) is just `return <name>_post()`.

    Then the vulnerable flow also runs on GET, so the key leaves runtime.method null (any method).
    Otherwise GET renders the form page and the flow is POST-only.
    """
    gets = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == f"{name}_get"]
    if len(gets) != 1:
        _fail(f"{name}: expected one {name}_get, found {len(gets)}")
    get_path, get_methods = _route(gets[0])
    if get_path != path or get_methods != ["GET"]:
        _fail(f"{name}: unexpected GET route {get_methods} {get_path}")
    body = gets[0].body
    return len(body) == 1 and ast.unparse(body[0]) == f"return {name}_post()"


def _source_param(fn: ast.FunctionDef, inputs: list[tuple[str, str]]) -> tuple[str | None, int, str]:
    """(param, line, expression) of the first request read in the handler.

    param is set only when the read is request.form/request.args by a literal name that the official
    crawler also sends as formparam/getparam; anything else (headers, cookies, path, query string,
    key loops, the request_wrapper helper) is left None.
    """
    reads = []
    for node in ast.walk(fn):
        text = ast.unparse(node) if isinstance(node, (ast.Call, ast.Attribute, ast.Subscript)) else ""
        if text.startswith("request.") or "request_wrapper(" in text:
            reads.append((node.lineno, node.col_offset, node))
    if not reads:
        _fail(f"{fn.name}: no request read")
    line, _, node = min(reads, key=lambda r: (r[0], r[1]))
    expr = ast.unparse(node)
    want = {"request.form": "formparam", "request.args": "getparam"}
    for prefix, tag in want.items():
        for call in [n for n in ast.walk(fn) if isinstance(n, ast.Call) and n.lineno == line]:
            fname = ast.unparse(call.func)
            if fname in (f"{prefix}.get", f"{prefix}.getlist") and call.args:
                arg = call.args[0]
                if isinstance(arg, ast.Constant) and (tag, arg.value) in inputs:
                    return arg.value, line, fname + f"({arg.value!r})"
    return (
        None,
        line,
        expr.split("(")[0] if "request_wrapper" not in expr else "helpers.separate_request.request_wrapper",
    )


def _sink_lines(fn: ast.FunctionDef, cat: str, real: bool) -> list[int]:
    names = SCOPE[cat][3]
    if cat == "xss":
        lines = [n.lineno for n in ast.walk(fn) if isinstance(n, ast.Return) and n.value is not None]
    else:
        lines = [n.lineno for n in ast.walk(fn) if isinstance(n, ast.Call) and _calls(n, names)]
    if not lines:
        _fail(f"{fn.name}: no {cat} sink ({sorted(names) or 'return'}) in the POST handler")
    if cat == "securecookie":
        flags = {
            kw.value.value
            for n in ast.walk(fn)
            if isinstance(n, ast.Call) and _calls(n, {"set_cookie"})
            for kw in n.keywords
            if kw.arg == "secure" and isinstance(kw.value, ast.Constant)
        }
        if flags != {not real}:
            _fail(f"{fn.name}: set_cookie secure={flags} disagrees with CSV real={real}")
    return sorted(set(lines))


def main() -> int:
    if not (SRC / ".git").is_dir():
        _fail(f"{SRC} missing; run scripts/bench_fetch.sh clone owasp-benchmark-python")
    head = subprocess.run(["git", "-C", str(SRC), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    if head != SHA:
        _fail(f"clone is at {head}, expected pinned {SHA}")
    crawler = _crawler_inputs()
    vulns, decoys = [], []
    with (SRC / CSV_NAME).open(encoding="utf-8") as fh:
        rows = [r for r in csv.reader(fh) if r and not r[0].startswith("#")]
    for name, cat, real_s, cwe_s in rows:
        if cat not in SCOPE:
            continue
        cwe, kind, label, _ = SCOPE[cat]
        if int(cwe_s) != cwe:
            _fail(f"{name}: CSV CWE {cwe_s} != {cwe}")
        real = real_s == "true"
        rel = f"testcode/{name}.py"
        tree = ast.parse((SRC / rel).read_text(encoding="utf-8"))
        posts = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == f"{name}_post"]
        if len(posts) != 1:
            _fail(f"{name}: expected one {name}_post, found {len(posts)}")
        fn = posts[0]
        path, methods = _route(fn)
        if methods != ["POST"] or not path.endswith(f"/{name}") or f"/{cat}-" not in path:
            _fail(f"{name}: unexpected route {methods} {path}")
        inputs = crawler.get(name)
        if inputs is None:
            _fail(f"{name}: not in {XML_NAME}")
        delegates = _get_delegates(tree, name, path)
        param, src_line, src_expr = _source_param(fn, inputs)
        sinks = _sink_lines(fn, cat, real)
        start, end = fn.lineno, fn.end_lineno or fn.lineno
        csv_row = f"{name},{cat},{real_s},{cwe_s}"
        sent = ", ".join(f"{t} {n}" for t, n in inputs) or "none"
        where = f"{BLOB}/{rel}#L{start}-L{end}"
        if real:
            notes = (
                f"Official: {CSV_NAME} row '{csv_row}' ({BLOB}/{CSV_NAME}). Code: {where}; "
                f"POST handler {name}_post L{start}-{end}, input read at L{src_line} ({src_expr}), "
                f"{'sink' if cat != 'securecookie' else 'insecure set_cookie'} at L{', L'.join(map(str, sinks))}. "
                f"Official request recipe ({XML_NAME}): {sent}."
            )
            if delegates:
                notes += f" Runtime method null: {name}_get on the same path is just 'return {name}_post()'."
            else:
                notes += f" Runtime method POST: {name}_get renders the form page only."
            if kind == "pair" and param is None:
                notes += " Runtime param left null: the input is not a plain form/query field (see recipe)."
            if cat == "securecookie":
                where_set = "GET and POST responses" if delegates else "POST response only"
                notes += f" Insecure cookie (secure=False) is set on the {where_set}; runtime-only per our scope."
            entry: dict = {"id": f"V{name[-5:]}", "cwe": cwe, "kind": kind, "title": f"{label} in {name}"}
            if kind == "pair":
                entry["code"] = {"file": rel, "line_start": start, "line_end": end, "function": f"{name}_post"}
            method = None if delegates else "POST"
            entry["runtime"] = {"method": method, "path": path, "param": param if kind == "pair" else None}
            entry["notes"] = notes
            vulns.append(entry)
        else:
            reason = (
                f"Official {CSV_NAME} row '{csv_row}': known-safe {cat} test case (not a real vulnerability). "
                f"POST handler {name}_post {where}."
            )
            decoys.append(
                {"id": f"D{name[-5:]}", "cwe": cwe, "file": rel, "line_start": start, "line_end": end, "reason": reason}
            )
    key = {
        "schema_version": "1",
        "app": "owasp-benchmark-python",
        "language": "python",
        "framework": "flask",
        "base_url": "http://127.0.0.1:8110",
        "vulns": sorted(vulns, key=lambda v: v["id"]),
        "decoys": sorted(decoys, key=lambda d: d["id"]),
    }
    OUT.write_text(json.dumps(key, indent=2) + "\n", encoding="utf-8")
    kinds = {k: sum(v["kind"] == k for v in vulns) for k in ("pair", "code_only", "runtime_only")}
    methods = {str(m): sum(v["runtime"]["method"] == m for v in vulns) for m in (None, "POST")}
    print(f"wrote {OUT.relative_to(HERE.parent.parent)}: {len(vulns)} vulns {kinds}, {len(decoys)} decoys")
    print(f"runtime.method: {methods}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
