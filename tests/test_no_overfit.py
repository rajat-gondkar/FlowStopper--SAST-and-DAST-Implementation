"""R6 no-overfitting guard (shared).

Collects app-specific strings (file paths, route paths, qualified function names) from every
answer key present locally - keys/*.json (git-ignored, organisers' app), apps/*/answer_key.json
and fixtures/answer_key.json - and fails if any appears inside a string literal in FlowStopper/.
Comments and docstrings are ignored, so documentation examples are fine.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path

from tests.conftest import ROOT

# Generic probe paths the DAST may legitimately contain (spec P1-B2 / P2-B2).
GENERIC = {"/", "*", "/robots.txt", "/sitemap.xml", "/openapi.json", "/swagger.json", "/.git/HEAD", "/.env", "/console"}
MIN_LEN = 5


def _key_files() -> list[Path]:
    files = sorted((ROOT / "keys").glob("*.json")) + sorted((ROOT / "apps").glob("*/answer_key.json"))
    return files + [ROOT / "fixtures" / "answer_key.json"]


def _tokens(key: dict) -> set[str]:
    out: set[str] = set()
    for v in key.get("vulns", []) + key.get("decoys", []):
        code = v.get("code") or {}
        for s in (code.get("file"), code.get("function"), v.get("file")):
            if s:
                out.add(s)
        rt = v.get("runtime") or {}
        if rt.get("path"):
            out.add(rt["path"])
    return {t for t in out if t not in GENERIC and len(t) >= MIN_LEN}


def _string_literals(path: Path) -> list[tuple[int, str]]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    docstrings = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)) and node.body:
            first = node.body[0]
            if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant):
                docstrings.add(id(first.value))
    return [
        (n.lineno, n.value)
        for n in ast.walk(tree)
        if isinstance(n, ast.Constant) and isinstance(n.value, str) and id(n) not in docstrings
    ]


def test_no_answer_key_strings_in_tool_code():
    tokens: set[str] = set()
    for f in _key_files():
        try:
            tokens |= _tokens(json.loads(f.read_text(encoding="utf-8")))
        except (OSError, json.JSONDecodeError, AttributeError):
            continue  # malformed or unconventional local key: validate it with keyschema instead
    hits = []
    for py in sorted((ROOT / "FlowStopper").rglob("*.py")):
        for lineno, lit in _string_literals(py):
            hits += [f"{py.relative_to(ROOT)}:{lineno}: {t!r}" for t in tokens if t in lit]
    assert not hits, "App-specific strings found in FlowStopper/ (rule R6):\n" + "\n".join(hits)
