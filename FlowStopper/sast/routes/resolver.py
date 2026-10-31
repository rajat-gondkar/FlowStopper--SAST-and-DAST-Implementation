"""Path templates -> anchored path_regex, prefixes, params (Owner: A, P1-A2).

Generic framework syntax only (no app-specific constants, R6):
  - Flask/Werkzeug and Django `path()`:  ``<int:id>``, ``<id>``, ``<path:p>``
  - FastAPI/Starlette:                    ``{id}``, ``{id:path}``
  - Django `re_path()`:                   raw regex with ``(?P<name>...)`` groups
"""

from __future__ import annotations

import ast
import re
from typing import Optional

# <conv:name> or <name>  (Flask, Django path())   |   {name} or {name:conv}  (FastAPI, Starlette)
_PLACEHOLDER = re.compile(
    r"<(?:(?P<fconv>[A-Za-z_]\w*):)?(?P<fname>[A-Za-z_]\w*)>"
    r"|\{(?P<cname>[A-Za-z_]\w*)(?::(?P<cconv>[^}]+))?\}"
)
_NAMED_GROUP = re.compile(r"\(\?P<(?P<name>[A-Za-z_]\w*)>")

# Converters that match across '/' (consume the rest of the path).
PATH_CONVERTERS = frozenset({"path"})


def _converter(match: re.Match[str]) -> str:
    return (match.group("fconv") or match.group("cconv") or "").split(":")[0].strip()


def split_params(template: str) -> list[tuple[str, bool]]:
    """`(name, is_path_converter)` for each placeholder in a Flask/FastAPI template, in order."""
    out: list[tuple[str, bool]] = []
    for m in _PLACEHOLDER.finditer(template):
        out.append(((m.group("fname") or m.group("cname")), _converter(m) in PATH_CONVERTERS))
    return out


def template_regex(template: str) -> str:
    """Anchored regex matching concrete URL paths for a Flask/FastAPI template, trailing slash optional."""
    parts: list[str] = []
    used: set[str] = set()
    last = 0
    for m in _PLACEHOLDER.finditer(template):
        parts.append(re.escape(template[last : m.start()]))
        name = m.group("fname") or m.group("cname")
        body = ".+" if _converter(m) in PATH_CONVERTERS else "[^/]+"
        if name in used:  # a duplicated name cannot be a second capture group
            parts.append(f"(?:{body})")
        else:
            used.add(name)
            parts.append(f"(?P<{name}>{body})")
        last = m.end()
    parts.append(re.escape(template[last:]))
    return _anchor("".join(parts))


def repath_regex(pattern: str) -> tuple[str, str, list[str]]:
    """Django `re_path` -> (anchored regex, readable template, named params)."""
    body = pattern
    if body.startswith("^"):
        body = body[1:]
    if body.endswith("$"):
        body = body[:-1]
    if not body.startswith("/"):
        body = "/" + body
    names = _NAMED_GROUP.findall(pattern)
    template = re.sub(r"\(\?P<([A-Za-z_]\w*)>[^)]*\)", r"<\1>", body)
    return _anchor(body), template, names


def _anchor(core: str) -> str:
    if core in ("", "/"):
        return "^/?$"
    if len(core) > 1 and core.endswith("/"):
        core = core[:-1]
    return f"^{core}/?$"


def join_paths(*parts: Optional[str]) -> str:
    """Join URL fragments into a single POSIX path with one leading slash and no duplicate slashes."""
    segments: list[str] = []
    for part in parts:
        if not part:
            continue
        segments.extend(seg for seg in part.split("/") if seg)
    return "/" + "/".join(segments) if segments else "/"


def const_str(node: Optional[ast.AST]) -> Optional[str]:
    """The value of a string-literal AST node, else None."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def str_sequence(node: Optional[ast.AST]) -> Optional[list[str]]:
    """The string values of a list/tuple/set literal of string constants, else None."""
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        values = [const_str(e) for e in node.elts]
        if values and all(v is not None for v in values):
            return [v for v in values if v is not None]
    return None


def keyword(call: ast.Call, name: str) -> Optional[ast.expr]:
    """The value expression of keyword argument `name` in a call, else None."""
    for kw in call.keywords:
        if kw.arg == name:
            return kw.value
    return None


def first_str_arg(call: ast.Call) -> Optional[str]:
    """The first positional argument of a call when it is a string literal, else None."""
    return const_str(call.args[0]) if call.args else None
