"""Template scan (Owner: A, P2-A5).

Which template variables are rendered **unescaped**, found with a regex tokeniser (the spec calls a
tokeniser sufficient here - templates are read as text, never compiled or rendered):

- `{{ expr|safe }}` - the first identifier in `expr` is unescaped;
- everything between `{% autoescape false %}` and `{% endautoescape %}` (Django's `off` too) -
  every `{{ var }}` inside is unescaped;
- `Markup(...)` inside a template expression - the line is recorded and the first identifier inside
  the call counts as unescaped.

An explicit escaping filter (`|e`, `|escape`, `|forceescape`, `|striptags`, `|urlencode`) wins over
all three, so a variable escaped by hand is not reported.

`TemplateIndex.unescaped(name)` resolves the literal a `render_template("page.html")` call passes
against the discovered files by POSIX path suffix, preferring the shortest match, and answers
`{variable: [lines]}`. The taint driver turns a matching keyword argument whose value is tainted
into the CWE-79 template sink (DECISIONS A-18); a `|safe` with no tainted value is not a finding on
its own (A-04).

Files are selected by **extension** (`SastConfig.template_extensions`), never by directory name, so
nothing app-specific enters the tool (R6); discovery and reading come from `sast/textfiles.py`,
shared with the P2-A4 secrets scan.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Protocol

from FlowStopper.sast.config import SastConfig
from FlowStopper.sast.textfiles import read_text, text_files

# `{{ ... }}` expressions and `{% ... %}` tags, in source order.
_TOKEN_RE = re.compile(r"\{\{(?P<expr>.*?)\}\}|\{%-?(?P<tag>.*?)-?%\}", re.DOTALL)
_IDENTIFIER_RE = re.compile(r"[A-Za-z_][A-Za-z_0-9]*")
_STRING_RE = re.compile(r"'[^']*'|\"[^\"]*\"")
_SAFE_FILTER_RE = re.compile(r"\|\s*safe\b")
_ESCAPE_FILTER_RE = re.compile(r"\|\s*(escape|forceescape|striptags|urlencode|e)\b")
_MARKUP_RE = re.compile(r"\bMarkup\s*\(")

_AUTOESCAPE_TAG = "autoescape"
_END_AUTOESCAPE_TAG = "endautoescape"
_AUTOESCAPE_OFF = frozenset({"false", "off", "no", "0", "none"})
# Jinja/Django literals and operators that are never a template variable.
_NON_VARIABLES = frozenset(
    {"true", "false", "none", "and", "or", "not", "if", "else", "in", "is", "with", "without", "context"}
)


@dataclass(frozen=True)
class TemplateFile:
    """One template: the variables it renders unescaped, with the lines they appear on."""

    file: str  # POSIX path relative to the scan root
    unescaped: Mapping[str, tuple[int, ...]] = field(default_factory=dict)
    markup_lines: tuple[int, ...] = ()  # lines using `Markup(...)` inside an expression

    @property
    def names(self) -> tuple[str, ...]:
        return tuple(sorted(self.unescaped))


@dataclass(frozen=True)
class TemplateIndex:
    """Every template under one scan root, keyed by POSIX path relative to it."""

    root: Path
    files: Mapping[str, TemplateFile] = field(default_factory=dict)

    def resolve(self, template_name: str) -> Optional[TemplateFile]:
        """The template a render call's literal names, matched by path suffix (shortest match wins)."""
        wanted = template_name.strip().replace("\\", "/").strip("/")
        if not wanted:
            return None
        matches = [found for rel, found in self.files.items() if rel == wanted or rel.endswith(f"/{wanted}")]
        if not matches:
            return None
        return min(matches, key=lambda found: (len(found.file), found.file))

    def unescaped(self, template_name: str) -> dict[str, list[int]]:
        """Variables `template_name` renders unescaped, with their lines ({} when it is unknown)."""
        found = self.resolve(template_name)
        if found is None:
            return {}
        return {name: list(lines) for name, lines in sorted(found.unescaped.items())}

    @property
    def unescaped_variables(self) -> int:
        """How many (template, variable) pairs render unescaped, for stats."""
        return sum(len(found.unescaped) for found in self.files.values())


class TemplateLookup(Protocol):
    """What the taint driver needs from a template index (`TemplateIndex` implements it)."""

    def unescaped(self, template_name: str) -> dict[str, list[int]]:
        """Variables a template renders unescaped, with the lines they appear on."""


def scan_templates(root: Path | str, config: Optional[SastConfig] = None) -> TemplateIndex:
    """Index every template under `root`, read as text and never rendered (P2-A5)."""
    cfg = config or SastConfig()
    base = Path(root).resolve()
    files: dict[str, TemplateFile] = {}
    for path in text_files(base, cfg, cfg.template_extensions):
        rel = path.relative_to(base).as_posix()
        text = read_text(path, rel, cfg, scanner="templates")
        if text is not None:
            files[rel] = scan_template_text(rel, text)
    return TemplateIndex(root=base, files=files)


def scan_template_text(file: str, text: str) -> TemplateFile:
    """Tokenise one template's text; public so callers can scan a string they already hold."""
    unescaped: dict[str, list[int]] = {}
    markup: list[int] = []
    autoescape: list[bool] = []
    for match in _TOKEN_RE.finditer(text):
        tag = match.group("tag")
        if tag is not None:
            _autoescape_tag(tag, autoescape)
            continue
        line = text.count("\n", 0, match.start()) + 1
        expr = match.group("expr") or ""
        if _MARKUP_RE.search(expr):
            markup.append(line)
        name = _unescaped_name(expr, escaping=autoescape[-1] if autoescape else True)
        if name is None:
            continue
        lines = unescaped.setdefault(name, [])
        if line not in lines:
            lines.append(line)
    return TemplateFile(
        file=file,
        unescaped={name: tuple(lines) for name, lines in sorted(unescaped.items())},
        markup_lines=tuple(markup),
    )


# --------------------------------------------------------------------------- tokeniser helpers
def _unescaped_name(expr: str, *, escaping: bool) -> Optional[str]:
    """The variable this `{{ ... }}` renders unescaped, or None when the output is escaped."""
    if _ESCAPE_FILTER_RE.search(expr):
        return None  # escaped by hand, whatever the surrounding autoescape block says
    markup = _MARKUP_RE.search(expr)
    if not (markup or _SAFE_FILTER_RE.search(expr) or not escaping):
        return None
    head = expr[markup.end() :] if markup else expr.split("|")[0]
    return _first_identifier(head)


def _first_identifier(text: str) -> Optional[str]:
    """First identifier in `text` that is not a literal or an operator word."""
    for match in _IDENTIFIER_RE.finditer(_STRING_RE.sub(" ", text)):
        name = match.group(0)
        if name.lower() not in _NON_VARIABLES:
            return name
    return None


def _autoescape_tag(tag: str, stack: list[bool]) -> None:
    """Track `{% autoescape false %}` ... `{% endautoescape %}` nesting on `stack`."""
    words = tag.strip().split()
    if not words:
        return
    name = words[0].lower()
    if name == _AUTOESCAPE_TAG:
        state = words[1].strip("\"'").lower() if len(words) > 1 else "true"
        stack.append(state not in _AUTOESCAPE_OFF)
    elif name == _END_AUTOESCAPE_TAG and stack:
        stack.pop()
