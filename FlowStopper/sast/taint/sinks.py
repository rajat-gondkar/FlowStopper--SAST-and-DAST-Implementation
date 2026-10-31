"""Taint sinks per CWE, including which argument matters (Owner: A, P2-A3).

The five rows of the spec's P2-A3 sink table, encoded as `SinkSpec` records. Matching is by the
resolved dotted callee first and by the attribute leaf name second (DECISIONS A-08): the index never
guesses what `conn.execute` is (A-02), yet the CWE-89 row has to catch it. Leaf matching is skipped
when the callee resolves to a project symbol, so a project function called `execute` stays a call,
not a sink.

Every sink result is a taint barrier (A-09): a cursor, a file handle, a response or a rendered page
is not the request string, and treating it as tainted would cascade derived findings.

Rule ids and titles follow the agreed oracle in `fixtures/sast_findings.json`
(`py.sqli.fstring.execute`, `py.sqli.concat.execute`, `py.xss.fstring.html-response`,
`py.cmdi.subprocess`); the string-building kind is part of the id for the families whose oracle ids
carry it.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Callable, Optional

from FlowStopper.sast import suppress
from FlowStopper.sast.index import ModuleContext, dotted_parts
from FlowStopper.sast.routes.resolver import const_str, keyword

RECEIVER = -1  # `arg_index` value meaning "the receiver", e.g. `Path(p).read_text()`


@dataclass(frozen=True)
class SinkSpec:
    """One sink row: what to match, which argument carries the tainted value, when it is unsafe."""

    cwe: int
    rule_family: str  # "sqli" | "cmdi" | "traversal" | "redirect" | "xss"
    token: str  # short sink name used in the rule id
    dotted: frozenset[str] = frozenset()  # resolved callee names
    leaf_methods: frozenset[str] = frozenset()  # attribute leaf names (A-08)
    arg_index: int = 0  # RECEIVER for methods called on the tainted value
    arg_keywords: frozenset[str] = frozenset()  # keyword spellings of that argument
    requires_string_built: bool = False  # a constant string with tainted binds is safe
    requires_shell: bool = False  # needs shell=True (or a shell-only callee) to be unsafe
    result_barrier: bool = True


SQL_EXECUTE = SinkSpec(
    cwe=89,
    rule_family="sqli",
    token="execute",
    dotted=frozenset(
        {
            "sqlalchemy.text",
            "sqlalchemy.sql.text",
            "sqlalchemy.sql.expression.text",
            "pandas.read_sql",
            "pandas.read_sql_query",
            "pandas.read_sql_table",
        }
    ),
    leaf_methods=frozenset(
        {
            "execute",
            "executemany",
            "executescript",
            "raw",
            "extra",
            "read_sql",
            "read_sql_query",
            "read_sql_table",
        }
    ),
    arg_keywords=frozenset({"sql", "raw_query", "query"}),
    requires_string_built=True,
)

SHELL_COMMAND = SinkSpec(
    cwe=78,
    rule_family="cmdi",
    token="shell",
    dotted=frozenset(
        {
            "os.system",
            "os.popen",
            "commands.getoutput",
            "commands.getstatusoutput",
            "subprocess.getoutput",
            "subprocess.getstatusoutput",
        }
    ),
    arg_keywords=frozenset({"cmd", "command"}),
)

SUBPROCESS = SinkSpec(
    cwe=78,
    rule_family="cmdi",
    token="subprocess",
    dotted=frozenset(
        {
            "subprocess.run",
            "subprocess.call",
            "subprocess.check_call",
            "subprocess.check_output",
            "subprocess.Popen",
        }
    ),
    arg_keywords=frozenset({"args"}),
    requires_shell=True,
)

FILE_OPEN = SinkSpec(
    cwe=22,
    rule_family="traversal",
    token="open",
    dotted=frozenset({"builtins.open", "io.open", "codecs.open", "os.open"}),
    arg_keywords=frozenset({"file", "filename", "path"}),
)

PATH_ACCESS = SinkSpec(
    cwe=22,
    rule_family="traversal",
    token="path-access",
    leaf_methods=frozenset({"open", "read_text", "read_bytes", "write_text", "write_bytes"}),
    arg_index=RECEIVER,
)

SEND_FILE = SinkSpec(
    cwe=22,
    rule_family="traversal",
    token="send-file",
    dotted=frozenset(
        {
            "flask.send_file",
            "flask.helpers.send_file",
            "fastapi.responses.FileResponse",
            "starlette.responses.FileResponse",
            "django.http.FileResponse",
        }
    ),
    leaf_methods=frozenset({"send_file", "FileResponse"}),
    arg_keywords=frozenset({"path_or_file", "path", "filename"}),
)

LIST_DIR = SinkSpec(
    cwe=22,
    rule_family="traversal",
    token="listdir",
    dotted=frozenset({"os.listdir", "os.scandir", "os.walk"}),
    arg_keywords=frozenset({"path", "top"}),
)

REDIRECT = SinkSpec(
    cwe=601,
    rule_family="redirect",
    token="unvalidated",
    dotted=frozenset(
        {
            "flask.redirect",
            "flask.helpers.redirect",
            "werkzeug.utils.redirect",
            "django.shortcuts.redirect",
            "django.http.HttpResponseRedirect",
            "django.http.HttpResponsePermanentRedirect",
            "fastapi.responses.RedirectResponse",
            "starlette.responses.RedirectResponse",
        }
    ),
    leaf_methods=frozenset({"HttpResponseRedirect", "RedirectResponse"}),
    arg_keywords=frozenset({"location", "url", "to", "redirect_to"}),
)

HTML_RESPONSE = SinkSpec(
    cwe=79,
    rule_family="xss",
    token="html-response",
    dotted=frozenset(
        {
            "flask.make_response",
            "flask.Response",
            "flask.wrappers.Response",
            "werkzeug.wrappers.Response",
            "django.http.HttpResponse",
            "fastapi.responses.HTMLResponse",
            "starlette.responses.HTMLResponse",
        }
    ),
    leaf_methods=frozenset({"make_response", "HTMLResponse"}),
    arg_keywords=frozenset({"content", "response", "body"}),
)

MARKUP = SinkSpec(
    cwe=79,
    rule_family="xss",
    token="markup",
    dotted=frozenset(
        {
            "markupsafe.Markup",
            "flask.Markup",
            "jinja2.Markup",
            "django.utils.safestring.mark_safe",
        }
    ),
    leaf_methods=frozenset({"mark_safe"}),
    arg_keywords=frozenset({"base", "value", "s"}),
)

# The template *source* of `render_template_string` (DECISIONS A-45): request data in it is rendered
# as markup (and template code). Its keyword arguments stay ordinary escaped template variables.
TEMPLATE_STRING = SinkSpec(
    cwe=79,
    rule_family="xss",
    token="template-string",
    dotted=frozenset({"flask.render_template_string", "flask.templating.render_template_string"}),
    leaf_methods=frozenset({"render_template_string"}),
    arg_keywords=frozenset({"source"}),
)

# Order matters only for determinism: the first row that matches wins.
SINKS: tuple[SinkSpec, ...] = (
    SQL_EXECUTE,
    SHELL_COMMAND,
    SUBPROCESS,
    FILE_OPEN,
    SEND_FILE,
    LIST_DIR,
    PATH_ACCESS,
    REDIRECT,
    HTML_RESPONSE,
    MARKUP,
    TEMPLATE_STRING,
)

# Sinks that are not call expressions; the engine reports them directly.
HANDLER_RETURN = SinkSpec(cwe=79, rule_family="xss", token="html-response")
LOCATION_HEADER = SinkSpec(cwe=601, rule_family="redirect", token="location-header")
TEMPLATE_RENDER = SinkSpec(cwe=79, rule_family="xss", token="template")

# Template renderers: taint barriers here; P2-A5 turns their keyword arguments into CWE-79 sinks.
TEMPLATE_RENDERERS: frozenset[str] = frozenset(
    {
        "flask.render_template",
        "flask.render_template_string",
        "flask.templating.render_template",
        "django.shortcuts.render",
        "django.template.loader.render_to_string",
    }
)
TEMPLATE_RENDER_LEAVES: frozenset[str] = frozenset({"render_template", "render_template_string", "TemplateResponse"})
# Keyword spellings of a render call's template name, and of a context dictionary passed as one value.
TEMPLATE_NAME_KEYWORDS: frozenset[str] = frozenset({"template_name_or_list", "template_name", "template"})
TEMPLATE_CONTEXT_KEYWORDS: frozenset[str] = frozenset({"context", "dictionary"})
# Starlette's `Jinja2Templates.TemplateResponse(request=..., name="x.html", context={...})` (A-67): on
# that renderer only, `name` is the template and `context` may be a local dict. Elsewhere `name` stays
# a template variable, as in Flask's `render_template("x.html", name=v)`.
TEMPLATE_RESPONSE_LEAF = "TemplateResponse"
TEMPLATE_RESPONSE_NAME_KEYWORDS: frozenset[str] = frozenset({"name"})

# Response wrappers that are safe for CWE-79 (spec: the decoys), and the content types they imply.
SAFE_RESPONSES: frozenset[str] = frozenset(
    {
        "flask.jsonify",
        "flask.json.jsonify",
        "django.http.JsonResponse",
        "fastapi.responses.JSONResponse",
        "starlette.responses.JSONResponse",
        "fastapi.responses.PlainTextResponse",
        "starlette.responses.PlainTextResponse",
    }
)
SAFE_RESPONSE_LEAVES: frozenset[str] = frozenset({"jsonify", "JsonResponse", "JSONResponse", "PlainTextResponse"})
SAFE_CONTENT_TYPES: frozenset[str] = frozenset({"application/json", "text/plain"})
CONTENT_TYPE_KEYWORDS: tuple[str, ...] = ("mimetype", "content_type")

# Header mutation: `resp.headers["Location"] = tainted` / `resp.headers.add("Location", tainted)`.
HEADER_SETTERS: frozenset[str] = frozenset({"add", "set", "setdefault", "setlist", "add_header", "__setitem__"})
REDIRECT_HEADER = "location"

# How a value was built; the first kind present names the rule.
BUILT_PRIORITY: tuple[str, ...] = ("fstring", "concat", "percent", "format", "join")
FAMILIES_WITH_BUILT_IN_ID: frozenset[str] = frozenset({"sqli", "xss"})
# Rows whose rule id does not follow the `py.<family>[.<built kind>].<token>` shape: how the value
# was built says nothing about a template sink, the template's own escaping does (P2-A5).
FIXED_RULE_IDS: dict[tuple[str, str], str] = {("xss", "template"): "py.xss.template.unescaped"}

_BUILT_PHRASE: dict[str, str] = {
    "fstring": "through an f-string",
    "concat": "through string concatenation",
    "percent": "through % formatting",
    "format": "through .format()",
    "join": "through .join()",
    "tainted": "without escaping",
}
_TITLES: dict[tuple[str, str], str] = {
    ("sqli", "execute"): "SQL injection: request data reaches execute() {phrase}",
    ("cmdi", "shell"): "OS command injection: request data reaches a shell command",
    ("cmdi", "subprocess"): "OS command injection: request data reaches a subprocess call with shell=True",
    ("traversal", "open"): "Path traversal: request data reaches a file open() with no containment check",
    ("traversal", "path-access"): "Path traversal: request data reaches a file read/write with no containment check",
    ("traversal", "send-file"): "Path traversal: request data reaches a file response with no containment check",
    ("traversal", "listdir"): "Path traversal: request data reaches a directory listing with no containment check",
    ("redirect", "unvalidated"): "Open redirect: request data reaches redirect() without validation",
    ("redirect", "location-header"): "Open redirect: request data written to a Location header without validation",
    ("xss", "html-response"): "XSS: request data returned in an HTML response without escaping",
    ("xss", "markup"): "XSS: request data wrapped in a safe-HTML marker without escaping",
    ("xss", "template"): "XSS: request data rendered by a template without escaping",
    ("xss", "template-string"): "XSS: request data used as the template source of render_template_string() {phrase}",
}
# Wording the cross-team oracle fixes for a specific (family, token, built kind).
_SPECIAL_TITLES: dict[tuple[str, str, str], str] = {
    ("sqli", "execute", "concat"): "SQL injection: request data concatenated into SQL passed to execute()",
}
SUPPRESS_LIST_NO_SHELL = suppress.SAFE_SUBPROCESS_LIST_NO_SHELL
SUPPRESS_NO_SHELL = suppress.SAFE_SUBPROCESS_NO_SHELL
_SUPPRESSED_TITLES: dict[str, str] = {
    SUPPRESS_LIST_NO_SHELL: "Command execution with request data (list form, no shell)",
    SUPPRESS_NO_SHELL: "Command execution with request data (no shell)",
    suppress.SAFE_SQL_PARAMETERISED: "Parameterised SQL query with request data in bind parameters",
}


def sink_at(call: ast.Call, ctx: ModuleContext) -> Optional[SinkSpec]:
    """The sink row `call` matches, else None. Dotted name first, attribute leaf name second (A-08)."""
    resolved = ctx.resolve(call.func)
    if resolved is not None:
        for spec in SINKS:
            if resolved in spec.dotted:
                return spec
        if ctx.index.is_project_symbol(resolved):
            return None  # a project function, even one called `execute`, is a call and not a sink
    leaf = leaf_name(call.func)
    if leaf is None:
        return None
    for spec in SINKS:
        if leaf in spec.leaf_methods:
            return spec
    return None


def safe_response_at(call: ast.Call, ctx: ModuleContext) -> Optional[str]:
    """Name of the recognised safe response wrapper `call` is, else None (spec: the XSS decoys)."""
    resolved = ctx.resolve(call.func)
    leaf = leaf_name(call.func)
    if resolved in SAFE_RESPONSES or (leaf in SAFE_RESPONSE_LEAVES and not _is_project(resolved, ctx)):
        return leaf or resolved
    if resolved in HTML_RESPONSE.dotted or (leaf in HTML_RESPONSE.leaf_methods and not _is_project(resolved, ctx)):
        for name in CONTENT_TYPE_KEYWORDS:
            value = const_str(keyword(call, name))
            if is_safe_content_type(value):
                return f"{name}={value}"
    return None


def is_safe_content_type(text: Optional[str]) -> bool:
    """True for a constant content type that browsers do not render as HTML (`text/plain; charset=...`)."""
    return text is not None and text.split(";")[0].strip().lower() in SAFE_CONTENT_TYPES


def later_safe_content_type(stmts: list[ast.stmt], name: str) -> bool:
    """True when straight-line `stmts` set a safe content type on response `name` (DECISIONS A-38).

    Covers `resp = Response(...)` followed by `resp.mimetype = "application/json"`,
    `resp.content_type = ...` or `resp.headers["Content-Type"] = ...`. The last such write in the
    straight-line range decides, so a later override to `text/html` wins (A-53). Other plain
    assignments and expression statements are skipped; a reassignment of `name`, a return/raise or any
    compound statement ends the range (a write inside a branch may not run). Anything else that may
    change the type gives False: a call on `name.headers` (`resp.headers.set(...)`), a write to
    `name.headers` itself or to a computed header key, a compound statement that mentions the content
    type or headers of `name`, or a returned tuple with non-constant extras (`return resp, 200, hdrs`).
    """
    safe = False
    for stmt in stmts:
        if isinstance(stmt, ast.Expr):
            if _calls_headers(stmt, name):
                return False
            continue
        if not isinstance(stmt, (ast.Assign, ast.AnnAssign)):
            return safe and not _mentions_content_type(stmt, name) and not _returns_headers(stmt)
        if _calls_headers(stmt, name):
            return False
        targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
        for target in targets:
            if _rebinds(target, name):
                return safe
            if _is_attribute_of(target, name, ("headers",)) or _is_computed_header(target, name):
                return False
            if _is_attribute_of(target, name, CONTENT_TYPE_KEYWORDS) or _is_content_type_header(target, name):
                safe = is_safe_content_type(const_str(stmt.value))
    return safe


def _calls_headers(node: ast.AST, name: str) -> bool:
    """Some call in `node` is a method of `name.headers` (`resp.headers.set("Content-Type", ...)`)."""
    return any(
        isinstance(sub, ast.Call)
        and isinstance(sub.func, ast.Attribute)
        and _is_attribute_of(sub.func.value, name, ("headers",))
        for sub in ast.walk(node)
    )


def _mentions_content_type(node: ast.AST, name: str) -> bool:
    """`node` refers to `name.mimetype`, `name.content_type` or `name.headers` anywhere."""
    return any(_is_attribute_of(sub, name, (*CONTENT_TYPE_KEYWORDS, "headers")) for sub in ast.walk(node))


def _returns_headers(stmt: ast.stmt) -> bool:
    """`return resp, 200, headers`: a returned tuple whose extra items are not all constants may set headers."""
    if not (isinstance(stmt, ast.Return) and isinstance(stmt.value, ast.Tuple)):
        return False
    return any(not isinstance(item, ast.Constant) for item in stmt.value.elts[1:])


def _is_computed_header(target: ast.expr, name: str) -> bool:
    """`name.headers[key]` with a key that is not a string constant (it may be Content-Type)."""
    return (
        isinstance(target, ast.Subscript)
        and _is_attribute_of(target.value, name, ("headers",))
        and const_str(target.slice) is None
    )


def _rebinds(target: ast.expr, name: str) -> bool:
    """True when assignment target `target` stores to the bare name `name` (also inside a tuple)."""
    return any(
        isinstance(node, ast.Name) and node.id == name and isinstance(node.ctx, ast.Store) for node in ast.walk(target)
    )


def _is_attribute_of(target: ast.expr, name: str, attrs: tuple[str, ...]) -> bool:
    """`name.<attr>` for one of `attrs`."""
    return (
        isinstance(target, ast.Attribute)
        and target.attr in attrs
        and isinstance(target.value, ast.Name)
        and target.value.id == name
    )


def _is_content_type_header(target: ast.expr, name: str) -> bool:
    """`name.headers["Content-Type"]` (header names are case-insensitive)."""
    if not (isinstance(target, ast.Subscript) and _is_attribute_of(target.value, name, ("headers",))):
        return False
    key = const_str(target.slice)
    return key is not None and key.strip().lower() == "content-type"


def is_template_render(call: ast.Call, ctx: ModuleContext) -> bool:
    """True when `call` renders a template (a barrier here; P2-A5 adds the keyword-argument sink)."""
    resolved = ctx.resolve(call.func)
    if resolved in TEMPLATE_RENDERERS:
        return True
    leaf = leaf_name(call.func)
    return leaf in TEMPLATE_RENDER_LEAVES and not _is_project(resolved, ctx)


def template_name(call: ast.Call) -> Optional[str]:
    """The template literal a render call names, else None (a computed name is never guessed, A-02).

    The first constant string argument wins, which covers both `render_template("page.html", ...)`
    and Django's `render(request, "page.html", context)`. Starlette's `TemplateResponse` also accepts
    the template as `name=` (A-67).
    """
    for arg in call.args:
        text = const_str(arg)
        if text:
            return text
    for name in sorted(_name_keywords(call)):
        text = const_str(keyword(call, name))
        if text:
            return text
    return None


def template_context(
    call: ast.Call, local_value: Optional[Callable[[str], Optional[ast.expr]]] = None
) -> dict[str, ast.expr]:
    """Template variables a render call passes: keyword arguments plus constant context-dict keys.

    A `**ctx` splat counts when it is an inline dict literal, or a local name that `local_value`
    maps to a dict literal or a `dict(k=v, ...)` call (DECISIONS A-39); anything else is not guessed.
    For Starlette's `TemplateResponse` a `context=` keyword or a positional argument that is such a
    local dict counts the same way (A-67).
    """
    out: dict[str, ast.expr] = {}
    contexts: list[ast.Dict] = [arg for arg in call.args if isinstance(arg, ast.Dict)]
    response = is_template_response(call)
    if response:
        for arg in call.args:
            if isinstance(arg, ast.Name):
                _add_context(_local_dict(arg, local_value), contexts, out)
    name_keywords = _name_keywords(call)
    for word in call.keywords:
        if word.arg is None:
            _add_context(_local_dict(word.value, local_value), contexts, out)
            continue
        if word.arg in name_keywords:
            continue
        if word.arg in TEMPLATE_CONTEXT_KEYWORDS:
            if isinstance(word.value, ast.Dict):
                contexts.append(word.value)  # a context dictionary: its keys are the variables
                continue
            if response and _add_context(_local_dict(word.value, local_value), contexts, out):
                continue
        out[word.arg] = word.value
    for node in contexts:
        for key, value in zip(node.keys, node.values, strict=True):
            text = const_str(key) if key is not None else None
            if text:
                out.setdefault(text, value)
    return out


def is_template_response(call: ast.Call) -> bool:
    """`<templates>.TemplateResponse(...)`: Starlette's renderer, whose `name=` is the template (A-67)."""
    return leaf_name(call.func) == TEMPLATE_RESPONSE_LEAF


def _name_keywords(call: ast.Call) -> frozenset[str]:
    """Keyword spellings of the template name for this render call."""
    if is_template_response(call):
        return TEMPLATE_NAME_KEYWORDS | TEMPLATE_RESPONSE_NAME_KEYWORDS
    return TEMPLATE_NAME_KEYWORDS


def _local_dict(
    value: Optional[ast.expr], local_value: Optional[Callable[[str], Optional[ast.expr]]]
) -> Optional[ast.expr]:
    """`value`, or the single assigned value of local name `value` (None when it cannot be known)."""
    if isinstance(value, ast.Name):
        return local_value(value.id) if local_value is not None else None
    return value


def _add_context(node: Optional[ast.expr], contexts: list[ast.Dict], out: dict[str, ast.expr]) -> bool:
    """Record a dict literal or `dict(k=v, ...)` call as template context; False for anything else."""
    if isinstance(node, ast.Dict):
        contexts.append(node)
        return True
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "dict":
        for kw in node.keywords:
            if kw.arg is not None:
                out.setdefault(kw.arg, kw.value)
        return True
    return False


def shell_true(call: ast.Call) -> bool:
    """True when the call passes a truthy literal `shell=`."""
    value = keyword(call, "shell")
    return isinstance(value, ast.Constant) and bool(value.value)


def is_sequence_argument(value: Optional[ast.expr]) -> bool:
    """True when the command argument is a list/tuple/set literal (the safe `subprocess` form)."""
    return isinstance(value, (ast.List, ast.Tuple, ast.Set))


def argument_node(call: ast.Call, spec: SinkSpec) -> Optional[ast.expr]:
    """The AST node of the argument `spec` cares about (None when the call does not pass it)."""
    if spec.arg_index == RECEIVER:
        return call.func.value if isinstance(call.func, ast.Attribute) else None
    if 0 <= spec.arg_index < len(call.args):
        node = call.args[spec.arg_index]
        return None if isinstance(node, ast.Starred) else node
    for name in sorted(spec.arg_keywords):
        found = keyword(call, name)
        if found is not None:
            return found
    return None


def is_redirect_header(expr: ast.expr) -> bool:
    """True for a `...headers` attribute chain (the manual `Location` header sink)."""
    parts = dotted_parts(expr)
    return bool(parts) and parts[-1] == "headers"


def is_redirect_header_key(node: Optional[ast.expr]) -> bool:
    key = const_str(node)
    return key is not None and key.strip().lower() == REDIRECT_HEADER


def leaf_name(expr: ast.expr) -> Optional[str]:
    """`a.b.c` -> "c", `f` -> "f", anything else -> None."""
    if isinstance(expr, ast.Attribute):
        return expr.attr
    if isinstance(expr, ast.Name):
        return expr.id
    return None


def built_kind(built: frozenset[str]) -> str:
    """The highest-priority string-building kind in `built`, or "tainted" when nothing built it."""
    for kind in BUILT_PRIORITY:
        if kind in built:
            return kind
    return "tainted"


def rule_id(family: str, token: str, built: frozenset[str]) -> str:
    """Stable rule id, e.g. "py.sqli.fstring.execute", "py.cmdi.subprocess", "py.xss.template.unescaped"."""
    fixed = FIXED_RULE_IDS.get((family, token))
    if fixed is not None:
        return fixed
    if family in FAMILIES_WITH_BUILT_IN_ID:
        return f"py.{family}.{built_kind(built)}.{token}"
    return f"py.{family}.{token}"


def sink_title(family: str, token: str, built: frozenset[str], suppress_reason: Optional[str] = None) -> str:
    """One-line human title for a finding, following the cross-team oracle wording."""
    if suppress_reason in _SUPPRESSED_TITLES:
        return _SUPPRESSED_TITLES[suppress_reason]
    title = _base_title(family, token, built)
    if suppress_reason is not None and suppress_reason.startswith(suppress.SANITIZED_PREFIX):
        names = suppress_reason[len(suppress.SANITIZED_PREFIX) :].replace("+", ", ")
        return f"{title} (sanitised: {names})"
    return title


def _base_title(family: str, token: str, built: frozenset[str]) -> str:
    kind = built_kind(built)
    special = _SPECIAL_TITLES.get((family, token, kind))
    if special is not None:
        return special
    template = _TITLES.get((family, token))
    if template is None:
        return f"Tainted data reaches a {family} sink"
    return template.format(phrase=_BUILT_PHRASE[kind])


def _is_project(resolved: Optional[str], ctx: ModuleContext) -> bool:
    return resolved is not None and ctx.index.is_project_symbol(resolved)
