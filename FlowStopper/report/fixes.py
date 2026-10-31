"""Plain-English fix templates keyed by CweEntry.fix_key (Owner: B, P5-B3, bonus B-4).

`fix_for(issue)` returns one deterministic suggestion with three parts:

    What is wrong: <one sentence naming the function/file/endpoint and parameter>

    Minimal fix:
    ```python
    <one short code example for the pattern>
    ```

    Prevention: <one tip>

Templates are per CWE family (cwe.CweEntry.fix_key), with per-CWE wording where a family covers
different problems (cookie flags, headers, verbose errors, information exposure). Everything is
filled from the issue itself; nothing here is specific to a scanned app (R6). No network.
The correlator sets `Issue.fix` with this (B-25); the reports render the ``` fence as code.
"""

from __future__ import annotations

import builtins
import keyword
import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Optional

from FlowStopper import cwe as cwe_mod
from FlowStopper.models import Issue

_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
# Names a code example must not use as its variable: builtins, and names the examples already use.
_RESERVED = frozenset(dir(builtins)) | {"base", "target", "parts", "html", "cur", "subprocess", "escape", "os"}


@dataclass(frozen=True)
class Context:
    """What a template may mention about the issue."""

    cwe: int
    where: str  # "find_items in services/store.py:9", "GET /x", "this host"
    param: Optional[str]
    var: str  # a Python identifier for the code example
    file: Optional[str]
    secret_name: str


@dataclass(frozen=True)
class Fix:
    what: str
    code: str
    tip: str
    lang: str = "python"  # code fence language


# --------------------------------------------------------------------------- context
def _param(issue: Issue) -> Optional[str]:
    for f in issue.code_findings:
        if f.taint is not None and f.taint.source_param:
            return f.taint.source_param
    if issue.primary_runtime is not None and issue.primary_runtime.param:
        return issue.primary_runtime.param
    return None


def _where(issue: Issue) -> str:
    loc = issue.primary_code
    if loc is not None:
        at = f"{loc.file}:{loc.line_start}"
        return f"{loc.function} ({at})" if loc.function else at
    rt = issue.primary_runtime
    if rt is not None and rt.route_id:
        return rt.route_id
    if rt is not None and rt.param:
        return f"{rt.method} {rt.path}"
    return "this host"


def _secret_name(issue: Issue) -> str:
    for f in issue.code_findings:
        name = f.raw.get("name") if isinstance(f.raw, dict) else None
        if isinstance(name, str) and _IDENT.match(name):
            return name
    m = re.search(r"\(([A-Za-z_][A-Za-z0-9_]*)\)\s*$", issue.title or "")
    return m.group(1) if m else "SECRET_VALUE"


def context_for(issue: Issue) -> Context:
    param = _param(issue)
    usable = bool(param and _IDENT.match(param) and not keyword.iskeyword(param) and param not in _RESERVED)
    var = param if usable else "value"
    return Context(
        cwe=issue.cwe,
        where=_where(issue),
        param=param,
        var=var,
        file=issue.primary_code.file if issue.primary_code else None,
        secret_name=_secret_name(issue),
    )


def _p(ctx: Context) -> str:
    return f"the request parameter '{ctx.param}'" if ctx.param else "request data"


# --------------------------------------------------------------------------- templates
def _sqli(ctx: Context) -> Fix:
    return Fix(
        f"{ctx.where} puts {_p(ctx)} into an SQL statement instead of binding it as a parameter, so the "
        "input can change the query itself.",
        "# bind the value as a parameter; never put it inside the SQL text\n"
        f'cur.execute("SELECT * FROM table_name WHERE column_name = ?", ({ctx.var},))',
        "Use parameterised queries or an ORM everywhere, and never build SQL with f-strings, % or +.",
    )


def _cmdi(ctx: Context) -> Fix:
    return Fix(
        f"{ctx.where} passes {_p(ctx)} to a shell, so characters such as ; | or $( ) run extra commands.",
        "import subprocess\n"
        "# argument list, no shell: the value is one argument, never parsed by a shell\n"
        f'subprocess.run(["program", "--option", {ctx.var}], shell=False, check=True, timeout=10)\n'
        "# if a shell string is unavoidable: shlex.quote(value)",
        "Call programs with an argument list and shell=False, and check the value against an allow-list "
        "(for example a strict regex) first.",
    )


def _xss(ctx: Context) -> Fix:
    return Fix(
        f"{ctx.where} writes {_p(ctx)} into HTML without escaping, so a script in the input runs in the "
        "victim's browser.",
        "from markupsafe import escape\n"
        f'html = f"<p>{{escape({ctx.var})}}</p>"\n'
        "# better: render a template with autoescape on, and never apply |safe to user input",
        "Produce HTML only through autoescaping templates; never build markup from user input by string formatting.",
    )


def _traversal(ctx: Context) -> Fix:
    return Fix(
        f"{ctx.where} opens a file path built from {_p(ctx)}, so ../ sequences or absolute paths can read "
        "files outside the intended folder.",
        "from pathlib import Path\n"
        "from werkzeug.utils import secure_filename\n"
        "base = Path(BASE_DIR).resolve()\n"
        f"target = (base / secure_filename({ctx.var})).resolve()\n"
        "if not target.is_relative_to(base):\n"
        "    abort(404)",
        "Resolve every user-supplied path against a fixed base directory and reject anything outside it; "
        "prefer ids that map to files over raw file names.",
    )


def _redirect(ctx: Context) -> Fix:
    return Fix(
        f"{ctx.where} redirects to the address in {_p(ctx)} without checking it, so a link on a trusted "
        "site can send users to an attacker's site.",
        "from urllib.parse import urlparse\n"
        f'target = {ctx.var} or "/"\n'
        "parts = urlparse(target)\n"
        'if parts.scheme or parts.netloc or target.startswith(("//", "\\\\")):\n'
        '    target = "/"  # only same-site relative paths\n'
        "return redirect(target)",
        "Redirect only to relative paths or to hosts on an explicit allow-list.",
    )


def _secret(ctx: Context) -> Fix:
    name = ctx.secret_name
    where = ctx.file or ctx.where
    return Fix(
        f"{where} contains a hard-coded credential ({name}), so anyone who can read the source can use it.",
        f'import os\n{name} = os.environ["{name}"]  # set it in the environment or a secret manager',
        "Keep secrets out of source control, rotate the exposed value now, and run a secret scanner in CI.",
    )


_HEADER_FIX = {
    1021: (
        "Pages can be framed by another site (no X-Frame-Options or CSP frame-ancestors), which enables clickjacking.",
        'resp.headers.setdefault("X-Frame-Options", "DENY")\n'
        'resp.headers.setdefault("Content-Security-Policy", "frame-ancestors \'none\'")',
    ),
}


def _headers(ctx: Context, title: str) -> Fix:
    what, lines = _HEADER_FIX.get(
        ctx.cwe,
        (
            f"Responses miss a browser security header ({_strip_host_wide(title)}), so the browser does not "
            "apply that protection.",
            'resp.headers.setdefault("X-Content-Type-Options", "nosniff")\n'
            'resp.headers.setdefault("Content-Security-Policy", "default-src \'self\'")\n'
            'resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")',
        ),
    )
    return Fix(
        what,
        "@app.after_request\ndef add_security_headers(resp):\n"
        + "\n".join(f"    {line}" for line in lines.split("\n"))
        + "\n    return resp",
        "Set security headers once, in middleware or the reverse proxy, so every response gets them.",
    )


_COOKIE_WHAT = {
    1004: "A cookie is set without HttpOnly, so any script on the page (for example via XSS) can read it.",
    614: "A cookie is set without Secure, so it can be sent over plain HTTP and intercepted.",
    1275: "A cookie is set without a SameSite attribute, so other sites can make the browser send it (CSRF).",
}


def _cookies(ctx: Context, title: str) -> Fix:
    return Fix(
        _COOKIE_WHAT.get(ctx.cwe, f"A cookie is missing a security flag ({_strip_host_wide(title)})."),
        'resp.set_cookie("name", value, httponly=True, secure=True, samesite="Lax")\n'
        "# framework session cookie, e.g. Flask:\n"
        'app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SECURE=True, SESSION_COOKIE_SAMESITE="Lax")',
        "Set HttpOnly, Secure and SameSite on every cookie by default, and serve the site only over HTTPS.",
    )


def _cors(ctx: Context, title: str) -> Fix:
    return Fix(
        "The CORS policy accepts any origin (wildcard or reflected), so other sites can read responses from this one.",
        'ALLOWED_ORIGINS = {"https://app.example.com"}\n'
        'origin = request.headers.get("Origin")\n'
        "if origin in ALLOWED_ORIGINS:\n"
        '    resp.headers["Access-Control-Allow-Origin"] = origin\n'
        '    resp.headers["Vary"] = "Origin"',
        "Keep an explicit origin allow-list, and never combine a reflected or * origin with credentials.",
    )


_VERBOSE_WHAT = {
    209: "Error responses show stack traces or internal details that help an attacker map the application.",
    489: "The framework's debug mode is on; its interactive console can run code on the server.",
    215: "Debug output exposes internal details to anyone who triggers it.",
}


def _verbose(ctx: Context, title: str) -> Fix:
    return Fix(
        _VERBOSE_WHAT.get(ctx.cwe, f"{_strip_host_wide(title)}."),
        "app.run(debug=False)  # and leave FLASK_DEBUG / DEBUG unset in production\n\n"
        "@app.errorhandler(Exception)\ndef handle_error(exc):\n"
        '    app.logger.exception("unhandled error")\n'
        '    return {"error": "internal error"}, 500',
        "Never deploy with debug mode on; log details on the server and return a generic error to clients.",
    )


_INFO = {
    497: (
        "Response headers reveal the server software and version, which helps an attacker pick exploits.",
        "@app.after_request\ndef hide_version(resp):\n"
        '    resp.headers.pop("X-Powered-By", None)\n'
        '    resp.headers["Server"] = "server"\n'
        "    return resp\n"
        "# reverse proxy: server_tokens off; (nginx) / ServerTokens Prod (Apache)",
        "Strip version banners at the reverse proxy and keep the software patched.",
    ),
    538: (
        "A sensitive file (such as repository metadata or an environment file) is served to anyone.",
        "# reverse proxy (nginx): refuse dotfiles\n"
        "location ~ /\\. { deny all; }\n"
        "# and deploy only the build output, not the repository",
        "Deploy only what the application needs to run, and block dotfiles at the web server.",
    ),
}
_INFO_LANG = {538: "nginx"}


def _info(ctx: Context, title: str) -> Fix:
    what, code, tip = _INFO.get(
        ctx.cwe,
        (
            f"The application exposes information it does not need to ({_strip_host_wide(title)}).",
            '# return only the fields the client needs\nreturn {"status": "ok"}',
            "Review responses for internal data and return the minimum.",
        ),
    )
    return Fix(what, code, tip, _INFO_LANG.get(ctx.cwe, "python"))


def _listing(ctx: Context, title: str) -> Fix:
    return Fix(
        "The web server lists directory contents, so files that were never linked can be found and downloaded.",
        "# nginx\nautoindex off;\n# Apache\nOptions -Indexes",
        "Turn directory listing off globally and serve static files only from a dedicated folder.",
        "nginx",
    )


def _generic(ctx: Context, title: str) -> Fix:
    entry = cwe_mod.CATALOGUE.get(ctx.cwe)
    name = entry.name if entry else f"CWE-{ctx.cwe}"
    return Fix(
        f"{ctx.where} has a {name} weakness ({_strip_host_wide(title)}).",
        f"# see https://cwe.mitre.org/data/definitions/{ctx.cwe}.html for the recommended mitigation",
        "Validate input at the trust boundary and apply the framework's safe API for this operation.",
    )


def _strip_host_wide(title: str) -> str:
    return re.sub(r"\s*\(host-wide\)\s*$", "", title or "").strip() or "see the evidence"


_CODE_TEMPLATES: dict[str, Callable[[Context], Fix]] = {
    "sqli": _sqli,
    "cmdi": _cmdi,
    "xss": _xss,
    "path_traversal": _traversal,
    "open_redirect": _redirect,
    "hardcoded_secret": _secret,
}
_RUNTIME_TEMPLATES: dict[str, Callable[[Context, str], Fix]] = {
    "security_headers": _headers,
    "cookie_flags": _cookies,
    "cors": _cors,
    "verbose_errors": _verbose,
    "info_exposure": _info,
    "directory_listing": _listing,
}


def fix_parts(issue: Issue) -> Fix:
    """The (what, code, tip) suggestion for an issue."""
    ctx = context_for(issue)
    entry = cwe_mod.CATALOGUE.get(issue.cwe)
    key = entry.fix_key if entry else ""
    if key in _CODE_TEMPLATES:
        return _CODE_TEMPLATES[key](ctx)
    title = issue.runtime_findings[0].title if issue.runtime_findings else issue.title
    return _RUNTIME_TEMPLATES.get(key, _generic)(ctx, title)


def render_fix(fix: Fix) -> str:
    return f"What is wrong: {fix.what}\n\nMinimal fix:\n```{fix.lang}\n{fix.code}\n```\n\nPrevention: {fix.tip}"


def fix_for(issue: Issue) -> str:
    """Plain-English, deterministic fix suggestion for `issue` (what is wrong, minimal fix, prevention)."""
    return render_fix(fix_parts(issue))
