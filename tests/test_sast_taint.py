"""P2-A1..A3 taint analysis: source/sink/sanitiser tables, the engine and the summaries (Owner: A)."""

from __future__ import annotations

import ast
import logging

from FlowStopper.models import ParamLocation, Route, RouteParam
from FlowStopper.sast.callgraph import annotate_reachable, build_call_graph
from FlowStopper.sast.config import SastConfig
from FlowStopper.sast.index import build_index
from FlowStopper.sast.routes import extract_routes
from FlowStopper.sast.taint import sinks
from FlowStopper.sast.taint.sanitizers import ALL_CWES, guard_clearance, sanitizer_at
from FlowStopper.sast.taint.sinks import argument_node, safe_response_at, sink_at
from FlowStopper.sast.taint.sources import handler_param_sources, request_source
from FlowStopper.sast.taint.summaries import TaintFinding, analyse_taint, compute_summaries
from tests.sast_helpers import make_tree

FLASK_HEADER = "from flask import request"
DJANGO_HEADER = "from django.http import HttpResponse"


# --------------------------------------------------------------------------- helpers
def _exprs(tmp_path, header: str, expressions: list[str], *, params: str = "", name: str = "t"):
    """Parse `expressions` as the right-hand sides of one function's assignments.

    Returns `(ctx, nodes)` where `nodes[i]` is the AST of `expressions[i]`.
    """
    body = "\n".join(f"    v{index} = {expr}" for index, expr in enumerate(expressions))
    source = f"{header}\n\n\ndef probe({params}):\n{body}\n"
    index = build_index(make_tree(tmp_path / name, {"m.py": source}))
    fn = index.functions["m.probe"]
    ctx = index.context("m", fn)
    nodes = [stmt.value for stmt in fn.node.body if isinstance(stmt, ast.Assign)]
    assert len(nodes) == len(expressions)
    return ctx, nodes


def _findings(tmp_path, files: dict[str, str], *, name: str = "app", config=None) -> list[TaintFinding]:
    """Run the whole taint driver over a synthetic project."""
    index = build_index(make_tree(tmp_path / name, files), config)
    graph = build_call_graph(index, config)
    routes = _routes(index, graph, config)
    return analyse_taint(index, routes, graph, None, config)


def _routes(index, graph, config=None) -> list[Route]:
    return annotate_reachable(index, extract_routes(index), config, graph=graph)


def _by_cwe(findings: list[TaintFinding], cwe: int) -> list[TaintFinding]:
    return [f for f in findings if f.cwe == cwe]


def _live(findings: list[TaintFinding]) -> list[TaintFinding]:
    """Reported findings only: P4-A2 keeps sanitised/safe flows as suppressed findings (A-47)."""
    return [f for f in findings if not f.suppressed]


def _suppressed(findings: list[TaintFinding]) -> list[tuple]:
    return [(f.function, f.cwe, f.suppress_reason) for f in findings if f.suppressed]


# --------------------------------------------------------------------------- P2-A3 sources
FLASK_SOURCES: dict[str, tuple[str | None, ParamLocation, bool]] = {
    'request.args.get("q")': ("q", ParamLocation.QUERY, False),
    'request.args["q"]': ("q", ParamLocation.QUERY, False),
    'request.args.getlist("q")': ("q", ParamLocation.QUERY, False),
    "request.args": (None, ParamLocation.QUERY, True),
    "request.args.to_dict()": (None, ParamLocation.QUERY, True),
    'request.values.get("q")': ("q", ParamLocation.QUERY, False),
    'request.form.get("user")': ("user", ParamLocation.FORM, False),
    'request.form["user"]': ("user", ParamLocation.FORM, False),
    'request.files["upload"]': ("upload", ParamLocation.FORM, False),
    'request.cookies.get("sid")': ("sid", ParamLocation.COOKIE, False),
    'request.headers.get("X-Real-IP")': ("X-Real-IP", ParamLocation.HEADER, False),
    'request.view_args["id"]': ("id", ParamLocation.PATH, False),
    'request.json["id"]': ("id", ParamLocation.JSON, False),
    "request.get_json()": (None, ParamLocation.JSON, True),
    'request.get_json().get("id")': ("id", ParamLocation.JSON, False),
    "request.data": (None, ParamLocation.JSON, True),
}

DJANGO_SOURCES: dict[str, tuple[str | None, ParamLocation, bool]] = {
    'request.GET.get("q")': ("q", ParamLocation.QUERY, False),
    'request.GET["q"]': ("q", ParamLocation.QUERY, False),
    'request.POST.get("user")': ("user", ParamLocation.FORM, False),
    "request.POST": (None, ParamLocation.FORM, True),
    "request.body": (None, ParamLocation.JSON, True),
    'request.COOKIES.get("sid")': ("sid", ParamLocation.COOKIE, False),
    'request.META.get("HTTP_X_REAL_IP")': ("HTTP_X_REAL_IP", ParamLocation.HEADER, False),
    'request.FILES["upload"]': ("upload", ParamLocation.FORM, False),
}


def test_flask_request_sources(tmp_path):
    ctx, nodes = _exprs(tmp_path, FLASK_HEADER, list(FLASK_SOURCES))
    for node, (expr, expected) in zip(nodes, FLASK_SOURCES.items(), strict=True):
        ref = request_source(node, ctx)
        assert ref is not None, f"not recognised: {expr}"
        assert (ref.param_name, ref.location_kind, ref.is_container) == expected, expr


def test_django_request_sources(tmp_path):
    """Django handlers take `request` as a parameter, so the receiver never resolves (A-08 fallback)."""
    ctx, nodes = _exprs(tmp_path, DJANGO_HEADER, list(DJANGO_SOURCES), params="request")
    for node, (expr, expected) in zip(nodes, DJANGO_SOURCES.items(), strict=True):
        ref = request_source(node, ctx)
        assert ref is not None, f"not recognised: {expr}"
        assert (ref.param_name, ref.location_kind, ref.is_container) == expected, expr


def test_non_request_expressions_are_not_sources(tmp_path):
    ctx, nodes = _exprs(tmp_path, "import os", ['os.environ.get("HOME")', 'data["id"]', '"literal"'], params="data")
    assert [request_source(node, ctx) for node in nodes] == [None, None, None]


def test_handler_param_sources_come_from_route_params(tmp_path):
    files = {
        "app.py": """
            from flask import Flask

            app = Flask(__name__)


            @app.route("/docs/<path:name>")
            def docs(name, unused=None):
                return name
        """
    }
    index = build_index(make_tree(tmp_path / "app", files))
    fn = index.functions["app.docs"]
    route = Route(
        id="GET /docs/<path:name>",
        method="GET",
        path_template="/docs/<path:name>",
        path_regex="^/docs/(?P<name>.+)/?$",
        handler=fn.qualname,
        file=fn.file,
        line_start=fn.line_start,
        line_end=fn.line_end,
        params=[RouteParam(name="name", location=ParamLocation.PATH, required=True)],
    )
    sources = handler_param_sources(fn, route)
    assert set(sources) == {"name"}
    assert sources["name"].location_kind is ParamLocation.PATH
    assert sources["name"].is_container is False


# --------------------------------------------------------------------------- P2-A3 sinks
SINK_HEADER = """
import os
import subprocess
from pathlib import Path
from django.http import HttpResponseRedirect
from django.utils.safestring import mark_safe
from flask import make_response, redirect, send_file
from markupsafe import Markup
from sqlalchemy import text
""".strip()

# expression -> (cwe, token, source of the argument that matters)
SINK_CASES: dict[str, tuple[int, str, str]] = {
    "conn.execute(q)": (89, "execute", "q"),
    "conn.executemany(q, rows)": (89, "execute", "q"),
    "conn.executescript(q)": (89, "execute", "q"),
    "Model.objects.raw(q)": (89, "execute", "q"),
    "text(q)": (89, "execute", "q"),
    "os.system(cmd)": (78, "shell", "cmd"),
    "os.popen(cmd)": (78, "shell", "cmd"),
    "subprocess.run(cmd, shell=True)": (78, "subprocess", "cmd"),
    "subprocess.check_output(cmd, shell=True)": (78, "subprocess", "cmd"),
    "subprocess.Popen(cmd, shell=True)": (78, "subprocess", "cmd"),
    "open(path)": (22, "open", "path"),
    'open(file=path, mode="rb")': (22, "open", "path"),
    "Path(path).read_text()": (22, "path-access", "Path(path)"),
    "send_file(path)": (22, "send-file", "path"),
    "os.listdir(path)": (22, "listdir", "path"),
    "redirect(target)": (601, "unvalidated", "target"),
    "HttpResponseRedirect(target)": (601, "unvalidated", "target"),
    "make_response(body)": (79, "html-response", "body"),
    "Markup(body)": (79, "markup", "body"),
    "mark_safe(body)": (79, "markup", "body"),
}


def test_every_sink_row_matches_with_the_right_argument(tmp_path):
    params = "conn, q, rows, cmd, path, target, body, Model"
    ctx, nodes = _exprs(tmp_path, SINK_HEADER, list(SINK_CASES), params=params)
    for node, (expr, (cwe, token, argument)) in zip(nodes, SINK_CASES.items(), strict=True):
        spec = sink_at(node, ctx)
        assert spec is not None, f"not recognised as a sink: {expr}"
        assert (spec.cwe, spec.token) == (cwe, token), expr
        assert ast.unparse(argument_node(node, spec)) == argument, expr
        assert spec.result_barrier is True, expr  # A-09


def test_project_function_named_execute_is_not_a_sink(tmp_path):
    files = {
        "m.py": """
            def execute(sql):
                return sql


            def caller(sql):
                return execute(sql)
        """
    }
    index = build_index(make_tree(tmp_path / "app", files))
    fn = index.functions["m.caller"]
    ctx = index.context("m", fn)
    call = next(node for node in ast.walk(fn.node) if isinstance(node, ast.Call))
    assert sink_at(call, ctx) is None


def test_shell_form_and_sequence_argument(tmp_path):
    expressions = [
        "subprocess.run(cmd, shell=True)",
        'subprocess.run(["ping", host], shell=False)',
        "subprocess.run([prog, host])",
    ]
    ctx, nodes = _exprs(tmp_path, "import subprocess", expressions, params="cmd, host, prog")
    assert [sinks.shell_true(node) for node in nodes] == [True, False, False]
    arguments = [argument_node(node, sinks.SUBPROCESS) for node in nodes]
    assert [sinks.is_sequence_argument(arg) for arg in arguments] == [False, True, True]


def test_safe_response_wrappers(tmp_path):
    header = "from flask import jsonify, make_response\nfrom fastapi.responses import JSONResponse"
    expressions = [
        "jsonify({})",
        "JSONResponse({})",
        'make_response(body, mimetype="application/json")',
        'make_response(body, content_type="text/plain; charset=utf-8")',
        'make_response(body, mimetype="text/html")',
    ]
    ctx, nodes = _exprs(tmp_path, header, expressions, params="body")
    matched = [safe_response_at(node, ctx) is not None for node in nodes]
    assert matched == [True, True, True, True, False]


# --------------------------------------------------------------------------- P2-A3 sanitisers
SANITIZER_HEADER = """
import bleach
import html
import os
import shlex
import uuid
from flask import url_for
from werkzeug.utils import safe_join, secure_filename
""".strip()

SANITIZER_CASES: dict[str, tuple[str, frozenset[int]]] = {
    "int(v)": ("builtins.int", ALL_CWES),
    "float(v)": ("builtins.float", ALL_CWES),
    "bool(v)": ("builtins.bool", ALL_CWES),
    "uuid.UUID(v)": ("uuid.UUID", ALL_CWES),
    "html.escape(v)": ("html.escape", frozenset({79})),
    "bleach.clean(v)": ("bleach.clean", frozenset({79})),
    "shlex.quote(v)": ("shlex.quote", frozenset({78})),
    "secure_filename(v)": ("werkzeug.utils.secure_filename", frozenset({22})),
    "os.path.basename(v)": ("os.path.basename", frozenset({22})),
    "safe_join(base, v)": ("werkzeug.utils.safe_join", frozenset({22})),
    "url_for(v)": ("flask.url_for", frozenset({601})),
}


def test_sanitizers_clear_the_cwes_the_spec_gives_them(tmp_path):
    ctx, nodes = _exprs(tmp_path, SANITIZER_HEADER, list(SANITIZER_CASES), params="v, base")
    for node, (expr, (name, cwes)) in zip(nodes, SANITIZER_CASES.items(), strict=True):
        found = sanitizer_at(node, ctx)
        assert found is not None, f"not recognised as a sanitiser: {expr}"
        assert (found.name, found.cwes) == (name, cwes), expr


def test_unknown_call_is_not_a_sanitiser(tmp_path):
    ctx, nodes = _exprs(tmp_path, "import os", ["os.fspath(v)"], params="v")
    assert sanitizer_at(nodes[0], ctx) is None


# --------------------------------------------------------------------------- P2-A3 guards
GUARD_HEADER = """
import os
import re
from pathlib import Path
from urllib.parse import urlparse
from django.utils.http import url_has_allowed_host_and_scheme

ALLOWED = {"a.example", "b.example"}
BASE = "/srv/data"
""".strip()

# expression -> (guard label, cleared CWEs, names the guard must constrain)
GUARD_CASES: dict[str, tuple[str, frozenset[int], set[str]]] = {
    "name in ALLOWED": ("allow-list", ALL_CWES, {"name"}),
    'name in ("a", "b")': ("allow-list", ALL_CWES, {"name"}),
    "urlparse(target).netloc in ALLOWED": ("same-host-allow-list", ALL_CWES, {"target"}),
    'urlparse(target).netloc == ""': ("same-site", frozenset({601}), {"target"}),
    "url_has_allowed_host_and_scheme(target, ALLOWED)": ("same-host-check", frozenset({601}), {"target"}),
    "os.path.realpath(path).startswith(BASE)": ("path-containment", frozenset({22}), {"path"}),
    "os.path.commonpath([BASE, path]) == BASE": ("commonpath", frozenset({22}), {"path"}),
    "Path(path).resolve().is_relative_to(BASE)": ("path-containment", frozenset({22}), {"path"}),
    "value.isdigit()": ("isdigit-check", ALL_CWES, {"value"}),
    "value.isalnum()": ("isalnum-check", ALL_CWES, {"value"}),
    're.fullmatch("[a-z]+", value)': ("regex-fullmatch", ALL_CWES, {"value"}),
}


def test_guard_patterns_clear_their_cwes(tmp_path):
    ctx, nodes = _exprs(tmp_path, GUARD_HEADER, list(GUARD_CASES), params="name, target, path, value")
    for node, (expr, (label, cwes, names)) in zip(nodes, GUARD_CASES.items(), strict=True):
        matches = guard_clearance(node, ctx)
        assert len(matches) == 1, f"expected one guard for {expr}, got {matches}"
        match = matches[0]
        assert (match.label, match.cwes) == (label, cwes), expr
        assert names <= match.names, expr


def test_guards_hold_only_under_the_truth_value_that_constrains_the_value(tmp_path):
    expressions = ["name in ALLOWED", "name not in ALLOWED", "not value.isdigit()", "name and name not in ALLOWED"]
    ctx, nodes = _exprs(tmp_path, GUARD_HEADER, expressions, params="name, value")
    positive = [bool(guard_clearance(node, ctx)) for node in nodes]
    negated = [bool(guard_clearance(node, ctx, negated=True)) for node in nodes]
    assert positive == [True, False, False, False]
    assert negated == [False, True, True, True]  # the `if not guard: return` fall-through (A-11)


def test_allow_list_must_be_a_constant(tmp_path):
    header = "ALLOWED = {'a'}\nALLOWED = load()\nDYNAMIC = load()"
    ctx, nodes = _exprs(tmp_path, header, ["name in ALLOWED", "name in DYNAMIC"], params="name")
    assert [guard_clearance(node, ctx) for node in nodes] == [[], []]


# --------------------------------------------------------------------------- P2-A1 engine
PROPAGATION = {
    "app.py": '''
        """Every string-building form the spec lists, each reaching one SQL sink."""

        import sqlite3

        from flask import Flask, request

        app = Flask(__name__)


        def db():
            return sqlite3.connect("shop.db")


        @app.route("/fstring")
        def fstring():
            q = request.args.get("q", "")
            db().execute(f"SELECT {q}")
            return "ok"


        @app.route("/concat")
        def concat():
            q = request.args.get("q", "")
            db().execute("SELECT " + q)
            return "ok"


        @app.route("/percent")
        def percent():
            q = request.args.get("q", "")
            db().execute("SELECT %s" % q)
            return "ok"


        @app.route("/formatted")
        def formatted():
            q = request.args.get("q", "")
            db().execute("SELECT {}".format(q))
            return "ok"


        @app.route("/joined")
        def joined():
            parts = ["SELECT ", request.args.get("q", "")]
            db().execute("".join(parts))
            return "ok"


        @app.route("/sliced")
        def sliced():
            q = request.args.get("q", "")
            db().execute("SELECT " + q[:10])
            return "ok"


        @app.route("/casts")
        def casts():
            q = request.args.get("q", "")
            db().execute("SELECT " + str(q).strip().lower().replace("x", "y"))
            return "ok"


        @app.route("/unpacked")
        def unpacked():
            first, second = request.args.get("a", ""), request.args.get("b", "")
            db().execute("SELECT " + first)
            return "ok"


        @app.route("/augmented")
        def augmented():
            sql = "SELECT "
            sql += request.args.get("q", "")
            db().execute(sql)
            return "ok"


        @app.route("/comprehension")
        def comprehension():
            values = [value for value in request.args.getlist("v")]
            db().execute("".join(values))
            return "ok"
    ''',
}


def test_every_propagation_form_reaches_the_sink(tmp_path):
    findings = _findings(tmp_path, PROPAGATION)
    assert {(f.function, f.rule_id) for f in findings} == {
        ("app.fstring", "py.sqli.fstring.execute"),
        ("app.concat", "py.sqli.concat.execute"),
        ("app.percent", "py.sqli.percent.execute"),
        ("app.formatted", "py.sqli.format.execute"),
        ("app.joined", "py.sqli.join.execute"),
        ("app.sliced", "py.sqli.concat.execute"),
        ("app.casts", "py.sqli.concat.execute"),
        ("app.unpacked", "py.sqli.concat.execute"),
        ("app.augmented", "py.sqli.concat.execute"),
        ("app.comprehension", "py.sqli.join.execute"),
    }
    assert all(f.cwe == 89 and f.confidence == 0.9 for f in findings)
    assert [f.taint.source_param for f in findings if f.function == "app.unpacked"] == ["a"]


def test_container_source_refines_on_member_access(tmp_path):
    files = {
        "app.py": """
            import sqlite3

            from flask import Flask, request

            app = Flask(__name__)


            @app.route("/refined")
            def refined():
                body = request.get_json()
                conn = sqlite3.connect("shop.db")
                conn.execute("SELECT " + body["order"])
                return "ok"


            @app.route("/whole")
            def whole():
                body = request.args.to_dict()
                conn = sqlite3.connect("shop.db")
                conn.execute("SELECT " + str(body))
                return "ok"
        """
    }
    findings = _findings(tmp_path, files)
    refined = next(f for f in findings if f.function == "app.refined")
    assert (refined.taint.source_param, refined.taint.source_kind) == ("order", ParamLocation.JSON)
    assert refined.confidence == 0.9
    whole = next(f for f in findings if f.function == "app.whole")
    assert whole.taint.source_param is None  # an unrefined container stays unnamed (A-15)
    assert whole.confidence == 0.7


def test_branch_join_keeps_taint_from_one_arm(tmp_path):
    files = {
        "app.py": """
            from flask import Flask, request

            app = Flask(__name__)


            @app.route("/branch")
            def branch():
                if request.args.get("mode") == "a":
                    value = request.args.get("a", "")
                else:
                    value = "safe"
                return f"<p>{value}</p>"
        """
    }
    findings = _findings(tmp_path, files)
    assert len(findings) == 1
    assert (findings[0].cwe, findings[0].taint.source_param) == (79, "a")
    assert findings[0].rule_id == "py.xss.fstring.html-response"


LOOP_APP = {
    "app.py": """
        import sqlite3

        from flask import Flask, request

        app = Flask(__name__)


        @app.route("/loop")
        def loop():
            conn = sqlite3.connect("shop.db")
            sql = "SELECT 1"
            for part in request.args.getlist("f"):
                conn.execute(sql)
                sql = sql + part
            return "ok"
    """
}


def test_loop_finds_taint_on_the_second_iteration(tmp_path):
    findings = _findings(tmp_path, LOOP_APP, name="two")
    assert [(f.cwe, f.line_start, f.taint.source_param) for f in findings] == [(89, 13, "f")]


def test_loop_with_a_single_iteration_misses_it(tmp_path):
    """The extra iteration is what finds it: with one pass the sink still reads the constant."""
    findings = _findings(tmp_path, LOOP_APP, name="one", config=SastConfig(taint_loop_iterations=1))
    assert findings == []


def test_int_clears_every_cwe_and_escape_clears_only_xss(tmp_path):
    files = {
        "app.py": """
            import html
            import sqlite3

            from flask import Flask, request

            app = Flask(__name__)


            @app.route("/cast")
            def cast():
                number = int(request.args.get("n", "0"))
                conn = sqlite3.connect("shop.db")
                conn.execute(f"SELECT {number}")
                return f"<p>{number}</p>"


            @app.route("/escaped")
            def escaped():
                name = html.escape(request.args.get("name", ""))
                conn = sqlite3.connect("shop.db")
                conn.execute("SELECT '" + name + "'")
                return f"<p>{name}</p>"
        """
    }
    findings = _findings(tmp_path, files)
    live = _live(findings)
    assert [(f.function, f.cwe) for f in live] == [("app.escaped", 89)]
    assert live[0].taint.sanitizers_seen == ["html.escape"]
    assert _suppressed(findings) == [
        ("app.cast", 89, "sanitized:builtins.int"),
        ("app.cast", 79, "sanitized:builtins.int"),
        ("app.escaped", 79, "sanitized:html.escape"),
    ]


def test_sink_results_are_taint_barriers(tmp_path):
    files = {
        "app.py": """
            from flask import Flask, jsonify, request

            app = Flask(__name__)


            @app.route("/read")
            def read():
                with open(request.args.get("f", ""), "rb") as handle:
                    return handle.read()


            @app.route("/echo")
            def echo():
                return jsonify({"echo": request.args.get("q", "")})
        """
    }
    findings = _findings(tmp_path, files)
    assert [(f.function, f.cwe, f.rule_id) for f in findings] == [("app.read", 22, "py.traversal.open")]


def test_guards_make_a_redirect_safe(tmp_path):
    files = {
        "app.py": """
            from urllib.parse import urlparse

            from flask import Flask, redirect, request

            app = Flask(__name__)

            ALLOWED_HOSTS = {"localhost", "shop.example"}


            @app.route("/raw")
            def raw():
                return redirect(request.args.get("next", "/"))


            @app.route("/checked")
            def checked():
                target = request.args.get("next", "/")
                host = urlparse(target).netloc
                if host and host not in ALLOWED_HOSTS:
                    return redirect("/")
                return redirect(target)


            @app.route("/listed")
            def listed():
                target = request.args.get("next", "/")
                if target in ALLOWED_HOSTS:
                    return redirect(target)
                return redirect("/")
        """
    }
    findings = _findings(tmp_path, files)
    assert [(f.function, f.cwe) for f in _live(findings)] == [("app.raw", 601)]
    assert _suppressed(findings) == [
        ("app.checked", 601, "sanitized:guard:allow-list"),
        ("app.listed", 601, "sanitized:guard:allow-list"),
    ]


def test_location_header_assignment_is_a_redirect_sink(tmp_path):
    files = {
        "app.py": """
            from flask import Flask, make_response, request

            app = Flask(__name__)


            @app.route("/header")
            def header():
                response = make_response("", 302)
                response.headers["Location"] = request.args.get("next", "/")
                return response
        """
    }
    findings = _findings(tmp_path, files)
    assert [(f.cwe, f.rule_id, f.taint.source_param) for f in findings] == [
        (601, "py.redirect.location-header", "next")
    ]


# --------------------------------------------------------------------------- P2-A2 summaries
CROSS_FILE = {
    "app.py": """
        from flask import Flask, request

        from store import find_items

        app = Flask(__name__)


        @app.route("/items")
        def items():
            category = request.args.get("category", "")
            find_items(category)
            return "ok"
    """,
    "store.py": """
        from sqlrun import run_query


        def find_items(category):
            return run_query(f"SELECT id FROM items WHERE category = '{category}'")
    """,
    "sqlrun.py": """
        import sqlite3


        def run_query(query):
            conn = sqlite3.connect("shop.db")
            return conn.execute(query).fetchall()
    """,
}


def test_cross_file_flow_reports_at_the_helper_sink(tmp_path):
    findings = _findings(tmp_path, CROSS_FILE)
    assert len(findings) == 1
    finding = findings[0]
    assert (finding.file, finding.line_start, finding.function) == ("sqlrun.py", 6, "sqlrun.run_query")
    assert finding.rule_id == "py.sqli.fstring.execute"
    assert finding.title == "SQL injection: request data reaches execute() through an f-string"
    assert finding.taint.call_chain == ["app.items", "store.find_items", "sqlrun.run_query"]
    assert finding.taint.source_param == "category"
    assert finding.taint.source_kind is ParamLocation.QUERY
    assert finding.taint.source_location.file == "app.py"
    assert finding.taint.entry_routes == ["GET /items"]
    assert finding.confidence == 0.9


def test_param_to_return_taints_the_callers_variable(tmp_path):
    files = {
        "app.py": """
            from flask import Flask, request

            from helpers import unwrap

            app = Flask(__name__)


            @app.route("/echo")
            def echo():
                value = unwrap(request.args.get("q", ""))
                return f"<p>{value}</p>"
        """,
        "helpers.py": """
            def unwrap(value):
                return value.strip()
        """,
    }
    findings = _findings(tmp_path, files)
    assert [(f.file, f.line_start, f.cwe, f.taint.source_param) for f in findings] == [("app.py", 11, 79, "q")]
    assert findings[0].taint.call_chain == ["app.echo"]


def test_recursive_helper_terminates(tmp_path):
    files = {
        "app.py": """
            from flask import Flask, request

            from walker import descend

            app = Flask(__name__)


            @app.route("/walk")
            def walk():
                descend(request.args.get("p", ""), 3)
                return "ok"
        """,
        "walker.py": """
            def descend(path, depth):
                if depth <= 0:
                    return open(path).read()
                return descend(path + "/x", depth - 1)
        """,
    }
    findings = _findings(tmp_path, files)
    assert [(f.file, f.line_start, f.cwe) for f in findings] == [("walker.py", 3, 22)]
    assert findings[0].taint.call_chain == ["app.walk", "walker.descend"]


def test_path_converter_parameter_seeds_a_traversal_flow(tmp_path):
    files = {
        "app.py": """
            import os

            from flask import Flask, send_file

            app = Flask(__name__)

            DOCS = os.path.join(os.path.dirname(__file__), "docs")


            @app.route("/docs/<path:name>")
            def docs(name):
                return send_file(os.path.join(DOCS, name))
        """
    }
    findings = _findings(tmp_path, files)
    assert len(findings) == 1
    finding = findings[0]
    assert (finding.cwe, finding.rule_id) == (22, "py.traversal.send-file")
    assert (finding.taint.source_param, finding.taint.source_kind) == ("name", ParamLocation.PATH)
    assert finding.taint.entry_routes == ["GET /docs/<path:name>"]


def test_two_sources_reaching_one_sink_pick_the_earliest_read(tmp_path):
    files = {
        "app.py": """
            from flask import Flask, request

            from auth import find_user

            app = Flask(__name__)


            @app.route("/login", methods=["GET", "POST"])
            def login():
                username = request.form.get("username", "")
                password = request.form.get("password", "")
                find_user(username, password)
                return "ok"
        """,
        "auth.py": """
            import sqlite3


            def find_user(username, password):
                conn = sqlite3.connect("shop.db")
                query = "SELECT 1 FROM users WHERE u = '" + username + "' AND p = '" + password + "'"
                return conn.execute(query).fetchone()
        """,
    }
    findings = _findings(tmp_path, files)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "py.sqli.concat.execute"
    assert finding.taint.source_param == "username"  # read one line before `password` (A-12)
    assert finding.raw["source_params"] == ["password", "username"]
    assert finding.taint.entry_routes == ["GET /login", "POST /login"]  # one handler, two routes (A-13)


def test_list_form_subprocess_is_reported_as_suppressed(tmp_path):
    files = {
        "app.py": """
            import subprocess

            from flask import Flask, request

            app = Flask(__name__)


            @app.route("/diag")
            def diag():
                host = request.args.get("host", "127.0.0.1")
                subprocess.run(["ping", "-c", "1", host], capture_output=True, shell=False)
                return "ok"
        """
    }
    findings = _findings(tmp_path, files)
    assert len(findings) == 1
    finding = findings[0]
    assert (finding.cwe, finding.rule_id) == (78, "py.cmdi.subprocess")
    assert finding.suppressed is True
    assert finding.suppress_reason == "safe:subprocess-list-no-shell"
    assert finding.title == "Command execution with request data (list form, no shell)"


def test_constant_sql_with_tainted_binds_is_safe(tmp_path):
    files = {
        "app.py": """
            from flask import Flask, request

            from store import fetch

            app = Flask(__name__)


            @app.route("/products")
            def products():
                fetch(request.args.get("id", ""))
                return "ok"
        """,
        "store.py": """
            import sqlite3


            def fetch(product_id):
                conn = sqlite3.connect("shop.db")
                return conn.execute("SELECT id FROM products WHERE id = ?", (product_id,)).fetchall()
        """,
    }
    findings = _findings(tmp_path, files)
    assert _live(findings) == []
    assert _suppressed(findings) == [("store.fetch", 89, "safe:sql-parameterised")]
    assert findings[0].title == "Parameterised SQL query with request data in bind parameters"


def test_summaries_record_param_to_sink_and_param_to_return(tmp_path):
    files = {
        "m.py": """
            import os


            def runner(cmd):
                return os.system("echo " + cmd)


            def passthrough(value):
                return value.strip()


            def constant(value):
                return "fixed"
        """
    }
    index = build_index(make_tree(tmp_path / "app", files))
    summaries = compute_summaries(index, build_call_graph(index))
    runner = summaries["m.runner"]
    assert len(runner.param_to_sink) == 1
    hit = runner.param_to_sink[0]
    assert (hit.cwe, hit.token, hit.file, hit.line_start) == (78, "shell", "m.py", 5)
    assert hit.chain == ("m.runner",)
    assert hit.rule_id == "py.cmdi.shell"
    assert runner.param_to_return == frozenset()  # os.system's result is a barrier (A-09)
    assert summaries["m.passthrough"].param_to_return == frozenset({0})
    assert summaries["m.constant"].returns_constant_string is True


def test_findings_are_sorted_and_deterministic(tmp_path):
    index = build_index(make_tree(tmp_path / "app", PROPAGATION))
    graph = build_call_graph(index)
    routes = _routes(index, graph)
    first = analyse_taint(index, routes, graph)
    second = analyse_taint(index, routes, graph)
    keys = [(f.file, f.line_start, f.cwe, f.rule_id) for f in first]
    assert keys == sorted(keys)
    assert first == second


# --------------------------------------------------------------------------- P4: content type set after construction
def _response_app(*body: str) -> dict[str, str]:
    """A Flask route building `resp = Response(json.dumps(<request data>))`, then running `body`."""
    lines = "\n".join(f"    {line}" for line in body)
    source = (
        "import json\n\nfrom flask import Flask, Response, request\n\napp = Flask(__name__)\n\n\n"
        '@app.route("/api/user", methods=["POST"])\n'
        "def user():\n"
        '    resp = Response(json.dumps({"u": request.json["u"]}))\n'
        f"{lines}\n"
    )
    return {"app.py": source}


def test_content_type_set_after_construction_makes_the_response_safe(tmp_path):
    writes = [
        'resp.mimetype = "application/json"',
        'resp.content_type = "text/plain; charset=utf-8"',
        'resp.headers["Content-Type"] = "application/json"',
    ]
    for i, write in enumerate(writes):
        files = _response_app('resp.headers["Authorization"] = "x"', "resp.status_code = 200", write, "return resp")
        assert _by_cwe(_findings(tmp_path, files, name=f"safe{i}"), 79) == [], write


def test_content_type_write_that_may_not_apply_keeps_the_xss(tmp_path):
    bodies = {
        "branch": ("if request.args.get('fmt'):", '    resp.mimetype = "application/json"', "return resp"),
        "html": ('resp.mimetype = "text/html"', "return resp"),
        "reassigned": ('resp = Response("fixed")', 'resp.mimetype = "application/json"', "return resp"),
        "returned_first": ("return resp", 'resp.mimetype = "application/json"'),
    }
    for case, body in bodies.items():
        findings = _by_cwe(_findings(tmp_path, _response_app(*body), name=case), 79)
        assert [(f.function, f.line_start) for f in findings] == [("app.user", 10)], case


def test_last_content_type_write_decides(tmp_path):
    """A-53: a later straight-line write wins, and anything else that may retype the response keeps the XSS."""
    safe_first = 'resp.mimetype = "application/json"'
    overrides = {
        "header_override": (safe_first, 'resp.headers["Content-Type"] = "text/html"', "return resp"),
        "headers_set": (safe_first, 'resp.headers.set("Content-Type", "text/html")', "return resp"),
        "computed_key": (safe_first, 'resp.headers[request.args["h"]] = "text/html"', "return resp"),
        "headers_replaced": (safe_first, 'resp.headers = {"Content-Type": "text/html"}', "return resp"),
        "branch_after": (safe_first, "if request.args.get('fmt'):", '    resp.mimetype = "text/html"', "return resp"),
        "returned_headers": (safe_first, 'return resp, 200, {"Content-Type": "text/html"}'),
    }
    for case, body in overrides.items():
        findings = _by_cwe(_findings(tmp_path, _response_app(*body), name=case), 79)
        assert [(f.function, f.line_start) for f in findings] == [("app.user", 10)], case
    retyped = {
        "html_then_json": ('resp.mimetype = "text/html"', safe_first, "return resp"),
        "cookie_after": (safe_first, 'resp.set_cookie("s", "1")', "return resp, 200"),
    }
    for case, body in retyped.items():
        assert _by_cwe(_findings(tmp_path, _response_app(*body), name=case), 79) == [], case


# --------------------------------------------------------------------------- P4: block-ending calls, fixpoint cap
def test_resolved_abort_ends_the_block(tmp_path):
    files = {
        "app.py": """
            from flask import Flask, abort, redirect, request

            app = Flask(__name__)

            ALLOWED = {"/home", "/account"}


            @app.route("/go")
            def go():
                target = request.args.get("next", "/")
                if target not in ALLOWED:
                    abort(400)
                return redirect(target)
        """
    }
    findings = _findings(tmp_path, files)
    assert _by_cwe(_live(findings), 601) == []
    assert _suppressed(findings) == [("app.go", 601, "sanitized:guard:allow-list")]


def test_unresolved_abort_like_call_does_not_end_the_block(tmp_path):
    for i, call in enumerate(['checker.fail("x")', "obj.abort()"]):
        files = {
            "app.py": f"""
                from flask import Flask, request

                app = Flask(__name__)


                @app.route("/q")
                def q_view(checker, obj):
                    q = request.args.get("q", "")
                    {call}
                    return f"<p>{{q}}</p>"
            """
        }
        findings = _by_cwe(_findings(tmp_path, files, name=f"app{i}"), 79)
        assert [f.function for f in findings] == ["app.q_view"], call


def test_sys_exit_ends_the_block(tmp_path):
    files = {
        "app.py": """
            import sys

            from flask import Flask, request

            app = Flask(__name__)


            @app.route("/q")
            def q_view():
                q = request.args.get("q", "")
                sys.exit(1)
                return f"<p>{q}</p>"
        """
    }
    assert _by_cwe(_findings(tmp_path, files), 79) == []


FIXPOINT_TREE = {
    "m.py": """
        import os


        def outer(cmd):
            inner(cmd)


        def inner(cmd):
            os.system(cmd)
    """
}


def test_fixpoint_cap_logs_a_warning(tmp_path, caplog):
    index = build_index(make_tree(tmp_path / "app", FIXPOINT_TREE))
    graph = build_call_graph(index)
    logger = "FlowStopper.sast.taint.summaries"
    with caplog.at_level(logging.WARNING, logger=logger):
        compute_summaries(index, graph, SastConfig(fixpoint_max_iterations=1))
    assert any("fixpoint" in r.getMessage() for r in caplog.records if r.name == logger)
    caplog.clear()
    with caplog.at_level(logging.WARNING, logger=logger):
        compute_summaries(index, graph)
    assert [r for r in caplog.records if r.name == logger] == []


# --------------------------------------------------------------------------- P4: request URL, template source
URL_READS = ["request.url", "request.path", "request.full_path", "request.base_url"]


def test_request_url_attributes_are_unnamed_path_sources(tmp_path):
    ctx, nodes = _exprs(tmp_path, FLASK_HEADER, URL_READS)
    for node, expr in zip(nodes, URL_READS, strict=True):
        ref = request_source(node, ctx)
        assert ref is not None, f"not recognised: {expr}"
        assert (ref.param_name, ref.location_kind, ref.is_container) == (None, ParamLocation.PATH, False), expr
        assert ref.cleared == frozenset({601}), expr


def _one_route(body: str, imports: str = "request") -> dict[str, str]:
    return {
        "app.py": f"""
            from flask import Flask, {imports}

            app = Flask(__name__)


            @app.route("/page")
            def page():
                {body}
        """
    }


def test_render_template_string_source_is_an_xss_sink(tmp_path):
    files = _one_route(
        "return render_template_string('<h3>%s</h3>' % request.args.get('q', ''))",
        "render_template_string, request",
    )
    findings = _findings(tmp_path, files)
    assert [(f.cwe, f.rule_id, f.taint.source_param) for f in findings] == [(79, "py.xss.percent.template-string", "q")]
    assert findings[0].suppressed is False
    assert "render_template_string()" in findings[0].title


def test_render_template_string_variables_are_not_the_template_source(tmp_path):
    files = _one_route(
        "return render_template_string('<p>{{ q }}</p>', q=request.args.get('q'))",
        "render_template_string, request",
    )
    assert [f for f in _findings(tmp_path, files) if f.rule_id.endswith(".template-string")] == []


def test_redirect_to_the_request_url_is_not_an_open_redirect(tmp_path):
    for i, attr in enumerate(["url", "path"]):
        files = _one_route(f"return redirect(request.{attr})", "redirect, request")
        assert _by_cwe(_findings(tmp_path, files, name=f"app{i}"), 601) == [], attr


def test_request_path_in_html_is_xss_without_a_parameter_name(tmp_path):
    findings = _findings(tmp_path, _one_route('return f"<p>{request.path}</p>"'))
    assert [(f.cwe, f.suppressed) for f in findings] == [(79, False)]
    assert findings[0].taint.source_param is None
    assert findings[0].taint.source_kind is ParamLocation.PATH
