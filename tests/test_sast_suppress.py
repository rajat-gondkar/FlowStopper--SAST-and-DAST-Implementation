"""P4-A2 B-2 noise cut and P4 request hooks: suppress.py and the taint driver (Owner: A)."""

from __future__ import annotations

from FlowStopper.models import ParamLocation
from FlowStopper.sast.callgraph import annotate_reachable, build_call_graph
from FlowStopper.sast.index import build_index
from FlowStopper.sast.routes import extract_routes
from FlowStopper.sast.runner import run_sast
from FlowStopper.sast.suppress import unreachable_functions, unreachable_reason
from FlowStopper.sast.taint.summaries import TaintFinding, analyse_taint
from tests.sast_helpers import make_tree


def _findings(tmp_path, files: dict[str, str], *, name: str = "app") -> list[TaintFinding]:
    """Run the whole taint driver over a synthetic project."""
    index = build_index(make_tree(tmp_path / name, files))
    graph = build_call_graph(index)
    routes = annotate_reachable(index, extract_routes(index), graph=graph)
    return analyse_taint(index, routes, graph)


def _unreachable(tmp_path, files: dict[str, str], *, name: str = "app") -> frozenset[str]:
    index = build_index(make_tree(tmp_path / name, files))
    graph = build_call_graph(index)
    return unreachable_functions(index, extract_routes(index), graph)


def _live(findings: list[TaintFinding]) -> list[TaintFinding]:
    return [f for f in findings if not f.suppressed]


def _sites(findings: list[TaintFinding]) -> list[tuple]:
    return [(f.file, f.function, f.line_start, f.cwe) for f in findings]


def _assert_no_shared_sites(findings: list[TaintFinding]) -> None:
    """D5: a live finding never shares a (file, function, line, cwe) site with a suppressed one."""
    live = set(_sites(_live(findings)))
    assert not [site for site in _sites([f for f in findings if f.suppressed]) if site in live]


ROUTE = """
from flask import Flask

app = Flask(__name__)


@app.route("/")
def index():
    return "ok"
"""


# --------------------------------------------------------------------------- request hooks (D4)
def test_errorhandler_is_a_code_only_entry_point(tmp_path):
    files = {
        "app.py": ROUTE
        + """

@app.errorhandler(404)
def not_found(e):
    template = '<h3>%s</h3>' % request.url
    return render_template_string(template), 404
""",
    }
    files["app.py"] = files["app.py"].replace(
        "from flask import Flask", "from flask import Flask, render_template_string, request"
    )
    findings = _findings(tmp_path, files)
    assert len(findings) == 1
    finding = findings[0]
    assert (finding.cwe, finding.function, finding.suppressed) == (79, "app.not_found", False)
    lines = files["app.py"].lstrip("\n").splitlines()
    assert finding.line_start == lines.index("    return render_template_string(template), 404") + 1
    assert finding.rule_id == "py.xss.percent.template-string"
    assert finding.taint.entry_routes == []
    assert finding.taint.source_param is None
    assert finding.taint.source_kind is ParamLocation.PATH
    assert finding.confidence == 0.7


def test_before_request_hook_reaches_a_command_sink(tmp_path):
    files = {
        "app.py": """
            import os

            from flask import Flask, request

            app = Flask(__name__)


            @app.route("/")
            def index():
                return "ok"


            @app.before_request
            def audit():
                h = request.args.get("h", "")
                os.system("ping " + h)
        """
    }
    findings = _findings(tmp_path, files)
    assert [(f.cwe, f.function, f.suppressed) for f in findings] == [(78, "app.audit", False)]
    assert findings[0].taint.entry_routes == []
    assert findings[0].taint.source_param == "h"


def test_hook_and_route_sharing_a_helper_keep_their_own_route_ids(tmp_path):
    files = {
        "app.py": """
            from flask import Flask, request

            from tools import run

            app = Flask(__name__)


            @app.route("/ping")
            def ping():
                run(request.args.get("host", ""))
                return "ok"


            @app.after_request
            def stamp(response):
                run(request.headers.get("X-Trace", ""))
                return response
        """,
        "tools.py": """
            import os


            def run(arg):
                os.system("ping " + arg)
        """,
    }
    findings = _findings(tmp_path, files)
    assert [(f.function, f.cwe, f.suppressed) for f in findings] == [("tools.run", 78, False)]
    finding = findings[0]
    assert finding.taint.entry_routes == ["GET /ping"]  # the route's own id, nothing borrowed
    assert finding.taint.call_chain == ["app.ping", "tools.run"]
    assert finding.taint.source_param == "host"


def test_hook_only_helper_gets_no_route_id(tmp_path):
    """The reachability fallback is off for hooks: the route reaches the helper, yet lends it no id."""
    files = {
        "app.py": """
            from flask import Flask, request

            from tools import run

            app = Flask(__name__)


            @app.route("/ping")
            def ping():
                run("localhost")  # reaches the helper, but with no request data
                return "ok"


            @app.before_request
            def audit():
                run(request.args.get("h", ""))
        """,
        "tools.py": """
            import os


            def run(arg):
                os.system("ping " + arg)
        """,
    }
    findings = _findings(tmp_path, files)
    assert [(f.function, f.cwe, f.suppressed) for f in findings] == [("tools.run", 78, False)]
    assert findings[0].taint.entry_routes == []
    assert findings[0].taint.call_chain == ["app.audit", "tools.run"]


# --------------------------------------------------------------------------- sanitised / safe (D5, D7)
def test_html_escape_gives_a_suppressed_sanitized_finding(tmp_path):
    files = {
        "app.py": """
            import html

            from flask import Flask, request

            app = Flask(__name__)


            @app.route("/hi")
            def hi():
                return f"<p>{html.escape(request.args.get('name', ''))}</p>"
        """
    }
    findings = _findings(tmp_path, files)
    assert [(f.cwe, f.suppressed, f.suppress_reason) for f in findings] == [(79, True, "sanitized:html.escape")]
    assert findings[0].title.endswith("(sanitised: html.escape)")
    assert findings[0].taint.entry_routes == ["GET /hi"]


def test_cross_file_int_cast_is_sanitized_at_the_helper_sink(tmp_path):
    files = {
        "app.py": """
            from flask import Flask, request

            from store import lookup

            app = Flask(__name__)


            @app.route("/item")
            def item():
                lookup(int(request.args["id"]))
                return "ok"
        """,
        "store.py": """
            import sqlite3


            def lookup(item_id):
                conn = sqlite3.connect("shop.db")
                return conn.execute(f"SELECT * FROM items WHERE id = {item_id}").fetchall()
        """,
    }
    findings = _findings(tmp_path, files)
    assert [(f.function, f.cwe, f.suppressed, f.suppress_reason) for f in findings] == [
        ("store.lookup", 89, True, "sanitized:builtins.int")
    ]
    assert findings[0].line_start == 6
    assert findings[0].taint.call_chain == ["app.item", "store.lookup"]


def test_allow_list_guard_redirect_is_sanitized(tmp_path):
    files = {
        "app.py": """
            from flask import Flask, redirect, request

            app = Flask(__name__)

            ALLOWED = {"/home", "/account"}


            @app.route("/go")
            def go():
                target = request.args.get("next", "/")
                if target in ALLOWED:
                    return redirect(target)
                return redirect("/")
        """
    }
    findings = _findings(tmp_path, files)
    assert [(f.cwe, f.suppressed) for f in findings] == [(601, True)]
    assert findings[0].suppress_reason.startswith("sanitized:guard:")


def test_constant_sql_with_tainted_bind_tuple_is_safe(tmp_path):
    files = {
        "app.py": """
            import sqlite3

            from flask import Flask, request

            app = Flask(__name__)


            @app.route("/u")
            def user():
                conn = sqlite3.connect("shop.db")
                conn.execute("SELECT * FROM users WHERE name = ?", (request.args.get("name", ""),))
                return "ok"
        """
    }
    findings = _findings(tmp_path, files)
    assert [(f.cwe, f.suppressed, f.suppress_reason) for f in findings] == [(89, True, "safe:sql-parameterised")]
    assert findings[0].taint.source_param == "name"


def test_list_form_subprocess_keeps_its_reason(tmp_path):
    files = {
        "app.py": """
            import subprocess

            from flask import Flask, request

            app = Flask(__name__)


            @app.route("/ping")
            def ping():
                subprocess.run(["ping", "-c", "1", request.args.get("host", "")])
                return "ok"
        """
    }
    findings = _findings(tmp_path, files)
    assert [(f.cwe, f.suppressed, f.suppress_reason) for f in findings] == [(78, True, "safe:subprocess-list-no-shell")]


def test_sanitised_and_raw_routes_into_one_helper_give_one_live_finding(tmp_path):
    files = {
        "app.py": """
            from flask import Flask, request

            from store import lookup

            app = Flask(__name__)


            @app.route("/safe")
            def safe():
                return lookup(int(request.args.get("id", "0")))


            @app.route("/raw")
            def raw():
                return lookup(request.args.get("id", ""))
        """,
        "store.py": """
            import sqlite3


            def lookup(item_id):
                conn = sqlite3.connect("shop.db")
                return str(conn.execute(f"SELECT * FROM items WHERE id = {item_id}").fetchall())
        """,
    }
    findings = _findings(tmp_path, files)
    sql = [f for f in findings if f.cwe == 89]
    assert len(sql) == 1
    assert sql[0].suppressed is False
    assert sql[0].taint.entry_routes == ["GET /raw"]
    assert sql[0].taint.call_chain == ["app.raw", "store.lookup"]
    _assert_no_shared_sites(findings)


# --------------------------------------------------------------------------- unreachable (D6)
UNCALLED = {
    "app.py": ROUTE,
    "tools.py": """
        import os


        def run(cmd):
            os.system(cmd)
    """,
}


def test_uncalled_helper_sink_is_suppressed_unreachable(tmp_path):
    findings = _findings(tmp_path, UNCALLED)
    assert [(f.function, f.cwe, f.suppressed, f.suppress_reason) for f in findings] == [
        ("tools.run", 78, True, "unreachable")
    ]
    finding = findings[0]
    assert finding.taint.entry_routes == []
    assert finding.taint.call_chain == ["tools.run"]
    assert finding.taint.source_param is None
    assert finding.raw["function_params"] == ["cmd"]
    assert finding.confidence == 0.7


def test_no_unreachable_findings_without_routes(tmp_path):
    files = {"tools.py": UNCALLED["tools.py"]}
    assert _findings(tmp_path, files) == []
    assert _unreachable(tmp_path, files, name="again") == frozenset()


def test_unreachable_is_never_applied_to_secrets():
    assert unreachable_reason(798) is None
    assert unreachable_reason(78) == "unreachable"


HELPER = """
import os


def run(cmd):
    os.system(cmd)
"""

# Each tree uses `run` in a way the call graph cannot see; none may be called unreachable.
REFERENCED: dict[str, dict[str, str]] = {
    "celery-decorator": {"tools.py": "import celery\n" + HELPER.replace("def run", "@celery.task\ndef run")},
    "errorhandler": {
        "tools.py": "from app import app\n" + HELPER.replace("def run", "@app.errorhandler(500)\ndef run")
    },
    "passed-as-value": {"tools.py": HELPER + "\n\nregister(run)\n"},
    "dict-value": {"tools.py": HELPER + "\n\nHANDLERS = {'x': run}\n"},
    "thread-target": {
        "tools.py": "import threading\n" + HELPER + "\n\ndef start():\n    threading.Thread(target=run).start()\n"
    },
    "module-level-call": {"tools.py": HELPER + "\n\nrun('ls')\n"},
    "named-in-string": {"tools.py": HELPER + "\n\nimport tools\n\nfn = getattr(tools, 'run')\n"},
    "dotted-string": {"tools.py": HELPER + "\n\nTASKS = ['tools.run']\n"},
    "unresolved-call-leaf": {"tools.py": HELPER + "\n\ndef go(obj):\n    obj.run('x')\n"},
    "lambda-call": {"tools.py": HELPER + "\n\nLATER = lambda: run('ls')\n"},
    # A-52: a name built at run time may be any function
    "computed-getattr": {"tools.py": HELPER + "\n\ndef go(mod, a):\n    getattr(mod, 'r' + a)('x')\n"},
    "fstring-getattr": {"tools.py": HELPER + "\n\ndef go(mod, a):\n    getattr(mod, f'r{a}')('x')\n"},
    "globals-lookup": {"tools.py": HELPER + "\n\ndef go(a):\n    globals()['r' + a]('x')\n"},
    "vars-lookup": {"tools.py": HELPER + "\n\ndef go(mod, a):\n    vars(mod)['r' + a]('x')\n"},
    "dict-lookup": {"tools.py": HELPER + "\n\ndef go(mod, a):\n    mod.__dict__['r' + a]('x')\n"},
    "attrgetter": {
        "tools.py": "import operator\n" + HELPER + "\n\ndef go(m, a):\n    operator.attrgetter(a)(m)('x')\n"
    },
    "eval": {"tools.py": HELPER + "\n\ndef go(a):\n    eval(a + '(1)')\n"},
    "getmembers-registry": {
        "tools.py": "import inspect, sys\n"
        + HELPER
        + "\n\nREG = dict(inspect.getmembers(sys.modules[__name__], inspect.isfunction))\n"
    },
    "getattr-as-value": {
        "tools.py": "import functools\n"
        + HELPER
        + "\n\ndef go(mod, a):\n    functools.reduce(getattr, a.split('.'), mod)('x')\n"
    },
}


def test_helpers_referenced_outside_the_call_graph_are_not_unreachable(tmp_path):
    for i, (label, extra) in enumerate(REFERENCED.items()):
        files = {"app.py": ROUTE, **extra}
        assert "tools.run" not in _unreachable(tmp_path, files, name=f"ref{i}"), label
        assert [f for f in _findings(tmp_path, files, name=f"refs{i}") if f.suppress_reason == "unreachable"] == [], (
            label
        )


def test_route_dispatching_by_a_computed_name_reaches_its_helpers(tmp_path):
    """A-52: `getattr(tools, "cmd_" + action)` from a route leaves no helper suppressed as unreachable."""
    files = {
        "app.py": """
            from flask import Flask, request

            import tools

            app = Flask(__name__)


            @app.route("/do")
            def do():
                getattr(tools, "cmd_" + request.args["a"])(request.args["h"])
                return "ok"
        """,
        "tools.py": """
            import os


            def cmd_ping(arg):
                os.system("ping " + arg)
        """,
    }
    assert _unreachable(tmp_path, files) == frozenset()
    assert [f for f in _findings(tmp_path, files, name="again") if f.suppress_reason == "unreachable"] == []


def test_constant_getattr_keeps_the_unreachable_test(tmp_path):
    """A getattr with a constant name names its target; it does not switch the pass off."""
    files = {"app.py": ROUTE, "tools.py": HELPER + "\n\ndef go(mod):\n    return getattr(mod, 'other')\n"}
    assert "tools.run" in _unreachable(tmp_path, files)


def test_methods_and_their_callees_are_not_unreachable(tmp_path):
    files = {
        "app.py": ROUTE,
        "tools.py": HELPER
        + """

class Worker:
    def go(self, cmd):
        os.system(cmd)
        run(cmd)
""",
    }
    unreachable = _unreachable(tmp_path, files)
    assert "tools.Worker.go" not in unreachable
    assert "tools.run" not in unreachable  # called only from a method, which is a root


def test_helper_called_only_from_a_decorated_function_is_not_unreachable(tmp_path):
    files = {
        "app.py": ROUTE,
        "tools.py": "import celery\n" + HELPER + "\n\n@celery.task\ndef job(cmd):\n    run(cmd)\n",
    }
    assert _unreachable(tmp_path, files) == frozenset()


def test_unreachable_chain_of_helpers(tmp_path):
    files = {"app.py": ROUTE, "tools.py": HELPER + "\n\ndef outer(cmd):\n    run(cmd)\n"}
    assert _unreachable(tmp_path, files) == frozenset({"tools.outer", "tools.run"})
    findings = _findings(tmp_path, files, name="again")
    # only the function holding the sink reports it; outer's transitive hit is not repeated
    assert [(f.function, f.suppress_reason) for f in findings] == [("tools.run", "unreachable")]


def test_list_form_subprocess_in_an_unreachable_helper_keeps_its_safe_reason(tmp_path):
    files = {
        "app.py": ROUTE,
        "tools.py": """
            import subprocess


            def check_host(host):
                subprocess.run(["ping", host])
        """,
    }
    findings = _findings(tmp_path, files)
    assert [(f.function, f.suppressed, f.suppress_reason) for f in findings] == [
        ("tools.check_host", True, "safe:subprocess-list-no-shell")
    ]


def test_secret_in_an_unreachable_helper_stays_reported(tmp_path):
    files = {
        "app.py": ROUTE,
        "tools.py": """
            import os


            def run(cmd):
                password = "s3cr3t-Pa55word"
                os.system(cmd)
                return password
        """,
    }
    result = run_sast(make_tree(tmp_path / "app", files))
    secrets = [f for f in result.findings if f.cwe == 798]
    assert len(secrets) == 1 and secrets[0].suppressed is False
    unreachable = [f for f in result.findings if f.suppress_reason == "unreachable"]
    assert [(f.cwe, f.code.function) for f in unreachable] == [(78, "tools.run")]
    stats = result.stats
    assert stats["suppressed_unreachable"] == 1
    assert stats["unreachable_functions"] == 1
    assert stats["suppressed_findings"] == 1
    assert stats["reported_findings"] == len(result.findings) - 1
    assert (stats["suppressed_sanitized"], stats["suppressed_safe"], stats["request_hooks"]) == (0, 0, 0)
    assert all(isinstance(v, int) for k, v in stats.items() if k != "skipped")
