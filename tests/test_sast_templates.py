"""P2-A5 template scan: unescaped variables plus the CWE-79 render-call keyword rule (Owner: A)."""

from __future__ import annotations

import ast

from FlowStopper.sast.callgraph import annotate_reachable, build_call_graph
from FlowStopper.sast.config import SastConfig
from FlowStopper.sast.index import build_index
from FlowStopper.sast.routes import extract_routes
from FlowStopper.sast.taint import sinks
from FlowStopper.sast.taint.summaries import TaintFinding, analyse_taint
from FlowStopper.sast.templates import scan_template_text, scan_templates
from tests.sast_helpers import make_tree

# One handler, one template: `note` is rendered with |safe, `name` is escaped by Jinja.
APP = {
    "app.py": """
        from flask import Flask, render_template, request

        app = Flask(__name__)


        @app.route("/product")
        def product():
            note = request.args.get("note", "")
            name = request.args.get("name", "")
            return render_template("product.html", note=note, name=name)
    """,
    "templates/product.html": """
        <h1>{{ name }}</h1>
        <div class="note">{{ note|safe }}</div>
    """,
}


def _findings(tmp_path, files: dict[str, str], *, name: str = "app") -> list[TaintFinding]:
    """Run the taint driver with the template index wired in, as the runner does (P2-A6)."""
    root = make_tree(tmp_path / name, files)
    config = SastConfig()
    index = build_index(root, config)
    graph = build_call_graph(index, config)
    routes = annotate_reachable(index, extract_routes(index), config, graph=graph)
    return analyse_taint(index, routes, graph, scan_templates(root, config), config)


def _call_line(tmp_path, name: str, needle: str) -> int:
    """1-based line of the only line in `name` containing `needle` (keeps assertions edit-proof)."""
    lines = (tmp_path / "app" / name).read_text(encoding="utf-8").splitlines()
    found = [number for number, text in enumerate(lines, start=1) if needle in text]
    assert len(found) == 1, f"{needle!r} appears on {found} in {name}"
    return found[0]


# --------------------------------------------------------------------------- the tokeniser
def test_safe_filter_marks_the_first_identifier():
    found = scan_template_text("t.html", "<p>{{ note|safe }}</p>\n<p>{{ user.bio | safe }}</p>\n")
    assert found.unescaped == {"note": (1,), "user": (2,)}


def test_plain_and_hand_escaped_variables_are_not_reported():
    text = '<p>{{ note }}</p>\n<p>{{ note|e }}</p>\n<p>{{ note|escape }}</p>\n<p>{{ "x"|safe }}</p>\n'
    assert scan_template_text("t.html", text).unescaped == {}


def test_explicit_escape_wins_inside_an_autoescape_false_block():
    text = "{% autoescape false %}\n<p>{{ raw }}</p>\n<p>{{ clean|e }}</p>\n{% endautoescape %}\n<p>{{ after }}</p>\n"
    assert scan_template_text("t.html", text).unescaped == {"raw": (2,)}


def test_autoescape_off_block_marks_every_variable_until_it_ends():
    text = "{% autoescape off %}{{ a }}{{ b }}{% endautoescape %}{{ c }}"
    assert scan_template_text("t.html", text).unescaped == {"a": (1,), "b": (1,)}


def test_markup_call_is_recorded_and_its_argument_is_unescaped():
    found = scan_template_text("t.html", "<p>{{ Markup(note) }}</p>\n")
    assert found.markup_lines == (1,)
    assert found.unescaped == {"note": (1,)}


def test_discovery_selects_by_extension_and_honours_exclude_dirs(tmp_path):
    files = {
        "pages/a.html": "{{ x|safe }}",
        "pages/b.j2": "{{ y|safe }}",
        "pages/notes.txt": "{{ z|safe }}",
        "__pycache__/c.html": "{{ cached|safe }}",
    }
    index = scan_templates(make_tree(tmp_path, files))
    assert sorted(index.files) == ["pages/a.html", "pages/b.j2"]
    assert index.unescaped_variables == 2


def test_template_name_resolves_by_path_suffix_shortest_first(tmp_path):
    files = {
        "templates/product.html": "{{ note|safe }}",
        "themes/dark/templates/product.html": "{{ other|safe }}",
        "templates/index.html": "{{ title }}",
    }
    index = scan_templates(make_tree(tmp_path, files))
    assert index.unescaped("product.html") == {"note": [1]}  # shortest matching path wins
    assert index.unescaped("dark/templates/product.html") == {"other": [1]}
    assert index.unescaped("index.html") == {}  # escaped: nothing to report
    assert index.unescaped("missing.html") == {}


def test_context_dict_keys_count_as_template_variables():
    call = ast.parse('render(request, "page.html", {"note": note, "pid": pid})').body[0].value
    assert sinks.template_name(call) == "page.html"
    assert sorted(sinks.template_context(call)) == ["note", "pid"]


# --------------------------------------------------------------------------- end to end
def test_unescaped_kwarg_is_one_xss_finding_at_the_render_call(tmp_path):
    findings = _findings(tmp_path, APP)
    assert len(findings) == 1, [f.rule_id for f in findings]
    finding = findings[0]
    assert (finding.cwe, finding.rule_id) == (79, "py.xss.template.unescaped")
    assert finding.line_start == _call_line(tmp_path, "app.py", "render_template(")
    assert finding.function == "app.product"
    assert (finding.taint.source_param, finding.taint.entry_routes) == ("note", ["GET /product"])
    assert finding.confidence == 0.9
    assert finding.raw["source_params"] == ["note"]  # `name` is escaped, so it contributes nothing


def test_safe_filter_without_tainted_data_is_not_a_finding(tmp_path):
    files = {
        "app.py": """
            from flask import Flask, render_template

            app = Flask(__name__)


            @app.route("/product")
            def product():
                return render_template("product.html", note="a static note")
        """,
        "templates/product.html": "<div>{{ note|safe }}</div>",
    }
    assert _findings(tmp_path, files, name="app") == []


def test_render_call_without_the_template_index_reports_nothing(tmp_path):
    root = make_tree(tmp_path / "app", APP)
    index = build_index(root)
    graph = build_call_graph(index)
    routes = annotate_reachable(index, extract_routes(index), graph=graph)
    assert analyse_taint(index, routes, graph, None) == []  # A-18: the rule needs the template scan


# --------------------------------------------------------------------------- P4: **ctx splat (A-39)
def _splat_app(*assignments: str) -> dict[str, str]:
    """APP's handler, but passing its variables as `render_template("product.html", **ctx)`."""
    lines = "\n".join(f"    {line}" for line in assignments)
    source = (
        "from flask import Flask, render_template, request\n\napp = Flask(__name__)\n\n\n"
        '@app.route("/product")\n'
        "def product():\n"
        '    note = request.args.get("note", "")\n'
        '    name = request.args.get("name", "")\n'
        f"{lines}\n"
        '    return render_template("product.html", **ctx)\n'
    )
    return {"app.py": source, "templates/product.html": APP["templates/product.html"]}


def test_splat_of_a_single_assignment_dict_is_a_template_context(tmp_path):
    for i, assignment in enumerate(['ctx = {"note": note}', "ctx = dict(note=note)"]):
        findings = _findings(tmp_path, _splat_app(assignment), name=f"app{i}")
        assert [(f.rule_id, f.taint.source_param) for f in findings] == [("py.xss.template.unescaped", "note")]


def test_splat_that_is_not_a_single_dict_assignment_is_not_guessed(tmp_path):
    cases = {
        "twice": ('ctx = {"name": name}', 'ctx = {"note": note}'),
        "escaped_only": ('ctx = {"name": name}',),
    }
    for case, assignments in cases.items():
        assert _findings(tmp_path, _splat_app(*assignments), name=case) == [], case


# --------------------------------------------------------------------------- P6 r2: Starlette TemplateResponse (A-67)
def _call(source: str) -> ast.Call:
    return ast.parse(source).body[0].value


def _locals(**sources: str):
    """A `local_value` stand-in: each local name maps to the parsed expression it is assigned once."""
    values = {name: ast.parse(text).body[0].value for name, text in sources.items()}
    return values.get


def test_template_response_keyword_form_names_the_template():
    call = _call('pages.TemplateResponse(request=request, name="card.html", context={"note": note})')
    assert sinks.template_name(call) == "card.html"
    assert sorted(sinks.template_context(call)) == ["note", "request"]  # `name` is not a variable here


def test_template_response_keyword_and_positional_mixes():
    sources = [
        'pages.TemplateResponse(request, "card.html", {"note": note})',
        'pages.TemplateResponse(request, name="card.html", context={"note": note})',
        'pages.TemplateResponse("card.html", context={"note": note})',
        'pages.TemplateResponse("card.html", {"note": note}, status_code=200)',
    ]
    for source in sources:
        call = _call(source)
        assert sinks.template_name(call) == "card.html", source
        assert "note" in sinks.template_context(call), source
        assert "name" not in sinks.template_context(call), source


def test_template_response_context_from_a_local_dict():
    local = _locals(ctx='{"note": note, "title": "x"}', built="dict(note=note)")
    for source in [
        'pages.TemplateResponse(request=request, name="card.html", context=ctx)',
        'pages.TemplateResponse(request, "card.html", ctx)',
        'pages.TemplateResponse(request=request, name="card.html", context=built)',
    ]:
        context = sinks.template_context(_call(source), local)
        assert "note" in context and "context" not in context, source
    unknown = sinks.template_context(_call('pages.TemplateResponse(name="card.html", context=other)'), local)
    assert sorted(unknown) == ["context"]  # an unknown local is not guessed


def test_flask_name_keyword_stays_a_template_variable():
    call = _call('render_template("card.html", name=value)')
    assert sinks.template_name(call) == "card.html"
    assert sorted(sinks.template_context(call)) == ["name"]
    assert sinks.template_name(_call("render_template(name=value)")) is None
    flask_local = sinks.template_context(_call('render_template("card.html", context=ctx)'), _locals(ctx='{"a": b}'))
    assert sorted(flask_local) == ["context"]  # Flask behaviour unchanged: no local-dict resolution


FASTAPI_CARD = """
from fastapi import FastAPI, Query, Request
from fastapi.templating import Jinja2Templates

app = FastAPI()
pages = Jinja2Templates(directory="templates")


@app.get("/card")
def card(request: Request, note: str = Query(""), title: str = Query("")):
{body}
"""
CARD_TEMPLATE = "<h1>{{ title }}</h1>\n<p>{{ note|safe }}</p>\n"


def test_template_response_keyword_form_is_a_template_xss_sink(tmp_path):
    bodies = {
        "literal": '    return pages.TemplateResponse(request=request, name="card.html", '
        'context={"note": note, "title": title})',
        "local": '    ctx = {"note": note, "title": title}\n'
        '    return pages.TemplateResponse(request=request, name="card.html", context=ctx)',
    }
    for case, body in bodies.items():
        files = {"main.py": FASTAPI_CARD.format(body=body), "templates/card.html": CARD_TEMPLATE}
        findings = _findings(tmp_path, files, name=case)
        assert [(f.rule_id, f.taint.source_param) for f in findings] == [("py.xss.template.unescaped", "note")], case


def test_flask_name_variable_rendered_unescaped_is_still_a_finding(tmp_path):
    files = {
        "app.py": """
            from flask import Flask, render_template, request
            app = Flask(__name__)
            @app.route("/card")
            def card():
                return render_template("card.html", name=request.args.get("name", ""))
        """,
        "templates/card.html": "<p>{{ name|safe }}</p>",
    }
    findings = _findings(tmp_path, files)
    assert [(f.rule_id, f.taint.source_param) for f in findings] == [("py.xss.template.unescaped", "name")]
