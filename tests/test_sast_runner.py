"""P2-A6 SAST runner: findings built from taint + secrets + templates, and determinism (Owner: A)."""

from __future__ import annotations

from collections import Counter

import pytest

from FlowStopper import ids
from FlowStopper.cwe import get_cwe
from FlowStopper.models import Engine, Finding, SastResult, Severity
from FlowStopper.sast import index as index_module
from FlowStopper.sast.runner import run_sast
from tests.sast_helpers import make_tree

# Two handlers (a named parameter and an unrefined container), a cross-file SQL helper, a template
# rendered with |safe, and two hard-coded secrets: one finding of every kind the runner builds.
APP = {
    "shop/__init__.py": "",
    "shop/app.py": """
        from flask import Flask, render_template, request
        from shop.db import fetch_order, search

        app = Flask(__name__)
        FIELDS = ["created_from", "created_to"]


        @app.route("/api/orders")
        def get_orders():
            oid = request.args.get("id", "")
            return fetch_order(oid)


        @app.route("/api/report")
        def report():
            filters = request.args.to_dict()
            return search(filters.get(FIELDS[0], ""))


        @app.route("/product")
        def product():
            note = request.args.get("note", "")
            return render_template("product.html", note=note)
    """,
    "shop/db.py": """
        import sqlite3


        def connect():
            return sqlite3.connect("shop.db")


        def fetch_order(oid):
            return connect().execute(f"SELECT * FROM orders WHERE id = {oid}").fetchall()


        def search(term):
            return connect().execute("SELECT * FROM items WHERE name = '" + term + "'").fetchall()
    """,
    "shop/settings.py": """
        DEBUG = False
        PASSWORD = "hunter2"
        CLIENT_ID = "AKIAIOSFODNN7EXAMPLE"
    """,
    "shop/templates/product.html": "<div>{{ note|safe }}</div>\n",
}


@pytest.fixture(scope="module")
def result(tmp_path_factory) -> SastResult:
    return run_sast(make_tree(tmp_path_factory.mktemp("runner"), APP))


def _by_rule(result: SastResult, rule_id: str) -> Finding:
    found = [f for f in result.findings if f.rule_id == rule_id]
    assert len(found) == 1, f"{rule_id}: {[f.rule_id for f in result.findings]}"
    return found[0]


def test_every_kind_of_finding_is_emitted(result):
    assert {f.rule_id for f in result.findings} == {
        "py.sqli.fstring.execute",
        "py.sqli.concat.execute",
        "py.xss.template.unescaped",
        "py.secret.hardcoded.assign",
        "py.secret.hardcoded.prefix",
    }
    assert {f.engine for f in result.findings} == {Engine.SAST}
    assert {f.tool for f in result.findings} == {"FlowStopper-taint", "FlowStopper-secrets"}


def test_ids_come_from_the_shared_helper(result):
    for finding in result.findings:
        expected = ids.code_finding_id(
            Engine.SAST, finding.rule_id, finding.cwe, finding.code.file, finding.code.function, finding.code.line_start
        )
        assert finding.id == expected == ids.finding_id(finding)


def test_severity_comes_from_the_cwe_catalogue(result):
    for finding in result.findings:
        assert finding.severity is get_cwe(finding.cwe).severity
    assert _by_rule(result, "py.sqli.fstring.execute").severity is Severity.CRITICAL
    assert _by_rule(result, "py.xss.template.unescaped").severity is Severity.MEDIUM


def test_snippets_quote_the_offending_lines_with_one_line_of_context(result):
    secret = _by_rule(result, "py.secret.hardcoded.assign")
    assert secret.code.snippet.splitlines() == [
        "DEBUG = False",
        'PASSWORD = "hunter2"',
        'CLIENT_ID = "AKIAIOSFODNN7EXAMPLE"',
    ]
    sqli = _by_rule(result, "py.sqli.fstring.execute")
    assert sqli.code.snippet.startswith("def fetch_order(oid):")  # the line above the sink
    assert "SELECT * FROM orders" in sqli.code.snippet
    assert sqli.taint.source_location.snippet.strip() == 'oid = request.args.get("id", "")'
    assert all(len(f.code.snippet.splitlines()) <= 12 for f in result.findings)


def test_confidence_follows_the_documented_values(result):
    assert _by_rule(result, "py.sqli.fstring.execute").confidence == 0.9  # full chain, named param
    assert _by_rule(result, "py.sqli.concat.execute").confidence == 0.7  # unrefined container source
    assert _by_rule(result, "py.secret.hardcoded.assign").confidence == 0.7  # name-only match
    assert _by_rule(result, "py.secret.hardcoded.prefix").confidence == 0.9  # provider prefix


def test_taint_blocks_carry_the_chain_and_the_entry_route(result):
    sqli = _by_rule(result, "py.sqli.fstring.execute")
    assert sqli.taint.call_chain == ["shop.app.get_orders", "shop.db.fetch_order"]
    assert sqli.taint.entry_routes == ["GET /api/orders"]
    assert (sqli.taint.source_param, sqli.taint.source_kind.value) == ("id", "query")
    assert _by_rule(result, "py.sqli.concat.execute").taint.source_param is None
    assert all(f.taint is None for f in result.findings if f.tool == "FlowStopper-secrets")


def test_findings_are_sorted_by_location_then_rule(result):
    keys = [(f.code.file, f.code.line_start, f.cwe, f.rule_id, f.id) for f in result.findings]
    assert keys == sorted(keys)


def test_stats_are_counts_only(result):
    stats = result.stats
    assert stats["routes"] == 3
    assert stats["findings"] == len(result.findings) == stats["taint_findings"] + stats["secret_findings"]
    assert (stats["taint_findings"], stats["secret_findings"], stats["template_findings"]) == (3, 2, 1)
    assert stats["functions_analysed"] == stats["functions"]
    assert stats["summary_iterations"] >= 1
    assert all(isinstance(v, int) for k, v in stats.items() if k != "skipped")


def test_run_sast_parses_each_python_file_once(tmp_path, monkeypatch):
    # P4-A3: every later stage (routes, call graph, taint, secrets, snippets) reuses the parsed tree.
    calls: Counter[str] = Counter()
    original = index_module.parse_source

    def counting(source: str, filename: str):
        calls[filename] += 1
        return original(source, filename)

    monkeypatch.setattr(index_module, "parse_source", counting)
    run_sast(make_tree(tmp_path, APP))
    expected = {path: 1 for path in APP if path.endswith(".py")}
    assert dict(calls) == expected


def test_two_scans_of_one_tree_serialise_identically(tmp_path):
    root = make_tree(tmp_path, APP)
    assert run_sast(root).model_dump_json() == run_sast(root).model_dump_json()
