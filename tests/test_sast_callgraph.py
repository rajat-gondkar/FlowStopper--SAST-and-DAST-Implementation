"""P1-A3 call graph: resolved edges and per-route reachable_functions (Owner: A)."""

from __future__ import annotations

from FlowStopper.sast.callgraph import annotate_reachable, build_call_graph, reachable_functions
from FlowStopper.sast.config import SastConfig
from FlowStopper.sast.index import build_index
from FlowStopper.sast.routes import extract_routes
from tests.sast_helpers import make_tree

# A Flask handler that reaches a helper in another file, through one more hop (Phase 1 exit check).
CROSS_FILE = {
    "shop/__init__.py": "",
    "shop/app.py": """
        from flask import Flask, request
        from shop.db import fetch_order

        app = Flask(__name__)


        @app.route("/api/orders")
        def get_orders():
            oid = request.args.get("id")
            return fetch_order(oid)
    """,
    "shop/db.py": """
        from shop.sqlutil import run_query


        def fetch_order(oid):
            return run_query("SELECT * FROM orders WHERE id = " + oid)
    """,
    "shop/sqlutil.py": """
        def run_query(sql):
            return execute(sql)


        def execute(sql):
            return sql
    """,
}


def test_handler_reaches_helper_in_another_file(tmp_path):
    index = build_index(make_tree(tmp_path, CROSS_FILE))
    graph = build_call_graph(index)
    assert graph["shop.app.get_orders"] == ["shop.db.fetch_order"]
    assert graph["shop.db.fetch_order"] == ["shop.sqlutil.run_query"]

    routes = {r.id: r for r in annotate_reachable(index, extract_routes(index))}
    reachable = routes["GET /api/orders"].reachable_functions
    # cross-file, multi-hop reachability from the handler (handler itself excluded)
    assert reachable == ["shop.db.fetch_order", "shop.sqlutil.execute", "shop.sqlutil.run_query"]


def test_depth_limit_is_respected(tmp_path):
    graph = {"f0": ["f1"], "f1": ["f2"], "f2": ["f3"], "f3": ["f4"], "f4": ["f5"]}
    assert reachable_functions(graph, "f0", 4) == ["f1", "f2", "f3", "f4"]
    assert reachable_functions(graph, "f0", 2) == ["f1", "f2"]
    assert reachable_functions(graph, "f0", 0) == []


def test_cycles_are_safe(tmp_path):
    files = {
        "m.py": """
            def a():
                return b()


            def b():
                return a()
        """,
    }
    index = build_index(make_tree(tmp_path, files))
    graph = build_call_graph(index)
    assert graph["m.a"] == ["m.b"] and graph["m.b"] == ["m.a"]
    assert reachable_functions(graph, "m.a", 4) == ["m.b"]  # start excluded; cycle does not loop forever


def test_method_and_instance_edges(tmp_path):
    files = {
        "svc.py": """
            class Repo:
                def find(self, key):
                    return key


            class Service:
                def __init__(self):
                    self.repo = Repo()

                def run(self):
                    repo = Repo()
                    return repo.find(self.load())

                def load(self):
                    return 1


            def entry():
                svc = Service()
                return svc.run()
        """,
    }
    index = build_index(make_tree(tmp_path, files))
    graph = build_call_graph(index)
    # instantiating a class with an __init__ adds an edge to it; Repo has none, so no edge there
    assert graph["svc.entry"] == ["svc.Service.__init__", "svc.Service.run"]
    assert graph["svc.Service.run"] == ["svc.Repo.find", "svc.Service.load"]  # local instance resolves find()
    assert graph["svc.Service.__init__"] == []  # Repo() -> no __init__ defined
    assert reachable_functions(graph, "svc.entry", 4) == [
        "svc.Repo.find",
        "svc.Service.__init__",
        "svc.Service.load",
        "svc.Service.run",
    ]


def test_unresolved_calls_are_ignored(tmp_path):
    files = {
        "m.py": """
            import os


            def handler(cb, name):
                cb()
                os.system("x")
                getattr(os, name)()
                return helper()


            def helper():
                return 1
        """,
    }
    index = build_index(make_tree(tmp_path, files))
    graph = build_call_graph(index, SastConfig())
    assert graph["m.handler"] == ["m.helper"]  # cb(), os.system, getattr(...)() all ignored
