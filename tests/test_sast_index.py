"""P1-A1 source index: discovery, parsing, symbol table, import resolution (Owner: A)."""

from __future__ import annotations

import ast
import logging
import sys

import pytest

from FlowStopper.sast.config import SastConfig
from FlowStopper.sast.index import ProjectIndex, build_index, discover_files, module_name, resolve_call
from tests.sast_helpers import make_tree


def _calls(index: ProjectIndex, qualname: str) -> dict[str, str | None]:
    """{callee source text: resolved name} for every call inside one function's body."""
    fn = index.functions[qualname]
    ctx = index.context(fn.module, fn)
    return {ast.unparse(n.func): resolve_call(n, ctx) for n in ast.walk(fn.node) if isinstance(n, ast.Call)}


# --------------------------------------------------------------------------- discovery and parsing
def test_discovery_prunes_vendor_dirs_and_skips_large_files(tmp_path):
    make_tree(
        tmp_path,
        {
            "app.py": "x = 1\n",
            "pkg/__init__.py": "",
            "pkg/mod.py": "y = 2\n",
            "venv/lib/a.py": "",
            ".venv/b.py": "",
            "lib/python3.12/site-packages/c.py": "",
            "pkg/__pycache__/d.py": "",
            ".git/hooks/e.py": "",
            "web/node_modules/f.py": "",
            "README.md": "not python",
        },
    )
    (tmp_path / "big.py").write_text("x = 1\n" + "#" * 1_100_000 + "\n")
    files, skipped = discover_files(tmp_path)
    root = tmp_path.resolve()
    assert [p.relative_to(root).as_posix() for p in files] == ["app.py", "pkg/__init__.py", "pkg/mod.py"]
    assert [s.file for s in skipped] == ["big.py"] and "larger than 1000000 bytes" in skipped[0].reason
    files, skipped = discover_files(tmp_path, SastConfig(max_file_bytes=5))
    assert [p.name for p in files] == ["__init__.py"]  # only the empty file is under 5 bytes


def test_syntax_errors_are_logged_and_skipped(tmp_path, caplog):
    make_tree(
        tmp_path,
        {"good.py": "def ok():\n    return 1\n", "bad.py": "def broken(:\n    pass\n", "py2.py": "print 'hi'\n"},
    )
    with caplog.at_level(logging.WARNING, logger="FlowStopper.sast.index"):
        index = build_index(tmp_path)
    assert list(index.modules) == ["good"] and "good.ok" in index.functions
    assert [s.file for s in index.skipped] == ["bad.py", "py2.py"]
    assert all(s.reason.startswith("syntax error at line 1") for s in index.skipped)
    assert "bad.py" in caplog.text and "py2.py" in caplog.text
    stats = index.stats()
    assert (stats["files_discovered"], stats["files_parsed"], stats["files_skipped"]) == (3, 1, 2)


def test_coding_cookie_and_bom_are_honoured(tmp_path):
    (tmp_path / "latin.py").write_bytes("# -*- coding: latin-1 -*-\nNAME = 'caf\xe9'\n".encode("latin-1"))
    (tmp_path / "bom.py").write_bytes(b"\xef\xbb\xbfdef f():\n    return 1\n")
    index = build_index(tmp_path)
    assert index.variables["latin.NAME"].value.value == "caf\xe9"
    assert "bom.f" in index.functions


def test_index_never_imports_or_executes_target_code(tmp_path):
    """R7: building the index must not run a single line of the scanned project."""
    marker = tmp_path / "executed.txt"
    src = make_tree(
        tmp_path / "src",
        {
            "fs_r7_probe.py": f"open({str(marker)!r}, 'w').write('ran')\nraise SystemExit('imported')\n",
            "fs_r7_pkg/__init__.py": f"import pathlib\npathlib.Path({str(marker)!r}).touch()\n",
        },
    )
    index = build_index(src)
    assert {"fs_r7_probe", "fs_r7_pkg"} <= set(index.modules)
    assert not marker.exists()
    assert "fs_r7_probe" not in sys.modules and "fs_r7_pkg" not in sys.modules
    assert not list(src.rglob("__pycache__")), "no bytecode may be written for target files"


# --------------------------------------------------------------------------- symbol table
@pytest.mark.parametrize(
    ("rel", "expected"),
    [("app.py", ("app", False)), ("pkg/__init__.py", ("pkg", True)), ("pkg/sub/mod.py", ("pkg.sub.mod", False))],
)
def test_module_names(rel, expected):
    assert module_name(rel) == expected


SYMBOLS = '''
import functools


def login_required(f):
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        return f(*args, **kwargs)

    return wrapper


class Base:
    def helper(self, x, *, flag=False):
        return x


class Service(Base):
    """Doc."""

    limit = 10

    @staticmethod
    def make(a, b=1, *rest, c, **extra):
        return a

    @login_required
    async def run(self, item_id: int):
        def inner():
            return item_id

        return inner()

    class Meta:
        def describe(self):
            return "meta"
'''


def test_symbol_table_has_qualified_names_spans_params_and_decorators(tmp_path):
    index = build_index(make_tree(tmp_path, {"pkg/__init__.py": "", "pkg/svc.py": SYMBOLS}))
    assert sorted(index.classes) == ["pkg.svc.Base", "pkg.svc.Service", "pkg.svc.Service.Meta"]
    assert sorted(index.functions) == [
        "pkg.svc.Base.helper",
        "pkg.svc.Service.Meta.describe",
        "pkg.svc.Service.make",
        "pkg.svc.Service.run",
        "pkg.svc.Service.run.inner",
        "pkg.svc.login_required",
        "pkg.svc.login_required.wrapper",
    ]
    make = index.functions["pkg.svc.Service.make"]
    assert make.params == ["a", "b", "rest", "c", "extra"]
    assert make.decorators == ["staticmethod"] and make.is_staticmethod and make.class_name == "pkg.svc.Service"
    run = index.functions["pkg.svc.Service.run"]
    assert run.is_async and run.is_method and run.decorators == ["login_required"]
    assert (run.file, run.line_start, run.line_end, run.params) == ("pkg/svc.py", 27, 31, ["self", "item_id"])
    inner = index.functions["pkg.svc.Service.run.inner"]
    assert inner.parent == run.qualname and inner.class_name is None and not inner.is_method
    assert index.functions["pkg.svc.login_required.wrapper"].decorators == ["functools.wraps"]
    assert index.functions["pkg.svc.Base.helper"].params == ["self", "x", "flag"]
    svc = index.classes["pkg.svc.Service"]
    assert (svc.line_start, svc.line_end, svc.bases) == (17, 35, ["pkg.svc.Base"])
    assert svc.methods == {"make": "pkg.svc.Service.make", "run": "pkg.svc.Service.run"}
    assert svc.nested_classes == {"Meta": "pkg.svc.Service.Meta"} and "limit" in svc.attributes
    assert index.function_at("pkg/svc.py", 29).qualname == "pkg.svc.Service.run.inner"
    assert index.function_at("pkg/svc.py", 30).qualname == "pkg.svc.Service.run"
    assert index.function_at("pkg/svc.py", 21) is None  # class body, outside any function


def test_root_package_prefixes_module_names(tmp_path):
    root = make_tree(
        tmp_path / "shop",
        {
            "__init__.py": "",
            "db.py": "def q():\n    return 1\n",
            "views.py": "from shop.db import q\n\n\ndef v():\n    return q()\n",
        },
    )
    index = build_index(root)
    assert sorted(index.modules) == ["shop", "shop.db", "shop.views"]
    assert index.modules["shop.views"].file == "views.py"
    assert _calls(index, "shop.views.v") == {"q": "shop.db.q"}


# --------------------------------------------------------------------------- import resolution
IMPORTS = {
    "app.py": """
        import os
        import os.path as osp
        import subprocess as sp
        import pkg.helpers
        from flask import redirect as go, request
        from pkg import helpers as h
        from pkg.helpers import build_query as bq
        from pkg import reexported
        from utils.shell import run_ping


        def handler():
            os.system("x")
            osp.join("a", "b")
            sp.run(["ls"])
            pkg.helpers.build_query(1)
            h.build_query(2)
            bq(3)
            reexported(4)
            run_ping("h")
            go(request.args.get("next"))
            open("f")
    """,
    "pkg/__init__.py": "from .impl import reexported\n",
    "pkg/helpers.py": "def build_query(x):\n    return x\n",
    "pkg/impl.py": "def reexported(x):\n    return x\n",
    "utils/shell.py": "def run_ping(host):\n    return host\n",  # namespace package: no __init__.py
}


def test_import_forms_resolve_to_canonical_names(tmp_path):
    index = build_index(make_tree(tmp_path, IMPORTS))
    assert _calls(index, "app.handler") == {
        "os.system": "os.system",
        "osp.join": "os.path.join",
        "sp.run": "subprocess.run",
        "pkg.helpers.build_query": "pkg.helpers.build_query",
        "h.build_query": "pkg.helpers.build_query",
        "bq": "pkg.helpers.build_query",
        "reexported": "pkg.impl.reexported",
        "run_ping": "utils.shell.run_ping",
        "go": "flask.redirect",
        "request.args.get": "flask.request.args.get",
        "open": "builtins.open",
    }
    assert index.canonical("pkg.missing") is None  # inside the project, defined nowhere: no guess


RELATIVE = {
    "shop/__init__.py": "",
    "shop/db.py": "def fetch(x):\n    return x\n",
    "shop/views/__init__.py": "from .orders import bp\n",
    "shop/views/helpers.py": "def fmt(x):\n    return x\n",
    "shop/views/orders.py": """
        from .. import db
        from ..db import fetch as f2
        from . import helpers
        from .helpers import fmt

        bp = object()


        def view():
            db.fetch(1)
            f2(2)
            helpers.fmt(3)
            fmt(4)
    """,
    "other.py": "from shop.views import bp\nfrom shop import views\n",
}


def test_relative_imports_and_init_reexports(tmp_path):
    index = build_index(make_tree(tmp_path, RELATIVE))
    assert _calls(index, "shop.views.orders.view") == {
        "db.fetch": "shop.db.fetch",
        "f2": "shop.db.fetch",
        "helpers.fmt": "shop.views.helpers.fmt",
        "fmt": "shop.views.helpers.fmt",
    }
    assert index.canonical("other.bp") == "shop.views.orders.bp"
    assert index.canonical("shop.views.bp") == "shop.views.orders.bp"
    assert index.canonical("other.views") == "shop.views"


STAR = {
    "lib.py": "__all__ = ['public']\n\n\ndef public():\n    return 1\n\n\ndef hidden():\n    return 2\n",
    "flat.py": "def a():\n    return 1\n\n\ndef _private():\n    return 2\n",
    "app.py": """
        from lib import *
        from flat import *


        def use():
            public()
            hidden()
            a()
            _private()
    """,
    "ext.py": """
        from flask import *


        def view():
            return redirect(url_for("x"))
    """,
}


def test_star_imports_respect_all_and_public_names(tmp_path):
    index = build_index(make_tree(tmp_path, STAR))
    assert _calls(index, "app.use") == {"public": "lib.public", "hidden": None, "a": "flat.a", "_private": None}
    # a bare name that is neither defined, imported nor a builtin can only come from the one star import
    assert _calls(index, "ext.view") == {"redirect": "flask.redirect", "url_for": "flask.url_for"}


def test_try_except_fallback_import_does_not_shadow_the_primary(tmp_path):
    src = """
        try:
            from fastjson import loads
        except ImportError:
            from json import loads


        def f():
            return loads("1")
    """
    index = build_index(make_tree(tmp_path, {"m.py": src}))
    assert _calls(index, "m.f") == {"loads": "fastjson.loads"}


SIBLINGS = {
    "src/app.py": """
        import email
        import config
        from db import query


        def handler():
            query(config.SQL)
            email.message_from_string("x")
    """,
    "src/db.py": "def query(sql):\n    return sql\n",
    "src/config.py": "SQL = 'select 1'\n",
    "src/email.py": "def message_from_string(s):\n    return s\n",
}


def test_sibling_imports_fall_back_to_the_importing_directory_but_never_shadow_stdlib(tmp_path):
    index = build_index(make_tree(tmp_path, SIBLINGS))
    assert _calls(index, "src.app.handler") == {
        "query": "src.db.query",
        "email.message_from_string": "email.message_from_string",
    }
    assert index.canonical("src.app.config") == "src.config"


def test_module_level_aliases_and_constructor_targets(tmp_path):
    files = {
        "core.py": "from flask import Flask\n\napp = Flask(__name__)\napplication = app\n",
        "wsgi.py": "from core import application\n",
    }
    index = build_index(make_tree(tmp_path, files))
    assert index.canonical("wsgi.application") == "core.app"
    assert index.call_target(index.variables["core.app"].value, "core") == "flask.Flask"


# --------------------------------------------------------------------------- no guessing on locals
LOCALS = {
    "helpers.py": "def run(x):\n    return x\n",
    "app.py": """
        import helpers


        def shadowed(helpers):
            return helpers.run(1)


        def assigned():
            helpers = get()
            return helpers.run(2)


        def dynamic(name):
            getattr(helpers, name)()
            (lambda: 1)()
            get().run()


        def uses_global():
            global helpers
            return helpers.run(3)


        def closure():
            def inner():
                return helpers.run(4)

            return inner()


        def get():
            return None
    """,
}


def test_local_variables_and_dynamic_callees_are_not_guessed(tmp_path):
    index = build_index(make_tree(tmp_path, LOCALS))
    assert _calls(index, "app.shadowed") == {"helpers.run": None}
    assert _calls(index, "app.assigned") == {"get": "app.get", "helpers.run": None}
    assert _calls(index, "app.dynamic") == {
        "getattr(helpers, name)": None,
        "getattr": "builtins.getattr",
        "lambda: 1": None,
        "get().run": None,
        "get": "app.get",
    }
    assert _calls(index, "app.uses_global") == {"helpers.run": "helpers.run"}
    assert _calls(index, "app.closure.inner") == {"helpers.run": "helpers.run"}
    assert _calls(index, "app.closure") == {"inner": "app.closure.inner", "helpers.run": "helpers.run"}


# --------------------------------------------------------------------------- classes and methods
CLASSES = {
    "base.py": """
        class Repo:
            def find(self, key):
                return key

            def save(self, obj):
                return obj
    """,
    "svc.py": """
        from base import Repo


        class OrderRepo(Repo):
            def find(self, key):
                return super().find(key)

            @classmethod
            def build(cls):
                return cls.create()

            @classmethod
            def create(cls):
                return cls()

            def store(self, obj):
                self.save(obj)
                return self.find(obj)


        repo = OrderRepo()


        def direct():
            OrderRepo().store(1)
            OrderRepo.build()
            repo.store(2)
    """,
    "views.py": """
        import svc
        from svc import repo


        def view():
            repo.find(1)
            svc.repo.store(2)
    """,
}


def test_methods_resolve_through_self_cls_super_bases_and_instances(tmp_path):
    index = build_index(make_tree(tmp_path, CLASSES))
    assert index.classes["svc.OrderRepo"].bases == ["base.Repo"]
    assert index.mro("svc.OrderRepo") == ["svc.OrderRepo", "base.Repo"]
    assert _calls(index, "svc.OrderRepo.find") == {"super().find": "base.Repo.find", "super": "builtins.super"}
    assert _calls(index, "svc.OrderRepo.build") == {"cls.create": "svc.OrderRepo.create"}
    assert _calls(index, "svc.OrderRepo.create") == {"cls": "svc.OrderRepo"}
    assert _calls(index, "svc.OrderRepo.store") == {"self.save": "base.Repo.save", "self.find": "svc.OrderRepo.find"}
    assert _calls(index, "svc.direct") == {
        "OrderRepo().store": "svc.OrderRepo.store",
        "OrderRepo": "svc.OrderRepo",
        "OrderRepo.build": "svc.OrderRepo.build",
        "repo.store": "svc.OrderRepo.store",
    }
    assert _calls(index, "views.view") == {"repo.find": "svc.OrderRepo.find", "svc.repo.store": "svc.OrderRepo.store"}


def test_local_types_hook_resolves_tracked_instances(tmp_path):
    index = build_index(make_tree(tmp_path, CLASSES))
    fn = index.functions["svc.direct"]
    call = ast.parse("tracked.store(1)").body[0].value
    assert resolve_call(call, index.context("svc", fn)) is None  # unknown name
    assert resolve_call(call, index.context("svc", fn, {"tracked": "svc.OrderRepo"})) is None  # not a local
    fn_local = index.functions["svc.OrderRepo.store"]  # `obj` is a local there
    obj_call = ast.parse("obj.find(1)").body[0].value
    assert resolve_call(obj_call, index.context("svc", fn_local)) is None
    assert resolve_call(obj_call, index.context("svc", fn_local, {"obj": "base.Repo"})) == "base.Repo.find"
