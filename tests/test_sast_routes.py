"""P1-A2 route extractors: Flask, FastAPI, Django, and the resolver (Owner: A)."""

from __future__ import annotations

import pytest

from FlowStopper.sast.index import build_index
from FlowStopper.sast.routes import extract_routes
from FlowStopper.sast.routes.resolver import join_paths, split_params, template_regex
from tests.conftest import ROOT
from tests.sast_helpers import make_tree


def routes_of(tmp_path, files: dict[str, str]) -> dict:
    index = build_index(make_tree(tmp_path, files))
    return {r.id: r for r in extract_routes(index)}


def params(route) -> set[tuple[str, str]]:
    return {(p.name, p.location.value) for p in route.params}


# --------------------------------------------------------------------------- resolver
@pytest.mark.parametrize(
    ("template", "regex"),
    [
        ("/api/items", "^/api/items/?$"),
        ("/api/items/", "^/api/items/?$"),
        ("/", "^/?$"),
        ("/users/<int:id>", "^/users/(?P<id>[^/]+)/?$"),
        ("/docs/<path:name>", "^/docs/(?P<name>.+)/?$"),
        ("/items/{item_id}", "^/items/(?P<item_id>[^/]+)/?$"),
        ("/files/{p:path}", "^/files/(?P<p>.+)/?$"),
        ("/v1.0/x", r"^/v1\.0/x/?$"),
    ],
)
def test_template_regex(template, regex):
    assert template_regex(template) == regex


def test_template_regex_matches_concrete_paths():
    import re

    rx = re.compile(template_regex("/api/items/<int:item_id>"))
    assert rx.match("/api/items/42") and rx.match("/api/items/42/")
    assert not rx.match("/api/items/42/extra") and not rx.match("/api/items")


def test_split_params_and_join():
    assert split_params("/a/<int:id>/<path:rest>/{q}") == [("id", False), ("rest", True), ("q", False)]
    assert join_paths("/api/v2", "/orders/") == "/api/v2/orders"
    assert join_paths("", "/x") == "/x"
    assert join_paths(None, None) == "/"
    assert join_paths("/a/", "/b", "c") == "/a/b/c"


# --------------------------------------------------------------------------- Flask
FLASK_APP = {
    "shop/__init__.py": "",
    "shop/app.py": """
        from flask import Flask
        from shop.views.orders import bp as orders_bp
        from shop.views.api import api


        def health():
            return "ok"


        def create_app():
            app = Flask(__name__)
            app.register_blueprint(orders_bp)
            app.register_blueprint(api, url_prefix="/api/v2")
            app.add_url_rule("/health", view_func=health)
            return app
    """,
    "shop/views/__init__.py": "",
    "shop/views/orders.py": """
        from flask import Blueprint, request
        from flask_login import login_required

        bp = Blueprint("orders", __name__, url_prefix="/orders")


        @bp.route("/")
        def list_orders():
            status = request.args.get("status")
            return status


        @bp.route("/<int:order_id>", methods=["GET", "DELETE"])
        @login_required
        def get_order(order_id):
            return str(order_id)


        @bp.post("/")
        def create_order():
            data = request.get_json()
            return data["name"]
    """,
    "shop/views/api.py": """
        from flask import Blueprint, request
        from flask.views import MethodView

        api = Blueprint("api", __name__)
        items = Blueprint("items", __name__, url_prefix="/items")
        api.register_blueprint(items)


        @items.route("/search")
        def search():
            q = request.args["q"]
            request.headers.get("X-Token")
            request.cookies.get("sid")
            return q


        class ItemView(MethodView):
            def get(self, item_id):
                return item_id

            def post(self):
                return "created"


        items.add_url_rule("/<item_id>", view_func=ItemView.as_view("item"))
    """,
}


def test_flask_decorators_blueprints_prefixes_and_params(tmp_path):
    r = routes_of(tmp_path, FLASK_APP)
    assert set(r) == {
        "GET /orders",
        "POST /orders",
        "GET /orders/<int:order_id>",
        "DELETE /orders/<int:order_id>",
        "GET /api/v2/items/search",
        "GET /api/v2/items/<item_id>",
        "POST /api/v2/items/<item_id>",
        "GET /health",
    }
    assert r["GET /orders"].handler == "shop.views.orders.list_orders"
    assert params(r["GET /orders"]) == {("status", "query")}
    assert params(r["POST /orders"]) == {("name", "json")}
    assert r["GET /orders/<int:order_id>"].auth_required is True
    assert r["DELETE /orders/<int:order_id>"].auth_required is True
    assert r["GET /orders"].auth_required is False
    assert params(r["GET /orders/<int:order_id>"]) == {("order_id", "path")}
    assert params(r["GET /api/v2/items/search"]) == {("q", "query"), ("X-Token", "header"), ("sid", "cookie")}
    assert r["GET /api/v2/items/<item_id>"].handler == "shop.views.api.ItemView.get"
    assert r["POST /api/v2/items/<item_id>"].handler == "shop.views.api.ItemView.post"
    assert ("item_id", "path") in params(r["GET /api/v2/items/<item_id>"])
    assert r["GET /health"].handler == "shop.app.health"


def test_flask_module_level_app_and_verb_shortcuts(tmp_path):
    files = {
        "srv.py": """
            from flask import Flask, request

            app = Flask(__name__)


            @app.get("/ping")
            def ping():
                return "pong"


            @app.route("/submit", methods=["POST"])
            def submit():
                return request.form.get("value")
        """,
    }
    r = routes_of(tmp_path, files)
    assert set(r) == {"GET /ping", "POST /submit"}
    assert params(r["POST /submit"]) == {("value", "form")}


def test_flask_routes_registered_on_a_function_parameter(tmp_path):
    files = {
        "portal/__init__.py": "",
        # loaded dynamically: no static call site, so the parameter's routes mount at the root
        "portal/plugins/notes.py": """
            from flask import request


            def setup(server):
                @server.route("/notes/view", methods=["GET"])
                def view_note():
                    return view_note_submit()

                @server.route("/notes/view", methods=["POST"])
                def view_note_submit():
                    return request.form.get("title")

                server.add_url_rule("/notes/count", view_func=view_note)
        """,
        # a static call site passing a blueprint: the parameter's routes take that blueprint's prefix
        "portal/plugins/tags.py": """
            from flask import Blueprint


            def attach(target):
                @target.get("/tags")
                def list_tags():
                    return "tags"


            tags_bp = Blueprint("tags", __name__, url_prefix="/v2")
            attach(target=tags_bp)
        """,
        "portal/main.py": """
            import importlib

            from flask import Flask

            server = Flask(__name__)
            importlib.import_module("portal.plugins.notes").setup(server)
        """,
    }
    r = routes_of(tmp_path, files)
    assert set(r) == {"GET /notes/view", "POST /notes/view", "GET /notes/count", "GET /v2/tags"}
    assert r["POST /notes/view"].handler == "portal.plugins.notes.setup.view_note_submit"
    assert params(r["POST /notes/view"]) == {("title", "form")}
    assert r["GET /v2/tags"].handler == "portal.plugins.tags.attach.list_tags"


def test_parameter_router_outside_flask_is_not_a_flask_route(tmp_path):
    files = {
        "svc.py": """
            from fastapi import FastAPI

            api = FastAPI()


            def mount(router):
                @router.get("/status")
                def status():
                    return "ok"
        """,
    }
    assert set(routes_of(tmp_path, files)) == set()


# --------------------------------------------------------------------------- FastAPI
FASTAPI_APP = {
    "api/__init__.py": "",
    "api/main.py": """
        from fastapi import FastAPI, APIRouter, Query, Depends
        from api.models import Item
        from api.deps import get_current_user

        app = FastAPI()
        router = APIRouter(prefix="/items")


        @app.get("/ping")
        def ping():
            return "pong"


        @router.get("/{item_id}")
        def read_item(item_id: int, verbose: bool = False, q: str = Query(None)):
            return item_id


        @router.post("/")
        def create_item(item: Item, user=Depends(get_current_user)):
            return item


        app.include_router(router, prefix="/api")
    """,
    "api/models.py": """
        from pydantic import BaseModel


        class Item(BaseModel):
            name: str
            price: float
            tags: list = []
    """,
    "api/deps.py": "def get_current_user():\n    return 'u'\n",
}


def test_fastapi_router_prefix_signature_and_pydantic_body(tmp_path):
    r = routes_of(tmp_path, FASTAPI_APP)
    assert set(r) == {"GET /ping", "GET /api/items/{item_id}", "POST /api/items"}
    read = r["GET /api/items/{item_id}"]
    assert read.handler == "api.main.read_item"
    assert params(read) == {("item_id", "path"), ("verbose", "query"), ("q", "query")}
    create = r["POST /api/items"]
    assert params(create) == {("name", "json"), ("price", "json"), ("tags", "json")}
    assert create.auth_required is True
    assert read.auth_required is False


def test_fastapi_annotated_and_security(tmp_path):
    files = {
        "svc.py": """
            from typing import Annotated
            from fastapi import FastAPI, Header, Security
            from fastapi.security import APIKeyHeader

            app = FastAPI()
            key = APIKeyHeader(name="X-Key")


            @app.get("/a/{name}")
            def a(name: str, x_token: Annotated[str, Header()], auth=Security(key)):
                return name
        """,
    }
    r = routes_of(tmp_path, files)
    route = r["GET /a/{name}"]
    assert params(route) == {("name", "path"), ("x_token", "header")}
    assert route.auth_required is True


# --------------------------------------------------------------------------- Django
DJANGO_APP = {
    "proj/__init__.py": "",
    "proj/urls.py": """
        from django.urls import path, re_path, include
        from proj import views

        urlpatterns = [
            path("home/", views.home),
            re_path(r"^articles/(?P<year>[0-9]{4})/$", views.year_archive),
            path("blog/", include("proj.blog_urls")),
        ]
    """,
    "proj/blog_urls.py": """
        from django.urls import path
        from proj.views import PostView

        urlpatterns = [
            path("<int:post_id>/", PostView.as_view()),
        ]
    """,
    "proj/views.py": """
        from django.views import View


        def home(request):
            return request.GET.get("q")


        def year_archive(request, year):
            return year


        class PostView(View):
            def get(self, request, post_id):
                return post_id

            def post(self, request, post_id):
                return post_id
    """,
}


def test_django_path_repath_include_and_cbv(tmp_path):
    r = routes_of(tmp_path, DJANGO_APP)
    assert set(r) == {
        "GET /home",
        "GET /articles/<year>",
        "GET /blog/<int:post_id>",
        "POST /blog/<int:post_id>",
    }
    assert r["GET /home"].handler == "proj.views.home"
    assert params(r["GET /home"]) == {("q", "query")}
    assert params(r["GET /articles/<year>"]) == {("year", "path")}
    assert r["GET /blog/<int:post_id>"].handler == "proj.views.PostView.get"
    assert params(r["POST /blog/<int:post_id>"]) == {("post_id", "path")}


# --------------------------------------------------------------------------- real app sanity
BENCH_SRC = ROOT / "bench" / "vulnerable-flask-app" / "src"


def test_bench_flask_app_routes():
    if not BENCH_SRC.is_dir():
        pytest.skip("benchmark app not fetched (git-ignored); run `make bench-fetch` to enable")
    index = build_index(BENCH_SRC)
    ids = {r.id for r in extract_routes(index)}
    assert ids == {
        "GET /",
        "POST /register/user",
        "POST /register/customer",
        "POST /login",
        "POST /fetch/customer",
        "GET /get/<cust_id>",
        "POST /search",
        "GET /xxe",
        "GET /xxe_uploader",
        "POST /xxe_uploader",
        "GET /yaml",
        "POST /yaml_hammer",
    }
    by_id = {r.id: r for r in extract_routes(index)}
    assert ("search", "json") in params(by_id["POST /search"])
    assert ("cust_id", "path") in params(by_id["GET /get/<cust_id>"])
