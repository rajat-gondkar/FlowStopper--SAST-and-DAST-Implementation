"""Mock A users/catalog blueprint (no prefix). Owner: Dev A.

Planted: M02 (SQLi login), M03 (reflected XSS /search), M04 (template |safe /product/<id>),
M09 (open redirect /go), M10 (post-login redirect). Decoys: D03 (escape), D06 (allow-list redirect).
"""

import html
from urllib.parse import urlparse

from db import find_user
from flask import (
    Blueprint,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

bp = Blueprint("users", __name__)

ALLOWED_HOSTS = {"localhost", "127.0.0.1", "shoplite.example"}


@bp.route("/")
def index():
    session["visited"] = True  # sets the (weakly configured, R02) session cookie
    return render_template("index.html")


@bp.route("/about")
def about():
    return render_template("index.html")


@bp.route("/health")
def health():
    return jsonify({"status": "ok"})


@bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        user = find_user(username, password)  # M02 (CWE-89): username concatenated into SQL
        if user:
            session["user"] = username
        next_url = request.args.get("next", "/")
        return redirect(next_url)  # M10 (CWE-601): post-login redirect to an unvalidated target
    return render_template("login.html")


@bp.route("/search")
def search():
    # M03 (CWE-79): request value reflected into an HTML response via an f-string.
    q = request.args.get("q", "")
    return f"<html><body><h1>Results for {q}</h1></body></html>"


@bp.route("/greet")
def greet():
    # D03 (decoy): value escaped with html.escape before being returned — safe.
    name = request.args.get("name", "")
    return f"<p>Hello {html.escape(name)}</p>"


@bp.route("/product/<id>")
def product(id):
    # M04 (CWE-79): note rendered with |safe in product.html.
    note = request.args.get("note", "")
    return render_template("product.html", pid=id, note=note)


@bp.route("/go")
def go():
    # M09 (CWE-601): next reflected straight into redirect() with no validation.
    target = request.args.get("next", "/")
    return redirect(target)


@bp.route("/redirect")
def safe_redirect():
    # D06 (decoy): redirect target validated against an allow-list — safe.
    target = request.args.get("url", "/")
    host = urlparse(target).netloc
    if host and host not in ALLOWED_HOSTS:
        return redirect("/")
    return redirect(target)


@bp.route("/profile")
def profile():
    return jsonify({"user": session.get("user")})


@bp.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("users.index"))
