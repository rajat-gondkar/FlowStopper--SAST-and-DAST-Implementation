"""Mock A products/misc blueprint (prefix /api). Owner: Dev A.

Planted: M05 (command injection via /api/ping), R03 (verbose error via /api/crash),
D01 (safe query via /api/products), D04 (safe subprocess via /api/diag), D07 (JSON echo via /api/echo).
"""

from db import fetch_product
from flask import Blueprint, jsonify, request
from utils.shell import ping_host, safe_ping

bp = Blueprint("products", __name__, url_prefix="/api")


@bp.route("/products")
def list_products():
    # D01 (decoy): parameterised query — safe.
    pid = request.args.get("id", "")
    rows = fetch_product(pid)
    return jsonify([dict(r) for r in rows])


@bp.route("/ping")
def ping():
    # M05 (CWE-78): host reaches os.system via utils.shell.ping_host.
    host = request.args.get("host", "")
    code = ping_host(host)
    return jsonify({"host": host, "exit": code})


@bp.route("/diag")
def diag():
    # D04 (decoy): list-form subprocess with shell=False — safe.
    host = request.args.get("host", "127.0.0.1")
    safe_ping(host)
    return jsonify({"ok": True})


@bp.route("/echo")
def echo():
    # D07 (decoy): request value reflected as JSON, not HTML — safe (not XSS).
    q = request.args.get("q", "")
    return jsonify({"echo": q})


@bp.route("/crash")
def crash():
    # R03 (CWE-209): division by zero surfaces a verbose traceback at runtime.
    n = int(request.args.get("n", "0"))
    return jsonify({"result": 10 / n})
