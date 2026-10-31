"""Mock A orders blueprint (prefix /api). Owner: Dev A. Planted: M01 (SQLi), D02 (safe)."""

from db import fetch_order, fetch_order_by_int
from flask import Blueprint, jsonify, request

bp = Blueprint("orders", __name__, url_prefix="/api")


@bp.route("/orders")
def get_orders():
    # M01 (CWE-89): id flows cross-file into db.fetch_order, which builds SQL with an f-string.
    order_id = request.args.get("id", "")
    rows = fetch_order(order_id)
    return jsonify([dict(r) for r in rows])


@bp.route("/orders/<int:order_id>")
def get_order(order_id):
    # D02 (decoy): the path converter guarantees an int, and db.fetch_order_by_int re-casts it.
    rows = fetch_order_by_int(order_id)
    return jsonify([dict(r) for r in rows])
