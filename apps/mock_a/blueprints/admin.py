"""Mock A admin blueprint (prefix /admin). Owner: Dev A. Planted: M06 (command injection)."""

import subprocess

from flask import Blueprint, jsonify, request

bp = Blueprint("admin", __name__, url_prefix="/admin")


@bp.route("/backup", methods=["POST"])
def backup():
    # M06 (CWE-78): name concatenated into a shell command run with shell=True.
    name = request.form.get("name", "")
    subprocess.run("tar czf /tmp/" + name + ".tgz /var/data", shell=True)
    return jsonify({"status": "ok"})


@bp.route("/status")
def status():
    return jsonify({"status": "running"})


@bp.route("/jobs")
def jobs():
    return jsonify({"jobs": []})
