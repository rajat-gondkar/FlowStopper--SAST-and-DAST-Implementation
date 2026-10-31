"""Mock A files blueprint (no prefix). Owner: Dev A.

Planted: M07 (path traversal via /download + open), M08 (path traversal via /docs/<path:name> + send_file).
Decoy: D05 (secure_filename + send_from_directory via /safe-download).
"""

import os

from flask import Blueprint, request, send_file, send_from_directory
from werkzeug.utils import secure_filename

bp = Blueprint("files", __name__)

BASE_DIR = os.path.join(os.path.dirname(__file__), "..", "data")
DOCS_DIR = os.path.join(os.path.dirname(__file__), "..", "docs_store")


def ensure_dirs():
    """Create the served directories with a benign sample file so file serving (and its bugs) work."""
    for directory in (BASE_DIR, DOCS_DIR):
        os.makedirs(directory, exist_ok=True)
        sample = os.path.join(directory, "welcome.txt")
        if not os.path.exists(sample):
            with open(sample, "w", encoding="utf-8") as fh:
                fh.write("ShopLite A sample file.\n")


@bp.route("/download")
def download():
    # M07 (CWE-22): file joined onto BASE_DIR and opened with no containment check.
    name = request.args.get("file", "")
    path = os.path.join(BASE_DIR, name)
    with open(path, "rb") as fh:
        return fh.read()


@bp.route("/docs/<path:name>")
def docs(name):
    # M08 (CWE-22): multi-segment path passed to send_file.
    return send_file(os.path.join(DOCS_DIR, name))


@bp.route("/safe-download")
def safe_download():
    # D05 (decoy): secure_filename + send_from_directory — safe.
    name = secure_filename(request.args.get("file", ""))
    return send_from_directory(BASE_DIR, name)
