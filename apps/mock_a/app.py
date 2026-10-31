"""Mock A — a small Flask shop used as our own SAST/DAST regression fixture (spec Appendix D).

Owner: Dev A. Application factory + blueprint registration. Runs via `flask --app app run` and via
`docker compose -f apps/mock_a/docker-compose.yml up`. Deliberately insecure: see answer_key.json.
"""

import os

from blueprints.admin import bp as admin_bp
from blueprints.files import bp as files_bp
from blueprints.files import ensure_dirs
from blueprints.orders import bp as orders_bp
from blueprints.products import bp as products_bp
from blueprints.users import bp as users_bp
from config import Config
from db import init_db
from flask import Flask


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    # R01 (CWE-693/1021): no security headers are set (no CSP / X-Frame-Options / X-Content-Type-Options).
    init_db()
    ensure_dirs()
    app.register_blueprint(orders_bp)
    app.register_blueprint(products_bp)
    app.register_blueprint(users_bp)
    app.register_blueprint(files_bp)
    app.register_blueprint(admin_bp)
    return app


app = create_app()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5050")), debug=True)
