# Mock A — ShopLite A (our own Flask fixture)

A small, deliberately insecure Flask shop used as FlowStopper's development and regression fixture
(spec Appendix D). **Our own work** (rule R8); not a third-party app. The planted vulnerabilities and
safe decoys are documented in [`answer_key.json`](answer_key.json) (schema: `docs/ANSWER_KEY_FORMAT.md`).

## Run

```bash
# Docker (dev port 5050)
docker compose -f apps/mock_a/docker-compose.yml up

# or directly
cd apps/mock_a && pip install -r requirements.txt && flask --app app run -p 5050 --debug
```

The app seeds a tiny SQLite database (`shop.db`) on startup so the SQL-injection bugs actually fire.

## Layout

```
app.py              application factory + blueprint registration
config.py           config incl. planted hard-coded secrets (C01, C02) and an env decoy (D08)
db.py               query helpers: SQL sinks (M01, M02) and safe decoys (D01, D02)
blueprints/         orders, products, users, files, admin  (url_prefix on orders/products/admin)
utils/              shell (M05 os.system, D04 safe subprocess), payments (C03 token)
templates/          Jinja templates incl. product.html (M04 |safe XSS)
```

## Scan it with FlowStopper

```bash
FlowStopper sast apps/mock_a --routes-out routes.json      # route map (Phase 1)
```

Planted total (Appendix D): 10 pairs + 3 code-only + 3 runtime-only, plus 8 safe decoys.
