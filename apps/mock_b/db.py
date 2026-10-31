"""SQLite access for shoplite-b. Our own work (R8).

Deliberately different from Mock A: a module-level connection factory with a row factory, and all
SQL text lives in the repositories/ layer rather than next to the handlers.
"""

from __future__ import annotations

import sqlite3

from .config import DATA_DIR

SCHEMA = """
CREATE TABLE IF NOT EXISTS items (
    sku    TEXT PRIMARY KEY,
    name   TEXT NOT NULL,
    price  REAL NOT NULL,
    band   TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS members (
    handle  TEXT PRIMARY KEY,
    secret  TEXT NOT NULL,
    display TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS baskets (
    ref     TEXT PRIMARY KEY,
    handle  TEXT NOT NULL,
    sku     TEXT NOT NULL,
    units   INTEGER NOT NULL
);
"""

SEED_ITEMS = [
    ("SKU-1001", "Walnut Desk Lamp", 48.0, "home"),
    ("SKU-1002", "Linen Cushion", 22.5, "home"),
    ("SKU-2001", "Trail Backpack", 96.0, "outdoor"),
    ("SKU-2002", "Insulated Flask", 28.0, "outdoor"),
    ("SKU-3001", "Ceramic Mug", 14.0, "kitchen"),
]
SEED_MEMBERS = [
    ("avery", "pepper-ridge", "Avery Stone"),
    ("bram", "harbour-lamp", "Bram Vale"),
]
SEED_BASKETS = [
    ("BR-77", "avery", "SKU-1001", 1),
    ("BR-78", "bram", "SKU-2001", 2),
]


def db_path() -> str:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    return str(DATA_DIR / "shoplite_b.sqlite3")


def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(db_path())
    conn.row_factory = sqlite3.Row
    return conn


def bootstrap() -> None:
    """Create the schema and seed demo rows (idempotent)."""
    conn = connect()
    try:
        conn.executescript(SCHEMA)
        conn.executemany("INSERT OR REPLACE INTO items VALUES (?, ?, ?, ?)", SEED_ITEMS)
        conn.executemany("INSERT OR REPLACE INTO members VALUES (?, ?, ?)", SEED_MEMBERS)
        conn.executemany("INSERT OR REPLACE INTO baskets VALUES (?, ?, ?, ?)", SEED_BASKETS)
        conn.commit()
    finally:
        conn.close()
