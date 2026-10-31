"""Mock A query helpers (spec Appendix D). Owner: Dev A.

Cross-file SQL sinks for the taint engine: `fetch_order` / `find_user` build SQL from request
data (M01, M02), while `fetch_product` / `fetch_order_by_int` are safe decoys (D01, D02).
"""

import sqlite3

DB_PATH = "shop.db"


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def fetch_order(order_id):
    # M01 (CWE-89): order_id (from the request) formatted straight into SQL via an f-string.
    conn = get_db()
    query = f"SELECT id, item, total FROM orders WHERE id = {order_id}"
    return conn.execute(query).fetchall()


def find_user(username, password):
    # M02 (CWE-89): username/password concatenated into the SQL string.
    conn = get_db()
    query = "SELECT id, username FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
    return conn.execute(query).fetchone()


def fetch_product(product_id):
    # D01 (decoy): parameterised query with a bound placeholder — safe.
    conn = get_db()
    return conn.execute("SELECT id, name, price FROM products WHERE id = ?", (product_id,)).fetchall()


def fetch_order_by_int(order_id):
    # D02 (decoy): value cast to int before being used in SQL — safe.
    oid = int(order_id)
    conn = get_db()
    return conn.execute(f"SELECT id, item, total FROM orders WHERE id = {oid}").fetchall()


def init_db():
    """Create the demo tables and seed a couple of rows so the planted bugs can actually fire."""
    conn = get_db()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS orders (id INTEGER PRIMARY KEY, item TEXT, total REAL);
        CREATE TABLE IF NOT EXISTS products (id INTEGER PRIMARY KEY, name TEXT, price REAL);
        CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT);
        """
    )
    if conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        conn.execute("INSERT INTO users (username, password) VALUES ('admin', 'admin123')")
        conn.execute("INSERT INTO orders (item, total) VALUES ('widget', 9.99)")
        conn.execute("INSERT INTO products (name, price) VALUES ('widget', 9.99)")
        conn.commit()
    conn.close()
