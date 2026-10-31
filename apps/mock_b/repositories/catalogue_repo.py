"""Catalogue persistence for shoplite-b. Our own work (R8).

The injection lives one layer below the router (router -> repository), so finding it requires
following a cross-module call - the same shape as Mock A's helper bug but a different layout.
"""

from __future__ import annotations

from ..db import connect


def search_items(fragment: str) -> list[dict]:
    """Free-text catalogue search."""
    conn = connect()
    try:
        # vuln:B01 - the caller's text is interpolated straight into the SQL statement
        statement = f"SELECT sku, name, price FROM items WHERE name LIKE '%{fragment}%' ORDER BY sku"
        return [dict(row) for row in conn.execute(statement).fetchall()]
    finally:
        conn.close()


def fetch_by_sku(sku: str) -> dict | None:
    """Single item lookup."""
    conn = connect()
    try:
        # decoy:D01 - bound parameter, so the value can never change the statement
        row = conn.execute("SELECT sku, name, price, band FROM items WHERE sku = ?", (sku,)).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def newest_in_band(band: str, how_many: str) -> list[dict]:
    """Latest items in a band, with a caller-supplied page size."""
    conn = connect()
    try:
        # decoy:D02 - int() makes the interpolation safe (a non-number raises before the query)
        size = int(how_many)
        statement = f"SELECT sku, name FROM items WHERE band = ? ORDER BY sku LIMIT {size}"
        return [dict(row) for row in conn.execute(statement, (band,)).fetchall()]
    finally:
        conn.close()


def all_bands() -> list[str]:
    conn = connect()
    try:
        return [row["band"] for row in conn.execute("SELECT DISTINCT band FROM items ORDER BY band").fetchall()]
    finally:
        conn.close()
