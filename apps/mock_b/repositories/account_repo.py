"""Member persistence for shoplite-b. Our own work (R8)."""

from __future__ import annotations

from ..db import connect


def authenticate(handle: str, secret: str) -> dict | None:
    """Look up a member by handle and shared secret."""
    conn = connect()
    try:
        # vuln:B02 - the JSON body's handle is concatenated into the statement
        statement = "SELECT handle, display FROM members WHERE handle = '" + handle + "'"
        row = conn.execute(statement).fetchone()
        if row is None:
            return None
        expected = conn.execute("SELECT secret FROM members WHERE handle = ?", (handle,)).fetchone()
        if expected is None or expected["secret"] != secret:
            return None
        return dict(row)
    finally:
        conn.close()


def profile_for(handle: str) -> dict | None:
    conn = connect()
    try:
        row = conn.execute("SELECT handle, display FROM members WHERE handle = ?", (handle,)).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()
