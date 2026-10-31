"""Snapshot/archive helpers for shoplite-b. Our own work (R8)."""

from __future__ import annotations

import subprocess

from ..config import DATA_DIR


def snapshot(tag: str) -> str:
    """Write a tagged snapshot of the data directory."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    # vuln:B06 - shell=True with the caller's tag inside the command string
    done = subprocess.run(
        f"echo snapshot-{tag} >> {DATA_DIR}/snapshots.log",
        shell=True,
        capture_output=True,
        text=True,
        timeout=5,
    )
    return done.stdout or f"snapshot {tag} queued"
