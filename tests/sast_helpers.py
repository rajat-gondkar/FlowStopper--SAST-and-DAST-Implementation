"""Test helpers for the SAST modules (Owner: A)."""

from __future__ import annotations

import textwrap
from pathlib import Path


def make_tree(root: Path, files: dict[str, str]) -> Path:
    """Write `{relative POSIX path: source}` under `root` (sources are dedented) and return `root`."""
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(textwrap.dedent(text).lstrip("\n"), encoding="utf-8")
    return root
