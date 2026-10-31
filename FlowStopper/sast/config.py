"""SAST configuration (Owner: A). Add fields freely; this is A's file (DECISIONS D-06)."""

from __future__ import annotations

from pydantic import BaseModel


class SastConfig(BaseModel):
    exclude_dirs: list[str] = ["venv", ".venv", "site-packages", "__pycache__", ".git", "node_modules"]
    max_file_bytes: int = 1_000_000  # P1-A1: skip files > 1 MB
    max_call_depth: int = 4  # P1-A3: reachable_functions BFS depth
    fixpoint_max_iterations: int = 10  # P2-A2: summary fixpoint cap
