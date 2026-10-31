"""SAST configuration (Owner: A). Add fields freely; this is A's file (DECISIONS D-06)."""

from __future__ import annotations

from pydantic import BaseModel


class SastConfig(BaseModel):
    exclude_dirs: list[str] = ["venv", ".venv", "site-packages", "__pycache__", ".git", "node_modules"]
    max_file_bytes: int = 1_000_000  # P1-A1: skip files > 1 MB
    max_call_depth: int = 4  # P1-A3: reachable_functions BFS depth
    fixpoint_max_iterations: int = 10  # P2-A2: summary fixpoint cap
    taint_loop_iterations: int = 2  # P2-A1: times a loop body is re-analysed (spec: one extra iteration)
    # P2-A5 template scan / P2-A4 secrets: files are selected by extension only, never by basename (R6).
    template_extensions: list[str] = [".html", ".htm", ".jinja", ".jinja2", ".j2"]
    secret_file_extensions: list[str] = [".py", ".env", ".ini", ".cfg", ".yaml", ".yml", ".json", ".toml"]
    secret_min_length: int = 6  # P2-A4: shortest reported literal
    secret_entropy_bits: float = 3.0  # P2-A4: Shannon bits/char that raise confidence
    secret_entropy_min_length: int = 16  # P2-A4: length from which entropy is measured
    max_text_file_bytes: int = 1_000_000  # P2-A4/A5: skip non-Python text files > 1 MB
