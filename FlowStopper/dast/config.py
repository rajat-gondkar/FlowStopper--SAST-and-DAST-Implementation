"""DAST configuration (Owner: B). Add fields freely; this is B's file (DECISIONS D-06)."""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel


class DastConfig(BaseModel):
    allowed_hosts: list[str] = ["localhost", "127.0.0.1", "::1"]  # P0-B1; env ALLOWED_HOSTS overrides
    extra_allowed_hosts: list[str] = []  # --allow-host (must log a WARNING)
    concurrency: int = 20
    max_rps: Optional[float] = None  # global request-rate cap
    connect_timeout_s: float = 3.0
    total_timeout_s: float = 10.0
    time_budget_s: int = 240
    allow_mutating: bool = False  # PUT/PATCH only with --allow-mutating; DELETE never
    crawl_max_depth: int = 3
    crawl_max_urls: int = 300
    seed: Optional[int] = None  # per-scan seed for canaries; recorded in scan metadata
    keep_secrets: bool = False  # R7: redact Authorization/Cookie unless set
