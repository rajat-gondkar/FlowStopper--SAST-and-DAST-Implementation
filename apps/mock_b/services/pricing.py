"""Pricing / vendor feed helpers for shoplite-b. Our own work (R8)."""

from __future__ import annotations

# vuln:B23 - vendor API token committed as a literal
PRICING_FEED_TOKEN = "pk_live_mb_4c7d19a8f2b6e0"

MARKUP_BY_BAND = {"home": 1.10, "outdoor": 1.18, "kitchen": 1.05}


def retail_price(base: float, band: str) -> float:
    return round(base * MARKUP_BY_BAND.get(band, 1.0), 2)


def feed_headers() -> dict[str, str]:
    return {"Authorization": f"Bearer {PRICING_FEED_TOKEN}"}
