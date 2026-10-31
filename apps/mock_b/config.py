"""Settings for shoplite-b. Our own work (rule R8) - a deliberately vulnerable fixture app.

HELD OUT: Dev A must not read apps/mock_b/ until Phase 6 (generalisation round).
"""

from __future__ import annotations

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
ASSET_ROOT = BASE_DIR / "assets"
TEMPLATE_ROOT = BASE_DIR / "templates"
DATA_DIR = Path(os.environ.get("SHOPLITE_B_DATA", BASE_DIR / "data"))

# vuln:B21 - session signing key committed as a literal
SIGNING_SECRET = "mb-signing-7f3a9c21e5d4"

# vuln:B22 - database password committed as a literal (also embedded in the DSN below)
WAREHOUSE_PASSWORD = "shopliteB-pg-9931x"
WAREHOUSE_DSN = f"postgresql://shoplite:{WAREHOUSE_PASSWORD}@warehouse:5432/shoplite"

# decoy:D08 - read from the environment, so this is NOT a hard-coded credential
COURIER_API_KEY = os.environ.get("COURIER_API_KEY", "")

# Onward targets the bounce endpoint is willing to honour (used by the safe variant only).
PERMITTED_ONWARD = ("/", "/catalogue/items", "/accounts/profile")

SESSION_COOKIE = "shoplite_b_session"
SERVER_BANNER = "shoplite-b/1.4.2"
