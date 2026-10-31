"""Mock A configuration (our own fixture app — spec Appendix D). Owner: Dev A.

Contains deliberately planted hard-coded-secret bugs (C01, C02) and one safe decoy (D08)
for the SAST secrets detector to find / correctly ignore. Not production code.
"""

import os


class Config:
    # C01 (CWE-798): hard-coded Flask SECRET_KEY used to sign the session cookie.
    SECRET_KEY = "mock-a-super-secret-key-9f3b2c1d8e7a6b5c"

    # C02 (CWE-798): hard-coded database password.
    DB_PASSWORD = "P@ssw0rd-shoplite-prod-2024"

    SQLALCHEMY_DATABASE_URI = "sqlite:///shop.db"

    # D08 (decoy): secret read from the environment — safe, must NOT be reported.
    STRIPE_KEY = os.environ.get("STRIPE_KEY", "")

    # Planted misconfiguration R02: weaken the session cookie (no HttpOnly, no SameSite).
    SESSION_COOKIE_HTTPONLY = False
    SESSION_COOKIE_SAMESITE = None
