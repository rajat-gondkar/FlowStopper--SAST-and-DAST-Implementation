"""Mock A payment helper (spec Appendix D). Owner: Dev A.

Contains a planted hard-coded API token (C03) and a safe env-var read.
"""

import os

# C03 (CWE-798): hard-coded payment API token.
API_TOKEN = "sk_live_mocka_8d7f6e5c4b3a29100f1e2d3c"


def charge(amount):
    env_key = os.environ.get("PAYMENT_KEY", "")  # safe: read from the environment
    return {"amount": amount, "token": API_TOKEN, "env_key_set": bool(env_key)}
