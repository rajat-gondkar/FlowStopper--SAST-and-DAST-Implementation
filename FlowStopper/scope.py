"""Scope guard (Owner: B, P0-B1). Rule R3: scan only authorised targets.

Allow-list from ALLOWED_HOSTS (default localhost,127.0.0.1,::1 plus explicitly named
compose services). Refuse any other hostname even if it resolves to a private IP,
re-check every redirect hop, refuse non-http(s) schemes, log a WARNING for --allow-host.
Enforced inside dast/client.py for every request.
"""
