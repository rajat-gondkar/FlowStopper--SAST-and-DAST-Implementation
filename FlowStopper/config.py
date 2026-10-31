"""Global settings (Owner: B). Env parsing such as ALLOWED_HOSTS lives here (P0-B1).

Engine configs live with their engines (DECISIONS D-06):
FlowStopper.sast.config.SastConfig (A), FlowStopper.dast.config.DastConfig (B),
FlowStopper.correlate.config.CorrelateConfig (B).
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from typing import Optional

# Rule R3 scope guard. The ALLOWED_HOSTS env var (comma-separated) overrides this base list;
# compose service names are added there or via --allow-host. Keep this generic (no app-specific
# host in FlowStopper/ - rule R6); benchmark/target hosts come from config only.
ALLOWED_HOSTS_ENV = "ALLOWED_HOSTS"
DEFAULT_ALLOWED_HOSTS: tuple[str, ...] = ("localhost", "127.0.0.1", "::1")


def parse_allowed_hosts(value: Optional[str]) -> list[str]:
    """Split a comma-separated ALLOWED_HOSTS value into a clean list (order kept, duplicates dropped)."""
    if not value:
        return []
    out: list[str] = []
    for part in value.split(","):
        host = part.strip()
        if host and host not in out:
            out.append(host)
    return out


def allowed_hosts_from_env(env: Optional[Mapping[str, str]] = None) -> Optional[list[str]]:
    """Return the ALLOWED_HOSTS override if the env var names a non-empty list, else None.

    None means "not configured" so callers keep their own default allow-list. A set-but-empty or
    whitespace-only value also yields None, so a stray `ALLOWED_HOSTS=` never silently empties the
    allow-list (which would refuse every target).
    """
    source = os.environ if env is None else env
    hosts = parse_allowed_hosts(source.get(ALLOWED_HOSTS_ENV))
    return hosts or None
