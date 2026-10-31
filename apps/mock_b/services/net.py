"""Network diagnostics for shoplite-b. Our own work (R8)."""

from __future__ import annotations

import os
import subprocess


def probe_endpoint(endpoint: str) -> str:
    """Resolve an endpoint for the operations dashboard."""
    # vuln:B05 - the endpoint string reaches a shell through os.system
    os.system(f"getent hosts {endpoint} > /tmp/shoplite_b_probe.txt 2>&1")
    try:
        with open("/tmp/shoplite_b_probe.txt", encoding="utf-8", errors="replace") as handle:
            return handle.read()
    except OSError:
        return ""


def reachability(endpoint: str) -> str:
    """Latency check for the operations dashboard."""
    # decoy:D04 - argument vector, no shell, so separators are inert data
    done = subprocess.run(
        ["getent", "hosts", endpoint],
        capture_output=True,
        text=True,
        timeout=5,
        shell=False,
    )
    return done.stdout
