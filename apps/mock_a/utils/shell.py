"""Mock A shell helpers (spec Appendix D). Owner: Dev A.

`ping_host` is the command-injection sink reached cross-file from /api/ping (M05);
`safe_ping` is the safe list-form decoy (D04).
"""

import os
import subprocess


def ping_host(host):
    # M05 (CWE-78): host concatenated into a shell command run by os.system.
    return os.system("ping -c 1 " + host)


def safe_ping(host):
    # D04 (decoy): subprocess with a list argument and shell=False — safe.
    return subprocess.run(["ping", "-c", "1", host], capture_output=True, shell=False)
