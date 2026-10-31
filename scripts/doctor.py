"""Check that this machine can build, test and run FlowStopper. Run: make doctor

Uses only the standard library so it works before `make setup`.
"""

from __future__ import annotations

import shutil
import socket
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VENV_PY = ROOT / ".venv" / "bin" / "python"
problems = 0


def report(ok: bool, msg: str, hint: str = "", fatal: bool = True) -> None:
    global problems
    mark = "OK  " if ok else ("FAIL" if fatal else "WARN")
    print(f"[{mark}] {msg}" + (f"\n       -> {hint}" if hint and not ok else ""))
    if not ok and fatal:
        problems += 1


def run(*cmd: str) -> str:
    try:
        return subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=30).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return ""


v = sys.version_info
report(v >= (3, 11), f"interpreter {sys.executable} is Python {v.major}.{v.minor}", "install Python 3.12")
report(shutil.which("git") is not None, "git installed", "install git")
report(shutil.which("docker") is not None, "docker installed (needed for mock apps and P5)", "install Docker", False)

if VENV_PY.exists():
    report(True, f".venv present ({run(str(VENV_PY), '--version')})")
    lock = {}
    for line in (ROOT / "requirements-dev.lock").read_text().splitlines():
        if "==" in line and not line.startswith("#"):
            name, ver = line.split("==", 1)
            lock[name.lower().replace("_", "-")] = ver.strip()
    frozen = {}
    for line in run(str(VENV_PY), "-m", "pip", "freeze", "--exclude-editable").splitlines():
        if "==" in line:
            name, ver = line.split("==", 1)
            frozen[name.lower().replace("_", "-")] = ver.strip()
    drift = sorted(f"{n} {frozen.get(n, 'missing')} != {want}" for n, want in lock.items() if frozen.get(n) != want)
    report(not drift, "installed packages match requirements-dev.lock", "run: make setup  (" + "; ".join(drift) + ")")
    ok = run(str(VENV_PY), "-c", "import FlowStopper, sys; sys.stdout.write(FlowStopper.__version__)")
    report(bool(ok), f"package importable from .venv (FlowStopper {ok or '?'})", "run: make setup")
else:
    report(False, ".venv missing", "run: make setup")

branch = run("git", "rev-parse", "--abbrev-ref", "HEAD")
report(bool(branch), f"git checkout (branch: {branch or '?'})", "clone the repo with git", False)
remote = run("git", "remote", "get-url", "origin")
report(bool(remote), f"git remote origin: {remote or 'not set'}", "git remote add origin <url>", False)
tracked = run("git", "ls-files", "target_src", "keys")
report(not tracked, "no organisers' files tracked by git (R5)", f"git rm --cached: {tracked}")

for d, why in (("target_src", "organisers' app source"), ("keys", "answer key for the organisers' app")):
    present = (ROOT / d).is_dir() and any((ROOT / d).iterdir())
    report(
        present,
        f"{d}/ (optional until you scan the real app: {why}; out-of-band, never committed)",
        f"copy it into {d}/ when you have it (see docs/SETUP.md)",
        False,
    )

for port, who in ((5050, "Mock A"), (8090, "Mock B"), (8000, "FlowStopper API")):
    with socket.socket() as s:
        free = s.connect_ex(("127.0.0.1", port)) != 0
    report(free, f"port {port} free for {who}", "stop whatever listens there or change the port", False)

print("\nAll required checks passed." if problems == 0 else f"\n{problems} required check(s) failed.")
sys.exit(1 if problems else 0)
