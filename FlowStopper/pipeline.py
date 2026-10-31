"""End-to-end pipeline and `FlowStopper scan` (Owner: A, P3-A1).

SAST -> DAST (seeded with routes) -> correlate -> store -> write issues.json + scan_meta.json
(per-stage timings, seed, tool versions) into --out.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Optional

import typer


def scan_command(
    source: Annotated[Path, typer.Option("--source", help="source root of the target app")],
    target: Annotated[str, typer.Option("--target", help="base URL of the running target")],
    out: Annotated[Path, typer.Option("--out", help="output directory")] = Path("out"),
    fail_on: Annotated[
        Optional[str], typer.Option("--fail-on", help="CI gate, e.g. confirmed:high (exit code 2)")
    ] = None,
    time_budget: Annotated[int, typer.Option("--time-budget", help="DAST budget, seconds")] = 240,
    allow_host: Annotated[
        Optional[list[str]], typer.Option("--allow-host", help="extra allowed host (logs a WARNING)")
    ] = None,
    allow_mutating: Annotated[bool, typer.Option("--allow-mutating", help="also send PUT/PATCH")] = False,
    keep_secrets: Annotated[bool, typer.Option("--keep-secrets", help="do not redact auth headers")] = False,
) -> None:
    """Run the full pipeline and write a prioritised issue list."""
    typer.echo("FlowStopper scan: not implemented yet (P3-A1)", err=True)
    raise typer.Exit(code=1)
