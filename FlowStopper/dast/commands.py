"""`FlowStopper dast` command (Owner: B, P1-B4 / P2-B4). Registered in FlowStopper/cli.py."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Optional

import typer


def dast_command(
    url: Annotated[str, typer.Argument(help="Base URL of the running target (must be allow-listed)")],
    routes: Annotated[Optional[Path], typer.Option("--routes", help="routes.json from `sast`")] = None,
    out: Annotated[Path, typer.Option("--out", "-o", help="DastResult JSON")] = Path("dast.json"),
    time_budget: Annotated[int, typer.Option("--time-budget", help="seconds")] = 240,
    allow_mutating: Annotated[bool, typer.Option("--allow-mutating", help="also send PUT/PATCH")] = False,
    allow_host: Annotated[
        Optional[list[str]], typer.Option("--allow-host", help="extra allowed host (logs a WARNING)")
    ] = None,
    keep_secrets: Annotated[bool, typer.Option("--keep-secrets", help="do not redact auth headers")] = False,
) -> None:
    """Dynamic scan: write the DastResult to --out."""
    typer.echo("FlowStopper dast: not implemented yet (P1-B4 / P2-B4)", err=True)
    raise typer.Exit(code=1)
