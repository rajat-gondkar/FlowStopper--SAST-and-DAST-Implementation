"""`FlowStopper sast` command (Owner: A, P1-A2 / P2-A6). Registered in FlowStopper/cli.py."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer


def sast_command(
    path: Annotated[Path, typer.Argument(help="Source root to scan (parsed, never executed)")],
    out: Annotated[Path, typer.Option("--out", "-o", help="SastResult JSON")] = Path("sast.json"),
    routes_out: Annotated[Path, typer.Option("--routes-out", help="routes list JSON")] = Path("routes.json"),
) -> None:
    """Static scan: write the SastResult to --out and the route map to --routes-out."""
    typer.echo("FlowStopper sast: not implemented yet (P1-A2 / P2-A6)", err=True)
    raise typer.Exit(code=1)
