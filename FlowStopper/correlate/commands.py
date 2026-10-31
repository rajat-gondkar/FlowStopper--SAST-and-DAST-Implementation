"""`FlowStopper correlate` command (Owner: B, P2-B6). Registered in FlowStopper/cli.py."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer


def correlate_command(
    sast: Annotated[Path, typer.Option("--sast", help="SastResult JSON (includes routes)")] = Path("sast.json"),
    dast: Annotated[Path, typer.Option("--dast", help="DastResult JSON")] = Path("dast.json"),
    out: Annotated[Path, typer.Option("--out", "-o", help="issues JSON")] = Path("issues.json"),
) -> None:
    """Correlate SAST and DAST results into issues."""
    typer.echo("FlowStopper correlate: not implemented yet (P2-B6)", err=True)
    raise typer.Exit(code=1)
