"""`FlowStopper report` command (Owner: B, P5-B1/B2/B4). Registered in FlowStopper/cli.py."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Optional

import typer


def report_command(
    scan: Annotated[Optional[str], typer.Option("--scan", help="scan id stored in the DB")] = None,
    issues: Annotated[Optional[Path], typer.Option("--issues", help="issues.json instead of --scan")] = None,
    fmt: Annotated[str, typer.Option("--format", "-f", help="html | sarif | md")] = "html",
    out: Annotated[Optional[Path], typer.Option("--out", "-o", help="output file")] = None,
) -> None:
    """Render a report for a stored scan or an issues file."""
    typer.echo("FlowStopper report: not implemented yet (P5-B1 / P5-B2 / P5-B4)", err=True)
    raise typer.Exit(code=1)
