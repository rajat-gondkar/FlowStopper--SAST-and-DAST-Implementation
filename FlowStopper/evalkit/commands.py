"""`FlowStopper eval` command (Owner: B, P1-B5 / P3-B1). Registered in FlowStopper/cli.py."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Optional

import typer


def eval_command(
    key: Annotated[Path, typer.Option("--key", help="answer key in our format (docs/ANSWER_KEY_FORMAT.md)")],
    scan: Annotated[Optional[str], typer.Option("--scan", help="scan id stored in the DB")] = None,
    issues: Annotated[Optional[Path], typer.Option("--issues", help="issues.json instead of --scan")] = None,
    out: Annotated[
        Optional[Path], typer.Option("--out", "-o", help="metrics JSON (default docs/metrics/<timestamp>.json)")
    ] = None,
) -> None:
    """Print the section 4 metrics table for a scan (or an issues file) against a key."""
    typer.echo("FlowStopper eval: not implemented yet (P1-B5 / P3-B1)", err=True)
    raise typer.Exit(code=1)
