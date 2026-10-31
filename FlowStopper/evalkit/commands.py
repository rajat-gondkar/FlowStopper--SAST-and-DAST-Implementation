"""`FlowStopper eval` command (Owner: B, P1-B5 / P3-B1). Registered in FlowStopper/cli.py."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Optional

import typer

from FlowStopper.evalkit.metrics import format_metrics_table
from FlowStopper.evalkit.runner import run_eval


def eval_command(
    key: Annotated[Path, typer.Option("--key", help="answer key in our format (docs/ANSWER_KEY_FORMAT.md)")],
    scan: Annotated[Optional[str], typer.Option("--scan", help="scan id stored in the DB")] = None,
    issues: Annotated[Optional[Path], typer.Option("--issues", help="issues.json instead of --scan")] = None,
    out: Annotated[
        Optional[Path], typer.Option("--out", "-o", help="metrics JSON (default docs/metrics/<timestamp>.json)")
    ] = None,
) -> None:
    """Print the section 4 metrics table for a scan (or an issues file) against a key."""
    if issues is None:
        if scan is not None:
            typer.echo("eval --scan needs the SQLite store (P2-B5); for now pass --issues issues.json", err=True)
        else:
            typer.echo("eval: pass --issues issues.json (or --scan once storage lands)", err=True)
        raise typer.Exit(code=1)
    metrics, out_path = run_eval(key, issues, out)
    typer.echo(format_metrics_table(metrics))
    typer.echo(f"\nwrote {out_path}")
