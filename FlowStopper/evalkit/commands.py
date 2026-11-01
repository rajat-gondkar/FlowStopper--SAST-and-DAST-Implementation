"""`FlowStopper eval` command (Owner: B, P1-B5 / P3-B1). Registered in FlowStopper/cli.py."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated, Optional

import typer
from pydantic import ValidationError

from FlowStopper.evalkit.metrics import format_metrics_table
from FlowStopper.evalkit.runner import EvalError, run_eval
from FlowStopper.storage import DEFAULT_DB_PATH


def eval_command(
    key: Annotated[Path, typer.Option("--key", help="answer key in our format (docs/ANSWER_KEY_FORMAT.md)")],
    scan: Annotated[Optional[str], typer.Option("--scan", help="scan id stored in the DB, or 'latest'")] = None,
    issues: Annotated[Optional[Path], typer.Option("--issues", help="issues.json instead of --scan")] = None,
    out: Annotated[
        Optional[Path], typer.Option("--out", "-o", help="metrics JSON (default docs/metrics/<timestamp>.json)")
    ] = None,
    db: Annotated[Path, typer.Option("--db", help="scan database used by --scan")] = DEFAULT_DB_PATH,
) -> None:
    """Print the section 4 metrics table for a scan (or an issues file) against a key."""
    if (scan is None) == (issues is None):
        typer.echo("eval: pass exactly one of --scan <id|latest> or --issues <issues.json>", err=True)
        raise typer.Exit(code=1)
    try:
        report, out_path = run_eval(key, issues, out, scan_id=scan, db_path=db)
    except EvalError as exc:
        typer.echo(f"eval: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    except OSError as exc:
        typer.echo(f"eval: cannot read the key {key}: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    except (ValidationError, json.JSONDecodeError) as exc:
        typer.echo(f"eval: {key} is not a valid answer key (validate it with `make validate-key`):\n{exc}", err=True)
        raise typer.Exit(code=1) from exc

    source = report["source"]
    where = f"scan {source['scan_id']}" if source["kind"] == "scan" else source["issues"]
    counts = report["issues"]
    typer.echo(
        f"eval: {report['app']} - {counts['reported']} reported issue(s) ({counts['suppressed']} suppressed) "
        f"from {where} vs {report['key']}\n"
    )
    typer.echo(format_metrics_table(report["metrics"], report["run_time_s"]))
    typer.echo(f"\nunplanted (informational): {report['unplanted']} reported issue(s) match no planted vuln or decoy")
    if report["run_time_s"] is None:
        typer.echo("note: run time unknown (no scan_meta.json next to the issues file).")
    typer.echo(f"\nwrote {out_path}")
