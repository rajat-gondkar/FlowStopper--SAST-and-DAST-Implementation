"""`FlowStopper sast` command (Owner: A, P1-A2 / P2-A6). Registered in FlowStopper/cli.py.

Phase 1: writes the route map (`routes.json`) and a `SastResult` (`sast.json`) with routes filled and
findings empty; taint/secret findings arrive in Phase 2 (P2-A6). Parse only; the target is never run (R7).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer

from FlowStopper.sast.runner import run_sast


def sast_command(
    path: Annotated[Path, typer.Argument(help="Source root to scan (parsed, never executed)")],
    out: Annotated[Path, typer.Option("--out", "-o", help="SastResult JSON")] = Path("sast.json"),
    routes_out: Annotated[Path, typer.Option("--routes-out", help="routes list JSON")] = Path("routes.json"),
) -> None:
    """Static scan: write the SastResult to --out and the route map to --routes-out."""
    if not path.is_dir():
        typer.echo(f"FlowStopper sast: source root is not a directory: {path}", err=True)
        raise typer.Exit(code=1)
    result = run_sast(path)
    routes_json = [r.model_dump(mode="json") for r in result.routes]
    routes_out.write_text(json.dumps(routes_json, indent=2) + "\n", encoding="utf-8")
    out.write_text(result.model_dump_json(indent=2) + "\n", encoding="utf-8")
    typer.echo(
        f"SAST: {result.stats.get('files_parsed', 0)} files, {len(result.routes)} routes"
        f" -> {routes_out} ({len(result.findings)} findings -> {out})"
    )
