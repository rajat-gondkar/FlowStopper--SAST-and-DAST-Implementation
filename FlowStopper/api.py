"""HTTP API (Owner: A, P5-A1) and `FlowStopper serve`.

POST /scans, GET /scans/{id}, GET /issues, GET /issues/{id}, GET /scans/{id}/report,
GET /scans/{id}/sarif, GET /health. Binds to 127.0.0.1 by default.
"""

from __future__ import annotations

from typing import Annotated

import typer


def serve_command(
    host: Annotated[str, typer.Option("--host", help="bind address")] = "127.0.0.1",
    port: Annotated[int, typer.Option("--port", help="bind port")] = 8000,
) -> None:
    """Serve the FlowStopper API."""
    typer.echo("FlowStopper serve: not implemented yet (P5-A1)", err=True)
    raise typer.Exit(code=1)
