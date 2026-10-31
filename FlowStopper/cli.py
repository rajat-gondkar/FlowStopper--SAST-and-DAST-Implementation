"""Command-line entry point (Owner: A, P5-A2; registry created in P0-J1).

Ownership pattern (docs/DECISIONS.md D-07): this file only *registers* commands.
Each command's function lives in the owner's package, so Dev B never edits this file:

  sast       -> FlowStopper/sast/commands.py        (A)
  dast       -> FlowStopper/dast/commands.py        (B)
  correlate  -> FlowStopper/correlate/commands.py   (B)
  eval       -> FlowStopper/evalkit/commands.py     (B)
  report     -> FlowStopper/report/commands.py      (B)
  scan       -> FlowStopper/pipeline.py             (A)
  serve      -> FlowStopper/api.py                  (A)

Exit codes: 0 ok, 1 error / not implemented, 2 CI gate tripped (--fail-on).
"""

from __future__ import annotations

from typing import Annotated

import typer

from FlowStopper import __version__
from FlowStopper.api import serve_command
from FlowStopper.correlate.commands import correlate_command
from FlowStopper.dast.commands import dast_command
from FlowStopper.evalkit.commands import eval_command
from FlowStopper.pipeline import scan_command
from FlowStopper.report.commands import report_command
from FlowStopper.sast.commands import sast_command

app = typer.Typer(
    name="FlowStopper",
    help="SAST + DAST correlation engine. Scan only targets you are authorised to test.",
    no_args_is_help=True,
    add_completion=False,
)


def _version(value: bool) -> None:
    if value:
        typer.echo(f"FlowStopper {__version__}")
        raise typer.Exit()


@app.callback()
def _root(
    version: Annotated[
        bool, typer.Option("--version", callback=_version, is_eager=True, help="Show version and exit.")
    ] = False,
) -> None:
    """FlowStopper command group."""


app.command("sast", help="Static scan: routes + taint + secrets -> sast.json, routes.json")(sast_command)
app.command("dast", help="Dynamic scan of a running app, seeded by routes.json -> dast.json")(dast_command)
app.command("correlate", help="Link SAST and DAST findings into issues -> issues.json")(correlate_command)
app.command("scan", help="Full pipeline: SAST -> DAST -> correlate -> store -> report")(scan_command)
app.command("serve", help="Run the HTTP API")(serve_command)
app.command("eval", help="Score issues against an answer key (section 4 metrics)")(eval_command)
app.command("report", help="Render HTML / SARIF / Markdown reports")(report_command)


def main() -> None:
    app()
