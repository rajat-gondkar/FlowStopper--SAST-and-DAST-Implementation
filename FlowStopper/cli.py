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

Exit codes (DECISIONS_Dev1 A-64): 0 ok, 1 error, 2 CI gate tripped (`scan --fail-on`) and nothing
else, 64 usage error (bad option or value, EX_USAGE). Click reports usage errors as 2 by default, so
`main()` maps them to 64 to keep 2 unambiguous for CI.
"""

from __future__ import annotations

import sys
from typing import Annotated

import typer
from typer.exceptions import TyperException

from FlowStopper import __version__
from FlowStopper.api import serve_command
from FlowStopper.correlate.commands import correlate_command
from FlowStopper.dast.commands import dast_command
from FlowStopper.evalkit.commands import eval_command
from FlowStopper.pipeline import scan_command
from FlowStopper.report.commands import report_command
from FlowStopper.sast.commands import sast_command

EX_USAGE = 64  # sysexits.h: the command was used incorrectly
CLICK_USAGE_EXIT = 2  # the exit code Click gives every UsageError (BadParameter, NoSuchOption, ...)

app = typer.Typer(
    name="FlowStopper",
    help="SAST + DAST correlation engine. Scan only targets you are authorised to test.",
    epilog="Exit codes: 0 ok, 1 error, 2 CI gate tripped (scan --fail-on), 64 usage error.",
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
app.command(
    "scan",
    help="Full pipeline: SAST -> DAST -> correlate -> auto-verify -> store. Writes issues.json, scan_meta.json, "
    "report.html, issues.sarif and findings.md into --out. Exit 0 ok, 1 error, 2 --fail-on gate tripped.",
)(scan_command)
app.command(
    "serve",
    help="Run the HTTP API (binds 127.0.0.1 by default; the API has no authentication, so only bind a "
    "non-loopback address inside a container or a trusted network).",
)(serve_command)
app.command("eval", help="Score issues against an answer key (section 4 metrics)")(eval_command)
app.command("report", help="Render HTML / SARIF / Markdown reports")(report_command)


def main() -> None:
    """Console entry point: run the app and map Typer's outcomes onto the A-64 exit codes.

    Typer (0.27) vendors Click and only exposes `TyperException` as the public base of its Click
    errors; a usage error (bad option or value, unknown command, no arguments) is the one that carries
    Click's usage exit code 2, which is remapped to 64 so 2 means "CI gate tripped" only.
    """
    try:
        rv = app(standalone_mode=False)
    except TyperException as exc:
        show = getattr(exc, "show", None)
        if callable(show):
            show()
        else:
            typer.echo(f"Error: {exc.format_message()}", err=True)
        sys.exit(EX_USAGE if exc.exit_code == CLICK_USAGE_EXIT else exc.exit_code)
    except typer.Abort:
        typer.echo("Aborted!", err=True)
        sys.exit(1)
    sys.exit(rv if isinstance(rv, int) else 0)
