"""`FlowStopper correlate` command (Owner: B, P2-B6). Registered in FlowStopper/cli.py."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer

from FlowStopper.correlate.engine import correlate
from FlowStopper.correlate.issues import is_suppressed
from FlowStopper.models import DastResult, Label, SastResult


def _load(path: Path, model):
    return model.model_validate_json(Path(path).read_text(encoding="utf-8"))


def correlate_command(
    sast: Annotated[Path, typer.Option("--sast", help="SastResult JSON (includes routes)")] = Path("sast.json"),
    dast: Annotated[Path, typer.Option("--dast", help="DastResult JSON")] = Path("dast.json"),
    out: Annotated[Path, typer.Option("--out", "-o", help="issues JSON")] = Path("issues.json"),
) -> None:
    """Correlate SAST and DAST results into issues."""
    try:
        sast_result = _load(sast, SastResult)
        dast_result = _load(dast, DastResult)
    except (OSError, ValueError) as exc:
        typer.echo(f"correlate: could not read inputs: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    issues = correlate(sast_result.findings, dast_result.findings, sast_result.routes)

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        json.dumps([i.model_dump(mode="json") for i in issues], indent=2) + "\n",
        encoding="utf-8",
    )

    reported = [i for i in issues if not is_suppressed(i)]
    counts = {label.value: sum(1 for i in reported if i.label is label) for label in Label}
    typer.echo(
        f"correlate: {len(reported)} issue(s) "
        f"(confirmed {counts['confirmed']}, code-only {counts['code_only']}, "
        f"runtime-only {counts['runtime_only']}; {len(issues) - len(reported)} suppressed)"
    )
    typer.echo(f"correlate: wrote {out}")
