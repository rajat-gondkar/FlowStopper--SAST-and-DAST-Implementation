"""`FlowStopper correlate` command (Owner: B, P2-B6). Registered in FlowStopper/cli.py."""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from typing import Annotated, Optional

import typer

from FlowStopper.correlate.autoverify import auto_verify
from FlowStopper.correlate.engine import correlate
from FlowStopper.correlate.issues import is_suppressed
from FlowStopper.dast.commands import build_auth
from FlowStopper.dast.config import DastConfig
from FlowStopper.models import DastResult, Label, SastResult
from FlowStopper.scope import ScopeError


def _load(path: Path, model):
    return model.model_validate_json(Path(path).read_text(encoding="utf-8"))


def correlate_command(
    sast: Annotated[Path, typer.Option("--sast", help="SastResult JSON (includes routes)")] = Path("sast.json"),
    dast: Annotated[Path, typer.Option("--dast", help="DastResult JSON")] = Path("dast.json"),
    out: Annotated[Path, typer.Option("--out", "-o", help="issues JSON")] = Path("issues.json"),
    target: Annotated[
        Optional[str],
        typer.Option(
            "--target", help="running app URL: auto-verify Code-only issues against it (must be allow-listed)"
        ),
    ] = None,
    auth_config: Annotated[
        Optional[Path],
        typer.Option("--auth-config", help="JSON file with static headers/cookies and/or a login step (auto-verify)"),
    ] = None,
    autoverify_budget: Annotated[
        int, typer.Option("--autoverify-budget", help="seconds for auto-verify probes (with --target)")
    ] = 60,
    seed: Annotated[int, typer.Option("--seed", help="seed for auto-verify canaries (reproducible)")] = 0,
) -> None:
    """Correlate SAST and DAST results into issues; with --target, auto-verify Code-only issues."""
    try:
        sast_result = _load(sast, SastResult)
        dast_result = _load(dast, DastResult)
    except (OSError, ValueError) as exc:
        typer.echo(f"correlate: could not read inputs: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    issues = correlate(sast_result.findings, dast_result.findings, sast_result.routes)

    if target is not None:
        try:
            auth = build_auth(auth_config, None, None)
        except (OSError, ValueError) as exc:
            typer.echo(f"correlate: bad authentication configuration: {exc}", err=True)
            raise typer.Exit(code=1) from exc
        config = DastConfig(seed=seed, auth=auth)
        deadline = time.monotonic() + autoverify_budget
        try:
            result = asyncio.run(auto_verify(issues, sast_result.routes, target, config, deadline=deadline))
        except ScopeError as exc:
            typer.echo(f"correlate: refusing to auto-verify against an out-of-scope target (rule R3): {exc}", err=True)
            raise typer.Exit(code=1) from exc
        issues = result.issues
        stats = result.stats
        typer.echo(
            f"correlate: auto-verify upgraded {stats['upgraded']} of {stats['eligible']} eligible code-only issue(s)"
            + (" [TRUNCATED: auto-verify budget reached]" if stats.get("truncated") else "")
        )

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
