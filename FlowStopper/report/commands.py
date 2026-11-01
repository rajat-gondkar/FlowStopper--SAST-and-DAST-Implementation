"""`FlowStopper report` command (Owner: B, P5-B1/B2/B4). Registered in FlowStopper/cli.py.

    FlowStopper report --issues out/issues.json [--meta out/scan_meta.json]
                       [--html r.html] [--sarif r.sarif] [--md r.md] [--fail-on confirmed:high]

Exit codes (cli.py): 0 ok, 1 error (bad input, nothing to write, unwritable output), 2 CI gate tripped.
Bad options are reported with exit 1 rather than Click's usage error, because 2 means "gate tripped".
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Annotated, Optional

import typer
from pydantic import ValidationError

from FlowStopper.models import Issue
from FlowStopper.report.common import split_issues
from FlowStopper.report.gate import GATE_EXIT_CODE, gate_matches, parse_fail_on
from FlowStopper.report.html import render_html
from FlowStopper.report.markdown import render_markdown
from FlowStopper.report.sarif import to_sarif


class ReportError(Exception):
    """Unusable input or output for `FlowStopper report`."""


def load_issues(path: Path) -> list[Issue]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ReportError(f"cannot read issues file {path}: {exc.strerror or exc}") from exc
    except ValueError as exc:
        raise ReportError(f"issues file {path} is not valid JSON: {exc}") from exc
    if not isinstance(data, list):
        raise ReportError(f"issues file {path} must hold a JSON array of issues")
    try:
        return [Issue.model_validate(item) for item in data]
    except ValidationError as exc:
        raise ReportError(f"issues file {path} does not match the Issue schema: {exc.error_count()} error(s)") from exc


def load_meta(path: Optional[Path]) -> Optional[dict]:
    if path is None:
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ReportError(f"cannot read meta file {path}: {exc.strerror or exc}") from exc
    except ValueError as exc:
        raise ReportError(f"meta file {path} is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ReportError(f"meta file {path} must hold a JSON object (scan_meta.json)")
    return data


def load_eval(path: Optional[Path]) -> Optional[dict]:
    """The JSON `FlowStopper eval --out` / `scan --key` wrote (shown on the HTML report's Evaluation tab)."""
    if path is None:
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ReportError(f"cannot read evaluation file {path}: {exc.strerror or exc}") from exc
    except ValueError as exc:
        raise ReportError(f"evaluation file {path} is not valid JSON: {exc}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("metrics"), dict):
        raise ReportError(f"evaluation file {path} is not an `eval` result (no 'metrics' object)")
    return data


def write_reports(
    issues: list[Issue],
    meta: Optional[dict],
    *,
    html: Optional[Path] = None,
    sarif: Optional[Path] = None,
    md: Optional[Path] = None,
    eval_report: Optional[dict] = None,
) -> list[tuple[str, Path]]:
    """Render and write each requested format; returns (format, path) for what was written."""
    jobs: list[tuple[str, Optional[Path], Callable[[], str]]] = [
        ("html", html, lambda: render_html(issues, meta, eval_report=eval_report)),
        ("sarif", sarif, lambda: json.dumps(to_sarif(issues, meta), indent=2, ensure_ascii=False) + "\n"),
        ("md", md, lambda: render_markdown(issues, meta)),
    ]
    written: list[tuple[str, Path]] = []
    for name, path, render in jobs:
        if path is None:
            continue
        text = render()
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        except OSError as exc:
            raise ReportError(f"cannot write {name} report {path}: {exc.strerror or exc}") from exc
        written.append((name, path))
    return written


def report_command(
    issues: Annotated[
        Optional[Path], typer.Option("--issues", help="issues.json written by `scan` or `correlate` (required)")
    ] = None,
    meta: Annotated[
        Optional[Path], typer.Option("--meta", help="scan_meta.json (target, timings) for the report header")
    ] = None,
    eval: Annotated[  # noqa: A002 - the option is named --eval
        Optional[Path],
        typer.Option("--eval", help="evaluation JSON from `eval --out` / `scan --key`: shown on the Evaluation tab"),
    ] = None,
    html: Annotated[Optional[Path], typer.Option("--html", help="write the self-contained HTML report here")] = None,
    sarif: Annotated[Optional[Path], typer.Option("--sarif", help="write SARIF 2.1.0 here")] = None,
    md: Annotated[Optional[Path], typer.Option("--md", help="write the Markdown findings list here")] = None,
    fail_on: Annotated[
        Optional[str],
        typer.Option("--fail-on", help="CI gate '<confirmed|code_only|runtime_only|any>:<severity>' (exit code 2)"),
    ] = None,
) -> None:
    """Render HTML / SARIF / Markdown reports from an issues file, optionally applying the CI gate."""
    if issues is None:  # checked here, not by Click, whose usage-error exit code 2 is the gate's code
        typer.echo("report: --issues is required", err=True)
        raise typer.Exit(code=1)
    if fail_on is not None:
        try:
            parse_fail_on(fail_on)
        except ValueError as exc:
            typer.echo(f"report: {exc}", err=True)
            raise typer.Exit(code=1) from None
    if html is None and sarif is None and md is None and fail_on is None:
        typer.echo("report: nothing to do; pass --html, --sarif, --md and/or --fail-on", err=True)
        raise typer.Exit(code=1)
    try:
        loaded = load_issues(issues)
        scan_meta = load_meta(meta)
        evaluation = load_eval(eval)
        written = write_reports(loaded, scan_meta, html=html, sarif=sarif, md=md, eval_report=evaluation)
    except ReportError as exc:
        typer.echo(f"report: {exc}", err=True)
        raise typer.Exit(code=1) from None

    reported, suppressed = split_issues(loaded)
    typer.echo(f"report: {len(loaded)} issue(s): {len(reported)} reported, {len(suppressed)} suppressed")
    for name, path in written:
        typer.echo(f"  {name:<5} -> {path}")

    if fail_on is not None:
        matches = gate_matches(loaded, fail_on)
        if matches:
            typer.echo(f"gate: --fail-on {fail_on} tripped by {len(matches)} issue(s)", err=True)
            for issue in matches[:10]:
                typer.echo(f"  [{issue.label.value}] {issue.severity.value} {issue.id} {issue.title}", err=True)
            raise typer.Exit(code=GATE_EXIT_CODE)
        typer.echo(f"gate: --fail-on {fail_on} passed")
