"""End-to-end pipeline and `FlowStopper scan` (Owner: A, P3-A1, P5-A2).

SAST -> DAST (seeded with routes) -> correlate -> store -> write issues.json + scan_meta.json
(per-stage timings, seed, tool versions) into --out.

`run_pipeline` is the reusable entry point (the P5-A1 API's `POST /scans` calls it too); the Typer
`scan_command` is a thin wrapper that maps options onto the engine configs and errors onto exit codes,
writes the HTML / SARIF / Markdown reports next to issues.json and applies the `--fail-on` CI gate.
`issues.json` holds no timings, timestamps or scan ids, so two scans of the same input serialise
byte-for-byte (FR-6); everything run-specific goes to `scan_meta.json` and the SQLite store.
"""

from __future__ import annotations

import asyncio
import json
import logging
import platform
import time
from dataclasses import dataclass, field
from importlib import metadata
from pathlib import Path
from typing import Annotated, Optional

import typer

from FlowStopper import __version__
from FlowStopper.correlate.autoverify import auto_verify
from FlowStopper.correlate.config import CorrelateConfig
from FlowStopper.correlate.engine import correlate
from FlowStopper.correlate.issues import is_suppressed
from FlowStopper.dast.commands import build_auth
from FlowStopper.dast.config import DastConfig
from FlowStopper.dast.runner import run_dast
from FlowStopper.models import DastResult, Issue, Label, SastResult
from FlowStopper.report.gate import GATE_EXIT_CODE, gate_tripped, parse_fail_on
from FlowStopper.report.html import render_html
from FlowStopper.report.markdown import render_markdown
from FlowStopper.report.sarif import to_sarif
from FlowStopper.sast.config import SastConfig
from FlowStopper.sast.runner import run_sast
from FlowStopper.scope import ScopeError
from FlowStopper.storage import DEFAULT_DB_PATH, Storage, make_scan_id, utc_now

logger = logging.getLogger("FlowStopper.pipeline")

ISSUES_FILE = "issues.json"
META_FILE = "scan_meta.json"
REPORT_HTML_FILE = "report.html"
SARIF_FILE = "issues.sarif"
MARKDOWN_FILE = "findings.md"
# Third-party packages whose versions are recorded in scan_meta.json (tool versions, spec P3-A1).
VERSIONED_PACKAGES = ("httpx", "pydantic", "typer", "beautifulsoup4", "jinja2")


class PipelineError(Exception):
    """A pipeline stage failed; `stage` names it (input, sast, dast, correlate, store, write)."""

    def __init__(self, stage: str, message: str) -> None:
        self.stage = stage
        super().__init__(f"{stage}: {message}")


@dataclass
class PipelineResult:
    """What one scan produced: the issues, the metadata written to scan_meta.json and the file paths."""

    scan_id: str
    issues: list[Issue]
    meta: dict
    issues_path: Path
    meta_path: Path
    sast: SastResult = field(repr=False)
    dast: DastResult = field(repr=False)


def tool_versions() -> dict[str, str]:
    """FlowStopper, Python and the third-party packages the scan depends on."""
    versions = {"FlowStopper": __version__, "python": platform.python_version()}
    for name in VERSIONED_PACKAGES:
        try:
            versions[name] = metadata.version(name)
        except metadata.PackageNotFoundError:
            versions[name] = "unknown"
    return versions


def label_counts(issues: list[Issue]) -> dict[str, int]:
    """Reported issues per label plus the suppressed bucket (same split as `FlowStopper correlate`)."""
    reported = [i for i in issues if not is_suppressed(i)]
    counts = {label.value: sum(1 for i in reported if i.label is label) for label in Label}
    counts["reported"] = len(reported)
    counts["suppressed"] = len(issues) - len(reported)
    counts["total"] = len(issues)
    return counts


def _config_snapshot(config: DastConfig) -> dict:
    """The DAST config for scan_meta.json / the store, without credential values (R7).

    Login bodies, header and cookie values never leave memory; only their shape is recorded.
    """
    data = config.model_dump(mode="json")
    auth = config.auth
    if auth is not None:
        login = auth.login
        data["auth"] = {
            "configured": True,
            "header_names": sorted(auth.headers),
            "cookie_names": sorted(auth.cookies),
            "login": None if login is None else {"url": login.url, "method": login.method, "redacted": True},
        }
    return data


def _write_json(path: Path, data: object) -> None:
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def write_reports(issues: list[Issue], meta: dict, out_dir: Path | str) -> dict[str, Path]:
    """Write report.html, issues.sarif and findings.md into `out_dir` (Dev B's renderers, P5-B1/B2)."""
    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    paths = {
        "html": out_path / REPORT_HTML_FILE,
        "sarif": out_path / SARIF_FILE,
        "markdown": out_path / MARKDOWN_FILE,
    }
    paths["html"].write_text(render_html(issues, meta), encoding="utf-8")
    _write_json(paths["sarif"], to_sarif(issues, meta))
    paths["markdown"].write_text(render_markdown(issues, meta), encoding="utf-8")
    return paths


def unique_scan_id(db: Storage, source: str, target: str, started_at: str) -> str:
    """Storage's scan id, made unique when another scan of the same input started in the same second.

    `make_scan_id` hashes a seconds-precision timestamp, so two scans of one app within a second would
    otherwise share (and overwrite) one `scans` row (DECISIONS_Dev1 A-35).
    """
    candidate = make_scan_id(source, target, started_at)
    n = 1
    while db.get_scan(candidate) is not None:
        candidate = make_scan_id(source, target, f"{started_at}#{n}")
        n += 1
    return candidate


def run_pipeline(
    source: Path | str,
    target: str,
    out_dir: Path | str,
    *,
    sast_config: Optional[SastConfig] = None,
    dast_config: Optional[DastConfig] = None,
    correlate_config: Optional[CorrelateConfig] = None,
    db_path: Path | str = DEFAULT_DB_PATH,
    autoverify: bool = True,
    autoverify_budget_s: float = 60.0,
    scan_id: Optional[str] = None,
) -> PipelineResult:
    """Scan `source` (parsed, never executed) and the running `target`, store and write the results.

    After correlation, eligible Code-only issues are auto-verified against `target` with one targeted
    check each (spec P4-B4, B-1), within `autoverify_budget_s` seconds; `autoverify=False` skips it.
    Authentication for DAST and auto-verify comes from `dast_config.auth`.

    `scan_id` lets a caller that reserved the id beforehand (the API's `POST /scans`, which must
    return it in its 202) reuse it; the store upserts that row. Without it a fresh id is generated
    with `unique_scan_id` (DECISIONS_Dev1 A-61).

    Raises `PipelineError` when the source is not a directory, the scope guard refuses the target
    (rule R3, raised by `run_dast` before any connection) or any stage fails; the scan row in the
    store is then marked `failed`. A DAST time-budget overrun is not an error: the scan completes
    and `scan_meta.json` records `truncated: true`.
    """
    source_path = Path(source)
    out_path = Path(out_dir)
    sast_config = sast_config or SastConfig()
    dast_config = dast_config or DastConfig()
    correlate_config = correlate_config or CorrelateConfig()
    seed = dast_config.seed if dast_config.seed is not None else 0
    dast_config = dast_config.model_copy(update={"seed": seed})  # record the seed actually used

    if not source_path.is_dir():
        raise PipelineError("input", f"source root is not a directory: {source_path}")

    config_snapshot = {
        "sast": sast_config.model_dump(mode="json"),
        "dast": _config_snapshot(dast_config),
        "correlate": correlate_config.model_dump(mode="json"),
    }
    timings: dict[str, float] = {}
    started_at = utc_now()
    total_start = time.perf_counter()

    try:
        db = Storage(db_path)
    except Exception as exc:  # sqlite3 / OS errors opening the store
        raise PipelineError("store", f"cannot open the database {db_path}: {exc}") from exc

    with db:
        try:
            scan_id = db.start_scan(
                source_path=str(source_path),
                target_url=target,
                config=config_snapshot,
                seed=seed,
                scan_id=scan_id or unique_scan_id(db, str(source_path), target, started_at),
                started_at=started_at,
            )
        except Exception as exc:  # sqlite3 errors recording the scan row
            raise PipelineError("store", f"cannot record the scan: {exc}") from exc
        stage = "sast"
        try:
            t0 = time.perf_counter()
            sast = run_sast(source_path, sast_config)
            timings["sast"] = round(time.perf_counter() - t0, 3)

            stage = "dast"
            t0 = time.perf_counter()
            try:
                dast = asyncio.run(run_dast(target, sast.routes, dast_config))
            except ScopeError as exc:
                raise PipelineError("dast", f"refusing to scan an out-of-scope target (rule R3): {exc}") from exc
            timings["dast"] = round(time.perf_counter() - t0, 3)

            stage = "correlate"
            t0 = time.perf_counter()
            issues = correlate(sast.findings, dast.findings, sast.routes, correlate_config)
            timings["correlate"] = round(time.perf_counter() - t0, 3)

            added_findings = []
            autoverify_stats: dict = {"enabled": autoverify}
            if autoverify:
                stage = "autoverify"
                t0 = time.perf_counter()
                deadline = time.monotonic() + autoverify_budget_s
                try:
                    verified = asyncio.run(
                        auto_verify(issues, sast.routes, target, dast_config, correlate_config, deadline=deadline)
                    )
                except ScopeError as exc:
                    raise PipelineError("autoverify", f"refusing an out-of-scope target (rule R3): {exc}") from exc
                issues = verified.issues
                added_findings = list(verified.findings_added)
                autoverify_stats.update(verified.stats)
                timings["autoverify"] = round(time.perf_counter() - t0, 3)

            stage = "store"
            t0 = time.perf_counter()
            db.save_findings(scan_id, sast.findings + dast.findings + added_findings)
            db.save_issues(scan_id, issues)
            timings["store"] = round(time.perf_counter() - t0, 3)

            stage = "write"
            t0 = time.perf_counter()
            out_path.mkdir(parents=True, exist_ok=True)
            issues_path = out_path / ISSUES_FILE
            _write_json(issues_path, [i.model_dump(mode="json") for i in issues])
            timings["write"] = round(time.perf_counter() - t0, 3)

            # scan_meta.json is written before the row is marked completed, so the store never says
            # "completed" for a scan whose metadata file is missing.
            timings["total"] = round(time.perf_counter() - total_start, 3)
            meta = {
                "scan_id": scan_id,
                "status": "completed",
                "started_at": started_at,
                "finished_at": utc_now(),
                "source": str(source_path),
                "target": target,
                "seed": seed,
                "truncated": bool(dast.stats.get("truncated", False)),
                "timings_s": timings,
                "versions": tool_versions(),
                "counts": {
                    "routes": len(sast.routes),
                    "sast_findings": len(sast.findings),
                    "dast_findings": len(dast.findings),
                    "dast_requests": dast.stats.get("requests"),
                    "issues": label_counts(issues),
                },
                "autoverify": autoverify_stats,
                "db_path": str(db_path),
                "config": config_snapshot,
                "sast_stats": sast.stats,
                "dast_stats": dast.stats,
            }
            meta_path = out_path / META_FILE
            _write_json(meta_path, meta)
        except PipelineError:
            db.finish_scan(scan_id, status="failed", timings=timings)
            raise
        except Exception as exc:  # any other stage crash: record it, report it as that stage's failure
            db.finish_scan(scan_id, status="failed", timings=timings)
            raise PipelineError(stage, f"{type(exc).__name__}: {exc}") from exc

        db.finish_scan(scan_id, status="completed", timings=timings)

    return PipelineResult(
        scan_id=scan_id,
        issues=issues,
        meta=meta,
        issues_path=issues_path,
        meta_path=meta_path,
        sast=sast,
        dast=dast,
    )


def scan_command(
    source: Annotated[Path, typer.Option("--source", help="source root of the target app (parsed, never executed)")],
    target: Annotated[
        str, typer.Option("--target", help="base URL of the running target (must be allow-listed, rule R3)")
    ],
    out: Annotated[
        Path,
        typer.Option(
            "--out",
            help="output directory for issues.json, scan_meta.json, report.html, issues.sarif and findings.md",
        ),
    ] = Path("out"),
    fail_on: Annotated[
        Optional[str],
        typer.Option(
            "--fail-on",
            help="CI gate '<label>:<severity>': label confirmed, code_only, runtime_only or any; severity "
            "critical, high, medium, low or info. Exit 2 when a reported issue with that label is at or "
            "above the severity (e.g. confirmed:high). Reports are still written.",
        ),
    ] = None,
    time_budget: Annotated[int, typer.Option("--time-budget", help="DAST budget, seconds")] = 240,
    allow_host: Annotated[
        Optional[list[str]], typer.Option("--allow-host", help="extra allowed host (logs a WARNING)")
    ] = None,
    allow_mutating: Annotated[bool, typer.Option("--allow-mutating", help="also send PUT/PATCH")] = False,
    keep_secrets: Annotated[bool, typer.Option("--keep-secrets", help="do not redact auth headers")] = False,
    seed: Annotated[int, typer.Option("--seed", help="per-scan seed for DAST canaries (reproducible)")] = 0,
    auth_config: Annotated[
        Optional[Path],
        typer.Option(
            "--auth-config",
            help="JSON file with static headers/cookies and/or a login step (keep it git-ignored, e.g. keys/)",
        ),
    ] = None,
    header: Annotated[
        Optional[list[str]], typer.Option("--header", help="static header, 'Name: value' (repeatable)")
    ] = None,
    cookie: Annotated[
        Optional[list[str]], typer.Option("--cookie", help="static cookie, 'name=value' (repeatable)")
    ] = None,
    autoverify: Annotated[
        bool, typer.Option("--autoverify/--no-autoverify", help="probe Code-only issues once more (B-1)")
    ] = True,
    autoverify_budget: Annotated[int, typer.Option("--autoverify-budget", help="seconds for auto-verify probes")] = 60,
    db: Annotated[
        Path, typer.Option("--db", envvar="FLOWSTOPPER_DB", help="SQLite store shared with `serve` and `eval --scan`")
    ] = DEFAULT_DB_PATH,
) -> None:
    """Run the full pipeline (SAST -> DAST -> correlate -> auto-verify -> store) and write the reports.

    Exit codes: 0 ok, 1 error (bad input, out-of-scope target, stage failure), 2 the --fail-on CI
    gate tripped (all outputs are still written).
    """
    if fail_on is not None:
        # Validate the gate before anything runs, so a typo is a usage error, not a silently open gate.
        try:
            parse_fail_on(fail_on)
        except ValueError as exc:
            raise typer.BadParameter(str(exc), param_hint="'--fail-on'") from exc
    try:
        auth = build_auth(auth_config, header, cookie)
    except (OSError, ValueError) as exc:
        typer.echo(f"FlowStopper scan: bad authentication configuration: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    dast_config = DastConfig(
        extra_allowed_hosts=list(allow_host or []),
        time_budget_s=time_budget,
        allow_mutating=allow_mutating,
        keep_secrets=keep_secrets,
        seed=seed,
        auth=auth,
    )
    try:
        result = run_pipeline(
            source,
            target,
            out,
            dast_config=dast_config,
            db_path=db,
            autoverify=autoverify,
            autoverify_budget_s=autoverify_budget,
        )
    except PipelineError as exc:
        typer.echo(f"FlowStopper scan: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    try:
        reports = write_reports(result.issues, result.meta, out)
    except Exception as exc:  # renderer or file-system error: the scan itself is stored and written
        typer.echo(f"FlowStopper scan: cannot write reports: {type(exc).__name__}: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    meta = result.meta
    counts = meta["counts"]["issues"]
    timings = meta["timings_s"]
    auth_stats = result.dast.stats.get("auth") or {}
    if auth_stats.get("attempted"):
        state = "ok" if auth_stats.get("ok") else "FAILED"
        typer.echo(f"scan: login {state} ({auth_stats.get('detail') or auth_stats.get('status')})")
    av = meta.get("autoverify") or {}
    if av.get("enabled") and "eligible" in av:
        typer.echo(
            f"scan: auto-verify upgraded {av.get('upgraded', 0)} of {av['eligible']} eligible code-only issue(s)"
            + (" [TRUNCATED: auto-verify budget reached]" if av.get("truncated") else "")
        )
    typer.echo(
        f"scan: {meta['counts']['routes']} route(s), {meta['counts']['sast_findings']} SAST finding(s), "
        f"{meta['counts']['dast_findings']} DAST finding(s)"
        + (" [DAST TRUNCATED: time budget reached]" if meta["truncated"] else "")
    )
    typer.echo(
        f"scan: {counts['reported']} issue(s) (confirmed {counts['confirmed']}, code-only {counts['code_only']}, "
        f"runtime-only {counts['runtime_only']}; {counts['suppressed']} suppressed) in {timings['total']}s"
    )
    typer.echo(
        f"scan: id {result.scan_id}; wrote {result.issues_path}, {result.meta_path}, {reports['html']}, "
        f"{reports['sarif']} and {reports['markdown']}"
    )
    if fail_on is not None and gate_tripped(result.issues, fail_on):
        typer.echo(f"scan: CI gate --fail-on {fail_on} tripped (exit {GATE_EXIT_CODE})", err=True)
        raise typer.Exit(code=GATE_EXIT_CODE)
