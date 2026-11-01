"""HTTP API (Owner: A, P5-A1) and `FlowStopper serve`.

POST /scans, GET /scans/{id}, GET /issues, GET /issues/{id}, GET /scans/{id}/report,
GET /scans/{id}/sarif, GET /health. Binds to 127.0.0.1 by default.

`POST /scans` validates the request at the trust boundary (the source must be a directory and the
target must pass the R3 scope guard, checked exactly as `run_dast` checks it), reserves the scan id
in the store and returns 202. The scan itself runs as a *sync* background task, which Starlette
executes in its thread pool, so `run_pipeline`'s own `asyncio.run` never touches the server's event
loop (DECISIONS_Dev1 A-30, A-61). Credential values sent in `options.auth` are never echoed back:
responses are built from explicit fields, the stored scan config is never returned, and validation
errors drop pydantic's `input` (A-62).
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Annotated, Optional

import typer
import uvicorn
from fastapi import BackgroundTasks, FastAPI, HTTPException, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from starlette.datastructures import State

from FlowStopper import __version__, pipeline
from FlowStopper.dast.config import AuthConfig, DastConfig
from FlowStopper.models import Label
from FlowStopper.report.html import render_html
from FlowStopper.report.sarif import to_sarif
from FlowStopper.scope import ScopeError, build_guard
from FlowStopper.storage import DEFAULT_DB_PATH, Storage, utc_now

logger = logging.getLogger("FlowStopper.api")

DEFAULT_OUT_ROOT = Path("out") / "api"
SARIF_MEDIA_TYPE = "application/sarif+json"
REDACTED = "[REDACTED]"


class ScanOptions(BaseModel):
    """The `scan` command's options, as JSON (same defaults as the CLI)."""

    model_config = ConfigDict(extra="forbid")

    time_budget: int = Field(240, ge=1, description="DAST budget, seconds")
    allow_host: list[str] = Field(default_factory=list, description="extra allowed hosts (logs a WARNING)")
    allow_mutating: bool = False
    keep_secrets: bool = False
    seed: int = 0
    autoverify: bool = True
    autoverify_budget: int = Field(60, ge=0, description="seconds for auto-verify probes")
    auth: Optional[AuthConfig] = None

    def to_dast_config(self) -> DastConfig:
        """Map onto the DastConfig fields `FlowStopper scan` sets from its options."""
        auth = self.auth if self.auth is not None and self.auth.is_configured else None
        return DastConfig(
            extra_allowed_hosts=list(self.allow_host),
            time_budget_s=self.time_budget,
            allow_mutating=self.allow_mutating,
            keep_secrets=self.keep_secrets,
            seed=self.seed,
            auth=auth,
        )


class ScanRequest(BaseModel):
    """Body of `POST /scans`."""

    model_config = ConfigDict(extra="forbid")

    source_path: str = Field(min_length=1, description="source root of the target app, as seen by the server")
    target_url: str = Field(min_length=1, description="base URL of the running target (must be allow-listed)")
    options: ScanOptions = Field(default_factory=ScanOptions)


def _secret_values(auth: Optional[AuthConfig]) -> list[str]:
    """Every credential string in `auth`, longest first, so error texts can be scrubbed (A-56)."""
    if auth is None:
        return []
    values: list[str] = [*auth.headers.values(), *auth.cookies.values()]
    login = auth.login
    if login is not None:
        values += list(login.headers.values())
        for body in (login.json_body, login.form_data):
            if body:
                values += _leaf_strings(body)
    return sorted({v for v in values if v}, key=len, reverse=True)


def _leaf_strings(data: object) -> list[str]:
    if isinstance(data, dict):
        return [s for v in data.values() for s in _leaf_strings(v)]
    if isinstance(data, (list, tuple)):
        return [s for v in data for s in _leaf_strings(v)]
    return [str(data)] if data is not None and not isinstance(data, bool) else []


def _scrub(text: str, secrets: list[str]) -> str:
    for secret in secrets:
        text = text.replace(secret, REDACTED)
    return text


def _run_scan(
    state: State,
    scan_id: str,
    source: Path,
    target: str,
    config: DastConfig,
    autoverify: bool,
    autoverify_budget: float,
) -> None:
    """Background task (sync, so it runs in a worker thread). Records failures; never raises."""
    db_path: Path = state.db_path
    errors: dict[str, str] = state.errors
    try:
        pipeline.run_pipeline(
            source,
            target,
            state.out_root / scan_id,
            dast_config=config,
            db_path=db_path,
            autoverify=autoverify,
            autoverify_budget_s=autoverify_budget,
            scan_id=scan_id,
        )
        return
    except pipeline.PipelineError as exc:
        message = str(exc)
    except Exception as exc:  # anything else: keep the server alive, report it on GET /scans/{id}
        message = f"{type(exc).__name__}: {exc}"
    message = _scrub(message, _secret_values(config.auth))
    errors[scan_id] = message
    logger.error("scan %s failed: %s", scan_id, message)
    try:
        with Storage(db_path) as db:
            row = db.get_scan(scan_id)
            if row is not None and row["status"] == "running":  # failed before run_pipeline recorded it
                db.finish_scan(scan_id, status="failed")
    except Exception:  # the store itself is broken; the in-memory error is all we can keep
        logger.exception("cannot mark scan %s as failed", scan_id)


def _scan_dirs(out_root: Path, row: dict) -> list[Path]:
    """Where a scan's output files can be: the API's own folder, and the folder the scan recorded.

    `FlowStopper scan --out DIR` records DIR in its stored row, so a CLI-run scan's `scan_meta.json`
    and `evaluation.json` are found too. Only those two fixed file names are ever read from it.
    """
    dirs = [out_root / str(row["id"])]
    output = (row.get("config") or {}).get("output")
    recorded = output.get("dir") if isinstance(output, dict) else None
    if isinstance(recorded, str) and recorded:
        dirs.append(Path(recorded))
    return dirs


def _read_json_file(dirs: list[Path], name: str) -> Optional[dict]:
    for directory in dirs:
        try:
            data = json.loads((directory / name).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(data, dict):
            return data
    return None


def _read_meta(out_root: Path, row: dict) -> Optional[dict]:
    """scan_meta.json of the scan, from the API's folder or the folder the scan was run into."""
    return _read_json_file(_scan_dirs(out_root, row), pipeline.META_FILE)


def _read_evaluation(out_root: Path, row: dict) -> Optional[dict]:
    """evaluation.json (`scan --key`) of the scan, or None when it was not scored."""
    return _read_json_file(_scan_dirs(out_root, row), pipeline.EVALUATION_FILE)


def create_app(db_path: Path | str = DEFAULT_DB_PATH, out_root: Path | str = DEFAULT_OUT_ROOT) -> FastAPI:
    """Build the API on the SQLite store at `db_path`; API-run scans write their files to `out_root/<id>/`."""
    app = FastAPI(
        title="FlowStopper",
        version=__version__,
        description="SAST + DAST correlation engine. Scan only targets you are authorised to test.",
    )
    app.state.db_path = Path(db_path)
    app.state.out_root = Path(out_root)
    app.state.errors = {}

    @app.exception_handler(RequestValidationError)
    async def _validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
        # FastAPI's default handler echoes the submitted body (`input`), which may hold credentials.
        detail = [
            {"loc": list(e.get("loc", ())), "msg": e.get("msg", ""), "type": e.get("type", "")} for e in exc.errors()
        ]
        return JSONResponse(status_code=422, content={"detail": detail})

    def _scan_row(db: Storage, scan_id: str) -> dict:
        row = db.get_scan(scan_id)
        if row is None:
            raise HTTPException(status_code=404, detail=f"unknown scan {scan_id!r}")
        return row

    def _completed_scan(db: Storage, scan_id: str) -> tuple[list, dict, Optional[dict]]:
        row = _scan_row(db, scan_id)
        if row["status"] != "completed":
            raise HTTPException(status_code=409, detail=f"scan {scan_id!r} is {row['status']}, not completed")
        issues = db.get_issues(scan_id=scan_id, include_suppressed=True)
        meta = _read_meta(app.state.out_root, row) or {
            "scan_id": scan_id,
            "status": row["status"],
            "source": row["source_path"],
            "target": row["target_url"],
            "started_at": row["started_at"],
        }
        return issues, meta, _read_evaluation(app.state.out_root, row)

    @app.get("/health")
    def health() -> dict:
        return {"status": "ok", "version": __version__}

    @app.post("/scans", status_code=202)
    async def create_scan(body: ScanRequest, background_tasks: BackgroundTasks, response: Response) -> dict:
        # async: id reservation runs on the event loop, one request at a time (no duplicate ids).
        source = Path(body.source_path)
        if not source.is_dir():
            raise HTTPException(status_code=400, detail=f"source_path is not a directory: {body.source_path}")
        config = body.options.to_dast_config()
        try:  # the same guard run_dast builds; checked here so a refusal is a 400, not a failed scan
            build_guard(config.allowed_hosts, extra_hosts=config.extra_allowed_hosts).check(body.target_url)
        except ScopeError as exc:
            raise HTTPException(status_code=400, detail=f"refusing an out-of-scope target (rule R3): {exc}") from exc
        started_at = utc_now()
        with Storage(app.state.db_path) as db:
            scan_id = pipeline.unique_scan_id(db, str(source), body.target_url, started_at)
            db.start_scan(
                source_path=str(source),
                target_url=body.target_url,
                config={},
                seed=config.seed,
                scan_id=scan_id,
                started_at=started_at,
            )
        background_tasks.add_task(
            _run_scan,
            app.state,
            scan_id,
            source,
            body.target_url,
            config,
            body.options.autoverify,
            float(body.options.autoverify_budget),
        )
        response.headers["Location"] = f"/scans/{scan_id}"
        return {"scan_id": scan_id, "status": "running"}

    @app.get("/scans/{scan_id}")
    def get_scan(scan_id: str) -> dict:
        with Storage(app.state.db_path) as db:
            row = _scan_row(db, scan_id)
            issues = db.get_issues(scan_id=scan_id, include_suppressed=True)
        meta = _read_meta(app.state.out_root, row)
        return {
            "scan_id": row["id"],
            "status": row["status"],
            "source": row["source_path"],
            "target": row["target_url"],
            "started_at": row["started_at"],
            "finished_at": row["finished_at"],
            "seed": row["seed"],
            "timings_s": row["timings"],
            "truncated": None if meta is None else meta.get("truncated"),
            "counts": pipeline.label_counts(issues),
            "error": app.state.errors.get(scan_id),
        }

    @app.get("/issues")
    def list_issues(
        scan_id: Optional[str] = None,
        label: Optional[Label] = None,
        cwe: Optional[int] = None,
        min_risk: Optional[float] = None,
        include_suppressed: bool = False,
    ) -> list[dict]:
        with Storage(app.state.db_path) as db:
            issues = db.get_issues(
                scan_id=scan_id,
                label=label.value if label is not None else None,
                cwe=cwe,
                min_risk=min_risk,
                include_suppressed=include_suppressed,
            )
        return [i.model_dump(mode="json") for i in issues]

    @app.get("/issues/{issue_id}")
    def get_issue(issue_id: str) -> dict:
        with Storage(app.state.db_path) as db:
            issue = db.get_issue(issue_id)
        if issue is None:
            raise HTTPException(status_code=404, detail=f"unknown issue {issue_id!r}")
        return issue.model_dump(mode="json")

    @app.get("/scans/{scan_id}/report", response_class=HTMLResponse)
    def get_report(scan_id: str) -> HTMLResponse:
        with Storage(app.state.db_path) as db:
            issues, meta, evaluation = _completed_scan(db, scan_id)
        return HTMLResponse(render_html(issues, meta, eval_report=evaluation))

    @app.get("/scans/{scan_id}/sarif")
    def get_sarif(scan_id: str) -> JSONResponse:
        with Storage(app.state.db_path) as db:
            issues, meta, _ = _completed_scan(db, scan_id)
        return JSONResponse(to_sarif(issues, meta), media_type=SARIF_MEDIA_TYPE)

    return app


def serve_command(
    host: Annotated[
        str,
        typer.Option(
            "--host",
            help="bind address (default loopback only; the API has no authentication, so a non-loopback "
            "address exposes it to the network)",
        ),
    ] = "127.0.0.1",
    port: Annotated[int, typer.Option("--port", help="bind port")] = 8000,
    db: Annotated[
        Path, typer.Option("--db", envvar="FLOWSTOPPER_DB", help="SQLite store shared with `scan`")
    ] = DEFAULT_DB_PATH,
    out_root: Annotated[
        Path,
        typer.Option("--out-root", envvar="FLOWSTOPPER_OUT", help="where API-run scans write <scan_id>/ outputs"),
    ] = DEFAULT_OUT_ROOT,
) -> None:
    """Serve the FlowStopper HTTP API with uvicorn."""
    uvicorn.run(create_app(db, out_root), host=host, port=port)
