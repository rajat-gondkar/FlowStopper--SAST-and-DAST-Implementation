"""`FlowStopper eval` implementation: load key + issues, print table, write docs/metrics (Owner: B).

Two ways to name the issues being scored (P3-B1):

- `--scan <id>` reads that scan's snapshot from the SQLite store the pipeline writes (`latest` picks
  the most recent completed scan). Run time comes from the stored stage timings.
- `--issues issues.json` reads a file. If the pipeline's `scan_meta.json` sits next to it, the run
  time, truncation flag and scan id are read from there too.

The written report keeps provenance (which key, which scan, when, whether DAST was truncated) so a
metrics file in docs/metrics/ can be trusted on its own later. It holds only counts and rates - never
file paths, routes or findings from the scanned app - so a report for the organisers' app is safe to
commit (rule R5); the answer-key path recorded is the one the caller passed.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from FlowStopper.correlate.issues import is_suppressed
from FlowStopper.evalkit.keyschema import AnswerKey, load_key
from FlowStopper.evalkit.metrics import _code_matches, _runtime_matches, assess, compute_metrics
from FlowStopper.models import Issue
from FlowStopper.storage import DEFAULT_DB_PATH, Storage

REPORT_SCHEMA = "flowstopper-metrics/1"
META_FILE = "scan_meta.json"  # written by the pipeline next to issues.json (P3-A1)
DEFAULT_METRICS_DIR = Path("docs") / "metrics"


class EvalError(Exception):
    """The issues to score could not be found or read (unknown scan, failed scan, bad file)."""


@dataclass
class IssueSource:
    """The issues being scored plus whatever is known about the run that produced them."""

    issues: list[Issue]
    kind: str  # "scan" | "issues"
    scan_id: Optional[str] = None
    issues_path: Optional[str] = None
    db_path: Optional[str] = None
    run_time_s: Optional[float] = None
    truncated: Optional[bool] = None  # None = unknown (the store does not record it)


# --------------------------------------------------------------------------- loading
def load_issues(path: str | Path) -> list[Issue]:
    """Load an issues.json (a JSON array of Issue objects)."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return [Issue.model_validate(x) for x in data]


def _read_sibling_meta(issues_path: Path) -> dict:
    meta_path = issues_path.parent / META_FILE
    if not meta_path.is_file():
        return {}
    try:
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return meta if isinstance(meta, dict) else {}


def issues_from_file(path: str | Path) -> IssueSource:
    p = Path(path)
    try:
        issues = load_issues(p)
    except OSError as exc:
        raise EvalError(f"cannot read issues file {p}: {exc}") from exc
    except ValueError as exc:
        raise EvalError(f"{p} is not a valid issues.json: {exc}") from exc
    meta = _read_sibling_meta(p)
    timings = meta.get("timings_s") if isinstance(meta.get("timings_s"), dict) else {}
    total = timings.get("total")
    truncated = meta.get("truncated")
    return IssueSource(
        issues=issues,
        kind="issues",
        scan_id=meta.get("scan_id"),
        issues_path=str(p),
        run_time_s=float(total) if isinstance(total, (int, float)) else None,
        truncated=truncated if isinstance(truncated, bool) else None,
    )


def issues_from_scan(scan_id: str, db_path: str | Path = DEFAULT_DB_PATH) -> IssueSource:
    """A stored scan's issues, as that scan reported them (its snapshot, not the latest state)."""
    db_file = Path(db_path)
    if not db_file.is_file():
        raise EvalError(f"no scan database at {db_file} (run `FlowStopper scan` first, or pass --db)")
    with Storage(db_file) as db:
        if scan_id == "latest":
            completed = [s for s in db.list_scans() if s["status"] == "completed"]
            if not completed:
                raise EvalError(f"no completed scan in {db_file}")
            scan = completed[0]  # list_scans() is newest first
        else:
            scan = db.get_scan(scan_id)
            if scan is None:
                raise EvalError(f"unknown scan id {scan_id!r} in {db_file}")
        if scan["status"] != "completed":
            raise EvalError(f"scan {scan['id']} has status {scan['status']!r}; only completed scans can be scored")
        # include_suppressed: suppressed findings still count for detection, and the false-alarm
        # metric needs them present to know they are *not* reported.
        issues = db.get_issues(scan_id=scan["id"], include_suppressed=True)
    total = scan.get("timings", {}).get("total")
    return IssueSource(
        issues=issues,
        kind="scan",
        scan_id=scan["id"],
        db_path=str(db_file),
        run_time_s=float(total) if isinstance(total, (int, float)) else None,
        truncated=None,
    )


# --------------------------------------------------------------------------- unplanted (Appendix C)
def unplanted_issues(issues: list[Issue], key: AnswerKey) -> list[Issue]:
    """Reported issues that match no planted vuln and no decoy.

    Appendix C asks for these as an informational count: they are not penalised by any section 4
    metric, but a high number is the first thing to look at when triaging (P3-J2).
    """
    out: list[Issue] = []
    for issue in issues:
        if is_suppressed(issue):
            continue
        matched = False
        for f in issue.code_findings:
            if any(
                v.code and _code_matches(f, v.cwe, v.code.file, v.code.line_start, v.code.line_end) for v in key.vulns
            ) or any(_code_matches(f, d.cwe, d.file, d.line_start, d.line_end) for d in key.decoys):
                matched = True
                break
        if not matched:
            matched = any(
                v.runtime and _runtime_matches(f, v.runtime, v.cwe) for f in issue.runtime_findings for v in key.vulns
            )
        if not matched:
            out.append(issue)
    return out


# --------------------------------------------------------------------------- the report
def default_out_path(now: Optional[datetime] = None) -> Path:
    ts = (now or datetime.now(timezone.utc)).strftime("%Y%m%dT%H%M%SZ")
    return DEFAULT_METRICS_DIR / f"{ts}.json"


def display_path(path: str | Path | None) -> Optional[str]:
    """POSIX path relative to the working directory when it lies under it, else as given.

    Keeps machine-specific prefixes (home directories, mount points) out of metrics files that get
    committed to docs/metrics/, so the same run reported on two machines reads the same.
    """
    if path is None:
        return None
    p = Path(path)
    try:
        return p.resolve().relative_to(Path.cwd().resolve()).as_posix()
    except (ValueError, OSError):
        return p.as_posix()


def build_report(key: AnswerKey, key_path: str | Path, source: IssueSource) -> dict:
    metrics = compute_metrics(source.issues, key)
    suppressed = sum(1 for i in source.issues if is_suppressed(i))
    return {
        "schema": REPORT_SCHEMA,
        "app": key.app,
        "key": display_path(key_path),
        "evaluated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "source": {
            "kind": source.kind,
            "scan_id": source.scan_id,
            "issues": display_path(source.issues_path),
            "db": display_path(source.db_path),
        },
        "run_time_s": source.run_time_s,
        "truncated": source.truncated,
        "issues": {"total": len(source.issues), "reported": len(source.issues) - suppressed, "suppressed": suppressed},
        "unplanted": len(unplanted_issues(source.issues, key)),
        "metrics": metrics,
        "status": assess(metrics, source.run_time_s),
    }


def run_eval(
    key_path: str | Path,
    issues_path: str | Path | None = None,
    out_path: str | Path | None = None,
    *,
    scan_id: Optional[str] = None,
    db_path: str | Path = DEFAULT_DB_PATH,
) -> tuple[dict, Path]:
    """Score issues (a file, or a stored scan) against an answer key; write the report.

    Returns (report, path written). Raises EvalError for a missing/failed scan or unreadable file;
    key validation errors propagate from keyschema.
    """
    if (issues_path is None) == (scan_id is None):
        raise EvalError("pass exactly one of an issues file or a scan id")
    key = load_key(key_path)
    source = issues_from_file(issues_path) if issues_path is not None else issues_from_scan(scan_id, db_path)
    report = build_report(key, key_path, source)
    out = Path(out_path) if out_path else default_out_path()
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report, out
