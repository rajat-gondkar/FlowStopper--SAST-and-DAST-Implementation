"""`FlowStopper eval` implementation: load key + issues, print table, write docs/metrics (Owner: B)."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from FlowStopper.evalkit.keyschema import load_key
from FlowStopper.evalkit.metrics import compute_metrics
from FlowStopper.models import Issue


def load_issues(path: str | Path) -> list[Issue]:
    """Load an issues.json (a JSON array of Issue objects)."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return [Issue.model_validate(x) for x in data]


def default_out_path() -> Path:
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return Path("docs/metrics") / f"{ts}.json"


def run_eval(key_path: str | Path, issues_path: str | Path, out_path: str | Path | None = None) -> tuple[dict, Path]:
    """Score an issues file against an answer key; write the metrics JSON and return (metrics, path)."""
    key = load_key(key_path)
    issues = load_issues(issues_path)
    metrics = compute_metrics(issues, key)
    out = Path(out_path) if out_path else default_out_path()
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(metrics, indent=2) + "\n", encoding="utf-8")
    return metrics, out
