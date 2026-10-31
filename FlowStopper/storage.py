"""SQLite storage (Owner: B, P2-B5).

Tables: scans, findings, issues (upsert on issues.id, FR-6), scan_issues. See spec P2-B5.

FR-6 idempotency is the point of this module: `Issue.id` is a content fingerprint, so re-scanning
an unchanged app re-saves the *same* rows. `issues` therefore upserts - `first_seen_scan` is written
once and never moves, `last_seen_scan` advances - which is what lets a Code-only issue become
Confirmed later without changing identity, and what `FlowStopper diff` (B-5) would compare.
`scan_issues` keeps a per-scan snapshot so historical scans stay accurate after an issue evolves.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Iterable, Sequence
from datetime import datetime, timezone
from pathlib import Path
from types import TracebackType
from typing import Optional

from FlowStopper.correlate.issues import is_suppressed, sort_issues
from FlowStopper.models import Finding, Issue

DEFAULT_DB_PATH = Path(".flowstopper") / "scans.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id            TEXT PRIMARY KEY,
    started_at    TEXT NOT NULL,
    finished_at   TEXT,
    source_path   TEXT,
    target_url    TEXT,
    status        TEXT NOT NULL,
    config_json   TEXT,
    timings_json  TEXT,
    seed          INTEGER
);
CREATE TABLE IF NOT EXISTS findings (
    id          TEXT NOT NULL,
    scan_id     TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    engine      TEXT NOT NULL,
    cwe         INTEGER NOT NULL,
    suppressed  INTEGER NOT NULL DEFAULT 0,
    json        TEXT NOT NULL,
    PRIMARY KEY (id, scan_id)
);
CREATE TABLE IF NOT EXISTS issues (
    id               TEXT PRIMARY KEY,
    cwe              INTEGER NOT NULL,
    json             TEXT NOT NULL,
    first_seen_scan  TEXT,
    last_seen_scan   TEXT
);
CREATE TABLE IF NOT EXISTS scan_issues (
    scan_id        TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    issue_id       TEXT NOT NULL REFERENCES issues(id) ON DELETE CASCADE,
    label          TEXT NOT NULL,
    risk           REAL NOT NULL,
    json_snapshot  TEXT NOT NULL,
    PRIMARY KEY (scan_id, issue_id)
);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_scan_issues_scan ON scan_issues(scan_id);
"""


def utc_now() -> str:
    """ISO-8601 UTC timestamp. Only ever stored, never fed into an ID (determinism)."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def make_scan_id(source_path: Optional[str], target_url: Optional[str], started_at: str) -> str:
    """Scan ids identify a *run*, so the timestamp is part of them (unlike finding/issue ids)."""
    material = f"{source_path or ''}|{target_url or ''}|{started_at}".encode()
    return hashlib.sha256(material).hexdigest()[:16]


class Storage:
    """Thin, explicit SQLite wrapper. Use as a context manager: `with Storage(path) as db:`."""

    def __init__(self, path: str | Path = DEFAULT_DB_PATH) -> None:
        self.path = Path(path)
        if self.path.parent and str(self.path.parent) not in ("", "."):
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.path))
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    # ------------------------------------------------------------------ lifecycle
    def __enter__(self) -> Storage:
        return self

    def __exit__(
        self,
        exc_type: Optional[type[BaseException]],
        exc: Optional[BaseException],
        tb: Optional[TracebackType],
    ) -> None:
        self.close()

    def close(self) -> None:
        self.conn.commit()
        self.conn.close()

    # ------------------------------------------------------------------ scans
    def start_scan(
        self,
        *,
        source_path: Optional[str] = None,
        target_url: Optional[str] = None,
        config: Optional[dict] = None,
        seed: Optional[int] = None,
        scan_id: Optional[str] = None,
        started_at: Optional[str] = None,
    ) -> str:
        started = started_at or utc_now()
        sid = scan_id or make_scan_id(source_path, target_url, started)
        self.conn.execute(
            """INSERT INTO scans (id, started_at, source_path, target_url, status, config_json, seed)
               VALUES (?, ?, ?, ?, 'running', ?, ?)
               ON CONFLICT(id) DO UPDATE SET
                   started_at = excluded.started_at,
                   source_path = excluded.source_path,
                   target_url = excluded.target_url,
                   status = 'running',
                   config_json = excluded.config_json,
                   seed = excluded.seed""",
            (sid, started, source_path, target_url, json.dumps(config or {}, sort_keys=True), seed),
        )
        self.conn.commit()
        return sid

    def finish_scan(self, scan_id: str, *, status: str = "completed", timings: Optional[dict] = None) -> None:
        self.conn.execute(
            "UPDATE scans SET finished_at = ?, status = ?, timings_json = ? WHERE id = ?",
            (utc_now(), status, json.dumps(timings or {}, sort_keys=True), scan_id),
        )
        self.conn.commit()

    def get_scan(self, scan_id: str) -> Optional[dict]:
        row = self.conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        if row is None:
            return None
        scan = dict(row)
        scan["config"] = json.loads(scan.pop("config_json") or "{}")
        scan["timings"] = json.loads(scan.pop("timings_json") or "{}")
        return scan

    def list_scans(self) -> list[dict]:
        rows = self.conn.execute("SELECT id FROM scans ORDER BY started_at DESC, id").fetchall()
        return [scan for scan in (self.get_scan(r["id"]) for r in rows) if scan is not None]

    # ------------------------------------------------------------------ findings
    def save_findings(self, scan_id: str, findings: Iterable[Finding]) -> int:
        rows = [
            (
                f.id,
                scan_id,
                f.engine.value,
                f.cwe,
                int(f.suppressed),
                f.model_dump_json(),
            )
            for f in findings
        ]
        self.conn.executemany(
            """INSERT INTO findings (id, scan_id, engine, cwe, suppressed, json)
               VALUES (?, ?, ?, ?, ?, ?)
               ON CONFLICT(id, scan_id) DO UPDATE SET
                   engine = excluded.engine,
                   cwe = excluded.cwe,
                   suppressed = excluded.suppressed,
                   json = excluded.json""",
            rows,
        )
        self.conn.commit()
        return len(rows)

    def get_findings(self, scan_id: str, *, engine: Optional[str] = None) -> list[Finding]:
        sql = "SELECT json FROM findings WHERE scan_id = ?"
        args: list[object] = [scan_id]
        if engine:
            sql += " AND engine = ?"
            args.append(engine)
        sql += " ORDER BY cwe, id"
        rows = self.conn.execute(sql, args).fetchall()
        return [Finding.model_validate_json(r["json"]) for r in rows]

    # ------------------------------------------------------------------ issues
    def save_issues(self, scan_id: str, issues: Sequence[Issue]) -> int:
        """Upsert issues (FR-6) and snapshot them against this scan."""
        for issue in issues:
            payload = issue.model_dump_json()
            self.conn.execute(
                """INSERT INTO issues (id, cwe, json, first_seen_scan, last_seen_scan)
                   VALUES (?, ?, ?, ?, ?)
                   ON CONFLICT(id) DO UPDATE SET
                       cwe = excluded.cwe,
                       json = excluded.json,
                       last_seen_scan = excluded.last_seen_scan""",
                (issue.id, issue.cwe, payload, scan_id, scan_id),
            )
            self.conn.execute(
                """INSERT INTO scan_issues (scan_id, issue_id, label, risk, json_snapshot)
                   VALUES (?, ?, ?, ?, ?)
                   ON CONFLICT(scan_id, issue_id) DO UPDATE SET
                       label = excluded.label,
                       risk = excluded.risk,
                       json_snapshot = excluded.json_snapshot""",
                (scan_id, issue.id, issue.label.value, issue.risk, payload),
            )
        self.conn.commit()
        return len(issues)

    def get_issue(self, issue_id: str) -> Optional[Issue]:
        row = self.conn.execute("SELECT json FROM issues WHERE id = ?", (issue_id,)).fetchone()
        return Issue.model_validate_json(row["json"]) if row else None

    def issue_history(self, issue_id: str) -> Optional[dict]:
        """first/last scan an issue was seen in - the basis for scan diffing."""
        row = self.conn.execute(
            "SELECT id, first_seen_scan, last_seen_scan FROM issues WHERE id = ?", (issue_id,)
        ).fetchone()
        return dict(row) if row else None

    def get_issues(
        self,
        *,
        scan_id: Optional[str] = None,
        label: Optional[str] = None,
        cwe: Optional[int] = None,
        min_risk: Optional[float] = None,
        include_suppressed: bool = False,
    ) -> list[Issue]:
        """Prioritised issue list (FR-9). Suppressed issues are hidden unless asked for (B-2).

        `scan_id` reads that scan's snapshots (what it reported at the time); without it, the
        latest state of every issue is returned. `label`/`min_risk` push down into SQL for the
        snapshot table, which stores them; `cwe` and the derived suppressed state are applied in
        Python so the schema stays exactly as the spec defines it.
        """
        if scan_id:
            sql = "SELECT json_snapshot AS json FROM scan_issues WHERE scan_id = ?"
            args: list[object] = [scan_id]
            if label:
                sql += " AND label = ?"
                args.append(label)
            if min_risk is not None:
                sql += " AND risk >= ?"
                args.append(min_risk)
            rows = self.conn.execute(sql, args).fetchall()
            issues = [Issue.model_validate_json(r["json"]) for r in rows]
        else:
            rows = self.conn.execute("SELECT json FROM issues").fetchall()
            issues = [Issue.model_validate_json(r["json"]) for r in rows]
            if label:
                issues = [i for i in issues if i.label.value == label]
            if min_risk is not None:
                issues = [i for i in issues if i.risk >= min_risk]

        if cwe is not None:
            issues = [i for i in issues if i.cwe == cwe]
        if not include_suppressed:
            issues = [i for i in issues if not is_suppressed(i)]
        return sort_issues(issues)

    def counts_by_label(self, scan_id: str) -> dict[str, int]:
        rows = self.conn.execute(
            "SELECT label, COUNT(*) AS n FROM scan_issues WHERE scan_id = ? GROUP BY label ORDER BY label",
            (scan_id,),
        ).fetchall()
        return {r["label"]: r["n"] for r in rows}
