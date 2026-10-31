"""SARIF 2.1.0 export (Owner: B, P5-B2, bonus B-6). The CI gate (exit code 2) is in report/gate.py.

`to_sarif(issues, meta)` is called by Dev A's api.py and pipeline.py; keep the name and signature.
"""

from __future__ import annotations

from typing import Optional

from FlowStopper import cwe as cwe_mod
from FlowStopper.correlate.issues import is_suppressed, sort_issues
from FlowStopper.models import Issue, Severity

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
TOOL_NAME = "FlowStopper"

LEVELS: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def rule_id(cwe: int) -> str:
    return f"CWE-{cwe}"


def _rule(cwe: int) -> dict:
    entry = cwe_mod.CATALOGUE.get(cwe)
    name = entry.name if entry else f"CWE-{cwe}"
    rule: dict = {
        "id": rule_id(cwe),
        "name": name,
        "shortDescription": {"text": name},
    }
    if entry:
        rule["helpUri"] = entry.mitre_url
    return rule


def _result(issue: Issue) -> dict:
    return {
        "ruleId": rule_id(issue.cwe),
        "level": LEVELS.get(issue.severity, "note"),
        "message": {"text": issue.title},
        "partialFingerprints": {"flowstopperIssueId": issue.id},
    }


def to_sarif(issues: list[Issue], meta: Optional[dict] = None) -> dict:
    """SARIF 2.1.0 log with one run: one rule per CWE, one result per reported (non-suppressed) issue.

    `meta` is the content of scan_meta.json (may be None).
    """
    reported = [i for i in sort_issues(issues) if not is_suppressed(i)]
    cwes = sorted({i.cwe for i in reported})
    run: dict = {
        "tool": {"driver": {"name": TOOL_NAME, "rules": [_rule(c) for c in cwes]}},
        "results": [_result(i) for i in reported],
    }
    if meta and meta.get("scan_id"):
        run["automationDetails"] = {"id": str(meta["scan_id"])}
    return {"$schema": SARIF_SCHEMA, "version": SARIF_VERSION, "runs": [run]}
