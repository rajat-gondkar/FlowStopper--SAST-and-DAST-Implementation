"""SARIF 2.1.0 export (Owner: B, P5-B2, bonus B-6). The CI gate (exit code 2) is in report/gate.py.

`to_sarif(issues, meta)` is called by Dev A's api.py and pipeline.py; keep the name and signature.

One run, `tool.driver.name = "FlowStopper"`, one rule per CWE, one result per reported
(non-suppressed) issue (B-24):
- `level`: critical/high -> error, medium -> warning, else note.
- code: `locations[0].physicalLocation` with a relative `artifactLocation.uri` (uriBaseId SRCROOT),
  `region` = the offending lines (startLine/endLine + snippet) and `contextRegion` = the whole snippet.
- runtime: `webRequest` / `webResponse` built from the recorded exchange (a body-only excerpt becomes
  the response body); the raw request text, payload, proof, evidence and curl also go in `properties`.
- `partialFingerprints` = the issue id; `properties` = {label, risk, cwe, owasp, url, param, ...}.
Hard-coded secret values are masked in snippets (B-22).
"""

from __future__ import annotations

import re
from typing import Optional

from FlowStopper import __version__ as FLOWSTOPPER_VERSION
from FlowStopper import cwe as cwe_mod
from FlowStopper.models import CodeLocation, Issue, RuntimeLocation, Severity
from FlowStopper.report import common

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
TOOL_NAME = "FlowStopper"
SRCROOT = "SRCROOT"
FINGERPRINT_KEY = "flowstopperIssueId/v1"

LEVELS: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def level_for(severity: Severity) -> str:
    return LEVELS.get(severity, "note")


def rule_id(cwe: int) -> str:
    return f"CWE-{cwe}"


# --------------------------------------------------------------------------- rules
def _rule(cwe: int) -> dict:
    entry = cwe_mod.CATALOGUE.get(cwe)
    name = entry.name if entry else f"CWE-{cwe}"
    tags = ["security", rule_id(cwe)]
    rule: dict = {
        "id": rule_id(cwe),
        "name": re.sub(r"[^A-Za-z0-9]+", "", name.title()) or rule_id(cwe),
        "shortDescription": {"text": name},
        "helpUri": common.cwe_url(cwe),
    }
    if entry is not None:
        tags.append(entry.owasp_2025)
        rule["fullDescription"] = {"text": f"{name} ({rule_id(cwe)}), OWASP {entry.owasp_2025}."}
        rule["defaultConfiguration"] = {"level": level_for(entry.severity)}
        rule["help"] = {"text": f"See {common.cwe_url(cwe)} and {cwe_mod.OWASP_2025_URL}"}
        # GitHub code scanning reads this to rank alerts.
        rule["properties"] = {"tags": tags, "security-severity": f"{entry.base_score:.1f}"}
    else:
        rule["properties"] = {"tags": tags}
    return rule


# --------------------------------------------------------------------------- code locations
def _physical_location(cwe: int, loc: CodeLocation) -> dict:
    lines = common.snippet_lines(cwe, loc)
    hot = [ln.text for ln in lines if ln.hot]
    region: dict = {"startLine": loc.line_start, "endLine": max(loc.line_end, loc.line_start)}
    if hot:
        region["snippet"] = {"text": "\n".join(hot)}
    physical: dict = {
        "artifactLocation": {"uri": loc.file.lstrip("/"), "uriBaseId": SRCROOT},
        "region": region,
    }
    if lines and len(lines) > len(hot):
        physical["contextRegion"] = {
            "startLine": lines[0].number,
            "endLine": lines[-1].number,
            "snippet": {"text": "\n".join(ln.text for ln in lines)},
        }
    return physical


def _location(issue: Issue) -> Optional[dict]:
    loc = issue.primary_code
    if loc is None:
        return None
    out: dict = {"physicalLocation": _physical_location(issue.cwe, loc)}
    if loc.function:
        out["logicalLocations"] = [{"fullyQualifiedName": loc.function, "kind": "function"}]
    return out


# --------------------------------------------------------------------------- web request / response
_REQUEST_LINE = re.compile(r"^(?P<method>[A-Z]+) (?P<target>\S+) (?P<protocol>[A-Z]+)/(?P<version>[\d.]+)$")
_STATUS_LINE = re.compile(r"^(?P<protocol>[A-Z]+)/(?P<version>[\d.]+) (?P<code>\d{3})(?: (?P<reason>.*))?$")


def _split_message(raw: str) -> tuple[str, dict[str, str], str]:
    """(start line, headers, body) of a raw HTTP message (CRLF or LF)."""
    text = raw.replace("\r\n", "\n")
    head, _, body = text.partition("\n\n")
    first, *header_lines = head.split("\n")
    headers: dict[str, str] = {}
    for line in header_lines:
        name, sep, value = line.partition(":")
        if sep and name.strip():
            headers[name.strip()] = value.strip()
    return first.strip(), headers, body


def _web_request(rt: RuntimeLocation) -> dict:
    req: dict = {"protocol": "HTTP", "target": rt.url, "method": rt.method}
    if rt.param:
        req["parameters"] = {rt.param: rt.payload or ""}
    if rt.request:
        first, headers, body = _split_message(rt.request)
        m = _REQUEST_LINE.match(first)
        if m:
            req["version"] = m["version"]
        if headers:
            req["headers"] = headers
        if body:
            req["body"] = {"text": body}
    return req


def _recorded_status(issue: Issue) -> Optional[int]:
    """A status code a check recorded in the primary runtime finding's raw data, if any."""
    for f in issue.runtime_findings:
        if f.runtime == issue.primary_runtime:
            status = f.raw.get("status") if isinstance(f.raw, dict) else None
            if isinstance(status, int) and 100 <= status <= 599:
                return status
    return None


def _web_response(rt: RuntimeLocation, status: Optional[int] = None) -> Optional[dict]:
    """webResponse from the stored excerpt: a full status line + headers when recorded, else the body."""
    if not rt.response_excerpt:
        return None
    first, headers, body = _split_message(rt.response_excerpt)
    m = _STATUS_LINE.match(first)
    if not m:
        # The DAST client stores the body excerpt only; keep it (and a recorded status) as the response.
        resp_body: dict = {"protocol": "HTTP", "body": {"text": rt.response_excerpt}}
        if status is not None:
            resp_body["statusCode"] = status
        return resp_body
    resp: dict = {"protocol": m["protocol"], "version": m["version"], "statusCode": int(m["code"])}
    if m["reason"]:
        resp["reasonPhrase"] = m["reason"]
    if headers:
        resp["headers"] = headers
    if body:
        resp["body"] = {"text": body}
    return resp


# --------------------------------------------------------------------------- results
def _message(issue: Issue) -> str:
    parts = [f"{issue.title}.", f"{common.LABEL_TEXT[issue.label]}, {issue.severity.value}, risk {issue.risk:.1f}/10."]
    rt = issue.primary_runtime
    if rt is not None and rt.evidence:
        parts.append(f"Runtime evidence: {rt.evidence}")
    return " ".join(parts)


def _properties(issue: Issue) -> dict:
    rt = issue.primary_runtime
    props: dict = {
        "label": issue.label.value,
        "risk": issue.risk,
        "cwe": issue.cwe,
        "owasp": common.owasp_for(issue),
        "url": rt.url if rt else None,
        "param": rt.param if rt else (_source_param(issue)),
        "severity": issue.severity.value,
        "cvss": issue.cvss,
    }
    if issue.link_score is not None:
        props["linkScore"] = issue.link_score
    if issue.verified_by:
        props["verifiedBy"] = issue.verified_by
    if rt is not None:
        props["method"] = rt.method
        if rt.payload is not None:
            props["payload"] = rt.payload
        props["proof"] = rt.proof
        if rt.repro_curl:
            props["reproCurl"] = rt.repro_curl
        if rt.evidence:
            props["evidence"] = rt.evidence
        if rt.request:
            props["request"] = rt.request  # the raw text, in case a consumer ignores webRequest
    if issue.reasons:
        props["reasons"] = [r.model_dump(mode="json") for r in issue.reasons]
    props["fix"] = common.fix_text(issue)
    return props


def _source_param(issue: Issue) -> Optional[str]:
    for f in issue.code_findings:
        if f.taint is not None and f.taint.source_param:
            return f.taint.source_param
    return None


def _result(issue: Issue, rule_index: int) -> dict:
    result: dict = {
        "ruleId": rule_id(issue.cwe),
        "ruleIndex": rule_index,
        "level": level_for(issue.severity),
        "message": {"text": _message(issue)},
    }
    location = _location(issue)
    if location is not None:
        result["locations"] = [location]
    rt = issue.primary_runtime
    if rt is not None:
        result["webRequest"] = _web_request(rt)
        response = _web_response(rt, _recorded_status(issue))
        if response is not None:
            result["webResponse"] = response
    result["partialFingerprints"] = {FINGERPRINT_KEY: issue.id}
    result["properties"] = _properties(issue)
    return result


def to_sarif(issues: list[Issue], meta: Optional[dict] = None) -> dict:
    """SARIF 2.1.0 log with one run: one rule per CWE, one result per reported (non-suppressed) issue.

    `meta` is the content of scan_meta.json (may be None). Output is deterministic for a given input.
    """
    meta = meta or {}
    reported, _ = common.split_issues(issues)
    cwes = sorted({i.cwe for i in reported})
    index = {c: n for n, c in enumerate(cwes)}
    version = (meta.get("versions") or {}).get(TOOL_NAME) or FLOWSTOPPER_VERSION
    run: dict = {
        "tool": {"driver": {"name": TOOL_NAME, "version": str(version), "rules": [_rule(c) for c in cwes]}},
        "originalUriBaseIds": {SRCROOT: {"description": {"text": "Root of the scanned source tree"}}},
        "results": [_result(i, index[i.cwe]) for i in reported],
        "columnKind": "unicodeCodePoints",
    }
    if meta.get("scan_id"):
        run["automationDetails"] = {"id": f"flowstopper/{meta['scan_id']}"}
    invocation: dict = {"executionSuccessful": meta.get("status", "completed") == "completed"}
    if meta.get("started_at"):
        invocation["startTimeUtc"] = meta["started_at"]
    if meta.get("finished_at"):
        invocation["endTimeUtc"] = meta["finished_at"]
    run["invocations"] = [invocation]
    props = {k: meta[k] for k in ("target", "source", "truncated", "seed") if k in meta}
    if props:
        run["properties"] = props
    return {"$schema": SARIF_SCHEMA, "version": SARIF_VERSION, "runs": [run]}
