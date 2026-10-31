"""SAST orchestration (Owner: A, P2-A6). Cross-developer interface (spec section 6).

index -> routes -> call graph -> templates -> taint -> secrets -> `SastResult`.
Never imports or executes target code (R7): parse only.

The template scan runs *before* the taint analysis because the CWE-79 template rule needs the
unescaped-variable map to decide whether a render call's keyword argument is a sink (DECISIONS
A-18). Findings are sorted by `(file, line, cwe, rule_id, id)` and `stats` carries counts only - no
timings, no timestamps - so two scans of the same tree serialise byte-for-byte (FR-6).
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from FlowStopper.cwe import get_cwe
from FlowStopper.ids import code_finding_id
from FlowStopper.models import CodeLocation, Engine, Finding, SastResult, TaintInfo
from FlowStopper.sast import suppress
from FlowStopper.sast.callgraph import annotate_reachable, build_call_graph
from FlowStopper.sast.config import SastConfig
from FlowStopper.sast.index import ProjectIndex, build_index
from FlowStopper.sast.routes import extract_routes
from FlowStopper.sast.secrets import SecretHit, scan_secrets
from FlowStopper.sast.taint import sinks
from FlowStopper.sast.taint.summaries import TaintFinding, TaintStats, analyse_taint
from FlowStopper.sast.templates import scan_templates
from FlowStopper.sast.textfiles import read_text

TAINT_TOOL = "FlowStopper-taint"
SECRETS_TOOL = "FlowStopper-secrets"
MAX_SNIPPET_LINES = 12  # models.CodeLocation: a snippet is at most 12 lines
SNIPPET_CONTEXT = 1  # lines kept on each side of the offending lines
# The rule id the P2-A5 template sink emits, for the stats counter (one source of truth: sinks.py).
TEMPLATE_RULE_ID = sinks.rule_id(sinks.TEMPLATE_RENDER.rule_family, sinks.TEMPLATE_RENDER.token, frozenset())


def run_sast(source_root: Path | str, config: Optional[SastConfig] = None) -> SastResult:
    """Return routes + findings for the sources under `source_root` (parsed, never executed)."""
    config = config or SastConfig()
    index = build_index(source_root, config)
    graph = build_call_graph(index, config)
    routes = annotate_reachable(index, extract_routes(index), config, graph=graph)
    templates = scan_templates(index.root, config)
    taint_stats = TaintStats()
    taint = analyse_taint(index, routes, graph, templates, config, stats=taint_stats)
    secrets = scan_secrets(index.root, index, config)

    snippets = _Snippets(index, config)
    findings = [_taint_finding(f, snippets) for f in taint] + [_secret_finding(h, snippets) for h in secrets]
    findings.sort(key=_order)

    stats = index.stats()
    stats["routes"] = len(routes)
    stats["findings"] = len(findings)
    stats["taint_findings"] = len(taint)
    stats["secret_findings"] = len(secrets)
    stats["template_findings"] = sum(1 for f in taint if f.rule_id == TEMPLATE_RULE_ID)
    stats["functions_analysed"] = taint_stats.functions_analysed
    stats["summary_iterations"] = taint_stats.summary_iterations
    # B-2 noise cut counters (P4-A2): how many findings were kept back, and why.
    reasons = [f.suppress_reason or "" for f in findings if f.suppressed]
    stats["reported_findings"] = len(findings) - len(reasons)
    stats["suppressed_findings"] = len(reasons)
    stats["suppressed_sanitized"] = sum(1 for r in reasons if r.startswith(suppress.SANITIZED_PREFIX))
    stats["suppressed_safe"] = sum(1 for r in reasons if r.startswith(suppress.SAFE_PREFIX))
    stats["suppressed_unreachable"] = sum(1 for r in reasons if r == suppress.UNREACHABLE)
    stats["request_hooks"] = taint_stats.request_hooks
    stats["unreachable_functions"] = taint_stats.unreachable_functions
    return SastResult(routes=routes, findings=findings, stats=stats)


# --------------------------------------------------------------------------- findings
def _code_finding(
    *,
    tool: str,
    rule_id: str,
    cwe: int,
    title: str,
    confidence: float,
    code: CodeLocation,
    taint: Optional[TaintInfo] = None,
    suppressed: bool = False,
    suppress_reason: Optional[str] = None,
    raw: Optional[dict] = None,
) -> Finding:
    """One code-side finding: stable id from `ids.py`, severity from the CWE catalogue."""
    return Finding(
        id=code_finding_id(Engine.SAST, rule_id, cwe, code.file, code.function, code.line_start),
        engine=Engine.SAST,
        tool=tool,
        rule_id=rule_id,
        cwe=cwe,
        title=title,
        severity=get_cwe(cwe).severity,
        confidence=confidence,
        code=code,
        taint=taint,
        suppressed=suppressed,
        suppress_reason=suppress_reason,
        raw=dict(raw or {}),
    )


def _taint_finding(finding: TaintFinding, snippets: _Snippets) -> Finding:
    """A taint finding with its snippets filled in (the driver leaves them empty)."""
    code = CodeLocation(
        file=finding.file,
        line_start=finding.line_start,
        line_end=finding.line_end,
        function=finding.function,
        snippet=snippets.of(finding.file, finding.line_start, finding.line_end),
    )
    return _code_finding(
        tool=TAINT_TOOL,
        rule_id=finding.rule_id,
        cwe=finding.cwe,
        title=finding.title,
        confidence=finding.confidence,
        code=code,
        taint=_with_source_snippet(finding.taint, snippets),
        suppressed=finding.suppressed,
        suppress_reason=finding.suppress_reason,
        raw=finding.raw,
    )


def _secret_finding(hit: SecretHit, snippets: _Snippets) -> Finding:
    """A hard-coded secret (CWE-798); the literal is reported redacted, never in full."""
    code = CodeLocation(
        file=hit.file,
        line_start=hit.line,
        line_end=hit.line,
        function=hit.function,
        snippet=snippets.of(hit.file, hit.line, hit.line),
    )
    return _code_finding(
        tool=SECRETS_TOOL,
        rule_id=hit.rule_id,
        cwe=hit.cwe,
        title=hit.title,
        confidence=hit.confidence,
        code=code,
        raw={"name": hit.name, "value_redacted": hit.redacted, "entropy": round(hit.entropy, 3)},
    )


def _with_source_snippet(taint: TaintInfo, snippets: _Snippets) -> TaintInfo:
    """`taint` with the source line quoted in `source_location.snippet` (no surrounding context)."""
    source = taint.source_location
    if source is None:
        return taint
    snippet = snippets.of(source.file, source.line_start, source.line_end, context=0)
    return taint.model_copy(update={"source_location": source.model_copy(update={"snippet": snippet})})


def _order(finding: Finding) -> tuple:
    code = finding.code
    file = code.file if code is not None else ""
    line = code.line_start if code is not None else 0
    return (file, line, finding.cwe, finding.rule_id, finding.id)


class _Snippets:
    """Source lines for snippets: the index's parsed modules for Python, the file itself otherwise."""

    def __init__(self, index: ProjectIndex, config: SastConfig) -> None:
        self.index = index
        self.config = config
        self._cache: dict[str, list[str]] = {}

    def of(self, file: str, line_start: int, line_end: int, context: int = SNIPPET_CONTEXT) -> str:
        """Lines `line_start`..`line_end` plus `context` lines on each side, capped at 12 lines."""
        lines = self._lines(file)
        start = max(line_start - 1 - context, 0)
        end = min(line_end + context, len(lines))
        return "\n".join(lines[start:end][:MAX_SNIPPET_LINES])

    def _lines(self, file: str) -> list[str]:
        cached = self._cache.get(file)
        if cached is None:
            module = self.index.module_for_file(file)
            cached = module.lines if module is not None else self._text_lines(file)
            self._cache[file] = cached
        return cached

    def _text_lines(self, file: str) -> list[str]:
        """Lines of a non-Python file a secret was reported in: read as text, never executed (R7)."""
        text = read_text(self.index.root / file, file, self.config, scanner="runner")
        return text.splitlines() if text is not None else []
