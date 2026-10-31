"""Phase 2 exit gate (Owner: A): SAST accuracy on apps/mock_a against its answer key.

The Appendix C code-match rule is implemented here rather than imported from Dev B's evalkit
(DECISIONS A-19): same normalised POSIX file, same CWE family, and the finding's line range
overlapping the key's range widened by `LINE_SLACK` lines. Every app-specific string stays in this
test and in the key file - nothing app-specific may enter `FlowStopper/` (R6).

Floors (spec Phase 2 exit): >= 12 of the 13 code-located planted vulns detected, <= 1 decoy false
alarm, the cross-file helper bugs M01/M02/M05 all matched, and every injection finding carrying
`taint.source_param` plus a non-empty `taint.entry_routes` of real route ids.
"""

from __future__ import annotations

import pytest

from FlowStopper.cwe import same_family
from FlowStopper.evalkit.keyschema import AnswerKey, KeyCode, KeyDecoy, load_key
from FlowStopper.models import Finding, SastResult
from FlowStopper.sast.runner import run_sast
from tests.conftest import ROOT

MOCK_A = ROOT / "apps" / "mock_a"
EXPECTED_ROUTES = 25
LINE_SLACK = 3  # Appendix C: a finding within three lines of the keyed range matches
DETECTION_FLOOR = 12  # of the 13 code-located planted vulns
DECOY_CEILING = 1  # non-suppressed findings landing on a decoy
CROSS_FILE_IDS = frozenset({"M01", "M02", "M05"})  # the handler -> helper -> sink flows
INJECTION_CWES = frozenset({89, 78, 22, 601, 79})


@pytest.fixture(scope="module")
def result() -> SastResult:
    return run_sast(MOCK_A)


@pytest.fixture(scope="module")
def key() -> AnswerKey:
    return load_key(MOCK_A / "answer_key.json")


def _norm(file: str) -> str:
    return file.replace("\\", "/").removeprefix("./")


def _overlaps(finding: Finding, line_start: int, line_end: int) -> bool:
    code = finding.code
    return code is not None and code.line_start <= line_end + LINE_SLACK and line_start - LINE_SLACK <= code.line_end


def _matches(finding: Finding, code: KeyCode, cwe: int) -> bool:
    """Appendix C code match: same file, same CWE family, overlapping line ranges."""
    if finding.code is None or _norm(finding.code.file) != _norm(code.file):
        return False
    return same_family(finding.cwe, cwe) and _overlaps(finding, code.line_start, code.line_end)


def _code_vulns(key: AnswerKey) -> list:
    return [v for v in key.vulns if v.code is not None]


def _detected(result: SastResult, key: AnswerKey) -> dict[str, Finding]:
    """Keyed id -> the finding that matches it; one finding answers for at most one keyed vuln.

    Suppressed findings do not count, and the assignment is unique so that a single finding sitting
    within the slack of two nearby keyed lines cannot inflate the detection count.
    """
    live = [f for f in result.findings if not f.suppressed]
    out: dict[str, Finding] = {}
    used: set[str] = set()
    for vuln in _code_vulns(key):
        for finding in live:
            if finding.id not in used and _matches(finding, vuln.code, vuln.cwe):
                out[vuln.id] = finding
                used.add(finding.id)
                break
    return out


def _false_alarms(result: SastResult, decoy: KeyDecoy) -> list[Finding]:
    """Non-suppressed findings whose code location overlaps the decoy's own range (spec Appendix C).

    The three-line slack belongs to the code-match rule, not here, so a true positive a few lines
    above a decoy is not counted against us.
    """
    return [
        f
        for f in result.findings
        if not f.suppressed
        and f.code is not None
        and _norm(f.code.file) == _norm(decoy.file)
        and f.code.line_start <= decoy.line_end
        and decoy.line_start <= f.code.line_end
    ]


def test_route_map_is_unchanged(result):
    assert len(result.routes) == EXPECTED_ROUTES
    assert result.stats["routes"] == EXPECTED_ROUTES
    assert result.findings, "the gate needs findings: the runner reported none"


def test_code_detection_meets_the_floor(result, key):
    planted = _code_vulns(key)
    detected = _detected(result, key)
    missed = sorted({v.id for v in planted} - set(detected))
    assert len(planted) == 13, f"the key has {len(planted)} code-located vulns, expected 13"
    assert len(detected) >= DETECTION_FLOOR, (
        f"detected {len(detected)}/{len(planted)} code-located vulns (floor {DETECTION_FLOOR}); missed {missed}"
    )


def test_cross_file_helper_bugs_are_matched(result, key):
    detected = _detected(result, key)
    missed = sorted(CROSS_FILE_IDS - set(detected))
    assert not missed, f"cross-file flows missed: {missed} (detected {sorted(detected)})"
    for keyed in sorted(CROSS_FILE_IDS):
        taint = detected[keyed].taint
        assert taint is not None and len(taint.call_chain) >= 2, f"{keyed}: call chain {taint and taint.call_chain}"


def test_decoys_raise_at_most_one_false_alarm(result, key):
    alarms = {decoy.id: _false_alarms(result, decoy) for decoy in key.decoys}
    noisy = {
        keyed: [f"{f.rule_id}@{f.code.file}:{f.code.line_start}" for f in found]
        for keyed, found in alarms.items()
        if found
    }
    total = sum(len(found) for found in alarms.values())
    assert total <= DECOY_CEILING, f"{total} decoy false alarms (ceiling {DECOY_CEILING}): {noisy}"


def test_injection_findings_carry_a_source_param_and_entry_routes(result):
    route_ids = {route.id for route in result.routes}
    for finding in result.findings:
        if finding.suppressed or finding.cwe not in INJECTION_CWES:
            continue
        where = f"{finding.rule_id}@{finding.code.file}:{finding.code.line_start}"
        assert finding.taint is not None, f"{where}: no taint block"
        assert finding.taint.source_param is not None, f"{where}: no source_param"
        assert finding.taint.entry_routes, f"{where}: no entry_routes"
        unknown = sorted(set(finding.taint.entry_routes) - route_ids)
        assert not unknown, f"{where}: entry_routes not in the route map: {unknown}"


def test_scanning_mock_a_twice_is_idempotent(result):
    assert run_sast(MOCK_A).model_dump_json() == result.model_dump_json()
