"""P4 SAST checks on the third-party benchmark app (Owner: A).

The clone under bench/vulnerable-flask-app/src is git-ignored, so every test here skips when it is
absent. App-specific lines and names stay in this test, never in `FlowStopper/` (R6).
"""

from __future__ import annotations

import pytest

from FlowStopper.models import SastResult
from FlowStopper.sast.runner import run_sast
from tests.conftest import ROOT

BENCH_SRC = ROOT / "bench" / "vulnerable-flask-app" / "src"
APP_FILE = "app/app.py"


@pytest.fixture(scope="module")
def result() -> SastResult:
    if not BENCH_SRC.is_dir():
        pytest.skip("benchmark app not fetched (git-ignored); run `make bench-fetch` to enable")
    return run_sast(BENCH_SRC)


def _at(result: SastResult, cwe: int, line: int) -> list:
    return [f for f in result.findings if f.cwe == cwe and f.code.file == APP_FILE and f.code.line_start == line]


def test_json_response_retyped_after_construction_is_not_xss(result):
    assert _at(result, 79, 185) == []


def test_404_handler_template_source_is_live_xss(result):
    found = [
        f
        for f in result.findings
        if f.cwe == 79 and f.code.function == "app.app.pnf" and 102 <= f.code.line_start <= 114 and not f.suppressed
    ]
    assert len(found) == 1, [(f.rule_id, f.code.line_start) for f in result.findings if f.cwe == 79]
    assert found[0].taint.entry_routes == []
    assert found[0].taint.source_param is None


def test_search_sqli_stays_live_with_its_route(result):
    found = _at(result, 89, 265)
    assert len(found) == 1
    assert found[0].suppressed is False
    assert found[0].taint.entry_routes == ["POST /search"]


def test_nothing_is_suppressed_as_unreachable(result):
    assert [f for f in result.findings if f.suppress_reason == "unreachable"] == []
    assert result.stats["suppressed_unreachable"] == 0
