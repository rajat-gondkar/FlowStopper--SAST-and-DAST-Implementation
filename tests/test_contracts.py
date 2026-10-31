"""Contract tests (P0-J2/J3): models, CWE catalogue, stable IDs, committed schemas."""

from __future__ import annotations

import subprocess
import sys

import pytest

from FlowStopper import cwe, ids
from FlowStopper.models import CodeLocation, Engine, Finding, Severity
from tests.conftest import ROOT


def test_finding_round_trip(fixture_sast):
    for f in fixture_sast:
        assert Finding.model_validate_json(f.model_dump_json()) == f


def test_confidence_bounds():
    with pytest.raises(ValueError):
        Finding(id="x", engine=Engine.SAST, tool="t", rule_id="r", cwe=89, title="t", severity="high", confidence=1.5)


def test_get_cwe_vector_and_score():
    e = cwe.get_cwe(89)
    assert e.vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert e.base_score == 9.8 and e.severity is Severity.CRITICAL
    assert e.owasp_2025 == "A05:2025 - Injection"
    assert cwe.get_cwe(22).severity is Severity.HIGH
    assert cwe.get_cwe(79).severity is Severity.MEDIUM
    assert cwe.get_cwe(1004).severity is Severity.LOW


def test_families():
    assert cwe.same_family(78, 77) and cwe.same_family(22, 36) and cwe.same_family(798, 321)
    assert not cwe.same_family(89, 79)
    assert cwe.family_of(12345) == frozenset({12345})
    assert cwe.family_name(12345) == "cwe-12345"
    for entry in cwe.CATALOGUE.values():
        assert entry.id in entry.family
        assert entry.vector in cwe.BASE_SCORES


def test_correlatable_families():
    assert {e.id for e in cwe.CATALOGUE.values() if e.correlatable} == {89, 78, 77, 79, 22, 23, 36, 601}


@pytest.mark.parametrize(
    ("score", "sev"),
    [(9.8, "critical"), (9.0, "critical"), (8.9, "high"), (7.0, "high"), (6.9, "medium"), (4.0, "medium"),
     (3.9, "low"), (0.1, "low"), (0.0, "info")],
)  # fmt: skip
def test_severity_buckets(score, sev):
    assert cwe.severity_from_score(score).value == sev


def test_id_helpers_are_stable_and_payload_free():
    a = ids.runtime_finding_id(Engine.DAST, "dast.sqli.error", 89, "get", "GET /x", "id")
    b = ids.runtime_finding_id("dast", "dast.sqli.error", 89, "GET", "GET /x", "id")
    assert a == b and len(a) == 40
    c = ids.code_finding_id(Engine.SAST, "r", 89, "a.py", None, 3)
    assert c == ids.code_finding_id("sast", "r", 89, "a.py", "", 3)
    assert len(ids.code_issue_id(89, "a.py", "m.f", 3)) == 16


def test_finding_id_requires_location():
    f = Finding(id="x", engine=Engine.SAST, tool="t", rule_id="r", cwe=89, title="t", severity="high", confidence=1)
    with pytest.raises(ValueError):
        ids.finding_id(f)
    f.code = CodeLocation(file="a.py", line_start=1, line_end=1)
    assert ids.finding_id(f) == ids.code_finding_id("sast", "r", 89, "a.py", None, 1)


def test_committed_schemas_are_current():
    r = subprocess.run(
        [sys.executable, "scripts/export_schemas.py", "--check"], cwd=ROOT, capture_output=True, text=True
    )
    assert r.returncode == 0, r.stdout + r.stderr
