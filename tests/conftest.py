"""Shared test helpers. Each developer owns the tests for their own modules."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from FlowStopper.models import Finding, Issue, Route

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures"


def load_json(name: str):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


@pytest.fixture(scope="session")
def fixture_routes() -> list[Route]:
    return [Route.model_validate(r) for r in load_json("routes.json")]


@pytest.fixture(scope="session")
def fixture_sast() -> list[Finding]:
    return [Finding.model_validate(f) for f in load_json("sast_findings.json")]


@pytest.fixture(scope="session")
def fixture_dast() -> list[Finding]:
    return [Finding.model_validate(f) for f in load_json("dast_findings.json")]


@pytest.fixture(scope="session")
def fixture_expected_issues() -> list[Issue]:
    return [Issue.model_validate(i) for i in load_json("expected_issues.json")]
