"""Repository rules: R2 disclosure file, R5 confidentiality ignores, CLI wiring."""

from __future__ import annotations

import subprocess
import sys

from typer.testing import CliRunner

from FlowStopper.cli import app
from tests.conftest import ROOT

REQUIRED_IGNORES = ["target_src/", "keys/", "*.key.json", "*.db", "__pycache__/", "docs/target_notes.local.md"]


def test_gitignore_protects_organiser_material():
    lines = {ln.strip() for ln in (ROOT / ".gitignore").read_text().splitlines()}
    missing = [p for p in REQUIRED_IGNORES if p not in lines]
    assert not missing, f".gitignore must contain {missing} (rule R5)"


def test_organiser_material_is_not_tracked():
    r = subprocess.run(["git", "ls-files", "target_src", "keys"], cwd=ROOT, capture_output=True, text=True)
    if r.returncode != 0:  # not a git checkout (e.g. sdist)
        return
    assert r.stdout.strip() == "", f"organisers' files are tracked by git (R5):\n{r.stdout}"


def test_third_party_disclosure_exists():
    text = (ROOT / "THIRD_PARTY.md").read_text()
    assert "AI" in text and "Own work" in text


def test_cli_lists_all_commands():
    result = CliRunner().invoke(app, ["--help"])
    assert result.exit_code == 0
    for cmd in ("sast", "dast", "correlate", "scan", "serve", "eval", "report"):
        assert cmd in result.output


def test_python_m_entry_point():
    r = subprocess.run([sys.executable, "-m", "FlowStopper", "--version"], cwd=ROOT, capture_output=True, text=True)
    assert r.returncode == 0 and "FlowStopper" in r.stdout
