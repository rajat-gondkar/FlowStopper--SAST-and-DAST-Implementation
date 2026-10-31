"""SAST orchestration (Owner: A, P2-A6). Cross-developer interface (spec section 6).

index -> routes -> call graph -> taint -> secrets -> templates -> SastResult.
Never imports or executes target code (R7): parse only.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from FlowStopper.models import SastResult
from FlowStopper.sast.config import SastConfig


def run_sast(source_root: Path, config: Optional[SastConfig] = None) -> SastResult:
    """Return routes + findings for the Python sources under `source_root`."""
    raise NotImplementedError("P2-A6: SAST runner not implemented yet")
