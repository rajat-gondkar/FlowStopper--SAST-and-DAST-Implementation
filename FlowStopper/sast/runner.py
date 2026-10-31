"""SAST orchestration (Owner: A). Cross-developer interface (spec section 6).

index -> routes -> call graph -> taint -> secrets -> templates -> SastResult.
Never imports or executes target code (R7): parse only.

Phase 1 fills `routes` (P1-A2) with `reachable_functions` from the call graph (P1-A3);
`findings` arrive in Phase 2 (P2-A6).
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from FlowStopper.models import SastResult
from FlowStopper.sast.callgraph import annotate_reachable
from FlowStopper.sast.config import SastConfig
from FlowStopper.sast.index import build_index
from FlowStopper.sast.routes import extract_routes


def run_sast(source_root: Path | str, config: Optional[SastConfig] = None) -> SastResult:
    """Return routes + findings for the Python sources under `source_root` (parsed, never executed)."""
    config = config or SastConfig()
    index = build_index(source_root, config)
    routes = annotate_reachable(index, extract_routes(index), config)
    stats = index.stats()
    stats["routes"] = len(routes)
    return SastResult(routes=routes, findings=[], stats=stats)
