"""DAST orchestration (Owner: B, P2-B4). Cross-developer interface (spec section 6).

Every request goes through the scope guard (R3); only Appendix B payloads (R4).
"""

from __future__ import annotations

from typing import Optional

from FlowStopper.dast.config import DastConfig
from FlowStopper.models import DastResult, Route


async def run_dast(target_url: str, routes: list[Route], config: Optional[DastConfig] = None) -> DastResult:
    """Scan the running app at `target_url`, seeded by the SAST route map."""
    raise NotImplementedError("P2-B4: DAST runner not implemented yet")
