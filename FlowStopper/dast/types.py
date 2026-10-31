"""Internal DAST data holders (Owner: B). Not a frozen contract - plain in-engine types.

`Endpoint`/`Param` are what discovery emits and what the checks consume; findings cross the stage
boundary as the pydantic models in FlowStopper/models.py.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from FlowStopper.models import ParamLocation


@dataclass
class Param:
    name: str
    location: ParamLocation
    value: str = ""  # benign sample value; checks substitute payloads for it
    required: bool = False


@dataclass
class Endpoint:
    method: str
    url: str  # concrete URL (path params filled), without an injected payload
    path: str  # path only, no query string
    route_id: Optional[str] = None
    params: list[Param] = field(default_factory=list)
    source: str = "seed"  # "seed" (from the route map) | "crawl"

    @property
    def key(self) -> tuple[str, str]:
        return (self.method.upper(), self.path)

    def param_names(self) -> set[str]:
        return {p.name for p in self.params}
