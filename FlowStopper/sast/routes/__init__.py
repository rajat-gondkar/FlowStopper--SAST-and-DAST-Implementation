"""Route extractors (Owner: A, P1-A2): Flask, FastAPI, Django -> list[Route].

`extract_routes` runs every framework extractor over one parsed project and returns a single,
deterministically sorted, de-duplicated route list. Each extractor is parse-only (R7).
"""

from __future__ import annotations

from FlowStopper.models import Route
from FlowStopper.sast.index import ProjectIndex
from FlowStopper.sast.routes import django, fastapi, flask

__all__ = ["extract_routes"]

_EXTRACTORS = (flask.extract, fastapi.extract, django.extract)


def extract_routes(index: ProjectIndex) -> list[Route]:
    """All routes found in `index`, sorted by (path_template, method); the first source wins per Route.id."""
    by_id: dict[str, Route] = {}
    for extract in _EXTRACTORS:
        for route in extract(index):
            by_id.setdefault(route.id, route)
    return sorted(by_id.values(), key=lambda r: (r.path_template, r.method))
