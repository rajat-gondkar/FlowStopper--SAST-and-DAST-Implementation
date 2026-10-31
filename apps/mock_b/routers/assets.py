"""Asset delivery routes for shoplite-b. Our own work (R8)."""

from __future__ import annotations

import os
from pathlib import Path

from fastapi import APIRouter, Query
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse

from ..config import ASSET_ROOT

router = APIRouter(prefix="/assets", tags=["assets"])


@router.get("/fetch", response_class=PlainTextResponse)
def fetch(doc: str = Query("readme.txt")) -> PlainTextResponse:
    """Return a stored document as text."""
    # vuln:B07 - the caller's name is joined onto the asset root with no containment check
    target = os.path.join(str(ASSET_ROOT), doc)
    try:
        with open(target, encoding="utf-8", errors="replace") as handle:
            return PlainTextResponse(handle.read())
    except OSError:
        return PlainTextResponse("not found", status_code=404)


@router.get("/raw/{name:path}")
def raw(name: str):
    """Stream a stored document."""
    # vuln:B08 - path converter contents flow into a file response
    candidate = os.path.join(str(ASSET_ROOT), name)
    if not os.path.isfile(candidate):
        return JSONResponse({"error": "not found"}, status_code=404)
    return FileResponse(candidate)


@router.get("/vault", response_class=PlainTextResponse)
def vault(doc: str = Query("readme.txt")) -> PlainTextResponse:
    """Return a stored document as text, confined to the asset root."""
    # decoy:D05 - basename strips traversal and the resolved path is checked against the root
    safe_name = os.path.basename(doc)
    resolved = (ASSET_ROOT / safe_name).resolve()
    if not resolved.is_relative_to(Path(ASSET_ROOT).resolve()) or not resolved.is_file():
        return PlainTextResponse("not found", status_code=404)
    return PlainTextResponse(resolved.read_text(encoding="utf-8", errors="replace"))
