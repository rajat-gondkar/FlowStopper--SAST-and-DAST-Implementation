"""Operations dashboard routes for shoplite-b. Our own work (R8)."""

from __future__ import annotations

from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel

from ..services import net
from ..services.archive import snapshot

router = APIRouter(prefix="/ops", tags=["ops"])


class ArchiveBody(BaseModel):
    """JSON body for a snapshot request."""

    tag: str = "manual"


@router.get("/diagnose", response_class=PlainTextResponse)
def diagnose(endpoint: str = Query("localhost")) -> PlainTextResponse:
    """Resolve an endpoint from the operations dashboard."""
    return PlainTextResponse(net.probe_endpoint(endpoint))  # vuln:B05 entry


@router.post("/archive")
def archive(body: ArchiveBody) -> JSONResponse:
    """Queue a tagged snapshot."""
    return JSONResponse({"result": snapshot(body.tag)})  # vuln:B06 entry


@router.get("/reachability", response_class=PlainTextResponse)
def reachability(endpoint: str = Query("localhost")) -> PlainTextResponse:
    """Latency check from the operations dashboard."""
    return PlainTextResponse(net.reachability(endpoint))  # decoy:D04 entry


@router.get("/boom")
def boom() -> JSONResponse:
    """Deliberately fail, to exercise the error page."""
    # vuln:B33 - the handler raises and the app renders the traceback
    totals = {"orders": 3}
    return JSONResponse({"ratio": totals["orders"] / totals["refunds"]})


@router.get("/health")
def health() -> JSONResponse:
    return JSONResponse({"status": "ok"})
