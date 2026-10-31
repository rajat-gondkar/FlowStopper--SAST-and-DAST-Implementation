"""Catalogue routes for shoplite-b. Our own work (R8)."""

from __future__ import annotations

import html

from fastapi import APIRouter, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

from ..config import TEMPLATE_ROOT
from ..repositories import catalogue_repo
from ..services.pricing import retail_price

router = APIRouter(prefix="/catalogue", tags=["catalogue"])
templates = Jinja2Templates(directory=str(TEMPLATE_ROOT))


@router.get("/items")
def list_items(fragment: str = Query("", alias="fragment")) -> JSONResponse:
    """Catalogue search. The fragment reaches the repository unchanged."""
    rows = catalogue_repo.search_items(fragment)  # vuln:B01 entry
    return JSONResponse({"count": len(rows), "items": rows})


@router.get("/lookup", response_class=HTMLResponse)
def lookup(term: str = Query("")) -> HTMLResponse:
    """Render a search summary as HTML."""
    # vuln:B03 - the term is pasted into the markup without escaping
    markup = f"<section><h2>Matches for {term}</h2><p>Refine your search above.</p></section>"
    return HTMLResponse(markup)


@router.get("/safe-lookup", response_class=HTMLResponse)
def safe_lookup(term: str = Query("")) -> HTMLResponse:
    """Render a search summary as HTML, escaped."""
    # decoy:D03 - html.escape neutralises the markup characters
    markup = f"<section><h2>Matches for {html.escape(term)}</h2></section>"
    return HTMLResponse(markup)


@router.get("/echo")
def echo(term: str = Query("")) -> JSONResponse:
    """Echo the search term back as JSON."""
    # decoy:D07 - a JSON response is not an HTML sink
    return JSONResponse({"term": term})


@router.get("/detail/{sku}", response_class=HTMLResponse)
def detail(request: Request, sku: str, label: str = Query("")) -> HTMLResponse:
    """Item detail page with an optional caller-supplied label."""
    item = catalogue_repo.fetch_by_sku(sku)
    price = retail_price(item["price"], item["band"]) if item else None
    # vuln:B04 - `label` is rendered through a template that marks it safe
    return templates.TemplateResponse(
        request=request,
        name="detail.html",
        context={"item": item, "price": price, "label": label},
    )


@router.get("/sku/{sku}")
def by_sku(sku: str) -> JSONResponse:
    """Single item lookup by SKU."""
    item = catalogue_repo.fetch_by_sku(sku)  # decoy:D01 entry
    return JSONResponse(item or {})


@router.get("/band")
def band(name: str = Query("home"), size: str = Query("5")) -> JSONResponse:
    """Newest items in a band."""
    return JSONResponse({"items": catalogue_repo.newest_in_band(name, size)})  # decoy:D02 entry


@router.get("/bands")
def bands() -> JSONResponse:
    return JSONResponse({"bands": catalogue_repo.all_bands()})
