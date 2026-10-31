"""shoplite-b: a deliberately vulnerable FastAPI fixture app. Our own work (rule R8).

HELD OUT: Dev A must not read apps/mock_b/ until Phase 6 (the generalisation round). Mock B exists
to answer one question honestly - does FlowStopper work on an app it was never tuned against? It is
written in a deliberately different style from Mock A: FastAPI instead of Flask, a layered
routers/services/repositories package instead of blueprints plus helpers, pydantic JSON bodies
instead of form posts, and different naming conventions throughout.

Run it:  uvicorn apps.mock_b.main:app --port 8090
"""

from __future__ import annotations

import traceback

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, PlainTextResponse
from fastapi.templating import Jinja2Templates

from .config import SERVER_BANNER, TEMPLATE_ROOT
from .db import bootstrap
from .routers import accounts, assets, catalogue, ops

templates = Jinja2Templates(directory=str(TEMPLATE_ROOT))


def create_app() -> FastAPI:
    """Application factory. Routers are mounted with their own prefixes."""
    app = FastAPI(title="shoplite-b", version="1.4.2")

    app.include_router(catalogue.router)
    app.include_router(accounts.router)
    app.include_router(assets.router)
    app.include_router(ops.router)

    @app.on_event("startup")
    def _startup() -> None:
        bootstrap()

    @app.middleware("http")
    async def _banner(request: Request, call_next):
        """Stamp a server banner on every response.

        vuln:B31 - no Content-Security-Policy, X-Frame-Options, X-Content-Type-Options or
        Referrer-Policy is ever set, so every response is missing its security headers.
        """
        response = await call_next(request)
        response.headers["Server"] = SERVER_BANNER  # vuln:B34 - version banner
        return response

    @app.exception_handler(Exception)
    async def _verbose_errors(request: Request, exc: Exception) -> PlainTextResponse:
        """vuln:B33 - the error page returns the raw traceback to the caller."""
        detail = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
        return PlainTextResponse(f"shoplite-b internal error\n\n{detail}", status_code=500)

    @app.get("/", response_class=HTMLResponse)
    def home(request: Request) -> HTMLResponse:
        return templates.TemplateResponse(request=request, name="index.html", context={})

    @app.get("/robots.txt", response_class=PlainTextResponse)
    def robots() -> PlainTextResponse:
        return PlainTextResponse("User-agent: *\nDisallow: /ops\n")

    return app


app = create_app()
