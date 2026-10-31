"""Member/session routes for shoplite-b. Our own work (R8)."""

from __future__ import annotations

from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel

from ..config import PERMITTED_ONWARD, SESSION_COOKIE
from ..repositories import account_repo

router = APIRouter(prefix="/accounts", tags=["accounts"])


class SigninBody(BaseModel):
    """JSON body for sign-in - pydantic fields become the request parameters."""

    handle: str = ""
    secret: str = ""


@router.post("/signin", response_model=None)
def signin(body: SigninBody, onward: str = Query("/")) -> JSONResponse | RedirectResponse:
    """Sign in with a JSON body, then bounce to `onward`."""
    member = account_repo.authenticate(body.handle, body.secret)  # vuln:B02 entry
    if member is None:
        return JSONResponse({"error": "invalid credentials"}, status_code=401)
    # vuln:B10 - the post-signin target is taken from the query string unchecked
    response = RedirectResponse(url=onward, status_code=303)
    # vuln:B32 - session cookie without HttpOnly, without Secure and with SameSite disabled
    response.set_cookie(SESSION_COOKIE, member["handle"], httponly=False, secure=False, samesite=None)
    return response


@router.get("/bounce")
def bounce(onward: str = Query("/")) -> RedirectResponse:
    """Send the visitor onward."""
    # vuln:B09 - unvalidated redirect target
    return RedirectResponse(url=onward, status_code=307)


@router.get("/depart")
def depart(onward: str = Query("/")) -> RedirectResponse:
    """Send the visitor onward, allow-list enforced."""
    # decoy:D06 - only known-good internal paths are honoured
    target = onward if onward in PERMITTED_ONWARD else "/"
    return RedirectResponse(url=target, status_code=307)


@router.get("/profile")
def profile(handle: str = Query("avery")) -> JSONResponse:
    """Member profile."""
    return JSONResponse(account_repo.profile_for(handle) or {})
