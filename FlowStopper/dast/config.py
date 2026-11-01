"""DAST configuration (Owner: B). Add fields freely; this is B's file (DECISIONS D-06)."""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel

AUTHORIZATION_HEADER = "Authorization"  # the standard header name, used as the default token sink


class LoginStep(BaseModel):
    """A login request whose result authenticates every later request (spec P1-B1).

    Two ways the target can hand back a session:
    - **cookies** - nothing to configure, the client's jar keeps them automatically;
    - **a token** - name where it arrives (`token_response_header` or `token_json_field`) and it is
      copied onto later requests as `token_request_header`, optionally behind `token_prefix`.

    Credentials live here, i.e. in configuration, never in `FlowStopper/` (rule R6).
    """

    url: str
    method: str = "POST"
    json_body: Optional[dict] = None  # JSON credentials
    form_data: Optional[dict] = None  # form-encoded credentials
    headers: dict[str, str] = {}

    # Where the token comes back (pick one; the header wins if both are set).
    token_response_header: Optional[str] = None
    token_json_field: Optional[str] = None  # dotted path into the JSON body, e.g. "data.token"
    # Where it goes on later requests.
    token_request_header: str = AUTHORIZATION_HEADER
    token_prefix: str = ""  # e.g. "Bearer "

    @property
    def expects_token(self) -> bool:
        return bool(self.token_response_header or self.token_json_field)


class AuthConfig(BaseModel):
    """How to authenticate to the target: static credentials and/or a login step."""

    headers: dict[str, str] = {}  # sent on every request (e.g. a pre-issued bearer token)
    cookies: dict[str, str] = {}  # sent on every request
    login: Optional[LoginStep] = None

    @property
    def is_configured(self) -> bool:
        return bool(self.headers or self.cookies or self.login)


class DastConfig(BaseModel):
    allowed_hosts: list[str] = ["localhost", "127.0.0.1", "::1"]  # P0-B1; env ALLOWED_HOSTS overrides
    extra_allowed_hosts: list[str] = []  # --allow-host (must log a WARNING)
    concurrency: int = 20
    max_rps: Optional[float] = None  # global request-rate cap
    connect_timeout_s: float = 3.0
    total_timeout_s: float = 10.0
    allow_mutating: bool = False  # PUT/PATCH only with --allow-mutating; DELETE never
    crawl_max_depth: int = 3
    crawl_max_urls: int = 300
    seed: Optional[int] = None  # per-scan seed for canaries; recorded in scan metadata
    keep_secrets: bool = False  # R7: redact Authorization/Cookie unless set
    auth: Optional[AuthConfig] = None  # P4-B1 item 7: reach routes that require a session
