"""`FlowStopper dast` command (Owner: B, P1-B4 / P2-B4). Registered in FlowStopper/cli.py."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Annotated, Optional

import typer

from FlowStopper.dast.config import AuthConfig, DastConfig
from FlowStopper.dast.runner import run_dast
from FlowStopper.models import Route
from FlowStopper.scope import ScopeError


def load_routes(path: Optional[Path]) -> list[Route]:
    """Read a route map: either a bare `routes.json` list or any JSON object with a "routes" key."""
    if path is None:
        return []
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(data, dict):
        data = data.get("routes", [])
    return [Route.model_validate(r) for r in data]


def parse_header(item: str) -> tuple[str, str]:
    """`"Name: value"` -> (Name, value)."""
    name, sep, value = item.partition(":")
    if not sep or not name.strip():
        raise ValueError(f"expected 'Name: value', got {item!r}")
    return name.strip(), value.strip()


def parse_pair(item: str) -> tuple[str, str]:
    """`name=value` -> (name, value)."""
    name, sep, value = item.partition("=")
    if not sep or not name.strip():
        raise ValueError(f"expected 'name=value', got {item!r}")
    return name.strip(), value


def build_auth(
    auth_config: Optional[Path],
    headers: Optional[list[str]],
    cookies: Optional[list[str]],
) -> Optional[AuthConfig]:
    """Assemble the auth config from a JSON file plus inline header/cookie overrides.

    Credentials belong in the file (keep it somewhere git-ignored, e.g. `keys/`): a password passed
    inline would sit in the shell history and the process list for anyone on the box to read.
    """
    auth = AuthConfig()
    if auth_config is not None:
        auth = AuthConfig.model_validate_json(Path(auth_config).read_text(encoding="utf-8"))
    merged_headers = dict(auth.headers)
    merged_headers.update(parse_header(h) for h in headers or [])
    merged_cookies = dict(auth.cookies)
    merged_cookies.update(parse_pair(c) for c in cookies or [])
    auth = auth.model_copy(update={"headers": merged_headers, "cookies": merged_cookies})
    return auth if auth.is_configured else None


def dast_command(
    url: Annotated[str, typer.Argument(help="Base URL of the running target (must be allow-listed)")],
    routes: Annotated[Optional[Path], typer.Option("--routes", help="routes.json from `sast`")] = None,
    out: Annotated[Path, typer.Option("--out", "-o", help="DastResult JSON")] = Path("dast.json"),
    time_budget: Annotated[
        int, typer.Option("--time-budget", help="seconds for the active checks (discovery + passive run first)")
    ] = 240,
    allow_mutating: Annotated[bool, typer.Option("--allow-mutating", help="also send PUT/PATCH")] = False,
    allow_host: Annotated[
        Optional[list[str]], typer.Option("--allow-host", help="extra allowed host (logs a WARNING)")
    ] = None,
    keep_secrets: Annotated[bool, typer.Option("--keep-secrets", help="do not redact auth headers")] = False,
    concurrency: Annotated[int, typer.Option("--concurrency", help="max requests in flight")] = 20,
    seed: Annotated[int, typer.Option("--seed", help="per-scan seed for canaries (reproducible)")] = 0,
    auth_config: Annotated[
        Optional[Path],
        typer.Option("--auth-config", help="JSON file with static headers/cookies and/or a login step"),
    ] = None,
    header: Annotated[
        Optional[list[str]], typer.Option("--header", help="static header, 'Name: value' (repeatable)")
    ] = None,
    cookie: Annotated[
        Optional[list[str]], typer.Option("--cookie", help="static cookie, 'name=value' (repeatable)")
    ] = None,
) -> None:
    """Dynamic scan: write the DastResult to --out."""
    try:
        route_list = load_routes(routes)
    except (OSError, ValueError) as exc:
        typer.echo(f"dast: could not read --routes {routes}: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    try:
        auth = build_auth(auth_config, header, cookie)
    except (OSError, ValueError) as exc:
        typer.echo(f"dast: bad authentication configuration: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    config = DastConfig(
        extra_allowed_hosts=list(allow_host or []),
        concurrency=concurrency,
        time_budget_s=time_budget,
        allow_mutating=allow_mutating,
        seed=seed,
        keep_secrets=keep_secrets,
        auth=auth,
    )

    try:
        result = asyncio.run(run_dast(url, route_list, config))
    except ScopeError as exc:
        typer.echo(f"dast: refusing to scan an out-of-scope target (rule R3): {exc}", err=True)
        raise typer.Exit(code=1) from exc

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result.model_dump(mode="json"), indent=2) + "\n", encoding="utf-8")

    stats = result.stats
    auth_stats = stats.get("auth") or {}
    if auth_stats.get("attempted"):
        state = "ok" if auth_stats.get("ok") else "FAILED"
        typer.echo(f"dast: login {state} ({auth_stats.get('detail') or auth_stats.get('status')})")
    typer.echo(
        f"dast: {stats['findings']} finding(s) from {stats['endpoints_scanned']} endpoint(s), "
        f"{stats['requests']} request(s) in {stats['elapsed_s']}s"
        + (" [TRUNCATED: time budget reached]" if stats.get("truncated") else "")
    )
    if stats.get("dropped_unverified"):
        typer.echo(f"dast: dropped {stats['dropped_unverified']} unverified candidate(s)")
    typer.echo(f"dast: wrote {out}")
