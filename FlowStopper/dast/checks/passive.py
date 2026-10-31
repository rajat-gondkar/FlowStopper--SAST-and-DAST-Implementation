"""Passive checks (Owner: B, P2-B2): headers, cookies, CORS, banners, errors, exposed files.

These are *host-wide* observations, not per-parameter injections, so each one is reported **once per
host** with the list of affected paths in the evidence and in `raw["affected_paths"]`. They have no
code location, so correlation labels them RUNTIME_ONLY.

Nothing here is an attack: we read response headers from pages we already fetch, send one
`Origin:` header to test CORS reflection, and request a tiny fixed list of well-known metadata paths
(spec P2-B2). All requests go through the scope-guarded client (R3).
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

import httpx

from FlowStopper import cwe as cwe_mod
from FlowStopper import ids
from FlowStopper.dast.checks.base import CheckContext
from FlowStopper.dast.client import HttpExchange
from FlowStopper.dast.types import Endpoint
from FlowStopper.models import Engine, Finding, RuntimeLocation
from FlowStopper.scope import ScopeError

SAMPLE_PATHS = 5  # how many distinct paths to sample for host-wide header/cookie observations
CORS_PROBE_ORIGIN = "https://sdc-probe.invalid"  # spec P2-B2; .invalid can never resolve
EXPOSED_PATHS: tuple[tuple[str, int, float, str], ...] = (
    # (path, cwe, confidence, body-shape regex) - a small fixed list, read-only
    ("/.git/HEAD", 538, 0.9, r"^\s*(ref:|[0-9a-f]{40})"),
    ("/.env", 538, 0.8, r"^\s*[A-Za-z_][A-Za-z0-9_]*\s*="),
    ("/robots.txt", 200, 0.3, r"(?i)(user-agent|disallow|allow)\s*:"),  # informational only
)
DEBUG_CONSOLE_PATH = "/console"

# Generic framework-agnostic traceback / debug markers (no app-specific strings - R6).
ERROR_MARKERS = re.compile(
    r"(Traceback \(most recent call last\)|Werkzeug Debugger|The debugger caught an exception|"
    r"DjangoUnicodeDecodeError|django\.core\.exceptions|<pre>Internal Server Error|"
    r"java\.lang\.[A-Za-z]+Exception|\.py\", line \d+, in )",
)
DIR_LISTING = re.compile(r"(?i)(<title>\s*(index of|directory listing for)|<h1>\s*index of\s*/)")
VERSION_BANNER = re.compile(r"\d")  # a banner is only interesting when it leaks a version number

# (header, cwe, rule suffix, human name) - checked on every sampled response.
HEADER_CHECKS: tuple[tuple[str, int, str, str], ...] = (
    ("content-security-policy", 693, "csp-missing", "Content-Security-Policy"),
    ("x-content-type-options", 693, "nosniff-missing", "X-Content-Type-Options"),
    ("referrer-policy", 693, "referrer-policy-missing", "Referrer-Policy"),
)
COOKIE_FLAGS: tuple[tuple[str, int, str], ...] = (
    ("httponly", 1004, "cookie-httponly"),
    ("samesite", 1275, "cookie-samesite"),
    ("secure", 614, "cookie-secure"),
)


def _host(ctx: CheckContext) -> str:
    return urlsplit(ctx.base_url).netloc


def _finding(
    ctx: CheckContext,
    ex: HttpExchange,
    *,
    cwe_id: int,
    rule_suffix: str,
    title: str,
    evidence: str,
    proof: str,
    confidence: float,
    affected: list[str] | None = None,
    extra_raw: dict | None = None,
) -> Finding:
    """Build a host-wide runtime Finding (no param, no code location)."""
    rule_id = f"dast.passive.{rule_suffix}"
    rt = RuntimeLocation(
        method="GET",
        url=ex.url,
        path=ex.path,
        param=None,
        payload=None,
        proof=proof,  # type: ignore[arg-type]
        request=ex.request_text,
        response_excerpt=ex.response_excerpt,
        evidence=evidence,
        repro_curl=ex.repro_curl,
    )
    raw: dict = dict(extra_raw or {})
    if affected is not None:
        raw["affected_paths"] = sorted(affected)
    return Finding(
        id=ids.runtime_finding_id(Engine.DAST, rule_id, cwe_id, "GET", rt.route_id or rt.path, None),
        engine=Engine.DAST,
        tool="FlowStopper-dast",
        rule_id=rule_id,
        cwe=cwe_id,
        title=title,
        severity=cwe_mod.get_cwe(cwe_id).severity,
        confidence=confidence,
        runtime=rt,
        raw=raw,
    )


def sample_paths(endpoints: list[Endpoint], limit: int = SAMPLE_PATHS) -> list[str]:
    """Deterministic, de-duplicated list of GET paths to observe, always starting at "/"."""
    paths = sorted({e.path for e in endpoints if e.method.upper() == "GET" and e.path})
    ordered = ["/"] + [p for p in paths if p != "/"]
    return ordered[:limit]


def _missing_on(exchanges: dict[str, HttpExchange], header: str) -> list[str]:
    return sorted(p for p, ex in exchanges.items() if not ex.response_headers.get(header))


def _evidence(name: str, missing: list[str], total: int) -> str:
    return f"No {name} header on {len(missing)} of {total} sampled paths: " + ", ".join(missing)


# --------------------------------------------------------------------------- individual checks
def _header_findings(ctx: CheckContext, exchanges: dict[str, HttpExchange], rep: HttpExchange) -> list[Finding]:
    out: list[Finding] = []
    total = len(exchanges)
    for header, cwe_id, suffix, name in HEADER_CHECKS:
        missing = _missing_on(exchanges, header)
        if missing:
            out.append(
                _finding(
                    ctx,
                    rep,
                    cwe_id=cwe_id,
                    rule_suffix=suffix,
                    title=f"Missing {name} header",
                    evidence=_evidence(name, missing, total),
                    proof="header",
                    confidence=0.9,
                    affected=missing,
                )
            )

    # Clickjacking protection: X-Frame-Options OR a CSP frame-ancestors directive satisfies it.
    unprotected = sorted(
        p
        for p, ex in exchanges.items()
        if not ex.response_headers.get("x-frame-options")
        and "frame-ancestors" not in ex.response_headers.get("content-security-policy", "").lower()
    )
    if unprotected:
        out.append(
            _finding(
                ctx,
                rep,
                cwe_id=1021,
                rule_suffix="clickjacking",
                title="No clickjacking protection (X-Frame-Options / CSP frame-ancestors)",
                evidence=(
                    f"Neither X-Frame-Options nor a CSP frame-ancestors directive on "
                    f"{len(unprotected)} of {total} sampled paths: " + ", ".join(unprotected)
                ),
                proof="header",
                confidence=0.9,
                affected=unprotected,
            )
        )

    # HSTS is only meaningful over HTTPS (spec P2-B2).
    if urlsplit(ctx.base_url).scheme == "https":
        missing = _missing_on(exchanges, "strict-transport-security")
        if missing:
            out.append(
                _finding(
                    ctx,
                    rep,
                    cwe_id=693,
                    rule_suffix="hsts-missing",
                    title="Missing Strict-Transport-Security header",
                    evidence=_evidence("Strict-Transport-Security", missing, total),
                    proof="header",
                    confidence=0.9,
                    affected=missing,
                )
            )
    return out


def _cookie_findings(ctx: CheckContext, exchanges: dict[str, HttpExchange], rep: HttpExchange) -> list[Finding]:
    """One finding per missing flag, listing every cookie that lacks it."""
    is_https = urlsplit(ctx.base_url).scheme == "https"
    cookies: dict[str, tuple[str, str]] = {}  # name -> (raw header, path seen on)
    for path, ex in sorted(exchanges.items()):
        for raw in ex.set_cookies:
            name = raw.split("=", 1)[0].strip()
            if name:
                cookies.setdefault(name, (raw, path))
    if not cookies:
        return []

    out: list[Finding] = []
    for flag, cwe_id, suffix in COOKIE_FLAGS:
        # A missing Secure flag is only a real finding over HTTPS (see docs/DECISIONS_Dev2.md B-04).
        if flag == "secure" and not is_https:
            continue
        offenders = sorted(n for n, (raw, _) in cookies.items() if flag not in raw.lower())
        if offenders:
            paths = sorted({cookies[n][1] for n in offenders})
            out.append(
                _finding(
                    ctx,
                    rep,
                    cwe_id=cwe_id,
                    rule_suffix=suffix,
                    title=f"Cookie without {flag.capitalize() if flag != 'samesite' else 'SameSite'} attribute",
                    evidence=(
                        f"Set-Cookie for {', '.join(repr(n) for n in offenders)} has no "
                        f"{'SameSite' if flag == 'samesite' else flag.capitalize()} attribute."
                    ),
                    proof="header",
                    confidence=0.9,
                    affected=paths,
                    extra_raw={"cookies": offenders},
                )
            )
    return out


async def _cors_finding(ctx: CheckContext, base: str, rep: HttpExchange) -> list[Finding]:
    """Reflecting an arbitrary Origin (or `*` with credentials) is a permissive CORS policy."""
    ctx.sent_payloads.append(CORS_PROBE_ORIGIN)  # auditable: the only value this check injects
    try:
        ex = await ctx.client.get(base + "/", headers={"Origin": CORS_PROBE_ORIGIN})
    except (ScopeError, httpx.HTTPError):
        return []
    acao = (ex.response_headers.get("access-control-allow-origin") or "").strip()
    creds = (ex.response_headers.get("access-control-allow-credentials") or "").strip().lower() == "true"
    if not acao:
        return []
    reflected = acao == CORS_PROBE_ORIGIN
    wildcard = acao == "*"
    if not (reflected or wildcard):
        return []
    detail = (
        f"reflected our arbitrary probe Origin ({CORS_PROBE_ORIGIN})"
        if reflected
        else "returned the wildcard '*' origin"
    )
    return [
        _finding(
            ctx,
            ex,
            cwe_id=942,
            rule_suffix="cors-permissive",
            title="Permissive CORS policy",
            evidence=(
                f"Access-Control-Allow-Origin {detail}"
                + (" together with Access-Control-Allow-Credentials: true" if creds else "")
                + " - any site could read authenticated responses."
            ),
            proof="header",
            confidence=0.9 if (reflected and creds) else 0.8,
            affected=["/"],
            extra_raw={"access_control_allow_origin": acao, "allow_credentials": creds},
        )
    ]


def _banner_findings(ctx: CheckContext, exchanges: dict[str, HttpExchange], rep: HttpExchange) -> list[Finding]:
    banners: dict[str, str] = {}
    for _, ex in sorted(exchanges.items()):
        for header in ("server", "x-powered-by"):
            value = (ex.response_headers.get(header) or "").strip()
            if value and VERSION_BANNER.search(value):  # only report when a version leaks
                banners.setdefault(header, value)
    if not banners:
        return []
    listed = ", ".join(f"{h}: {v}" for h, v in sorted(banners.items()))
    return [
        _finding(
            ctx,
            rep,
            cwe_id=497,
            rule_suffix="version-banner",
            title="Software version disclosed in response headers",
            evidence=f"Response headers leak component versions ({listed}), aiding targeted attacks.",
            proof="header",
            confidence=0.8,
            affected=sorted(exchanges),
            extra_raw={"banners": banners},
        )
    ]


def _directory_listing(ctx: CheckContext, exchanges: dict[str, HttpExchange]) -> list[Finding]:
    hits = sorted(p for p, ex in exchanges.items() if DIR_LISTING.search(ex.body))
    if not hits:
        return []
    rep = exchanges[hits[0]]
    return [
        _finding(
            ctx,
            rep,
            cwe_id=548,
            rule_suffix="directory-listing",
            title="Directory listing enabled",
            evidence=f"Auto-generated index page served at: {', '.join(hits)}",
            proof="file",
            confidence=0.9,
            affected=hits,
        )
    ]


async def _error_findings(ctx: CheckContext, base: str, exchanges: dict[str, HttpExchange]) -> list[Finding]:
    """Verbose tracebacks on an unknown path, plus an exposed interactive debugger."""
    out: list[Finding] = []
    probes: dict[str, HttpExchange] = dict(exchanges)
    for path in (f"/{ctx.token()}", DEBUG_CONSOLE_PATH):  # random path -> generic, no app constant
        try:
            probes[path] = await ctx.client.get(base + path)
        except (ScopeError, httpx.HTTPError):
            continue

    verbose = sorted(p for p, ex in probes.items() if ERROR_MARKERS.search(ex.body))
    if verbose:
        rep = probes[verbose[0]]
        m = ERROR_MARKERS.search(rep.body)
        out.append(
            _finding(
                ctx,
                rep,
                cwe_id=209,
                rule_suffix="verbose-error",
                title="Verbose error page leaks internal details",
                evidence=(
                    f"Response body contains a stack trace / debug marker ({m.group(0)!r}) at: " + ", ".join(verbose)
                ),
                proof="error",
                confidence=0.9,
                affected=verbose,
            )
        )

    console = probes.get(DEBUG_CONSOLE_PATH)
    if console is not None and console.status == 200 and re.search(r"(?i)(console|debugger)", console.body):
        out.append(
            _finding(
                ctx,
                console,
                cwe_id=489,
                rule_suffix="debug-console",
                title="Interactive debug console exposed",
                evidence=f"{DEBUG_CONSOLE_PATH} returned HTTP 200 and looks like an interactive debugger.",
                proof="error",
                confidence=0.8,
                affected=[DEBUG_CONSOLE_PATH],
            )
        )
    return out


async def _exposed_file_findings(ctx: CheckContext, base: str) -> list[Finding]:
    out: list[Finding] = []
    for path, cwe_id, confidence, shape in EXPOSED_PATHS:
        try:
            ex = await ctx.client.get(base + path)
        except (ScopeError, httpx.HTTPError):
            continue
        if ex.status != 200 or not re.search(shape, ex.body, re.MULTILINE):
            continue
        informational = cwe_id == 200
        out.append(
            _finding(
                ctx,
                ex,
                cwe_id=cwe_id,
                rule_suffix=f"exposed{path.replace('/', '-').replace('.', '')}",
                title=f"Exposed file {path}",
                evidence=(
                    f"{path} is publicly readable and returned matching content"
                    + (
                        " (informational: it is meant to be public, but it maps internal paths)."
                        if informational
                        else "."
                    )
                ),
                proof="file",
                confidence=confidence,
                affected=[path],
            )
        )
    return out


# --------------------------------------------------------------------------- entry point
async def run(ctx: CheckContext, endpoints: list[Endpoint] | None = None) -> list[Finding]:
    """Run every passive check once for the host. Deterministically ordered."""
    base = ctx.base_url.rstrip("/")
    exchanges: dict[str, HttpExchange] = {}
    for path in sample_paths(endpoints or []):
        try:
            exchanges[path] = await ctx.client.get(base + path)
        except (ScopeError, httpx.HTTPError):
            continue
    if not exchanges:
        return []
    rep = exchanges.get("/") or exchanges[sorted(exchanges)[0]]

    findings: list[Finding] = []
    findings += _header_findings(ctx, exchanges, rep)
    findings += _cookie_findings(ctx, exchanges, rep)
    findings += await _cors_finding(ctx, base, rep)
    findings += _banner_findings(ctx, exchanges, rep)
    findings += _directory_listing(ctx, exchanges)
    findings += await _error_findings(ctx, base, exchanges)
    findings += await _exposed_file_findings(ctx, base)
    return sorted(findings, key=lambda f: (f.cwe, f.rule_id))
