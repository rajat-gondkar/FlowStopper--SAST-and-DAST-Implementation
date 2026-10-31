"""Scope guard (Owner: B, P0-B1). Rule R3: scan only authorised targets.

Allow-list from ALLOWED_HOSTS (default localhost,127.0.0.1,::1 plus explicitly named
compose services). Refuse any other hostname even if it resolves to a private IP,
re-check every redirect hop, refuse non-http(s) schemes, log a WARNING for --allow-host.
Enforced inside dast/client.py for every request.

The decision is a pure string allow-list on the URL's parsed hostname: we never resolve
DNS, so a host that is not explicitly allowed is refused even when it would resolve to a
loopback/private address. That is what blocks DNS-rebinding / SSRF tricks (e.g. a name that
points at 127.0.0.1). IP *literals* are compared canonically (so ::1 == 0:0:0:0:0:0:0:1)
through the standard library, which resolves nothing.
"""

from __future__ import annotations

import ipaddress
import logging
from collections.abc import Iterable, Mapping
from typing import Optional
from urllib.parse import urljoin, urlsplit

from FlowStopper.config import DEFAULT_ALLOWED_HOSTS, allowed_hosts_from_env

__all__ = ["ALLOWED_SCHEMES", "ScopeError", "ScopeGuard", "build_guard", "normalize_host"]

logger = logging.getLogger("FlowStopper.scope")

ALLOWED_SCHEMES = ("http", "https")


class ScopeError(ValueError):
    """A URL is outside the authorised scope (rule R3). Carries the url and a short reason."""

    def __init__(self, url: str, reason: str) -> None:
        self.url = url
        self.reason = reason
        super().__init__(f"out-of-scope URL {url!r}: {reason}")


def normalize_host(raw: str) -> str:
    """Normalise a host (or an allow-list entry) for comparison.

    Lower-cases, unwraps a `scheme://`, bracketed `[v6]` or `host:port` form down to the bare
    host, and strips a trailing dot. Returns "" when no host can be extracted. Never touches the
    network.
    """
    if not raw:
        return ""
    h = raw.strip().lower()
    if not h:
        return ""
    if "://" in h:
        return (urlsplit(h).hostname or "").strip(".")
    if h.startswith("["):  # [::1] or [::1]:8000
        end = h.find("]")
        if end != -1:
            return h[1:end].strip(".")
    if h.count(":") >= 2:  # bare IPv6 literal, no port
        return h.strip(".")
    if ":" in h:  # host:port
        host, _, port = h.partition(":")
        if port.isdigit():
            return host.strip(".")
    return h.strip(".")


def _as_ip(host: str) -> Optional[ipaddress._BaseAddress]:
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


class ScopeGuard:
    """Allow-list guard. Build once per scan, then call check() for every request + redirect hop."""

    def __init__(self, allowed_hosts: Iterable[str]) -> None:
        exact: set[str] = set()
        ips: set[ipaddress._BaseAddress] = set()
        for entry in allowed_hosts:
            host = normalize_host(entry)
            if not host:
                continue
            exact.add(host)
            ip = _as_ip(host)
            if ip is not None:
                ips.add(ip)
        self._exact = frozenset(exact)
        self._ips = frozenset(ips)
        self.allowed_hosts: tuple[str, ...] = tuple(sorted(exact))

    def host_allowed(self, host: str) -> bool:
        """True if a bare host string is in scope. Matches exact names and canonical IP literals."""
        norm = normalize_host(host)
        if not norm:
            return False
        if norm in self._exact:
            return True
        ip = _as_ip(norm)
        return ip is not None and ip in self._ips

    def url_in_scope(self, url: str) -> bool:
        """Non-raising form of check()."""
        try:
            self.check(url)
        except ScopeError:
            return False
        return True

    def check(self, url: str) -> str:
        """Return the normalised host if `url` is in scope, else raise ScopeError.

        Refuses non-http(s) schemes and URLs with no host. This is the single choke point that
        every DAST request and every redirect hop must pass through (rule R3).
        """
        if not url or not url.strip():
            raise ScopeError(url, "empty URL")
        parts = urlsplit(url.strip())
        scheme = parts.scheme.lower()
        if scheme not in ALLOWED_SCHEMES:
            raise ScopeError(url, f"scheme {scheme or '(relative)'!r} is not http/https")
        try:
            host = parts.hostname or ""
        except ValueError as exc:  # malformed IPv6 brackets etc.
            raise ScopeError(url, f"unparseable host ({exc})") from exc
        if not host:
            raise ScopeError(url, "no host in URL")
        if not self.host_allowed(host):
            raise ScopeError(
                url,
                f"host {normalize_host(host)!r} is not in the allow-list {list(self.allowed_hosts)} "
                "(rule R3; hosts are never DNS-resolved - add it via ALLOWED_HOSTS or --allow-host)",
            )
        return normalize_host(host)

    def check_redirect(self, from_url: str, location: str) -> str:
        """Resolve a redirect Location against the current URL and scope-check the absolute result."""
        return self.check(urljoin(from_url, location))


def build_guard(
    base_hosts: Optional[Iterable[str]] = None,
    *,
    extra_hosts: Iterable[str] = (),
    env: Optional[Mapping[str, str]] = None,
) -> ScopeGuard:
    """Build a ScopeGuard, honouring the ALLOWED_HOSTS env override and --allow-host extras.

    Base allow-list precedence: ALLOWED_HOSTS env (if set) > `base_hosts` > the built-in default.
    `extra_hosts` (from --allow-host) are merged on top and logged at WARNING (rule R3).
    """
    env_hosts = allowed_hosts_from_env(env)
    if env_hosts is not None:
        base = list(env_hosts)
    elif base_hosts is not None:
        base = list(base_hosts)
    else:
        base = list(DEFAULT_ALLOWED_HOSTS)
    extras = [h for h in extra_hosts if h and h.strip()]
    if extras:
        logger.warning(
            "scope allow-list widened by --allow-host: %s "
            "(rule R3 override; only use hosts you are authorised to scan)",
            ", ".join(extras),
        )
    return ScopeGuard(base + extras)
