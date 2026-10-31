"""Scope guard tests (P0-B1, rule R3). Owner: B.

Covers the three required cases (allow-listed accepted, external refused, redirect-to-external
refused) plus scheme/host parsing, the "never resolve DNS" rule, IPv6 forms, env override and the
--allow-host warning.
"""

from __future__ import annotations

import logging

import pytest

from FlowStopper.config import allowed_hosts_from_env, parse_allowed_hosts
from FlowStopper.scope import ScopeError, ScopeGuard, build_guard, normalize_host


@pytest.fixture
def guard() -> ScopeGuard:
    return ScopeGuard(["localhost", "127.0.0.1", "::1", "flaskapp"])


# --- the three required cases -------------------------------------------------
def test_allow_listed_host_accepted(guard):
    assert guard.check("http://localhost:5050/api/items") == "localhost"
    assert guard.check("https://127.0.0.1/") == "127.0.0.1"
    assert guard.check("http://flaskapp:8100/search") == "flaskapp"


def test_external_host_refused(guard):
    with pytest.raises(ScopeError):
        guard.check("http://evil.com/")
    assert guard.url_in_scope("http://example.org/") is False


def test_redirect_to_external_refused(guard):
    # a redirect hop is just another check() on the resolved Location
    with pytest.raises(ScopeError):
        guard.check_redirect("http://localhost:8000/go", "http://evil.com/steal")
    # a relative redirect stays in scope
    assert guard.check_redirect("http://localhost:8000/a", "/b") == "localhost"


# --- scheme / host parsing ----------------------------------------------------
@pytest.mark.parametrize(
    "url",
    [
        "ftp://localhost/x",
        "file:///etc/passwd",
        "data:text/html,hi",
        "gopher://localhost/",
        "//localhost/x",  # scheme-relative
        "localhost:8000/x",  # no scheme
    ],
)
def test_non_http_schemes_refused(guard, url):
    with pytest.raises(ScopeError):
        guard.check(url)


@pytest.mark.parametrize("url", ["", "   ", "http:///nohost", "http://"])
def test_missing_host_refused(guard, url):
    with pytest.raises(ScopeError):
        guard.check(url)


# --- "refuse even if it resolves to a private IP" -----------------------------
def test_unlisted_host_refused_regardless_of_resolution(guard):
    # these names resolve to loopback/private IPs in the real world; the guard must still refuse
    # them because it never resolves - only the literal hostname string is matched (rule R3).
    for url in ("http://127.0.0.1.nip.io/", "http://localtest.me/", "http://db.internal/"):
        assert guard.url_in_scope(url) is False


def test_userinfo_cannot_smuggle_an_allowed_host(guard):
    # the real host is evil.com; "localhost@" is only userinfo
    with pytest.raises(ScopeError):
        guard.check("http://localhost@evil.com/")


# --- normalisation ------------------------------------------------------------
def test_port_and_case_and_trailing_dot_ignored(guard):
    assert guard.check("http://LOCALHOST:9999/") == "localhost"
    assert guard.check("http://localhost./") == "localhost"


def test_ipv6_forms(guard):
    assert guard.check("http://[::1]:8000/") == "::1"
    # an expanded IPv6 literal matches ::1 with no resolution
    assert guard.host_allowed("0:0:0:0:0:0:0:1") is True


def test_normalize_host_helper():
    assert normalize_host("HTTP://LocalHost:8000/path") == "localhost"
    assert normalize_host("[::1]:8000") == "::1"
    assert normalize_host("  Example.COM.  ") == "example.com"
    assert normalize_host("") == ""


# --- env + config parsing + --allow-host warning ------------------------------
def test_parse_allowed_hosts():
    assert parse_allowed_hosts("localhost, 127.0.0.1 ,::1,flaskapp") == ["localhost", "127.0.0.1", "::1", "flaskapp"]
    assert parse_allowed_hosts("") == []
    assert parse_allowed_hosts(None) == []
    assert parse_allowed_hosts("a,,a,b") == ["a", "b"]  # duplicates and blanks dropped


def test_allowed_hosts_from_env():
    assert allowed_hosts_from_env({}) is None
    assert allowed_hosts_from_env({"ALLOWED_HOSTS": "  "}) is None  # stray empty never empties the list
    assert allowed_hosts_from_env({"ALLOWED_HOSTS": "localhost,flaskapp"}) == ["localhost", "flaskapp"]


def test_build_guard_env_overrides_base():
    g = build_guard(["localhost"], env={"ALLOWED_HOSTS": "127.0.0.1,flaskapp"})
    assert g.url_in_scope("http://flaskapp:8100/") is True
    assert g.url_in_scope("http://127.0.0.1/") is True
    assert g.url_in_scope("http://localhost/") is False  # env replaced the base list


def test_build_guard_default_when_no_env():
    g = build_guard(env={})
    assert g.url_in_scope("http://localhost/") is True
    assert g.url_in_scope("http://127.0.0.1/") is True
    assert g.url_in_scope("http://[::1]/") is True


def test_build_guard_extra_hosts_logged_and_allowed(caplog):
    with caplog.at_level(logging.WARNING, logger="FlowStopper.scope"):
        g = build_guard(["localhost"], extra_hosts=["staging.box"], env={})
    assert g.url_in_scope("http://staging.box/") is True
    assert any("staging.box" in r.getMessage() and "--allow-host" in r.getMessage() for r in caplog.records)
