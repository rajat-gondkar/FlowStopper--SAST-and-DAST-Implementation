"""CWE catalogue (FlowStopper_BUILD_SPEC.md section 8).

SHARED file, part of `contract-v1` (P0-J3). Additive changes only after the tag,
logged in docs/CONTRACT_CHANGES.md.

For every CWE: name, family (the set treated as "same type" by the correlator and
the eval harness), OWASP Top 10:2025 category, CVSS 3.1 vector, the precomputed
CVSS 3.1 base score + severity bucket, and the fix-template key used by
report/fixes.py (B-4).

Decisions (see docs/DECISIONS.md):
- Each row of the spec table is one family; rows marked "own" form a family of the
  CWEs listed in that row (e.g. {693, 1021}).
- Vectors are stored in canonical form with the "CVSS:3.1/" prefix.
- base_score is precomputed here so SAST can set severities without importing
  cvss.py; cvss.py (Dev B, P2-B6) must reproduce these numbers (test required).
- OWASP categories were checked against the official 2025 mapped-CWE lists
  (top10.owasp.org/2025). Where the spec's convenience label differed, the official
  mapping wins (200, 497, 538, 548, 1275 are A01). CWEs absent from the official lists
  keep the spec's label.
"""

from __future__ import annotations

from dataclasses import dataclass

from FlowStopper.models import Severity

OWASP_2025 = {
    "A01": "A01:2025 - Broken Access Control",
    "A02": "A02:2025 - Security Misconfiguration",
    "A05": "A05:2025 - Injection",
    "A07": "A07:2025 - Authentication Failures",
    "A10": "A10:2025 - Mishandling of Exceptional Conditions",
}
OWASP_2025_URL = "https://top10.owasp.org/2025/"

# Families (spec section 8). Keys are family names used in reports and dedupe keys.
FAMILIES: dict[str, frozenset[int]] = {
    "sqli": frozenset({89}),
    "cmdi": frozenset({78, 77}),
    "xss": frozenset({79}),
    "path_traversal": frozenset({22, 23, 36}),
    "open_redirect": frozenset({601}),
    "hardcoded_secret": frozenset({798, 259, 321}),
    "security_headers": frozenset({693, 1021}),
    "cookie_flags": frozenset({1004, 614, 1275}),
    "cors": frozenset({942}),
    "verbose_errors": frozenset({209, 489, 215}),
    "info_exposure": frozenset({200, 497, 538}),
    "directory_listing": frozenset({548}),
}

# CWE families that have both a code side and a runtime side (correlation candidates).
CORRELATABLE_FAMILIES = frozenset({"sqli", "cmdi", "xss", "path_traversal", "open_redirect"})

V_INJECTION = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
V_CLIENT_SIDE = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
V_READ = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
V_SECRET = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
V_HEADERS = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N"
V_COOKIES = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"
V_CORS = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N"
V_INFO = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"

# Precomputed CVSS 3.1 base scores for the vectors above.
BASE_SCORES: dict[str, float] = {
    V_INJECTION: 9.8,
    V_CLIENT_SIDE: 6.1,
    V_READ: 7.5,
    V_SECRET: 9.1,
    V_HEADERS: 4.2,
    V_COOKIES: 3.1,
    V_CORS: 4.3,
    V_INFO: 5.3,
}


def severity_from_score(score: float) -> Severity:
    """Spec section 8: >=9.0 critical, 7.0-8.9 high, 4.0-6.9 medium, 0.1-3.9 low, 0 info."""
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0.0:
        return Severity.LOW
    return Severity.INFO


@dataclass(frozen=True)
class CweEntry:
    id: int
    name: str
    family_name: str
    owasp_2025: str
    vector: str
    fix_key: str

    @property
    def family(self) -> frozenset[int]:
        return FAMILIES[self.family_name]

    @property
    def base_score(self) -> float:
        return BASE_SCORES[self.vector]

    @property
    def severity(self) -> Severity:
        return severity_from_score(self.base_score)

    @property
    def correlatable(self) -> bool:
        return self.family_name in CORRELATABLE_FAMILIES

    @property
    def mitre_url(self) -> str:
        return f"https://cwe.mitre.org/data/definitions/{self.id}.html"


def _e(cwe: int, name: str, family: str, owasp: str, vector: str) -> CweEntry:
    # The fix-template key is the family name (one fix template per family).
    return CweEntry(cwe, name, family, OWASP_2025[owasp], vector, fix_key=family)


CATALOGUE: dict[int, CweEntry] = {
    e.id: e
    for e in [
        _e(89, "SQL Injection", "sqli", "A05", V_INJECTION),
        _e(78, "OS Command Injection", "cmdi", "A05", V_INJECTION),
        _e(77, "Command Injection", "cmdi", "A05", V_INJECTION),
        _e(79, "Cross-site Scripting", "xss", "A05", V_CLIENT_SIDE),
        _e(22, "Path Traversal", "path_traversal", "A01", V_READ),
        _e(23, "Relative Path Traversal", "path_traversal", "A01", V_READ),
        _e(36, "Absolute Path Traversal", "path_traversal", "A01", V_READ),
        _e(601, "Open Redirect", "open_redirect", "A01", V_CLIENT_SIDE),
        _e(798, "Use of Hard-coded Credentials", "hardcoded_secret", "A07", V_SECRET),
        _e(259, "Use of Hard-coded Password", "hardcoded_secret", "A07", V_SECRET),
        _e(321, "Use of Hard-coded Cryptographic Key", "hardcoded_secret", "A07", V_SECRET),
        _e(693, "Missing Security Headers", "security_headers", "A02", V_HEADERS),
        _e(1021, "Clickjacking (no frame protection)", "security_headers", "A02", V_HEADERS),
        _e(1004, "Cookie Without HttpOnly Flag", "cookie_flags", "A02", V_COOKIES),
        _e(614, "Cookie Without Secure Flag", "cookie_flags", "A02", V_COOKIES),
        _e(1275, "Cookie With Improper SameSite Attribute", "cookie_flags", "A01", V_COOKIES),
        _e(942, "Permissive CORS Policy", "cors", "A02", V_CORS),
        _e(209, "Verbose Error Message", "verbose_errors", "A10", V_INFO),
        _e(489, "Active Debug Code", "verbose_errors", "A02", V_INFO),
        _e(215, "Sensitive Information in Debugging Output", "verbose_errors", "A02", V_INFO),
        _e(200, "Information Exposure", "info_exposure", "A01", V_INFO),
        _e(497, "System Information Exposure (version banner)", "info_exposure", "A01", V_INFO),
        _e(538, "Sensitive File Exposed", "info_exposure", "A01", V_INFO),
        _e(548, "Directory Listing", "directory_listing", "A01", V_INFO),
    ]
}


def get_cwe(cwe: int) -> CweEntry:
    """Strict lookup. Raises KeyError for CWEs not in the catalogue (add them additively)."""
    return CATALOGUE[cwe]


def family_of(cwe: int) -> frozenset[int]:
    """Family set for a CWE; an unknown CWE is its own family."""
    entry = CATALOGUE.get(cwe)
    return entry.family if entry else frozenset({cwe})


def family_name(cwe: int) -> str:
    """Stable family key (e.g. "sqli"); unknown CWEs map to "cwe-<id>"."""
    entry = CATALOGUE.get(cwe)
    return entry.family_name if entry else f"cwe-{cwe}"


def same_family(a: int, b: int) -> bool:
    return family_name(a) == family_name(b)
