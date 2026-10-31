"""CVSS 3.1 base-score calculator (Owner: B, P2-B6).

Must reproduce FlowStopper.cwe.BASE_SCORES for every catalogue vector (add that test).

This is the official CVSS v3.1 base-score arithmetic (specification section 7.1), implemented from
the formulas rather than copied from a library, including the integer-based `roundup` that v3.1
introduced to avoid floating-point edge cases.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

from FlowStopper.models import Severity

# Metric weights (CVSS v3.1 table 14-18).
AV_WEIGHTS = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
AC_WEIGHTS = {"L": 0.77, "H": 0.44}
UI_WEIGHTS = {"N": 0.85, "R": 0.62}
CIA_WEIGHTS = {"H": 0.56, "L": 0.22, "N": 0.00}
# Privileges Required depends on Scope: a changed scope makes low/high privileges worth more.
PR_WEIGHTS = {
    "U": {"N": 0.85, "L": 0.62, "H": 0.27},
    "C": {"N": 0.85, "L": 0.68, "H": 0.50},
}
REQUIRED_METRICS = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")


class CvssError(ValueError):
    """A vector string is malformed or uses an unsupported metric value."""


@dataclass(frozen=True)
class CvssVector:
    av: str
    ac: str
    pr: str
    ui: str
    s: str
    c: str
    i: str
    a: str

    @property
    def scope_changed(self) -> bool:
        return self.s == "C"


def parse_vector(vector: str) -> CvssVector:
    """Parse a `CVSS:3.1/AV:N/AC:L/...` string (the prefix is optional)."""
    metrics: dict[str, str] = {}
    for part in vector.strip().split("/"):
        if not part or part.upper().startswith("CVSS:"):
            continue
        key, _, value = part.partition(":")
        if not value:
            raise CvssError(f"malformed metric {part!r} in {vector!r}")
        metrics[key.strip().upper()] = value.strip().upper()

    missing = [m for m in REQUIRED_METRICS if m not in metrics]
    if missing:
        raise CvssError(f"vector {vector!r} is missing base metrics: {missing}")

    v = CvssVector(
        av=metrics["AV"],
        ac=metrics["AC"],
        pr=metrics["PR"],
        ui=metrics["UI"],
        s=metrics["S"],
        c=metrics["C"],
        i=metrics["I"],
        a=metrics["A"],
    )
    for name, value, table in (
        ("AV", v.av, AV_WEIGHTS),
        ("AC", v.ac, AC_WEIGHTS),
        ("UI", v.ui, UI_WEIGHTS),
        ("C", v.c, CIA_WEIGHTS),
        ("I", v.i, CIA_WEIGHTS),
        ("A", v.a, CIA_WEIGHTS),
    ):
        if value not in table:
            raise CvssError(f"unsupported {name} value {value!r} in {vector!r}")
    if v.s not in PR_WEIGHTS:
        raise CvssError(f"unsupported S value {v.s!r} in {vector!r}")
    if v.pr not in PR_WEIGHTS[v.s]:
        raise CvssError(f"unsupported PR value {v.pr!r} in {vector!r}")
    return v


def roundup(value: float) -> float:
    """CVSS v3.1 Appendix A `Roundup`: round up to 1 decimal, using integer arithmetic."""
    integer = round(value * 100_000)
    if integer % 10_000 == 0:
        return integer / 100_000.0
    return (math.floor(integer / 10_000) + 1) / 10.0


def impact_sub_score(v: CvssVector) -> float:
    """ISS, then the scope-dependent Impact term."""
    iss = 1 - ((1 - CIA_WEIGHTS[v.c]) * (1 - CIA_WEIGHTS[v.i]) * (1 - CIA_WEIGHTS[v.a]))
    if v.scope_changed:
        return 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    return 6.42 * iss


def exploitability(v: CvssVector) -> float:
    return 8.22 * AV_WEIGHTS[v.av] * AC_WEIGHTS[v.ac] * PR_WEIGHTS[v.s][v.pr] * UI_WEIGHTS[v.ui]


def base_score(vector: str | CvssVector) -> float:
    """CVSS 3.1 base score (0.0-10.0) for a vector."""
    v = vector if isinstance(vector, CvssVector) else parse_vector(vector)
    impact = impact_sub_score(v)
    if impact <= 0:
        return 0.0
    raw = impact + exploitability(v)
    if v.scope_changed:
        raw *= 1.08
    return roundup(min(raw, 10.0))


def severity_of(vector: str | CvssVector) -> Severity:
    """Severity bucket for a vector (spec section 8 thresholds)."""
    from FlowStopper.cwe import severity_from_score

    return severity_from_score(base_score(vector))
