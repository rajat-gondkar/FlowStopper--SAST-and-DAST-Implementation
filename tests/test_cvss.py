"""CVSS 3.1 calculator tests (P2-B6). Owner: B.

The contract (DECISIONS D-08): `cvss.py` must reproduce every precomputed score in
`cwe.BASE_SCORES`, so SAST can set severities from the catalogue without importing this module.
Also checked against published CVSS v3.1 example vectors.
"""

from __future__ import annotations

import pytest

from FlowStopper import cvss, cwe
from FlowStopper.models import Severity


@pytest.mark.parametrize(("vector", "expected"), sorted(cwe.BASE_SCORES.items()))
def test_reproduces_catalogue_base_scores(vector, expected):
    assert cvss.base_score(vector) == expected


def test_every_catalogue_entry_scores_consistently():
    for entry in cwe.CATALOGUE.values():
        assert cvss.base_score(entry.vector) == entry.base_score
        assert cvss.severity_of(entry.vector) is entry.severity


@pytest.mark.parametrize(
    ("vector", "expected"),
    [
        # published CVSS v3.1 reference vectors
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
        ("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", 0.0),
        ("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.6),
        ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 6.5),
        ("CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 6.5),
    ],
)
def test_known_vectors(vector, expected):
    assert cvss.base_score(vector) == expected


def test_prefix_is_optional():
    assert cvss.base_score("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8


def test_zero_impact_is_zero_regardless_of_exploitability():
    assert cvss.base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N") == 0.0
    assert cvss.severity_of("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N") is Severity.INFO


def test_scope_change_raises_privilege_weights_and_score():
    unchanged = cvss.base_score("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H")
    changed = cvss.base_score("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H")
    assert changed > unchanged


def test_roundup_rounds_up_to_one_decimal():
    assert cvss.roundup(4.0) == 4.0
    assert cvss.roundup(4.01) == 4.1
    assert cvss.roundup(3.9999999) == 4.0  # integer arithmetic avoids the float edge case
    assert cvss.roundup(0.0) == 0.0


def test_parse_vector_fields():
    v = cvss.parse_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N")
    assert (v.av, v.ac, v.pr, v.ui, v.s, v.c, v.i, v.a) == ("N", "L", "N", "R", "C", "L", "L", "N")
    assert v.scope_changed is True


@pytest.mark.parametrize(
    "vector",
    [
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H",  # missing A
        "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # bad AV
        "CVSS:3.1/AV:N/AC:L/PR:X/UI:N/S:U/C:H/I:H/A:H",  # bad PR for the scope
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:X/C:H/I:H/A:H",  # bad S
        "AV/AC:L",  # malformed metric
        "",
    ],
)
def test_invalid_vectors_raise(vector):
    with pytest.raises(cvss.CvssError):
        cvss.base_score(vector)


def test_scores_stay_in_range():
    for av in "NALP":
        for ac in "LH":
            for scope in "UC":
                vector = f"CVSS:3.1/AV:{av}/AC:{ac}/PR:N/UI:N/S:{scope}/C:H/I:H/A:H"
                score = cvss.base_score(vector)
                assert 0.0 <= score <= 10.0
                assert round(score, 1) == score  # always one decimal
