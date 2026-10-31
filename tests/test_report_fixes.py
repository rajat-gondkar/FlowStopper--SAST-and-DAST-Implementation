"""Fix suggestion tests (Owner: B, P5-B3 / B-4): one template per CWE family, three parts each,
filled from the issue, deterministic, and set by the correlator on every issue.
"""

from __future__ import annotations

import re

import pytest

from FlowStopper import cwe as cwe_mod
from FlowStopper.correlate.engine import correlate
from FlowStopper.models import CodeLocation, Finding, Issue, Label, RuntimeLocation, TaintInfo
from FlowStopper.report import common
from FlowStopper.report.fixes import fix_for, fix_parts

SHAPE = re.compile(r"^What is wrong: .+\n\nMinimal fix:\n```[a-z]+\n.+\n```\n\nPrevention: .+$", re.S)
CODE_FAMILIES = {"sqli", "cmdi", "xss", "path_traversal", "open_redirect", "hardcoded_secret"}


def _code_issue(cwe: int, param: str | None = "category", function: str = "pkg.mod.handler") -> Issue:
    loc = CodeLocation(file="pkg/mod.py", line_start=7, line_end=7, function=function, snippet="x = 1")
    finding = Finding(
        id="a" * 40,
        engine="sast",
        tool="FlowStopper-taint",
        rule_id="py.test",
        cwe=cwe,
        title="Hard-coded secret assigned to SIGNING_KEY" if cwe in (798, 259, 321) else "t",
        severity="high",
        confidence=0.9,
        code=loc,
        taint=TaintInfo(source_param=param) if param else None,
        raw={"name": "SIGNING_KEY"} if cwe in (798, 259, 321) else {},
    )
    return Issue(
        id="1" * 16,
        cwe=cwe,
        title="Hard-coded credential in pkg/mod.py (SIGNING_KEY)" if cwe in (798, 259, 321) else "t",
        label=Label.CODE_ONLY,
        severity="high",
        cvss=7.5,
        risk=5.0,
        code_findings=[finding],
        primary_code=loc,
    )


def _runtime_issue(cwe: int, title: str = "Missing Some-Header header", route: str | None = None) -> Issue:
    rt = RuntimeLocation(method="GET", url="http://127.0.0.1:9/", path="/", route_id=route, proof="header")
    finding = Finding(
        id="b" * 40,
        engine="dast",
        tool="FlowStopper-dast",
        rule_id="dast.passive.x",
        cwe=cwe,
        title=title,
        severity="medium",
        confidence=0.9,
        runtime=rt,
    )
    return Issue(
        id="2" * 16,
        cwe=cwe,
        title=f"{title} (host-wide)",
        label=Label.RUNTIME_ONLY,
        severity="medium",
        cvss=4.2,
        risk=4.2,
        runtime_findings=[finding],
        primary_runtime=rt,
    )


def _issue_for(cwe: int) -> Issue:
    family = cwe_mod.CATALOGUE[cwe].fix_key
    return _code_issue(cwe) if family in CODE_FAMILIES else _runtime_issue(cwe)


@pytest.mark.parametrize("cwe", sorted(cwe_mod.CATALOGUE))
def test_every_catalogue_cwe_has_a_three_part_fix(cwe):
    text = fix_for(_issue_for(cwe))
    assert SHAPE.match(text), text
    blocks = common.fix_blocks(text)
    assert [kind for kind, _ in blocks] == ["text", "text", "code", "text"]
    assert fix_for(_issue_for(cwe)) == text  # deterministic


def test_every_family_has_its_own_template():
    texts = {}
    for cwe, entry in cwe_mod.CATALOGUE.items():
        texts.setdefault(entry.fix_key, fix_parts(_issue_for(cwe)).code)
    assert len(set(texts.values())) == len(texts), "two families share a code example"


@pytest.mark.parametrize(
    ("cwe", "needles"),
    [
        (89, ["?", "execute(", "parameterised"]),
        (78, ["shell=False", "shlex.quote", "argument list"]),
        (79, ["escape(", "autoescap"]),
        (22, ["secure_filename", "is_relative_to", "base directory"]),
        (601, ["urlparse", "allow-list", "relative"]),
        (798, ["os.environ", "secret manager"]),
    ],
)
def test_injection_fixes_name_the_specific_pattern(cwe, needles):
    text = fix_for(_code_issue(cwe))
    for needle in needles:
        assert needle in text, needle


def test_fix_is_filled_from_the_issue():
    text = fix_for(_code_issue(89, param="category", function="pkg.mod.handler"))
    assert "pkg.mod.handler (pkg/mod.py:7)" in text
    assert "'category'" in text and "(category,)" in text
    secret = fix_for(_code_issue(798))
    assert 'SIGNING_KEY = os.environ["SIGNING_KEY"]' in secret and "pkg/mod.py" in secret


def test_unknown_param_and_unsafe_variable_names_fall_back_to_value():
    assert "request data" in fix_for(_code_issue(89, param=None))
    for name in ("next", "id", "class", "my-param", "base"):
        text = fix_for(_code_issue(601, param=name))
        assert f"'{name}'" in text
        assert "target = value or" in text


def test_runtime_only_fix_names_the_route():
    issue = _code_issue(89)
    rt = RuntimeLocation(method="POST", url="http://127.0.0.1:9/a", path="/a", route_id="POST /a", param="pw")
    runtime_only = issue.model_copy(
        update={"label": Label.RUNTIME_ONLY, "code_findings": [], "primary_code": None, "primary_runtime": rt}
    )
    text = fix_for(runtime_only)
    assert text.startswith("What is wrong: POST /a puts the request parameter 'pw'")


def test_per_cwe_wording_inside_a_family():
    assert "HttpOnly" in fix_parts(_runtime_issue(1004)).what
    assert "Secure" in fix_parts(_runtime_issue(614)).what
    assert "SameSite" in fix_parts(_runtime_issue(1275)).what
    assert "clickjacking" in fix_parts(_runtime_issue(1021)).what
    assert "Some-Header" in fix_parts(_runtime_issue(693)).what
    assert "debug mode" in fix_parts(_runtime_issue(489)).what
    assert "version" in fix_parts(_runtime_issue(497)).what


def test_unknown_cwe_gets_a_generic_fix():
    text = fix_for(_runtime_issue(1234, title="Something odd"))
    assert SHAPE.match(text)
    assert "cwe.mitre.org/data/definitions/1234" in text


def test_correlator_sets_fix_on_every_issue(fixture_sast, fixture_dast, fixture_routes):
    issues = correlate(fixture_sast, fixture_dast, fixture_routes)
    assert issues
    for issue in issues:
        assert issue.fix == fix_for(issue)
        assert SHAPE.match(issue.fix)


def test_reports_render_the_fix(fixture_expected_issues):
    from FlowStopper.report.html import render_html

    issue = next(i for i in fixture_expected_issues if i.label is Label.CONFIRMED)
    page = render_html([issue])
    assert "How to fix" in page and "What is wrong:" in page and "Prevention:" in page
    legacy = issue.model_copy(update={"fix": None})  # an issues.json written before P5-B3
    assert "What is wrong:" in render_html([legacy])
