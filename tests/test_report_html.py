"""HTML report tests (Owner: B, P5-B1; multi-tab redesign P6, B-27/B-28): tabs, content, ordering,
suppressed tab, evaluation tab, R7 escaping, offline self-containment and hard-coded secret masking
(B-22). Also unit tests for report/common.py.
"""

from __future__ import annotations

import re

import pytest
from markupsafe import escape

from FlowStopper.correlate.config import CorrelateConfig
from FlowStopper.correlate.issues import is_suppressed
from FlowStopper.cwe import severity_from_score
from FlowStopper.evalkit.metrics import TARGETS
from FlowStopper.models import CodeLocation, Finding, Issue, Label, LinkReason
from FlowStopper.report import common
from FlowStopper.report.html import TABS, human_time, render_html

EVIL = "<script>alert('x')</script>"
ESCAPED_TAG = "&lt;script&gt;"
PANELS = ("overview", "issues", "evaluation", "method", "suppressed")

# A small inline eval report in the `FlowStopper eval --out` shape. The extra fields stand in for
# answer-key contents that must never reach the page (only counts and rates are read).
EVAL = {
    "schema": "flowstopper-metrics/1",
    "app": "demo-app",
    "key": "keys/confidential.key.json",
    "evaluated_at": "2026-10-31T16:59:58+00:00",
    "source": {"kind": "issues", "scan_id": "s1", "issues": "out/x/issues.json", "db": None},
    "run_time_s": 2.1,
    "issues": {"total": 22, "reported": 21, "suppressed": 1},
    "unplanted": 5,
    "metrics": {
        "code_detection": {"found": 13, "total": 13, "rate": 1.0},
        "runtime_detection": {"found": 10, "total": 13, "rate": 0.7692},
        "correct_links": {"found": 5, "total": 10, "rate": 0.5},
        "wrong_links": {"count": 0, "confirmed": 7, "rate": 0.0},
        "false_alarms": {"count": 1, "reported": 21, "rate": 0.0476},
    },
    "vulns": [{"id": "PLANTED-ZZ-01", "file": "secret_planted_module.py", "line_start": 4242}],
    "decoys": [{"file": "decoy_location_xyz.py", "line_start": 777}],
}
KEY_LEAKS = ("PLANTED-ZZ-01", "secret_planted_module.py", "4242", "decoy_location_xyz.py", "confidential.key.json")


def _confirmed(issues: list[Issue]) -> Issue:
    return next(i for i in issues if i.label is Label.CONFIRMED)


def _suppressed(issues: list[Issue]) -> Issue:
    return next(i for i in issues if is_suppressed(i))


def _reported(issues: list[Issue]) -> list[Issue]:
    return common.split_issues(issues)[0]


def _panel(page: str, key: str) -> str:
    return page.split(f'<section class="panel" id="tab-{key}"')[1].split("</section>")[0]


def _secret_issue(snippet: str, line_start: int = 12) -> Issue:
    loc = CodeLocation(file="settings.py", line_start=line_start, line_end=line_start, snippet=snippet)
    finding = Finding(
        id="f" * 40,
        engine="sast",
        tool="FlowStopper-secrets",
        rule_id="py.secret.assign",
        cwe=798,
        title="Hard-coded secret assigned to TOKEN",
        severity="critical",
        confidence=0.9,
        code=loc,
    )
    return Issue(
        id="0123456789abcdef",
        cwe=798,
        title="Hard-coded credential in settings.py (TOKEN)",
        label=Label.CODE_ONLY,
        severity="critical",
        cvss=9.1,
        risk=5.46,
        code_findings=[finding],
        primary_code=loc,
    )


# --------------------------------------------------------------------------- API compatibility
def test_render_html_call_sites_stay_compatible(fixture_expected_issues):
    assert render_html(fixture_expected_issues).startswith("<!DOCTYPE html>")
    assert render_html(fixture_expected_issues, None).startswith("<!DOCTYPE html>")
    assert render_html(fixture_expected_issues, {}, eval_report=None).startswith("<!DOCTYPE html>")
    with pytest.raises(TypeError):
        render_html(fixture_expected_issues, {}, EVAL)  # eval_report is keyword-only (B-28)


# --------------------------------------------------------------------------- tabs
def test_all_five_panels_and_tab_links_exist(fixture_expected_issues):
    page = render_html(fixture_expected_issues)
    assert [k for k, _ in TABS] == list(PANELS)
    nav = page.split('<nav class="tabs" aria-label="Report sections">')[1].split("</nav>")[0]
    for key in PANELS:
        assert page.count(f'<section class="panel" id="tab-{key}"') == 1, key
        assert f'href="#tab-{key}"' in nav, key
    # panel order follows the tab order (print shows them in this order)
    positions = [page.index(f'id="tab-{k}"') for k in PANELS]
    assert positions == sorted(positions)


def test_tabs_are_css_only_and_degrade_to_stacked_panels(fixture_expected_issues):
    page = render_html(fixture_expected_issues)
    style = page.split("<style>")[1].split("</style>")[0]
    supports = style.split("@supports selector(:has(*)) {")[1]
    # the only rule that hides panels lives inside the :has() feature query
    assert ".panel { display: none; }" in supports
    assert style.count(".panel { display: none; }") == 1
    assert ".panel:target, .panel:has(:target) { display: block; }" in supports
    assert "main:not(:has(:target)) #tab-overview { display: block; }" in supports
    printing = style.split("@media print {")[1]
    assert ".panel, .md .issue { display: block !important; }" in printing
    assert ".tabs, " in printing
    for aria in ('role="tab"', "aria-selected", 'role="tablist"'):
        assert aria not in page


def test_header_shows_target_and_one_h1(fixture_expected_issues):
    page = render_html(fixture_expected_issues, {"target": "http://127.0.0.1:9"})
    assert page.count("<h1>") == 1
    h1 = page.split("<h1>")[1].split("</h1>")[0]
    assert "http://127.0.0.1:9" in h1
    for landmark in ("<header", "<main>", "<footer>", '<nav class="tabs" aria-label='):
        assert landmark in page, landmark


# --------------------------------------------------------------------------- overview
def test_overview_hero_counts_risk_and_meta(fixture_expected_issues):
    meta = {
        "target": "http://127.0.0.1:9",
        "source": "src",
        "started_at": "2026-11-01T00:00:00Z",
        "scan_id": "abc123",
        "timings_s": {"total": 4.25},
        "versions": {"FlowStopper": "9.9.9"},
    }
    page = render_html(fixture_expected_issues, meta)
    overview = _panel(page, "overview")
    reported = _reported(fixture_expected_issues)
    confirmed = sum(1 for i in reported if i.label is Label.CONFIRMED)
    top = max(reported, key=lambda i: i.risk)
    assert f'<h2><span class="hero-num">{confirmed}</span><span class="word">Confirmed</span></h2>' in overview
    assert f"<strong>{confirmed} of {len(reported)}</strong>" in overview
    assert f'<span class="n">{top.risk:.1f}</span><span class="of">/ 10</span>' in overview
    assert f'aria-label="Risk {top.risk:.1f} out of 10"' in overview
    assert f'style="width: {top.risk * 10:.1f}%"' in overview
    for text in ("http://127.0.0.1:9", "1 Nov 2026, 00:00 UTC", "4.2 s"):
        assert text in overview, text
    assert '<time datetime="2026-11-01T00:00:00Z">' in overview
    assert "abc123" not in page.split("<footer>")[0]  # the scan id lives in the footer only
    assert '<span class="mono">abc123</span>' in page.split("<footer>")[1]
    assert "FlowStopper 9.9.9" in page.split("<footer>")[1]


def test_overview_severity_bar_and_label_split(fixture_expected_issues):
    overview = _panel(render_html(fixture_expected_issues), "overview")
    reported = _reported(fixture_expected_issues)
    counts = common.severity_counts(reported)
    for sev, n in counts.items():
        assert f'{sev.capitalize()}</span><span class="n">{n}</span>' in overview, sev
        if n:
            assert f'<span class="sev-{sev}" style="flex-grow: {n}"></span>' in overview
    labels = common.label_counts(reported)
    assert f'<div class="card lblock primary">\n          <div class="n">{labels["confirmed"]}</div>' in overview
    for word in ("Confirmed", "Code only", "Runtime only"):
        assert f'<div class="w">{word}</div>' in overview


def test_fix_first_lists_the_top_three(fixture_expected_issues):
    overview = _panel(render_html(fixture_expected_issues), "overview")
    cards = overview.split('<ol class="fixfirst">')[1].split("</ol>")[0]
    reported = _reported(fixture_expected_issues)
    assert cards.count('<li class="card ff">') == min(3, len(reported))
    for n, issue in enumerate(reported[:3], 1):
        assert str(escape(issue.title)) in cards
        assert f'<a class="open" href="#issue-{n}">Open details' in cards


def test_table_is_prioritised_confirmed_first(fixture_expected_issues):
    page = render_html(list(reversed(fixture_expected_issues)))
    table = page.split('<table class="issues-table">')[1].split("</table>")[0]
    labels = re.findall(r'<td><span class="label label-(\w+)">', table)
    risks = [float(x) for x in re.findall(r'<td class="risk">([\d.]+)</td>', table)]
    order = [int(x) for x in re.findall(r'<td class="title"><a href="#issue-(\d+)">', table)]
    assert order == list(range(1, len(order) + 1))
    first_other = next(n for n, label in enumerate(labels) if label != "confirmed")
    assert all(label == "confirmed" for label in labels[:first_other])
    assert "confirmed" not in labels[first_other:]
    assert risks[first_other:] == sorted(risks[first_other:], reverse=True)


def test_table_has_caption_scoped_headers_and_two_line_location(fixture_expected_issues):
    page = render_html(fixture_expected_issues)
    table = page.split('<table class="issues-table">')[1].split("</table>")[0]
    assert "<caption>" in table
    assert re.findall(r'<th scope="col">([^<]+)</th>', table) == [
        "Risk",
        "Severity",
        "Label",
        "Issue",
        "Location",
        "CWE",
    ]
    confirmed = _confirmed(fixture_expected_issues)
    endpoint, where = common.runtime_where(confirmed.primary_runtime), common.code_where(confirmed.primary_code)
    assert f'<span class="loc-main">{escape(endpoint)}</span><span class="loc-sub">{escape(where)}</span>' in table


def test_severity_and_label_are_words_not_just_colour(fixture_expected_issues):
    page = render_html(fixture_expected_issues)
    table = page.split('<table class="issues-table">')[1].split("</table>")[0]
    ilist = page.split('<ol class="ilist">')[1].split("</ol>")[0]
    for issue in _reported(fixture_expected_issues):
        word = issue.severity.value.capitalize()
        assert f'<span class="mark" aria-hidden="true"></span>{word}</span>' in table
        assert f'<span class="label label-{issue.label.value}">{common.LABEL_TEXT[issue.label]}</span>' in table
        assert f"<span>{common.LABEL_TEXT[issue.label]}</span>" in ilist


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("2026-10-31T21:47:05+00:00", "31 Oct 2026, 21:47 UTC"),
        ("2026-10-31T23:47:05+02:00", "31 Oct 2026, 21:47 UTC"),
        ("2026-01-02T03:04:05Z", "2 Jan 2026, 03:04 UTC"),
        ("2026-01-02T03:04:05", "2 Jan 2026, 03:04 UTC"),
        ("not a time", "not a time"),
        (None, None),
    ],
)
def test_scan_time_is_human_readable(value, expected):
    assert human_time(value) == expected


# --------------------------------------------------------------------------- issues tab
def test_every_reported_issue_has_an_anchor_and_a_list_entry(fixture_expected_issues):
    page = render_html(fixture_expected_issues)
    issues_tab = _panel(page, "issues")
    ilist = issues_tab.split('<ol class="ilist">')[1].split("</ol>")[0]
    reported = _reported(fixture_expected_issues)
    assert reported
    for n, issue in enumerate(reported, 1):
        assert page.count(f'id="issue-{n}"') == 1
        assert f'<article class="card issue" id="issue-{n}"' in issues_tab
        assert ilist.count(f'<li><a href="#issue-{n}">') == 1
        assert f'href="#issue-{n}"' in _panel(page, "overview")
        assert issue.id in issues_tab  # the stable id is still shown on the card
    assert issues_tab.count('<article class="card issue"') == len(reported)
    style = page.split("<style>")[1].split("</style>")[0]
    assert f'.md:has(#issue-{len(reported)}:target) .ilist a[href="#issue-{len(reported)}"]' in style


def test_confirmed_detail_shows_everything_fr8(fixture_expected_issues):
    issue = _confirmed(fixture_expected_issues).model_copy(update={"fix": "Use parameters.\n\n```python\nq(x)\n```"})
    page = render_html([issue])
    detail = _panel(page, "issues")
    rt, code = issue.primary_runtime, issue.primary_code
    expected = [
        'id="issue-1"',
        "Confirmed",
        f"{issue.risk:.1f} / 10",
        f"{issue.cvss:.1f}",
        f"{rt.method} {rt.url}",
        rt.param,
        rt.proof,
        f"{code.file}:{code.line_start}",
        code.function,
        f"CWE-{issue.cwe}",
        issue.owasp_2025,
        "Why these were linked",
        "How to fix",
        "<pre>q(x)</pre>",
        "Reproduce",
        "Raw request and response",
    ]
    for text in expected:
        assert text in detail, text
    for raw in (rt.payload, rt.evidence, rt.repro_curl, *(r.detail for r in issue.reasons)):
        assert str(escape(raw)) in detail, raw
    assert 'class="line hot"' in detail  # the offending line is highlighted
    assert '<details class="raw">' in detail and '<details class="raw" open' not in detail
    order = [
        detail.index(s) for s in ("Runtime proof", "Code location", "Why these were linked", "How to fix", "Reproduce")
    ]
    assert order == sorted(order)  # proof first


def test_reasons_show_detail_first_and_machine_id_secondary(fixture_expected_issues):
    issue = _confirmed(fixture_expected_issues)
    detail = _panel(render_html([issue]), "issues")
    for r in issue.reasons:
        assert f'<p class="d">{escape(r.detail)}</p><p class="x">{r.kind} &middot; weight {r.weight:+.2f}</p>' in detail
    if issue.link_score is not None:
        assert f"Link score {issue.link_score:.2f}; a link needs at least {CorrelateConfig().link_min:.2f}." in detail


def test_call_chain_is_drawn_as_boxes(fixture_expected_issues):
    issue = next(
        i
        for i in _reported(fixture_expected_issues)
        if any(f.taint and len(f.taint.call_chain) > 1 for f in i.code_findings)
    )
    detail = _panel(render_html([issue]), "issues")
    chain = detail.split('<ol class="chain"')[1].split("</ol>")[0]
    taint = next(f.taint for f in issue.code_findings if f.taint and len(f.taint.call_chain) > 1)
    for fn in taint.call_chain:
        assert f'<span class="fn">{escape(fn)}</span>' in chain
    assert chain.count('<use href="#i-arrow">') == len(taint.call_chain) - 1


# --------------------------------------------------------------------------- suppressed tab
def test_suppressed_tab_explains_reasons(fixture_expected_issues):
    page = render_html(fixture_expected_issues)
    tab = _panel(page, "suppressed")
    supp = _suppressed(fixture_expected_issues)
    assert "not hidden issues" in tab
    assert str(escape(supp.title)) in tab
    for reason in common.suppress_reasons(supp):
        assert f'<span class="why-raw">{escape(reason)}</span>' in tab
        text = common.explain_suppression(reason)
        assert str(escape(text[:1].upper() + text[1:])) in tab
    assert str(escape(supp.title)) not in _panel(page, "issues")  # not in the reported list or details


def test_suppressed_tab_empty_state(fixture_expected_issues):
    tab = _panel(render_html(_reported(fixture_expected_issues)), "suppressed")
    assert "Nothing was suppressed" in tab
    assert "<table" not in tab


@pytest.mark.parametrize(
    ("reason", "needle"),
    [
        ("sanitized:html.escape", "html.escape"),
        ("sanitized:a+b", "a, b"),
        ("safe:sql-parameterised", "parameterised"),
        ("safe:subprocess-list-no-shell", "without a shell"),
        ("unreachable", "not reachable"),
        ("dast:debug-traceback-reflection", "debug traceback"),
        ("safe:something-new", "something-new"),
    ],
)
def test_every_suppress_reason_is_explained(reason, needle):
    assert needle in common.explain_suppression(reason)


def test_suppressed_dast_traceback_reason_is_rendered(fixture_expected_issues):
    issue = next(i for i in fixture_expected_issues if i.label is Label.RUNTIME_ONLY and i.runtime_findings)
    rf = issue.runtime_findings[0].model_copy(
        update={"suppressed": True, "suppress_reason": "dast:debug-traceback-reflection"}
    )
    page = render_html([issue.model_copy(update={"runtime_findings": [rf]})])
    tab = _panel(page, "suppressed")
    assert "dast:debug-traceback-reflection" in tab and "debug traceback" in tab


# --------------------------------------------------------------------------- evaluation tab (B-28)
def test_evaluation_tab_without_data_says_not_evaluated(fixture_expected_issues):
    tab = _panel(render_html(fixture_expected_issues), "evaluation")
    assert "Not evaluated" in tab and "FlowStopper eval" in tab
    assert 'class="ev-val"' not in tab  # no values, so never a zero
    assert 'class="ev-count"' not in tab and "of 7 at Great" not in tab and 'class="track' not in tab


def test_evaluation_tab_with_data(fixture_expected_issues):
    page = render_html(fixture_expected_issues, {"scan_id": "s1"}, eval_report=EVAL)
    tab = _panel(page, "evaluation")
    assert "4 of 7 at Great, 1 at Good, 1 below Good, 1 not measured" in tab
    assert "against our own answer key" in tab and "Not the organisers' score" in tab
    assert "<strong>demo-app</strong>" in tab and "31 Oct 2026, 16:59 UTC" in tab
    assert "different scan" not in tab
    for name, value, count, status in (
        ("Code detection", "100%", "13/13", "Great"),
        ("Runtime detection", "76.9%", "10/13", "Good"),
        ("Correct links", "50%", "5/10", "Below Good"),  # exactly on the line misses it
        ("Wrong links", "0%", "0/7", "Great"),
        ("False alarms", "4.8%", "1/21", "Great"),
        ("Run time", "2.1 s", "", "Great"),
    ):
        row = tab.split(f'<p class="ev-name">{name}</p>')[1].split("</li>")[0]
        assert f'<p class="ev-val">{value}</p>' in row, name
        if count:
            assert f'<p class="ev-count">{count}</p>' in row, name
        assert f"</svg>{status}</span>" in row, name
    unseen = tab.split('<p class="ev-name">Unseen app</p>')[1].split("</li>")[0]
    assert "Not measured" in unseen and 'class="ev-val"' not in unseen
    for target in (">60%", ">85%", "<20%", "<5%", "<30%", "<10%", ">40%", ">65%", "<15 min", "<5 min"):
        assert str(escape(target)) in tab, target


def test_evaluation_never_shows_answer_key_contents(fixture_expected_issues):
    page = render_html(fixture_expected_issues, None, eval_report=EVAL)
    for leak in KEY_LEAKS:
        assert leak not in page, leak


def test_evaluation_notes_a_different_scan(fixture_expected_issues):
    tab = _panel(render_html(fixture_expected_issues, {"scan_id": "other"}, eval_report=EVAL), "evaluation")
    assert "different scan" in tab


@pytest.mark.parametrize(
    ("value", "targets", "expected"),
    [
        (0.86, common.TARGET_CODE_DETECTION, "great"),
        (0.85, common.TARGET_CODE_DETECTION, "good"),
        (0.60, common.TARGET_CODE_DETECTION, "below"),
        (0.04, common.TARGET_WRONG_LINKS, "great"),
        (0.05, common.TARGET_WRONG_LINKS, "good"),
        (0.20, common.TARGET_WRONG_LINKS, "below"),
        (299.0, common.TARGET_RUN_TIME_S, "great"),
        (900.0, common.TARGET_RUN_TIME_S, "below"),
    ],
)
def test_grade_uses_strict_comparisons(value, targets, expected):
    assert common.grade(value, *targets) == expected


def test_eval_rows_handle_missing_and_empty_data():
    rows = {r.key: r for r in common.eval_rows(None)}
    assert len(rows) == common.EVAL_METRIC_COUNT == 7
    assert all(r.status == "not_measured" and r.value_pct is None for r in rows.values())
    report = {
        "metrics": {"wrong_links": {"count": 0, "confirmed": 0, "rate": 0.0}, "unseen_app": {"found": 7, "total": 10}}
    }
    rows = {r.key: r for r in common.eval_rows(report)}
    assert rows["wrong_links"].status == "not_measured"  # 0 of 0 says nothing
    assert rows["unseen_app"].status == "great" and rows["unseen_app"].count_text == "7/10"
    assert rows["code_detection"].status == "not_measured"
    assert common.eval_summary(list(rows.values())) == "1 of 7 at Great, 0 at Good, 0 below Good, 6 not measured"


def test_targets_match_the_eval_harness():
    by_key = {k: t for k, _n, _a, _b, _d, t in common.EVAL_METRICS}
    for key, targets in TARGETS.items():
        expected = common.TARGET_RUN_TIME_S if key == "run_time" else by_key[key]
        assert targets == expected, key


# --------------------------------------------------------------------------- schema and method tab
def test_every_model_field_has_a_meaning():
    for model in common.SCHEMA_MODELS:
        assert set(common.FIELD_MEANINGS[model.__name__]) == set(model.model_fields), model.__name__


def test_method_tab_shows_generated_schema_rules_and_diagram(fixture_expected_issues):
    tab = _panel(render_html(fixture_expected_issues), "method")
    for model in common.SCHEMA_MODELS:
        assert f"<summary>{model.__name__} " in tab
        for name in model.model_fields:
            assert f'<td class="f">{name}</td>' in tab, (model.__name__, name)
    assert str(escape('"critical" | "high" | "medium" | "low" | "info"')) in tab
    assert "number (0-1)" in tab  # Finding.confidence bounds read from the model
    c = CorrelateConfig()
    assert f"at least {c.link_min:.2f}" in tab
    assert f"{c.w_route:.2f} x route match + {c.w_param:.2f} x same parameter" in tab
    assert f"within {c.ambiguity_margin:.2f}" in tab
    assert f"x {c.factor_code_only:g}" in tab
    assert '<svg viewBox="0 0 960 204" role="img"' in tab
    for text, _value, definition in [(common.LABEL_TEXT[k], k, v) for k, v in common.LABEL_DEFINITIONS.items()]:
        assert text in tab and str(escape(definition)) in tab


@pytest.mark.parametrize(("severity", "band"), common.SEVERITY_BANDS)
def test_severity_bands_match_cvss_mapping(severity, band):
    low, _, high = band.partition("-")
    assert severity_from_score(float(low)) is severity
    assert severity_from_score(float(high or low)) is severity


# --------------------------------------------------------------------------- R7 escaping
def test_all_dynamic_text_is_escaped(fixture_expected_issues):
    base = _confirmed(fixture_expected_issues)
    rt = base.primary_runtime.model_copy(
        update={
            "evidence": EVIL,
            "payload": EVIL,
            "url": f"http://127.0.0.1/x?q={EVIL}",
            "repro_curl": f"curl '{EVIL}'",
            "request": EVIL,
            "response_excerpt": EVIL,
            "param": EVIL,
        }
    )
    code = base.primary_code.model_copy(update={"snippet": EVIL, "function": EVIL, "file": EVIL})
    evil = base.model_copy(
        update={
            "title": EVIL,
            "primary_runtime": rt,
            "primary_code": code,
            "reasons": [LinkReason(kind="same_cwe", detail=EVIL, weight=0.0)],
            "fix": f"{EVIL}\n\n```\n{EVIL}\n```",
            "owasp_2025": EVIL,
        }
    )
    supp = _suppressed(fixture_expected_issues)
    sf = supp.code_findings[0].model_copy(update={"suppress_reason": EVIL})
    supp = supp.model_copy(update={"title": EVIL, "code_findings": [sf]})
    evil_eval = {**EVAL, "app": EVIL, "evaluated_at": EVIL, "source": {"scan_id": EVIL}}
    meta = {"target": EVIL, "source": EVIL, "scan_id": EVIL, "started_at": EVIL}
    page = render_html([evil, supp], meta, eval_report=evil_eval)
    assert "<script" not in page.lower()
    assert "alert('x')" not in page  # quotes are escaped too
    assert page.count(ESCAPED_TAG) >= 15


def test_page_is_self_contained_and_offline(fixture_expected_issues):
    page = render_html(fixture_expected_issues, {"target": "http://127.0.0.1:9"}, eval_report=EVAL)
    lowered = page.lower()
    for marker in ("<script", "<link", "<img", "<iframe", "<object", "<embed", "@import", "url(", " src=", "xmlns"):
        assert marker not in lowered, marker
    assert "<style>" in page
    # every <use> points into the inline sprite
    uses = set(re.findall(r'<use href="([^"]+)"', page))
    assert uses and all(u.startswith("#i-") and f'<symbol id="{u[1:]}"' in page for u in uses)


def test_no_remote_assets_only_plain_links(fixture_expected_issues):
    page = render_html(fixture_expected_issues, {"target": "http://127.0.0.1:9"})
    # Any absolute http(s) URL in an attribute must be an ordinary <a href> link (CWE/OWASP), never loaded.
    tags = re.findall(r'<(\w+)\b[^>]*\b(?:src|srcset|href|data|poster|action|xlink:href)="https?://', page, re.I)
    assert tags and {t.lower() for t in tags} == {"a"}
    style = page.split("<style>")[1].split("</style>")[0]
    assert "http://" not in style and "https://" not in style


def test_light_theme_only(fixture_expected_issues):
    page = render_html(fixture_expected_issues)
    assert "prefers-color-scheme" not in page
    assert '<meta name="color-scheme" content="light">' in page
    assert "color-scheme: light;" in page
    assert "gradient" not in page
    assert "@media (prefers-reduced-motion: reduce)" in page


def test_rendering_is_byte_identical(fixture_expected_issues):
    meta = {"target": "http://127.0.0.1:9", "started_at": "2026-11-01T00:00:00+00:00", "scan_id": "s1"}
    first = render_html(fixture_expected_issues, meta, eval_report=EVAL).encode("utf-8")
    assert render_html(fixture_expected_issues, meta, eval_report=EVAL).encode("utf-8") == first
    assert render_html(list(reversed(fixture_expected_issues)), meta, eval_report=EVAL).encode("utf-8") == first


def test_empty_scan_renders_every_panel():
    page = render_html([], {"target": "http://127.0.0.1:9"})
    for key in PANELS:
        assert f'id="tab-{key}"' in page
    assert "No reported issues" in page and "Nothing was suppressed" in page


# --------------------------------------------------------------------------- secret masking (B-22)
def test_secret_value_is_masked_in_the_report():
    issue = _secret_issue('# signing key\nTOKEN = "sk_live_abcdef123456"\n')
    page = render_html([issue])
    assert "sk_live_abcdef123456" not in page
    assert "sk***" in page


def test_secret_value_is_masked_in_a_full_page(fixture_expected_issues):
    issue = _secret_issue('TOKEN = "sk_live_abcdef123456"\n', line_start=1)
    page = render_html([*fixture_expected_issues, issue], {"target": "http://127.0.0.1:9"}, eval_report=EVAL)
    assert "sk_live_abcdef123456" not in page and "abcdef123456" not in page
    assert "TOKEN = &#34;sk***&#34;" in page


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ('TOKEN = "sk_live_abcdef"', 'TOKEN = "sk***"'),
        ("    KEY = 'abcdef'", "    KEY = 'ab***'"),
        ('PW = b"hunter2"', 'PW = b"hu***"'),
        ('cfg = {"password": "s3cret"}', 'cfg = {"pa***": "s3***"}'),
        ("DB_PASSWORD=plainvalue", "DB_PASSWORD=pl***"),
        ("api_key: abcdef123", "api_key: ab***"),
        ('X = "ab"', 'X = "***"'),
        ("# a comment: with a colon", "# a comment: with a colon"),
        ("", ""),
    ],
)
def test_mask_secret_line(line, expected):
    assert common.mask_secret_line(line) == expected


def test_only_secret_cwes_are_masked():
    assert common.display_snippet(89, 'q = "SELECT 1"') == 'q = "SELECT 1"'
    assert common.display_snippet(798, 'k = "abcdef"') == 'k = "ab***"'
    assert common.display_snippet(321, 'k = "abcdef"') == 'k = "ab***"'


# --------------------------------------------------------------------------- snippet numbering
@pytest.mark.parametrize(
    ("snippet", "start", "end", "numbers", "hot"),
    [
        ("a\nb\nc", 10, 10, [9, 10, 11], [10]),  # one line of context each side
        ("a\nb", 1, 1, [1, 2], [1]),  # first line of the file: no leading context
        ("a\nb", 20, 20, [19, 20], [20]),  # last line of the file: no trailing context
        ("a", 5, 5, [5], [5]),  # no context at all
        ("a\nb\nc\nd", 7, 8, [6, 7, 8, 9], [7, 8]),  # multi-line finding
    ],
)
def test_snippet_lines(snippet, start, end, numbers, hot):
    loc = CodeLocation(file="f.py", line_start=start, line_end=end, snippet=snippet)
    lines = common.snippet_lines(89, loc)
    assert [ln.number for ln in lines] == numbers
    assert [ln.number for ln in lines if ln.hot] == hot


def test_fix_blocks_split_text_and_code():
    text = "What is wrong.\n\n```python\nx = 1\ny = 2\n```\n\nTip: be careful."
    assert common.fix_blocks(text) == [
        ("text", "What is wrong."),
        ("code", "x = 1\ny = 2"),
        ("text", "Tip: be careful."),
    ]
    assert common.fix_blocks(None) == []
    assert common.fix_blocks("```\nunterminated") == [("code", "unterminated")]
