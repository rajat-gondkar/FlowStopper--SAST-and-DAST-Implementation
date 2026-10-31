"""Build the shared contract fixtures in fixtures/ (P0-J4).

The scenario below is written by hand: every finding, route, link decision, risk value and
the sort order are literal expectations, NOT computed by correlator code. Only IDs are
computed (through FlowStopper/ids.py, the same helpers SAST/DAST/correlator must use).

    python scripts/build_fixtures.py          # rewrite fixtures/*.json
    python scripts/build_fixtures.py --check  # exit 1 if fixtures/ is stale (used by tests)

Scenario "fixture-shop" (Flask-like, http://127.0.0.1:8080), see fixtures/README.md:
  F01 clean cross-file SQLi pair               -> CONFIRMED
  F02 hard-coded secret                        -> CODE_ONLY
  F03 missing CSP header (host-wide)           -> RUNTIME_ONLY
  F04/F05 two XSS sinks, same handler, params q / sort; DAST proves q only
                                               -> CONFIRMED(q) + CODE_ONLY(sort)  (param separates them)
  F06/F07 two SQLi sinks, same handler, SAST cannot name the param; DAST proves 'start'
                                               -> no link (ambiguity rule): 2x CODE_ONLY + RUNTIME_ONLY
  D01 list-form subprocess decoy               -> suppressed CODE_ONLY (never reported)
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from FlowStopper import ids  # noqa: E402
from FlowStopper.models import (  # noqa: E402
    CodeLocation,
    Engine,
    Finding,
    Issue,
    Label,
    LinkReason,
    ParamLocation,
    Route,
    RouteParam,
    RuntimeLocation,
    Severity,
    TaintInfo,
)

FIXTURES = ROOT / "fixtures"
BASE = "http://127.0.0.1:8080"
HOST = "127.0.0.1:8080"
Q = ParamLocation.QUERY


# --------------------------------------------------------------------------- routes
def routes() -> list[Route]:
    return [
        Route(
            id="GET /api/items",
            method="GET",
            path_template="/api/items",
            path_regex="^/api/items/?$",
            handler="views.catalog.list_items",
            file="views/catalog.py",
            line_start=10,
            line_end=16,
            params=[RouteParam(name="category", location=Q)],
            reachable_functions=["services.store.find_items"],
        ),
        Route(
            id="GET /api/items/<int:item_id>",
            method="GET",
            path_template="/api/items/<int:item_id>",
            path_regex="^/api/items/(?P<item_id>[^/]+)/?$",
            handler="views.catalog.get_item",
            file="views/catalog.py",
            line_start=19,
            line_end=23,
            params=[RouteParam(name="item_id", location=ParamLocation.PATH, required=True)],
            reachable_functions=["services.store.get_item"],
        ),
        Route(
            id="GET /search",
            method="GET",
            path_template="/search",
            path_regex="^/search/?$",
            handler="views.search.search_page",
            file="views/search.py",
            line_start=8,
            line_end=26,
            params=[RouteParam(name="q", location=Q), RouteParam(name="sort", location=Q)],
        ),
        Route(
            id="GET /api/report",
            method="GET",
            path_template="/api/report",
            path_regex="^/api/report/?$",
            handler="views.reports.report",
            file="views/reports.py",
            line_start=6,
            line_end=24,
            params=[RouteParam(name="start", location=Q), RouteParam(name="end", location=Q)],
        ),
        Route(
            id="GET /api/ping",
            method="GET",
            path_template="/api/ping",
            path_regex="^/api/ping/?$",
            handler="views.net.ping",
            file="views/net.py",
            line_start=5,
            line_end=12,
            params=[RouteParam(name="host", location=Q, required=True)],
            reachable_functions=["services.net.ping_host"],
        ),
    ]


# --------------------------------------------------------------------------- SAST
def _sast(rule: str, tool: str, cwe: int, title: str, sev: Severity, conf: float, code: CodeLocation, **kw) -> Finding:
    fid = ids.code_finding_id(Engine.SAST, rule, cwe, code.file, code.function, code.line_start)
    return Finding(
        id=fid,
        engine=Engine.SAST,
        tool=tool,
        rule_id=rule,
        cwe=cwe,
        title=title,
        severity=sev,
        confidence=conf,
        code=code,
        **kw,
    )


def sast_findings() -> dict[str, Finding]:
    taint = "FlowStopper-taint"
    return {
        "sqli_items": _sast(
            "py.sqli.fstring.execute",
            taint,
            89,
            "SQL injection: request data reaches execute() through an f-string",
            Severity.CRITICAL,
            0.9,
            CodeLocation(
                file="services/store.py",
                line_start=9,
                line_end=9,
                function="services.store.find_items",
                snippet=(
                    "    conn = get_db()\n"
                    "    rows = conn.execute(f\"SELECT id, name FROM items WHERE category = '{category}'\").fetchall()\n"
                    "    return [dict(r) for r in rows]"
                ),
            ),
            taint=TaintInfo(
                source_param="category",
                source_kind=Q,
                source_location=CodeLocation(
                    file="views/catalog.py",
                    line_start=12,
                    line_end=12,
                    function="views.catalog.list_items",
                    snippet='    category = request.args.get("category", "")',
                ),
                call_chain=["views.catalog.list_items", "services.store.find_items"],
                entry_routes=["GET /api/items"],
            ),
        ),
        "secret": _sast(
            "py.secret.hardcoded.assign",
            "FlowStopper-secrets",
            798,
            "Hard-coded secret assigned to SECRET_KEY",
            Severity.CRITICAL,
            0.7,
            CodeLocation(
                file="settings.py",
                line_start=4,
                line_end=4,
                snippet='DEBUG = False\nSECRET_KEY = "s3cr3t-fixture-key-123"\nDATABASE = "shop.db"',
            ),
        ),
        "xss_q": _sast(
            "py.xss.fstring.html-response",
            taint,
            79,
            "XSS: request data returned in an HTML response without escaping",
            Severity.MEDIUM,
            0.9,
            CodeLocation(
                file="views/search.py",
                line_start=14,
                line_end=14,
                function="views.search.search_page",
                snippet='    if q:\n        return f"<h1>Results for {q}</h1>"\n    sort = request.args.get("sort", "name")',
            ),
            taint=TaintInfo(
                source_param="q",
                source_kind=Q,
                source_location=CodeLocation(
                    file="views/search.py",
                    line_start=10,
                    line_end=10,
                    function="views.search.search_page",
                    snippet='    q = request.args.get("q", "")',
                ),
                call_chain=["views.search.search_page"],
                entry_routes=["GET /search"],
            ),
        ),
        "xss_sort": _sast(
            "py.xss.fstring.html-response",
            taint,
            79,
            "XSS: request data returned in an HTML response without escaping",
            Severity.MEDIUM,
            0.9,
            CodeLocation(
                file="views/search.py",
                line_start=24,
                line_end=24,
                function="views.search.search_page",
                snippet='    items = list_sorted(sort)\n    return f"<p>Sorted by {sort}</p>" + table(items)',
            ),
            taint=TaintInfo(
                source_param="sort",
                source_kind=Q,
                source_location=CodeLocation(
                    file="views/search.py",
                    line_start=15,
                    line_end=15,
                    function="views.search.search_page",
                    snippet='    sort = request.args.get("sort", "name")',
                ),
                call_chain=["views.search.search_page"],
                entry_routes=["GET /search"],
            ),
        ),
        "sqli_report_1": _sast(
            "py.sqli.concat.execute",
            taint,
            89,
            "SQL injection: request data concatenated into SQL passed to execute()",
            Severity.CRITICAL,
            0.7,
            CodeLocation(
                file="views/reports.py",
                line_start=12,
                line_end=12,
                function="views.reports.report",
                snippet=(
                    '    lo = filters.get(FIELDS[0], "")\n'
                    '    total = db.execute("SELECT SUM(total) FROM orders WHERE created >= \'" + lo + "\'").fetchone()'
                ),
            ),
            taint=TaintInfo(
                source_param=None,  # key comes from FIELDS[0]: SAST cannot name the parameter
                source_kind=Q,
                source_location=CodeLocation(
                    file="views/reports.py",
                    line_start=8,
                    line_end=8,
                    function="views.reports.report",
                    snippet="    filters = request.args.to_dict()",
                ),
                call_chain=["views.reports.report"],
                entry_routes=["GET /api/report"],
            ),
        ),
        "sqli_report_2": _sast(
            "py.sqli.concat.execute",
            taint,
            89,
            "SQL injection: request data concatenated into SQL passed to execute()",
            Severity.CRITICAL,
            0.7,
            CodeLocation(
                file="views/reports.py",
                line_start=20,
                line_end=20,
                function="views.reports.report",
                snippet=(
                    '    hi = filters.get(FIELDS[1], "")\n'
                    '    rows = db.execute("SELECT id, total FROM orders WHERE created <= \'" + hi + "\'").fetchall()'
                ),
            ),
            taint=TaintInfo(
                source_param=None,
                source_kind=Q,
                source_location=CodeLocation(
                    file="views/reports.py",
                    line_start=8,
                    line_end=8,
                    function="views.reports.report",
                    snippet="    filters = request.args.to_dict()",
                ),
                call_chain=["views.reports.report"],
                entry_routes=["GET /api/report"],
            ),
        ),
        "cmdi_decoy": _sast(
            "py.cmdi.subprocess",
            taint,
            78,
            "Command execution with request data (list form, no shell)",
            Severity.CRITICAL,
            0.9,
            CodeLocation(
                file="services/net.py",
                line_start=21,
                line_end=21,
                function="services.net.ping_host",
                snippet=(
                    "def ping_host(host):\n"
                    '    out = subprocess.run(["ping", "-c", "1", host], capture_output=True, text=True, timeout=5)\n'
                    "    return out.stdout"
                ),
            ),
            taint=TaintInfo(
                source_param="host",
                source_kind=Q,
                call_chain=["views.net.ping", "services.net.ping_host"],
                entry_routes=["GET /api/ping"],
            ),
            suppressed=True,
            suppress_reason="safe:subprocess-list-no-shell",
        ),
    }


# --------------------------------------------------------------------------- DAST
def _req(path_qs: str) -> str:
    return f"GET {path_qs} HTTP/1.1\r\nHost: {HOST}\r\nUser-Agent: FlowStopper-dast\r\nAccept: */*\r\n\r\n"


def _dast(rule: str, cwe: int, title: str, sev: Severity, conf: float, rt: RuntimeLocation, **kw) -> Finding:
    fid = ids.runtime_finding_id(Engine.DAST, rule, cwe, rt.method, rt.route_id or rt.path, rt.param)
    return Finding(
        id=fid,
        engine=Engine.DAST,
        tool="FlowStopper-dast",
        rule_id=rule,
        cwe=cwe,
        title=title,
        severity=sev,
        confidence=conf,
        runtime=rt,
        **kw,
    )


def dast_findings() -> dict[str, Finding]:
    return {
        "sqli_items": _dast(
            "dast.sqli.error",
            89,
            "SQL injection (error-based) in query parameter 'category'",
            Severity.CRITICAL,
            0.9,
            RuntimeLocation(
                method="GET",
                url=f"{BASE}/api/items?category=books%27",
                path="/api/items",
                route_id="GET /api/items",
                param="category",
                param_location=Q,
                payload="books'",
                proof="error",
                request=_req("/api/items?category=books%27"),
                response_excerpt=(
                    "HTTP/1.1 500 INTERNAL SERVER ERROR\r\nContent-Type: text/html; charset=utf-8\r\n\r\n"
                    "...sqlite3.OperationalError: unrecognized token: \"'books''\"..."
                ),
                evidence="Appending a quote to 'category' produced 'sqlite3.OperationalError: unrecognized token'; "
                "the baseline response has no SQL error.",
                repro_curl=f"curl -i '{BASE}/api/items?category=books%27'",
            ),
            raw={"other_payloads": ['books"']},
        ),
        "xss_q": _dast(
            "dast.xss.reflected",
            79,
            "Reflected XSS in query parameter 'q'",
            Severity.MEDIUM,
            0.9,
            RuntimeLocation(
                method="GET",
                url=f"{BASE}/search?q=sdcqkzmwa%3C%22%27%3E",
                path="/search",
                route_id="GET /search",
                param="q",
                param_location=Q,
                payload="sdcqkzmwa<\"'>",
                proof="echo",
                request=_req("/search?q=sdcqkzmwa%3C%22%27%3E"),
                response_excerpt=(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<h1>Results for sdcqkzmwa<\"'></h1>"
                ),
                evidence="Canary sdcqkzmwa<\"'> reflected unencoded in the HTML body (context: html_body).",
                repro_curl=f"curl -i '{BASE}/search?q=sdcqkzmwa%3C%22%27%3E'",
            ),
        ),
        "sqli_report": _dast(
            "dast.sqli.error",
            89,
            "SQL injection (error-based) in query parameter 'start'",
            Severity.CRITICAL,
            0.9,
            RuntimeLocation(
                method="GET",
                url=f"{BASE}/api/report?start=2024-01-01%27&end=2024-12-31",
                path="/api/report",
                route_id="GET /api/report",
                param="start",
                param_location=Q,
                payload="2024-01-01'",
                proof="error",
                request=_req("/api/report?start=2024-01-01%27&end=2024-12-31"),
                response_excerpt=(
                    "HTTP/1.1 500 INTERNAL SERVER ERROR\r\nContent-Type: text/html; charset=utf-8\r\n\r\n"
                    "...sqlite3.OperationalError: unrecognized token: \"''2024-01-01''\"..."
                ),
                evidence="Appending a quote to 'start' produced 'sqlite3.OperationalError: unrecognized token'; "
                "the baseline response has no SQL error.",
                repro_curl=f"curl -i '{BASE}/api/report?start=2024-01-01%27&end=2024-12-31'",
            ),
        ),
        "csp_missing": _dast(
            "dast.passive.csp-missing",
            693,
            "Missing Content-Security-Policy header",
            Severity.MEDIUM,
            0.9,
            RuntimeLocation(
                method="GET",
                url=f"{BASE}/",
                path="/",
                proof="header",
                request=_req("/"),
                response_excerpt="HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: 512\r\n",
                evidence="No Content-Security-Policy header on 5 of 5 sampled paths: "
                "/, /api/items, /api/ping, /api/report, /search",
                repro_curl=f"curl -sI '{BASE}/'",
            ),
            raw={"affected_paths": ["/", "/api/items", "/api/ping", "/api/report", "/search"]},
        ),
    }


# --------------------------------------------------------------------------- expected issues
def _r(kind: str, detail: str, weight: float) -> LinkReason:
    return LinkReason(kind=kind, detail=detail, weight=weight)


def expected_issues(s: dict[str, Finding], d: dict[str, Finding]) -> list[Issue]:
    def code_issue(f: Finding, title: str, cvss: float, risk: float, owasp: str, reasons=()) -> Issue:
        c = f.code
        assert c is not None
        sev = Severity.CRITICAL if cvss >= 9 else Severity.HIGH if cvss >= 7 else Severity.MEDIUM
        return Issue(
            id=ids.code_issue_id(f.cwe, c.file, c.function, c.line_start),
            cwe=f.cwe,
            title=title,
            label=Label.CODE_ONLY,
            severity=sev,
            cvss=cvss,
            risk=risk,
            code_findings=[f],
            primary_code=c,
            reasons=list(reasons),
            owasp_2025=owasp,
        )

    inj = "A05:2025 - Injection"
    ambiguous = "not linked: runtime finding GET /api/report param 'start' matches 2 code findings in "
    ambiguous += "views.reports.report equally (0.80 vs 0.80) and the SAST source param is unknown"

    i_sqli = code_issue(
        s["sqli_items"], "SQL Injection in services.store.find_items (parameter 'category')", 9.8, 9.8, inj
    )
    i_sqli = i_sqli.model_copy(
        update=dict(
            label=Label.CONFIRMED,
            runtime_findings=[d["sqli_items"]],
            primary_runtime=d["sqli_items"].runtime,
            link_score=1.0,
            verified_by="dast",
            reasons=[
                _r("same_cwe", "SAST CWE-89 and DAST CWE-89 are in the same family (sqli)", 0.0),
                _r(
                    "route_chain_origin",
                    "taint flow originates at handler views.catalog.list_items for route GET /api/items "
                    "(full taint chain, +0.05 specificity)",
                    0.55,
                ),
                _r("same_param", "DAST param 'category' == SAST source param 'category'", 0.35),
                _r("same_method", "DAST method GET == route method GET", 0.10),
            ],
        )
    )
    i_xss = code_issue(s["xss_q"], "Cross-site Scripting in views.search.search_page (parameter 'q')", 6.1, 6.1, inj)
    i_xss = i_xss.model_copy(
        update=dict(
            label=Label.CONFIRMED,
            runtime_findings=[d["xss_q"]],
            primary_runtime=d["xss_q"].runtime,
            link_score=1.0,
            verified_by="dast",
            reasons=[
                _r("same_cwe", "SAST CWE-79 and DAST CWE-79 are in the same family (xss)", 0.0),
                _r(
                    "route_chain_origin",
                    "taint flow originates at handler views.search.search_page for route GET /search "
                    "(full taint chain, +0.05 specificity)",
                    0.55,
                ),
                _r("same_param", "DAST param 'q' == SAST source param 'q'", 0.35),
                _r("same_method", "DAST method GET == route method GET", 0.10),
            ],
        )
    )
    rt = d["sqli_report"].runtime
    assert rt is not None and rt.route_id is not None
    i_report_rt = Issue(
        id=ids.runtime_issue_id(89, rt.route_id, rt.param),
        cwe=89,
        title="SQL Injection at GET /api/report (parameter 'start')",
        label=Label.RUNTIME_ONLY,
        severity=Severity.CRITICAL,
        cvss=9.8,
        risk=9.8,
        runtime_findings=[d["sqli_report"]],
        primary_runtime=rt,
        reasons=[_r("ambiguity_penalty", ambiguous, -0.8)],
        owasp_2025=inj,
    )
    report_code = sorted(
        [
            code_issue(
                s[k],
                "SQL Injection in views.reports.report (parameter unknown)",
                9.8,
                5.88,
                inj,
                [_r("ambiguity_penalty", ambiguous, -0.8)],
            )
            for k in ("sqli_report_1", "sqli_report_2")
        ],
        key=lambda i: i.id,
    )
    i_secret = code_issue(
        s["secret"],
        "Hard-coded credential in settings.py (SECRET_KEY)",
        9.1,
        5.46,
        "A07:2025 - Authentication Failures",
    )
    csp = d["csp_missing"].runtime
    assert csp is not None
    i_csp = Issue(
        id=ids.runtime_issue_id(693, HOST, None),
        cwe=693,
        title="Missing Content-Security-Policy header (host-wide)",
        label=Label.RUNTIME_ONLY,
        severity=Severity.MEDIUM,
        cvss=4.2,
        risk=4.2,
        runtime_findings=[d["csp_missing"]],
        primary_runtime=csp,
        owasp_2025="A02:2025 - Security Misconfiguration",
    )
    i_xss_sort = code_issue(
        s["xss_sort"], "Cross-site Scripting in views.search.search_page (parameter 'sort')", 6.1, 3.66, inj
    )
    i_decoy = code_issue(s["cmdi_decoy"], "OS Command Injection in services.net.ping_host (suppressed)", 9.8, 5.88, inj)

    # Order: confirmed first, then risk desc, severity, CWE, id; suppressed issues last (DECISIONS D-12).
    return [i_sqli, i_xss, i_report_rt, *report_code, i_secret, i_csp, i_xss_sort, i_decoy]


# --------------------------------------------------------------------------- key + metrics
def answer_key() -> dict:
    return {
        "schema_version": "1",
        "app": "fixture-shop",
        "language": "python",
        "framework": "flask",
        "base_url": BASE,
        "vulns": [
            {
                "id": "F01",
                "cwe": 89,
                "kind": "pair",
                "title": "SQLi in item listing, SQL built in a helper in another file",
                "code": {
                    "file": "services/store.py",
                    "line_start": 9,
                    "line_end": 9,
                    "function": "services.store.find_items",
                },
                "runtime": {"method": "GET", "path": "/api/items", "param": "category"},
            },
            {
                "id": "F02",
                "cwe": 798,
                "kind": "code_only",
                "title": "Hard-coded SECRET_KEY",
                "code": {"file": "settings.py", "line_start": 4, "line_end": 4},
            },
            {
                "id": "F03",
                "cwe": 693,
                "kind": "runtime_only",
                "title": "No Content-Security-Policy header",
                "runtime": {"method": "GET", "path": "*", "param": None},
            },
            {
                "id": "F04",
                "cwe": 79,
                "kind": "pair",
                "title": "Reflected XSS via q",
                "code": {"file": "views/search.py", "line_start": 14, "line_end": 14},
                "runtime": {"method": "GET", "path": "/search", "param": "q"},
            },
            {
                "id": "F05",
                "cwe": 79,
                "kind": "pair",
                "title": "Reflected XSS via sort (same handler as F04)",
                "code": {"file": "views/search.py", "line_start": 24, "line_end": 24},
                "runtime": {"method": "GET", "path": "/search", "param": "sort"},
            },
            {
                "id": "F06",
                "cwe": 89,
                "kind": "pair",
                "title": "SQLi via start (param name not statically visible)",
                "code": {"file": "views/reports.py", "line_start": 12, "line_end": 12},
                "runtime": {"method": "GET", "path": "/api/report", "param": "start"},
            },
            {
                "id": "F07",
                "cwe": 89,
                "kind": "pair",
                "title": "SQLi via end (same handler as F06)",
                "code": {"file": "views/reports.py", "line_start": 20, "line_end": 20},
                "runtime": {"method": "GET", "path": "/api/report", "param": "end"},
            },
        ],
        "decoys": [
            {
                "id": "D01",
                "cwe": 78,
                "file": "services/net.py",
                "line_start": 20,
                "line_end": 22,
                "reason": "subprocess.run with a list argument and no shell=True",
            }
        ],
    }


def expected_metrics() -> dict:
    return {
        "_comment": "Expected section 4 metrics for expected_issues.json vs answer_key.json (see fixtures/README.md)",
        "code_detection": {"found": 6, "total": 6, "rate": 1.0},
        "runtime_detection": {"found": 4, "total": 6, "rate": 0.6667},
        "correct_links": {"found": 2, "total": 5, "rate": 0.4},
        "wrong_links": {"count": 0, "confirmed": 2, "rate": 0.0},
        "false_alarms": {"count": 0, "reported": 8, "rate": 0.0},
    }


# --------------------------------------------------------------------------- output
def render() -> dict[str, str]:
    s, d = sast_findings(), dast_findings()

    def dump(obj) -> str:
        return json.dumps(obj, indent=2) + "\n"

    return {
        "routes.json": dump([r.model_dump(mode="json") for r in routes()]),
        "sast_findings.json": dump([f.model_dump(mode="json") for f in s.values()]),
        "dast_findings.json": dump([f.model_dump(mode="json") for f in d.values()]),
        "expected_issues.json": dump([i.model_dump(mode="json") for i in expected_issues(s, d)]),
        "answer_key.json": dump(answer_key()),
        "expected_metrics.json": dump(expected_metrics()),
    }


def stale_files() -> list[str]:
    out = []
    for name, text in render().items():
        p = FIXTURES / name
        if not p.exists() or p.read_text(encoding="utf-8") != text:
            out.append(name)
    return out


def main(argv: list[str]) -> int:
    if "--check" in argv:
        stale = stale_files()
        if stale:
            print(f"stale fixtures: {stale}; run: python scripts/build_fixtures.py")
            return 1
        print("fixtures up to date")
        return 0
    FIXTURES.mkdir(exist_ok=True)
    for name, text in render().items():
        (FIXTURES / name).write_text(text, encoding="utf-8")
        print(f"wrote fixtures/{name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
