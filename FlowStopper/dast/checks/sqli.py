"""SQL injection check, CWE-89 (Owner: B, P1-B4). Payloads: spec Appendix B only (R4).

Error-based: append `'`, `"`, `')`, `'"` to the original value and look for a database error string
that the baseline does not have. Boolean differential (stable baselines only): an always-true
payload must look like the baseline while an always-false payload changes the response, repeatably.

Status transition (B-13, last resort, lower confidence): for targets that hide DB error text, a stable
2xx/3xx baseline that turns into a repeatable 5xx on the unbalanced `'` only - the `"` form and the
balanced `' AND 'x'='x` form stay below 500, and a benign control is clean afterwards.
"""

from __future__ import annotations

import re

from FlowStopper.dast.baseline import Baseline, Fingerprint, differs
from FlowStopper.dast.checks.base import INJECTABLE, CheckContext, make_finding
from FlowStopper.dast.client import HttpExchange
from FlowStopper.dast.discovery import benign_value
from FlowStopper.dast.types import Endpoint, Param
from FlowStopper.models import Finding

CWE = 89

# Spec Appendix B error signatures (DB drivers / messages). Must be absent from the baseline.
SQL_ERRORS = re.compile(
    r"(sqlite3\.OperationalError|SQLITE_ERROR|unrecognized token|near \"|syntax error at or near|"
    r"You have an error in your SQL syntax|psycopg2|pymysql|ORA-\d{5}|SQLSTATE|"
    r"Unclosed quotation mark|OperationalError|ProgrammingError)",
    re.IGNORECASE,
)
_ERROR_SUFFIXES = ("'", '"', "')", "'\"")


async def _error_based(
    ctx: CheckContext, endpoint: Endpoint, param: Param, orig: str
) -> tuple[tuple[HttpExchange, str, str] | None, dict[str, HttpExchange]]:
    """Returns (hit or None, exchanges by suffix) so the status rule can reuse the responses."""
    exchanges: dict[str, HttpExchange] = {}
    for suffix in _ERROR_SUFFIXES:
        payload = orig + suffix
        ex = await ctx.send(endpoint, param, payload)
        exchanges[suffix] = ex
        m = SQL_ERRORS.search(ex.body)
        if m:
            return (ex, payload, m.group(0)), exchanges
    return None, exchanges


def _is_server_error(ex: HttpExchange) -> bool:
    return ex.status >= 500


async def _status_transition(
    ctx: CheckContext,
    endpoint: Endpoint,
    param: Param,
    orig: str,
    baseline: Baseline,
    exchanges: dict[str, HttpExchange],
) -> HttpExchange | None:
    """Unbalanced `'` -> repeatable 5xx from a stable 2xx/3xx baseline, with three negative controls.

    `"` must stay below 500 (a handler that chokes on any quote is not SQL-specific), the balanced
    `' AND 'x'='x` must stay below 500 (rules out int()-style conversion of anything non-numeric),
    and a benign control sent afterwards must be clean (the app is not simply broken now).
    """
    if baseline.unstable or not all(200 <= fp.status < 400 for fp in baseline.fingerprints):
        return None
    single, double = exchanges.get("'"), exchanges.get('"')
    if single is None or double is None or not _is_server_error(single) or _is_server_error(double):
        return None
    repeat = await ctx.send(endpoint, param, orig + "'")
    if not _is_server_error(repeat):
        return None
    rnd = ctx.token(6)
    if _is_server_error(await ctx.send(endpoint, param, f"{orig}' AND '{rnd}'='{rnd}")):
        return None
    if _is_server_error(await ctx.send(endpoint, param, orig)):
        return None
    return repeat


async def _differential(
    ctx: CheckContext, endpoint: Endpoint, param: Param, orig: str, baseline: Baseline
) -> tuple[HttpExchange, str, str] | None:
    if baseline.unstable:
        return None  # an unstable baseline cannot support a differential conclusion
    rnd, rnd2 = ctx.token(6), ctx.token(6)
    pairs = [
        (f"{orig}' AND '{rnd}'='{rnd}", f"{orig}' AND '{rnd}'='{rnd2}"),  # string context (AND)
        (f"{orig}' OR '{rnd}'='{rnd}", f"{orig}' AND '{rnd}'='{rnd2}"),  # string context (OR)
        (f"{orig} AND 1=1", f"{orig} AND 1=2"),  # numeric context
    ]
    for true_p, false_p in pairs:
        true_fps: list[Fingerprint] = []
        false_fps: list[Fingerprint] = []
        false_exchanges: list[HttpExchange] = []
        for _ in range(2):  # two repeats for consistency
            true_fps.append(Fingerprint.of(await ctx.send(endpoint, param, true_p)))
            ex_false = await ctx.send(endpoint, param, false_p)
            false_exchanges.append(ex_false)
            false_fps.append(Fingerprint.of(ex_false))
        if (
            all(baseline.matches(f) for f in true_fps)
            and all(differs(baseline.primary, f) for f in false_fps)
            and not differs(false_fps[0], false_fps[1])
        ):
            return false_exchanges[0], true_p, false_p
    return None


async def run(ctx: CheckContext, endpoint: Endpoint, param: Param) -> list[Finding]:
    if param.location not in INJECTABLE:
        return []
    orig = param.value or benign_value(param.name)
    baseline = await ctx.baseline(endpoint, param)

    # error-based (skipped if the benign page already shows a SQL error - cannot attribute it)
    error_hit, error_exchanges = None, {}
    if not SQL_ERRORS.search(baseline.sample.body):
        error_hit, error_exchanges = await _error_based(ctx, endpoint, param, orig)
    if error_hit:
        ex, payload, matched = error_hit
        evidence = (
            f"Appending {payload[len(orig) :]!r} to '{param.name}' produced a database error "
            f"({matched!r}); the baseline response has none."
        )
        return [
            make_finding(
                endpoint,
                param,
                ex,
                cwe_id=CWE,
                rule_id="dast.sqli.error",
                proof="error",
                payload=payload,
                evidence=evidence,
                confidence=0.9,
                title=f"SQL injection (error-based) in parameter '{param.name}'",
                raw={"matched_error": matched},
            )
        ]

    diff_hit = await _differential(ctx, endpoint, param, orig, baseline)
    if diff_hit:
        ex, true_p, false_p = diff_hit
        evidence = (
            f"Boolean test on '{param.name}': an always-true payload matched the baseline while an "
            "always-false payload changed the response, repeatably - the value reaches a SQL query."
        )
        return [
            make_finding(
                endpoint,
                param,
                ex,
                cwe_id=CWE,
                rule_id="dast.sqli.differential",
                proof="differential",
                payload=false_p,
                evidence=evidence,
                confidence=0.8,
                title=f"SQL injection (boolean) in parameter '{param.name}'",
                raw={"true_payload": true_p, "false_payload": false_p},
            )
        ]

    status_ex = await _status_transition(ctx, endpoint, param, orig, baseline, error_exchanges)
    if status_ex:
        payload = orig + "'"
        evidence = (
            f"Status transition on '{param.name}': appending a single quote turned a stable "
            f"{baseline.primary.status} into a repeatable {status_ex.status}, while a double quote, a "
            "balanced quoted AND payload and the benign value stay below 500. No database error text was "
            "shown; the proof is the status transition, not an error string."
        )
        return [
            make_finding(
                endpoint,
                param,
                status_ex,
                cwe_id=CWE,
                rule_id="dast.sqli.status",
                proof="error",
                payload=payload,
                evidence=evidence,
                confidence=0.65,
                title=f"SQL injection (status transition) in parameter '{param.name}'",
                raw={"baseline_status": baseline.primary.status, "payload_status": status_ex.status},
            )
        ]
    return []
