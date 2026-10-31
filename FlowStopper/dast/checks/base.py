"""Check interface + shared helpers (Owner: B, P1-B4).

A check is `async def run(ctx: CheckContext, endpoint: Endpoint, param: Param) -> list[Finding]`.
CheckContext owns the scope-guarded client, the per-scan seed (deterministic canaries), a per
endpoint/param baseline cache, and an audit list of every payload sent so a test can assert that
only Appendix B payloads leave the tool (R4).
"""

from __future__ import annotations

import random
import string
from dataclasses import dataclass, field
from urllib.parse import quote, urlencode, urlsplit, urlunsplit

from FlowStopper import cwe, ids
from FlowStopper.dast.baseline import Baseline, establish_baseline
from FlowStopper.dast.client import DastClient, HttpExchange
from FlowStopper.dast.config import DastConfig
from FlowStopper.dast.discovery import benign_value
from FlowStopper.dast.types import Endpoint, Param
from FlowStopper.models import Engine, Finding, ParamLocation, RuntimeLocation

# Locations a value-injection check can drive (passive checks handle headers/cookies separately).
INJECTABLE = (ParamLocation.QUERY, ParamLocation.FORM, ParamLocation.JSON, ParamLocation.PATH)


def build_request(endpoint: Endpoint, param: Param, value: str) -> tuple[str, str, dict]:
    """Build (method, url, kwargs) that injects `value` into `param`, other params left benign."""
    buckets: dict[ParamLocation, dict[str, str]] = {loc: {} for loc in ParamLocation}

    def value_for(p: Param) -> str:
        if p.name == param.name and p.location is param.location:
            return value
        return p.value or benign_value(p.name)

    for p in endpoint.params:
        buckets[p.location][p.name] = value_for(p)
    if param.location is not ParamLocation.PATH and param.name not in buckets[param.location]:
        buckets[param.location][param.name] = value

    url = endpoint.url
    if param.location is ParamLocation.PATH:
        s = urlsplit(endpoint.url)
        segs = s.path.split("/")
        if len(segs) > 1:
            segs[-1] = quote(str(value), safe="")
        url = urlunsplit((s.scheme, s.netloc, "/".join(segs), "", ""))

    headers = dict(buckets[ParamLocation.HEADER])
    if buckets[ParamLocation.COOKIE]:
        headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in buckets[ParamLocation.COOKIE].items())

    kw: dict = {}
    if buckets[ParamLocation.QUERY]:
        kw["params"] = buckets[ParamLocation.QUERY]
    if buckets[ParamLocation.FORM]:
        kw["data"] = buckets[ParamLocation.FORM]
    if buckets[ParamLocation.JSON]:
        kw["json"] = buckets[ParamLocation.JSON]
    if headers:
        kw["headers"] = headers
    return endpoint.method.upper(), url, kw


def build_raw_query_request(endpoint: Endpoint, param: Param, raw_value: str) -> tuple[str, str, dict]:
    """Like build_request, but splices `raw_value` into the query string **verbatim**.

    Needed for Appendix B payloads that are themselves percent-encoded (the `..%2f` traversal
    variant): httpx would re-encode the `%` and send `..%252f`, so the target would only ever see a
    literal `%2f` instead of the separator the payload is testing for.
    """
    method, url, kw = build_request(endpoint, param, raw_value)
    others = {k: v for k, v in (kw.pop("params", {}) or {}).items() if k != param.name}
    query = urlencode(others)
    raw = f"{param.name}={raw_value}"
    s = urlsplit(url)
    return method, urlunsplit((s.scheme, s.netloc, s.path, f"{query}&{raw}" if query else raw, "")), kw


@dataclass
class CheckContext:
    client: DastClient
    base_url: str
    config: DastConfig
    rng: random.Random
    _baselines: dict[tuple, Baseline] = field(default_factory=dict)
    sent_payloads: list[str] = field(default_factory=list)  # R4 provenance (asserted by tests)

    @classmethod
    def create(cls, client: DastClient, base_url: str, config: DastConfig | None = None) -> CheckContext:
        config = config or DastConfig()
        return cls(client, base_url, config, random.Random(config.seed if config.seed is not None else 0))

    def token(self, n: int = 7) -> str:
        """A per-scan random lowercase canary (the `sdcRND` token in Appendix B)."""
        return "sdc" + "".join(self.rng.choice(string.ascii_lowercase) for _ in range(n))

    def small_ints(self) -> tuple[int, int]:
        return self.rng.randint(11, 29), self.rng.randint(31, 49)

    async def baseline(self, endpoint: Endpoint, param: Param) -> Baseline:
        key = (endpoint.key, param.name, param.location.value)
        if key not in self._baselines:
            method, url, kw = build_request(endpoint, param, param.value or benign_value(param.name))
            self._baselines[key] = await establish_baseline(self.client, method, url, **kw)
        return self._baselines[key]

    async def send(self, endpoint: Endpoint, param: Param, payload: str, *, raw_query: bool = False) -> HttpExchange:
        """Send one payload. `raw_query` splices an already-encoded payload into the query verbatim."""
        self.sent_payloads.append(payload)
        if raw_query and param.location is ParamLocation.QUERY:
            method, url, kw = build_raw_query_request(endpoint, param, payload)
        else:
            method, url, kw = build_request(endpoint, param, payload)
        return await self.client.request(method, url, **kw)


def make_finding(
    endpoint: Endpoint,
    param: Param,
    ex: HttpExchange,
    *,
    cwe_id: int,
    rule_id: str,
    proof: str,
    payload: str,
    evidence: str,
    confidence: float,
    title: str,
    raw: dict | None = None,
) -> Finding:
    """Assemble a DAST Finding from the proving exchange (stable id, severity from the catalogue)."""
    rt = RuntimeLocation(
        method=endpoint.method.upper(),
        url=ex.url,
        path=endpoint.path,
        route_id=endpoint.route_id,
        param=param.name,
        param_location=param.location,
        payload=payload,
        proof=proof,  # type: ignore[arg-type]
        request=ex.request_text,
        response_excerpt=ex.response_excerpt,
        evidence=evidence,
        repro_curl=ex.repro_curl,
    )
    fid = ids.runtime_finding_id(Engine.DAST, rule_id, cwe_id, rt.method, rt.route_id or rt.path, rt.param)
    return Finding(
        id=fid,
        engine=Engine.DAST,
        tool="FlowStopper-dast",
        rule_id=rule_id,
        cwe=cwe_id,
        title=title,
        severity=cwe.get_cwe(cwe_id).severity,
        confidence=confidence,
        runtime=rt,
        raw=raw or {},
    )
