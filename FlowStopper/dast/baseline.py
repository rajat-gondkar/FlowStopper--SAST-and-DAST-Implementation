"""Baseline fingerprints and differential comparison (Owner: B, P1-B3).

Two benign requests per endpoint/param give a fingerprint `(status, normalised-body length, body
hash)`; an endpoint whose two baselines disagree is marked *unstable* so checks demand stricter
evidence. `differs()` ignores volatile content (timestamps, UUID/CSRF/nonce tokens, long hex blobs)
so a boolean-based SQLi check can tell a real content change from page noise.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

from FlowStopper.dast.client import BODY_MAX, DastClient, HttpExchange

# Volatile substrings normalised away before hashing, so re-renders of the "same" page match.
_VOLATILE: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?"), "<ts>"),
    (
        re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I),
        "<uuid>",
    ),
    # hidden CSRF input: <input name="csrf_token" ... value="TOKEN">
    (
        re.compile(
            r"(name=['\"]?(?:csrf|xsrf|authenticity)[\w-]*['\"]?[^>]*?value=['\"]?)[^'\"><\s]+",
            re.I,
        ),
        r"\1<csrf>",
    ),
    # assignment / JSON form: csrf_token = "TOKEN", "csrfToken": "TOKEN"
    (re.compile(r"((?:csrf|xsrf)[_-]?token['\"]?\s*[:=]\s*['\"]?)[\w.\-]+", re.I), r"\1<csrf>"),
    (re.compile(r"(nonce['\"]?\s*[:=]\s*['\"]?)[\w.\-]+", re.I), r"\1<nonce>"),
    (re.compile(r"\b[0-9a-f]{32,}\b", re.I), "<hex>"),
]
_WS = re.compile(r"\s+")


def normalise_body(text: str, max_len: int = BODY_MAX) -> str:
    """Strip volatile tokens and collapse whitespace so stable pages hash identically."""
    out = text[:max_len]
    for rx, repl in _VOLATILE:
        out = rx.sub(repl, out)
    return _WS.sub(" ", out).strip()


@dataclass(frozen=True)
class Fingerprint:
    status: int
    length: int  # length of the normalised body
    body_hash: str

    @classmethod
    def of(cls, ex: HttpExchange) -> Fingerprint:
        norm = normalise_body(ex.body)
        return cls(ex.status, len(norm), hashlib.sha1(norm.encode("utf-8")).hexdigest())


def differs(a: Fingerprint, b: Fingerprint) -> bool:
    """True if two responses differ in a way that matters (status or normalised body)."""
    return a.status != b.status or a.body_hash != b.body_hash


@dataclass
class Baseline:
    fingerprints: tuple[Fingerprint, ...]
    unstable: bool
    sample: HttpExchange  # representative response (evidence / content-type checks)

    @property
    def primary(self) -> Fingerprint:
        return self.fingerprints[0]

    def matches(self, fp: Fingerprint) -> bool:
        """True if `fp` looks like the baseline (used by the SQLi true-variant check)."""
        return not differs(self.primary, fp)


async def establish_baseline(
    client: DastClient,
    method: str,
    url: str,
    *,
    params: dict | None = None,
    data: dict | None = None,
    json: object = None,
    repeats: int = 2,
) -> Baseline:
    """Issue `repeats` benign requests and fold them into a Baseline."""
    exchanges = [await client.request(method, url, params=params, data=data, json=json) for _ in range(max(1, repeats))]
    fingerprints = tuple(Fingerprint.of(e) for e in exchanges)
    unstable = any(differs(fingerprints[0], f) for f in fingerprints[1:])
    return Baseline(fingerprints, unstable, exchanges[-1])
