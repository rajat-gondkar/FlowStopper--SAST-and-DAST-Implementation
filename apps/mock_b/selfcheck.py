"""Prove every planted bug in shoplite-b actually fires, and every decoy stays safe.

Deliberately NOT under tests/ - `make check` collects only tests/, and apps/mock_b is held out from
Dev A until Phase 6, so this stays inside the sealed directory. Run it directly:

    .venv/bin/python -m apps.mock_b.selfcheck

A planted bug that does not fire is worse than useless: it would make the Phase 6 generalisation
score a lie. Exits non-zero if any check fails.
"""

from __future__ import annotations

import sys

from fastapi.testclient import TestClient

from .db import bootstrap
from .main import create_app

CANARY = "sdcselfcheck"


def _client() -> TestClient:
    # bootstrap() explicitly: TestClient only runs startup events inside a `with` block, and a
    # missing schema would make every query raise OperationalError - which looks like a SQLi hit
    # and would let a *broken* fixture pass this very check.
    bootstrap()
    return TestClient(create_app(), raise_server_exceptions=False)


def main() -> int:
    client = _client()
    failures: list[str] = []

    def check(name: str, condition: bool, detail: str = "") -> None:
        if condition:
            print(f"  ok   {name}")
        else:
            print(f"  FAIL {name} {detail}")
            failures.append(name)

    print("planted vulnerabilities (must fire):")

    # sanity: a benign query must work, otherwise an "OperationalError" below proves nothing
    r = client.get("/catalogue/items", params={"fragment": "Lamp"})
    check("baseline catalogue query works", r.status_code == 200 and "SKU-1001" in r.text, f"body={r.text[:160]!r}")

    r = client.get("/catalogue/items", params={"fragment": "'"})
    check(
        "B01 SQLi via /catalogue/items",
        r.status_code == 500 and "OperationalError" in r.text and "no such table" not in r.text,
    )

    r = client.post("/accounts/signin", json={"handle": "avery' OR '1'='1", "secret": "x"})
    check("B02 SQLi via /accounts/signin body", r.status_code in (401, 500) and "no such" not in r.text.lower())
    r = client.post("/accounts/signin", json={"handle": "'", "secret": "x"})
    check("B02 SQLi error surfaces", r.status_code == 500 and "OperationalError" in r.text)

    r = client.get("/catalogue/lookup", params={"term": f"{CANARY}<\"'>"})
    check("B03 reflected XSS via /catalogue/lookup", f"{CANARY}<" in r.text)

    r = client.get("/catalogue/detail/SKU-1001", params={"label": f"<b>{CANARY}</b>"})
    check("B04 template XSS via |safe", f"<b>{CANARY}</b>" in r.text)

    r = client.get("/ops/diagnose", params={"endpoint": f"localhost;echo {CANARY}$((13*17))X"})
    check("B05 command injection via os.system", f"{CANARY}221X" in r.text, f"body={r.text[:120]!r}")

    r = client.post("/ops/archive", json={"tag": f"t;echo {CANARY}$((13*17))X"})
    check("B06 command injection via shell=True", r.status_code == 200)

    # Try every Appendix B traversal form our own DAST sends; the bug counts as reachable if any
    # one of them reads the file. (`../` x6 is not always enough depth, but an absolute path is.)
    traversal_payloads = ["../../../../../../etc/passwd", "/etc/passwd", "....//....//....//etc/passwd"]
    hits = [p for p in traversal_payloads if "root:" in client.get("/assets/fetch", params={"doc": p}).text]
    check("B07 traversal via /assets/fetch", bool(hits), f"none of {traversal_payloads} read the file")

    raw_payloads = ["..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd", "%2Fetc%2Fpasswd"]
    raw_hits = [p for p in raw_payloads if "root:" in client.get(f"/assets/raw/{p}").text]
    check("B08 traversal via /assets/raw", bool(raw_hits), f"none of {raw_payloads} read the file")

    r = client.get("/accounts/bounce", params={"onward": "//evil.invalid/"}, follow_redirects=False)
    check(
        "B09 open redirect via /accounts/bounce",
        r.status_code in (301, 302, 303, 307, 308) and "evil.invalid" in r.headers.get("location", ""),
    )

    r = client.post(
        "/accounts/signin",
        params={"onward": "//evil.invalid/"},
        json={"handle": "avery", "secret": "pepper-ridge"},
        follow_redirects=False,
    )
    check(
        "B10 open redirect after signin",
        r.status_code == 303 and "evil.invalid" in r.headers.get("location", ""),
    )

    r = client.get("/")
    check("B31 security headers absent", "content-security-policy" not in {k.lower() for k in r.headers})
    check("B34 version banner present", "shoplite-b" in r.headers.get("server", ""))

    r = client.post("/accounts/signin", json={"handle": "avery", "secret": "pepper-ridge"}, follow_redirects=False)
    cookie = r.headers.get("set-cookie", "")
    check(
        "B32 session cookie lacks HttpOnly/SameSite",
        "httponly" not in cookie.lower() and "samesite" not in cookie.lower(),
        f"cookie={cookie!r}",
    )

    r = client.get("/ops/boom")
    check("B33 verbose traceback", r.status_code == 500 and "Traceback (most recent call last)" in r.text)

    print("\ndecoys (must stay safe):")

    r = client.get("/catalogue/sku/SKU-1001'")
    check("D01 parameterised query unaffected", r.status_code == 200 and "OperationalError" not in r.text)

    r = client.get("/catalogue/band", params={"name": "home", "size": "5'"})
    check("D02 int() cast rejects injection", "OperationalError" not in r.text)

    r = client.get("/catalogue/safe-lookup", params={"term": f"{CANARY}<\"'>"})
    check("D03 escaped output", f"{CANARY}<" not in r.text and "&lt;" in r.text)

    r = client.get("/ops/reachability", params={"endpoint": f"localhost;echo {CANARY}$((13*17))X"})
    check("D04 argv form does not evaluate", f"{CANARY}221X" not in r.text)

    r = client.get("/assets/vault", params={"doc": "../../../../../../etc/passwd"})
    check("D05 basename + root check blocks traversal", "root:" not in r.text)

    r = client.get("/accounts/depart", params={"onward": "//evil.invalid/"}, follow_redirects=False)
    check("D06 allow-listed redirect stays internal", "evil.invalid" not in r.headers.get("location", ""))

    r = client.get("/catalogue/echo", params={"term": f"{CANARY}<\"'>"})
    check("D07 JSON response is not an HTML sink", "application/json" in r.headers.get("content-type", ""))

    # FastAPI >= 0.16x keeps included routers as wrapper objects instead of flattening them into
    # app.routes, so walk recursively to count what is really mounted.
    def walk(container) -> list[str]:
        found: list[str] = []
        for route in getattr(container, "routes", []) or []:
            methods = getattr(route, "methods", None)
            path = getattr(route, "path", None)
            if methods and path:
                found.append(f"{sorted(m for m in methods if m != 'HEAD')[0]} {path}")
            else:  # an included-router wrapper: descend into the router it came from
                inner = getattr(route, "original_router", None) or getattr(route, "router", None)
                if inner is not None:
                    found += walk(inner)
        return found

    mounted = sorted(set(walk(create_app())))
    print(f"\nroutes mounted ({len(mounted)}):")
    for entry in mounted:
        print(f"  {entry}")

    if failures:
        print(f"\n{len(failures)} check(s) FAILED: {failures}")
        return 1
    print("\nall planted bugs fire and all decoys are safe.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
