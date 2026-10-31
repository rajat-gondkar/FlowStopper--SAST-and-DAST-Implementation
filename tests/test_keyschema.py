"""Answer-key schema validation (our own format, docs/ANSWER_KEY_FORMAT.md)."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from FlowStopper.evalkit.keyschema import AnswerKey


def _key(*vulns, decoys=()):
    return {"app": "t", "vulns": list(vulns), "decoys": list(decoys)}


CODE = {"file": "a/b.py", "line_start": 3, "line_end": 4}
RT = {"method": "get", "path": "/x/<id>", "param": "id"}


def test_valid_key_normalises_method():
    k = AnswerKey.model_validate(_key({"id": "V1", "cwe": 89, "kind": "pair", "code": CODE, "runtime": RT}))
    assert k.vulns[0].runtime.method == "GET"


@pytest.mark.parametrize(
    "vuln",
    [
        {"id": "V1", "cwe": 89, "kind": "pair", "code": CODE},  # pair without runtime
        {"id": "V1", "cwe": 798, "kind": "code_only", "code": CODE, "runtime": RT},  # code_only with runtime
        {"id": "V1", "cwe": 693, "kind": "runtime_only", "code": CODE, "runtime": RT},
        {"id": "V1", "cwe": 89, "kind": "pair", "code": {**CODE, "file": "/abs.py"}, "runtime": RT},
        {"id": "V1", "cwe": 89, "kind": "pair", "code": {**CODE, "line_end": 1}, "runtime": RT},
        {"id": "V1", "cwe": 89, "kind": "pair", "code": CODE, "runtime": {**RT, "path": "x"}},
        {"id": "V1", "cwe": 89, "kind": "pair", "code": CODE, "runtime": RT, "typo_field": 1},
    ],
)
def test_invalid_vulns_rejected(vuln):
    with pytest.raises(ValidationError):
        AnswerKey.model_validate(_key(vuln))


def test_duplicate_ids_rejected():
    v = {"id": "V1", "cwe": 798, "kind": "code_only", "code": CODE}
    d = {"id": "V1", "cwe": 89, "file": "a.py", "line_start": 1, "line_end": 2, "reason": "param query"}
    with pytest.raises(ValidationError):
        AnswerKey.model_validate(_key(v, decoys=[d]))
