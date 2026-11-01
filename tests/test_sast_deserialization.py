"""CWE-502 insecure deserialization of request data (Owner: A). Generic rule, no app-specific names."""

from __future__ import annotations

import pytest

from FlowStopper.correlate.engine import correlate
from FlowStopper.cwe import CORRELATABLE_FAMILIES, family_name, get_cwe
from FlowStopper.models import Label, Severity
from FlowStopper.sast.runner import run_sast
from FlowStopper.sast.suppress import SAFE_YAML_SAFE_LOADER
from tests.sast_helpers import make_tree

HEADER = "from flask import Flask, request\napp = Flask(__name__)\n"


def scan(tmp_path, body: str, imports: str = ""):
    root = make_tree(tmp_path, {"app.py": HEADER + imports + body})
    return run_sast(root)


def of_502(result):
    return [f for f in result.findings if f.cwe == 502]


# --------------------------------------------------------------------------- positives
def test_pickle_loads_of_a_form_value_is_reported(tmp_path):
    result = scan(
        tmp_path,
        """
@app.route("/load", methods=["POST"])
def load():
    data = request.form.get("blob")
    return str(pickle.loads(data))
""",
        "import pickle\n",
    )
    (finding,) = of_502(result)
    assert finding.rule_id == "py.deserialization.load" and not finding.suppressed
    assert finding.taint is not None and finding.taint.source_param == "blob"
    assert finding.taint.entry_routes == ["POST /load"]
    assert finding.severity is Severity.CRITICAL and finding.tool == "FlowStopper-taint"


def test_taint_survives_a_base64_decode_before_the_pickle(tmp_path):
    result = scan(
        tmp_path,
        """
@app.route("/d", methods=["POST"])
def d():
    raw = base64.urlsafe_b64decode(request.form.get("pickled"))
    return str(pickle.loads(raw))
""",
        "import base64\nimport pickle\n",
    )
    (finding,) = of_502(result)
    assert finding.taint is not None and finding.taint.source_param == "pickled"


def test_request_body_bytes_reach_marshal_and_yaml_unsafe_load(tmp_path):
    result = scan(
        tmp_path,
        """
@app.route("/a", methods=["POST"])
def a():
    return str(marshal.loads(request.get_data()))

@app.route("/b", methods=["POST"])
def b():
    return str(yaml.unsafe_load(request.get_data()))
""",
        "import marshal\nimport yaml\n",
    )
    assert sorted(f.rule_id for f in of_502(result)) == ["py.deserialization.load", "py.deserialization.load"]


def test_yaml_load_without_a_safe_loader_is_reported(tmp_path):
    result = scan(
        tmp_path,
        """
@app.route("/y", methods=["POST"])
def y():
    return str(yaml.load(request.form.get("doc"), Loader=yaml.Loader))
""",
        "import yaml\n",
    )
    (finding,) = of_502(result)
    assert finding.rule_id == "py.deserialization.yaml-load" and not finding.suppressed


# --------------------------------------------------------------------------- negatives
@pytest.mark.parametrize(
    "call",
    [
        "json.loads(request.form.get('x'))",
        "yaml.safe_load(request.form.get('x'))",
        "pickle.loads(CONSTANT_BYTES)",
        "pickle.loads(int(request.form.get('x')))",
    ],
)
def test_safe_or_untainted_calls_are_not_reported(tmp_path, call):
    result = scan(
        tmp_path,
        f"""
CONSTANT_BYTES = b"cos\\nsystem\\n."

@app.route("/s", methods=["POST"])
def s():
    return str({call})
""",
        "import json\nimport pickle\nimport yaml\n",
    )
    assert [f for f in of_502(result) if not f.suppressed] == []  # a sanitised flow stays only as a hidden record


@pytest.mark.parametrize("loader_arg", ["yaml.SafeLoader", "Loader=yaml.SafeLoader", "Loader=yaml.CSafeLoader"])
def test_yaml_load_with_a_safe_loader_is_kept_as_suppressed(tmp_path, loader_arg):
    result = scan(
        tmp_path,
        f"""
@app.route("/y", methods=["POST"])
def y():
    return str(yaml.load(request.form.get("doc"), {loader_arg}))
""",
        "import yaml\n",
    )
    (finding,) = of_502(result)
    assert finding.suppressed and finding.suppress_reason == SAFE_YAML_SAFE_LOADER


def test_a_project_function_named_loads_is_not_a_sink(tmp_path):
    result = scan(
        tmp_path,
        """
def loads(value):
    return value

@app.route("/p", methods=["POST"])
def p():
    return loads(request.form.get("x"))
""",
    )
    assert of_502(result) == []


# --------------------------------------------------------------------------- catalogue + issue
def test_catalogue_entry_is_additive_and_code_only():
    entry = get_cwe(502)
    assert entry.family_name == "deserialization" and entry.base_score == 9.8
    assert entry.owasp_2025 == "A08:2025 - Software or Data Integrity Failures"
    assert "deserialization" not in CORRELATABLE_FAMILIES and family_name(502) == "deserialization"
    assert get_cwe(89).family_name == "sqli" and get_cwe(489).owasp_2025.startswith("A02")  # untouched


def test_issue_is_code_only_critical_with_a_specific_fix(tmp_path):
    result = scan(
        tmp_path,
        """
@app.route("/load", methods=["POST"])
def load():
    return str(pickle.loads(request.form.get("blob")))
""",
        "import pickle\n",
    )
    (issue,) = [i for i in correlate(result.findings, [], result.routes) if i.cwe == 502]
    assert issue.label is Label.CODE_ONLY and issue.severity is Severity.CRITICAL
    assert issue.owasp_2025 == "A08:2025 - Software or Data Integrity Failures"
    assert issue.fix is not None and "safe_load" in issue.fix and "blob" in issue.fix
