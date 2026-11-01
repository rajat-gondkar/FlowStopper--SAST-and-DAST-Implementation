"""CWE-489 debug mode left on (Owner: A). Generic rule, no app-specific names."""

from __future__ import annotations

import pytest

from FlowStopper.models import Severity
from FlowStopper.sast.index import build_index
from FlowStopper.sast.misconfig import scan_misconfig
from FlowStopper.sast.runner import run_sast
from tests.sast_helpers import make_tree


def hits(tmp_path, files: dict[str, str]):
    root = make_tree(tmp_path, files)
    return scan_misconfig(build_index(root))


def rules(found):
    return [(h.file, h.line, h.rule_id) for h in found]


# --------------------------------------------------------------------------- dev-server launch
def test_run_with_debug_true_under_the_main_guard_is_reported(tmp_path):
    found = hits(
        tmp_path,
        {
            "run.py": """
            from flask import Flask
            app = Flask(__name__)

            if __name__ == "__main__":
                app.run(host="127.0.0.1", port=5000, debug=True)
            """
        },
    )
    assert rules(found) == [("run.py", 5, "py.config.debug-run")]
    assert found[0].cwe == 489 and found[0].name == "app.run(debug=True)" and found[0].confidence == 0.9


def test_a_factory_app_launched_in_the_main_guard_is_reported_without_importing_flask(tmp_path):
    found = hits(
        tmp_path,
        {
            "run.py": """
            from mypkg import create_app
            app = create_app()

            if __name__ == '__main__':
                app.run(debug=True)
            """
        },
    )
    assert rules(found) == [("run.py", 5, "py.config.debug-run")]


@pytest.mark.parametrize(
    "launch",
    [
        "app.run(debug=False)",
        "app.run(debug=os.environ.get('DEBUG') == '1')",
        "app.run()",
        "app.run(debug=DEBUG)",
    ],
)
def test_non_literal_or_false_debug_is_not_reported(tmp_path, launch):
    found = hits(
        tmp_path,
        {"run.py": f"import os\nDEBUG = False\napp = object()\nif __name__ == '__main__':\n    {launch}\n"},
    )
    assert found == []


def test_run_with_debug_true_outside_the_main_guard_is_not_reported(tmp_path):
    found = hits(tmp_path, {"worker.py": "def start(runner):\n    runner.run(debug=True)\n"})
    assert found == []


# --------------------------------------------------------------------------- app objects and flags
def test_fastapi_constructed_with_debug_true_is_reported(tmp_path):
    found = hits(tmp_path, {"main.py": "from fastapi import FastAPI\napp = FastAPI(debug=True)\n"})
    assert rules(found) == [("main.py", 2, "py.config.debug-app")]


def test_app_debug_flag_and_config_writes_on_a_framework_app_are_reported(tmp_path):
    found = hits(
        tmp_path,
        {
            "web.py": """
            from flask import Flask
            app = Flask(__name__)
            app.debug = True
            app.config["DEBUG"] = True
            app.config.update(DEBUG=True)
            """
        },
    )
    assert rules(found) == [("web.py", n, "py.config.debug-flag") for n in (3, 4, 5)]


def test_the_same_writes_on_an_unrelated_object_are_not_reported(tmp_path):
    found = hits(
        tmp_path,
        {"other.py": 'cfg = {}\nclass T: pass\nt = T()\nt.debug = True\ncfg["DEBUG"] = True\n'},
    )
    assert found == []


# --------------------------------------------------------------------------- settings modules
def test_debug_true_in_a_settings_style_module_is_reported_by_content_not_name(tmp_path):
    found = hits(tmp_path, {"conf/site_values.py": 'DEBUG = True\nINSTALLED_APPS = ["a"]\nROOT_URLCONF = "u"\n'})
    assert rules(found) == [("conf/site_values.py", 1, "py.config.debug-setting")]
    assert found[0].confidence == 0.8


def test_debug_true_alone_or_debug_false_in_a_settings_module_is_not_reported(tmp_path):
    found = hits(
        tmp_path,
        {
            "lonely.py": "DEBUG = True\n",
            "prod.py": 'DEBUG = False\nINSTALLED_APPS = ["a"]\n',
        },
    )
    assert found == []


def test_test_code_is_skipped(tmp_path):
    found = hits(
        tmp_path,
        {"tests/test_app.py": "from flask import Flask\napp = Flask(__name__)\napp.debug = True\n"},
    )
    assert found == []


# --------------------------------------------------------------------------- through the runner
def test_runner_emits_a_code_only_config_finding_with_catalogue_severity(tmp_path):
    root = make_tree(
        tmp_path,
        {
            "run.py": "from flask import Flask\napp = Flask(__name__)\nif __name__ == '__main__':\n    app.run(debug=True)\n"
        },
    )
    result = run_sast(root)
    (finding,) = [f for f in result.findings if f.cwe == 489]
    assert finding.tool == "FlowStopper-config" and finding.rule_id == "py.config.debug-run"
    assert finding.taint is None and not finding.suppressed
    assert finding.severity is Severity.MEDIUM and finding.code is not None
    assert finding.code.file == "run.py" and finding.code.line_start == 4
    assert finding.raw == {"setting": "app.run(debug=True)"}
    assert result.stats["config_findings"] == 1


def test_scan_is_deterministic(tmp_path):
    root = make_tree(
        tmp_path,
        {
            "run.py": "from flask import Flask\napp = Flask(__name__)\napp.debug = True\nif __name__ == '__main__':\n    app.run(debug=True)\n"
        },
    )
    assert run_sast(root).model_dump_json() == run_sast(root).model_dump_json()
