"""P2-A4 hard-coded secrets detector, CWE-798 (Owner: A)."""

from __future__ import annotations

from typing import Optional

from FlowStopper.sast.config import SastConfig
from FlowStopper.sast.index import build_index
from FlowStopper.sast.secrets import SecretHit, is_test_path, scan_secrets, shannon_entropy
from tests.sast_helpers import make_tree


def scan(tmp_path, files: dict[str, str], config: Optional[SastConfig] = None) -> list[SecretHit]:
    root = make_tree(tmp_path, files)
    cfg = config or SastConfig()
    return scan_secrets(root, build_index(root, cfg), cfg)


def by_name(hits: list[SecretHit], name: str) -> Optional[SecretHit]:
    found = [h for h in hits if h.name == name]
    return found[0] if found else None


# --------------------------------------------------------------------------- Python positives
def test_module_level_name_match_is_reported(tmp_path):
    hits = scan(tmp_path, {"conf.py": 'DEBUG = False\nSECRET_KEY = "s3cr3t-key-123"\n'})
    assert [(h.file, h.line, h.name, h.rule_id, h.confidence) for h in hits] == [
        ("conf.py", 2, "SECRET_KEY", "py.secret.hardcoded.assign", 0.7)
    ]
    assert hits[0].title == "Hard-coded secret assigned to SECRET_KEY"
    assert hits[0].cwe == 798
    assert hits[0].function is None  # module level
    assert hits[0].value == "s3cr3t-key-123"
    assert hits[0].redacted == "s3c***********"


def test_class_attribute_and_function_body_are_located(tmp_path):
    files = {
        "pkg/__init__.py": "",
        "pkg/settings_values.py": """
            class Settings:
                DB_PASSWORD = "hunter2-prod-db"


            def connect():
                api_token = "local-dev-token-42"
                return api_token
        """,
    }
    hits = scan(tmp_path, files)
    attribute = by_name(hits, "DB_PASSWORD")
    local = by_name(hits, "api_token")
    assert attribute is not None and attribute.function is None  # class body reports no function
    assert attribute.rule_id == "py.secret.hardcoded.assign"
    assert local is not None and local.function == "pkg.settings_values.connect"


def test_credential_prefix_is_reported_even_without_a_matching_name(tmp_path):
    files = {"billing.py": 'CLIENT = "sk_live_51H8xQ2eZvKYlo2C0a1b2c3d4"\nNOTE = "plain configuration value"\n'}
    hits = scan(tmp_path, files)
    assert [(h.name, h.rule_id, h.confidence) for h in hits] == [("CLIENT", "py.secret.hardcoded.prefix", 0.9)]


def test_private_key_block_is_reported(tmp_path):
    files = {"keys_mod.py": 'BLOB = "-----BEGIN RSA PRIVATE KEY-----\\nMIIBOgIBAAJBAK\\n"\n'}
    hits = scan(tmp_path, files)
    assert [(h.name, h.rule_id) for h in hits] == [("BLOB", "py.secret.hardcoded.prefix")]


def test_literal_credential_comparison_is_reported(tmp_path):
    files = {
        "login_mod.py": """
            def check(password):
                if password == "letmein-2024":
                    return True
                return False
        """,
    }
    hits = scan(tmp_path, files)
    assert [(h.line, h.name, h.rule_id, h.confidence) for h in hits] == [
        (2, "password", "py.secret.hardcoded.compare", 0.9)
    ]
    assert hits[0].title == "Hard-coded credential compared against password"
    assert hits[0].function == "login_mod.check"


def test_subscript_config_write_and_keyword_config(tmp_path):
    files = {
        "boot.py": """
            from flask import Flask

            app = Flask(__name__)
            app.config["SECRET_KEY"] = "sign-this-cookie-99"
            app.config.update(API_KEY="kw-config-token-77")
        """,
    }
    hits = scan(tmp_path, files)
    assert [(h.line, h.name, h.rule_id) for h in hits] == [
        (4, "SECRET_KEY", "py.secret.hardcoded.config"),
        (5, "API_KEY", "py.secret.hardcoded.config"),
    ]
    assert hits[0].title == "Hard-coded secret written to config key SECRET_KEY"


def test_dict_literal_key_is_reported(tmp_path):
    files = {"headers_mod.py": 'HEADERS = {\n    "Authorization": "Bearer abc-def-ghi-jkl",\n}\n'}
    hits = scan(tmp_path, files)
    assert [(h.line, h.name, h.rule_id) for h in hits] == [(2, "Authorization", "py.secret.hardcoded.config")]


def test_jwt_signing_key_literal_is_reported(tmp_path):
    files = {
        "tokens.py": """
            import jwt


            def issue(uid):
                return jwt.encode({"uid": uid}, "jwt-signing-key-01", algorithm="HS256")
        """,
    }
    hits = scan(tmp_path, files)
    assert [(h.name, h.rule_id, h.function) for h in hits] == [
        ("jwt.encode()", "py.secret.hardcoded.assign", "tokens.issue")
    ]
    assert hits[0].title == "Hard-coded signing key passed to jwt.encode()"


def test_dsn_with_embedded_credentials_is_reported(tmp_path):
    files = {"dsn_mod.py": 'DB_URL = "postgresql://shop:Tr0ub4dor@db.internal:5432/shop"\n'}
    hits = scan(tmp_path, files)
    assert [(h.name, h.rule_id, h.confidence) for h in hits] == [("DB_URL", "py.secret.hardcoded.dsn", 0.9)]
    assert hits[0].title == "Hard-coded credentials embedded in connection string DB_URL"


def test_concatenated_literals_are_one_value(tmp_path):
    files = {"split_mod.py": 'TOKEN = "abc123-" + "def456-xyz"\n'}
    hits = scan(tmp_path, files)
    assert [(h.name, h.value) for h in hits] == [("TOKEN", "abc123-def456-xyz")]


# --------------------------------------------------------------------------- Python negatives
def test_environment_reads_are_not_reported(tmp_path):
    files = {
        "env_mod.py": """
            import os

            SECRET_KEY = os.environ.get("SECRET_KEY", "")
            API_TOKEN = os.getenv("API_TOKEN")
            DB_PASSWORD = os.environ["DB_PASSWORD"]
        """,
    }
    assert scan(tmp_path, files) == []


def test_environment_literal_default_is_reported_at_low_confidence(tmp_path):
    files = {
        "env_default_mod.py": """
            import os

            SECRET_KEY = os.getenv("SECRET_KEY", "fallback-signing-value")
        """,
    }
    hits = scan(tmp_path, files)
    assert [(h.name, h.rule_id, h.confidence) for h in hits] == [("SECRET_KEY", "py.secret.env_default", 0.5)]
    assert hits[0].title == "Hard-coded fallback secret for environment variable SECRET_KEY"


def test_placeholder_values_are_not_reported(tmp_path):
    files = {
        "placeholders.py": """
            A_PASSWORD = "changeme"
            B_PASSWORD = "change_me"
            C_PASSWORD = "your_password_here"
            D_PASSWORD = "xxxxxxxx"
            E_PASSWORD = "TODO"
            F_PASSWORD = "example"
            G_PASSWORD = "placeholder"
            H_PASSWORD = "dummy"
            I_PASSWORD = "none"
            J_PASSWORD = "NULL"
            K_PASSWORD = "redacted"
            L_PASSWORD = "<your-password>"
            M_PASSWORD = "${DB_PASSWORD}"
            N_PASSWORD = "{{ db_password }}"
            O_PASSWORD = "%(password)s"
            P_PASSWORD = "aaaaaaaaaa"
        """,
    }
    assert scan(tmp_path, files) == []


def test_short_values_urls_paths_and_sql_are_not_reported(tmp_path):
    files = {
        "benign.py": """
            PASSWORD = "abc"
            TOKEN_URL = "https://auth.vendor.test/oauth/token"
            API_KEY_FILE = "/etc/app/api_key.pem"
            SECRET_QUERY = "SELECT secret FROM vault WHERE id = ?"
        """,
    }
    assert scan(tmp_path, files) == []


def test_request_values_are_never_secrets(tmp_path):
    files = {
        "handler_mod.py": """
            from flask import request


            def login():
                password = request.form.get("password")
                token = request.headers["Authorization"]
                return password + token
        """,
    }
    assert scan(tmp_path, files) == []


def test_excluded_directories_are_skipped(tmp_path):
    files = {
        "vendor_pkg/__init__.py": "",
        "venv/libs.py": 'SECRET_KEY = "vendored-secret-value"\n',
        "venv/app.env": "API_TOKEN=vendored-token-value\n",
    }
    assert scan(tmp_path, files) == []


# --------------------------------------------------------------------------- config-like files
def test_env_file_key_is_reported(tmp_path):
    files = {"deploy.env": "# comment\nDEBUG=1\nDB_PASSWORD=secretpass\nAPP_URL=https://shop.test\n"}
    hits = scan(tmp_path, files)
    assert [(h.file, h.line, h.name, h.rule_id, h.confidence) for h in hits] == [
        ("deploy.env", 3, "DB_PASSWORD", "cfg.secret.hardcoded.key", 0.7)
    ]
    assert hits[0].title == "Hard-coded secret in config key DB_PASSWORD"
    assert hits[0].function is None


def test_ini_toml_and_json_values_are_reported(tmp_path):
    files = {
        "app.ini": "[main]\napi_key = ini-api-key-value\n",
        "app.toml": 'token = "toml-token-value"\n',
        "app.json": '{\n  "credential": "json-credential-value"\n}\n',
    }
    hits = scan(tmp_path, files)
    assert [(h.file, h.line, h.name) for h in hits] == [
        ("app.ini", 2, "api_key"),
        ("app.json", 2, "credential"),
        ("app.toml", 1, "token"),
    ]
    assert {h.rule_id for h in hits} == {"cfg.secret.hardcoded.key"}


def test_dockerfile_env_and_arg_lines_are_reported(tmp_path):
    files = {"Dockerfile": "FROM python:3.11\nENV API_TOKEN=docker-env-token-1\nARG DB_PASSWORD=docker-arg-pass-1\n"}
    hits = scan(tmp_path, files)
    assert [(h.line, h.name) for h in hits] == [(2, "API_TOKEN"), (3, "DB_PASSWORD")]


def test_compose_environment_entries_are_reported(tmp_path):
    files = {
        "stack.yml": """
            services:
              web:
                image: shop:latest
                environment:
                  - DB_PASSWORD=compose-list-password
                  SECRET_KEY: compose-mapping-secret
        """,
    }
    hits = scan(tmp_path, files)
    assert [(h.line, h.name) for h in hits] == [(5, "DB_PASSWORD"), (6, "SECRET_KEY")]


def test_config_placeholders_and_references_are_not_reported(tmp_path):
    files = {
        "sample.env": "DB_PASSWORD=changeme\nAPI_TOKEN=${API_TOKEN}\nSECRET_KEY=\n",
        "values.yml": "password: {{ vault_password }}\ntoken: *shared_token\napi_url: https://api.vendor.test/v2\n",
    }
    assert scan(tmp_path, files) == []


def test_config_dsn_is_reported_without_a_matching_name(tmp_path):
    files = {"stack.env": "DATABASE_URL=mysql://root:S3cr3tPass@db:3306/shop\n"}
    hits = scan(tmp_path, files)
    assert [(h.name, h.rule_id, h.confidence) for h in hits] == [("DATABASE_URL", "cfg.secret.hardcoded.key", 0.9)]


def test_unsupported_extensions_and_oversized_files_are_skipped(tmp_path):
    files = {
        "notes.txt": "DB_PASSWORD=txt-file-password-1\n",
        "big.env": "DB_PASSWORD=oversized-file-password\n",
    }
    hits = scan(tmp_path, files, SastConfig(max_text_file_bytes=10))
    assert hits == []


# --------------------------------------------------------------------------- entropy and ordering
def test_entropy_raises_confidence_but_low_entropy_still_reports(tmp_path):
    files = {
        "entropy_mod.py": """
            HIGH_SECRET = "xQ7bR2wZ91mKpTvD4LsNg8"
            LOW_SECRET = "aaaaaaab"
        """,
    }
    hits = scan(tmp_path, files)
    high = by_name(hits, "HIGH_SECRET")
    low = by_name(hits, "LOW_SECRET")
    assert high is not None and high.confidence == 0.9
    assert shannon_entropy(high.value) >= 3.0
    assert low is not None and low.confidence == 0.7  # low entropy never suppresses a name match
    assert shannon_entropy(low.value) < 3.0


def test_hits_are_deduplicated_and_sorted(tmp_path):
    files = {
        "b_mod.py": 'SECRET_KEY = "second-file-secret-1"\n',
        "a_mod.py": 'API_TOKEN = "first-file-token-1"\nPASSWORD = "first-file-password"\n',
    }
    hits = scan(tmp_path, files)
    assert [(h.file, h.line, h.name) for h in hits] == [
        ("a_mod.py", 1, "API_TOKEN"),
        ("a_mod.py", 2, "PASSWORD"),
        ("b_mod.py", 1, "SECRET_KEY"),
    ]
    assert len({(h.file, h.line, h.name) for h in hits}) == len(hits)


def test_secrets_in_test_code_are_reported_at_capped_confidence(tmp_path):
    literal = 'PASSWORD = "hunter2-pass"\n'  # short, so no entropy bonus: 0.7 outside test code
    paths = ["tests/test_login.py", "test_x.py", "pkg/x_test.py", "conftest.py", "app/settings.py"]
    hits = scan(tmp_path, dict.fromkeys(paths, literal))
    confidence = {h.file: h.confidence for h in hits if h.name == "PASSWORD"}
    assert sorted(confidence) == sorted(paths)
    assert all(confidence[p] <= 0.5 for p in paths[:4])
    assert confidence["app/settings.py"] == 0.7


def test_provider_key_in_tests_is_still_reported_but_capped(tmp_path):
    hits = scan(tmp_path, {"tests/fixtures_data.py": 'CLIENT = "AKIAZ3MQ7RXK2PLV9TQD"\n'})
    assert [(h.file, h.rule_id, h.confidence) for h in hits] == [
        ("tests/fixtures_data.py", "py.secret.hardcoded.prefix", 0.5)
    ]


def test_is_test_path():
    assert [is_test_path(p) for p in ["test/a.py", "a/tests/b.py", "testing.py", "contest.py", "src/app.py"]] == [
        True,
        True,
        False,
        False,
        False,
    ]


def test_scan_builds_its_own_index_when_none_is_given(tmp_path):
    root = make_tree(tmp_path, {"solo.py": 'SECRET_KEY = "standalone-index-secret"\n'})
    hits = scan_secrets(root)
    assert [(h.file, h.name) for h in hits] == [("solo.py", "SECRET_KEY")]
