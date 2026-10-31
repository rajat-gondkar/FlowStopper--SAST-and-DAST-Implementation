"""Hard-coded secrets detector, CWE-798 (Owner: A, P2-A4).

Two scanners, one result list:

Python
    The already-parsed `ProjectIndex` module trees are reused, so no file is parsed twice and no
    target code is ever imported, compiled or executed (R7). Reported shapes: assignments (module,
    class body and function body), dict literals, keyword arguments, subscript config writes,
    literal credential comparisons, a signing-key literal passed to a token encoder, values with a
    well-known provider credential prefix and connection strings with embedded credentials.

Config-like files
    Line-oriented regexes, no extra dependency. Files are selected by **extension** only
    (`SastConfig.secret_file_extensions`) plus the literal `Dockerfile` name - never by basename,
    so the detector stays generic (R6).

Exclusions: values read from the environment (a non-empty literal default is reported at low
confidence), placeholders, values that read as a credential-free URL, path or SQL statement,
literals shorter than `SastConfig.secret_min_length`, and anything under `SastConfig.exclude_dirs`.
Shannon entropy raises confidence; low entropy never suppresses a name match.
"""

from __future__ import annotations

import ast
import math
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Union

from FlowStopper.sast.config import SastConfig
from FlowStopper.sast.index import ModuleInfo, ProjectIndex, build_index, dotted_name
from FlowStopper.sast.textfiles import read_text, text_files

SECRET_CWE = 798

RULE_ASSIGN = "py.secret.hardcoded.assign"
RULE_COMPARE = "py.secret.hardcoded.compare"
RULE_PREFIX = "py.secret.hardcoded.prefix"
RULE_DSN = "py.secret.hardcoded.dsn"
RULE_CONFIG = "py.secret.hardcoded.config"
RULE_ENV_DEFAULT = "py.secret.env_default"
RULE_CONFIG_FILE = "cfg.secret.hardcoded.key"

# Spec P2-A4 name pattern. `authors?` is removed before matching so an author field is not a secret.
_NAME_RE = re.compile(
    r"passw(or)?d|passwd|pwd|secret|api[_-]?key|token|auth|private[_-]?key|credential|access[_-]?key",
    re.IGNORECASE,
)
_AUTHOR_RE = re.compile(r"author(s|ed)?(?![a-z])", re.IGNORECASE)  # not `authorization`, which is a credential

_CREDENTIAL_PREFIXES = (
    "AKIA",
    "ASIA",
    "ghp_",
    "gho_",
    "github_pat_",
    "sk-",
    "sk_live_",
    "sk_test_",
    "xoxb-",
    "xoxp-",
    "AIza",
)
_PRIVATE_KEY_RE = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")
# scheme://user:password@host - the password group is what makes it a credential.
_DSN_RE = re.compile(r"^[a-z][a-z0-9+.\-]*://[^:/?#@\s]+:([^@/\s]+)@[^\s]+$", re.IGNORECASE)
_URL_RE = re.compile(r"^[a-z][a-z0-9+.\-]*://", re.IGNORECASE)
_PATH_RE = re.compile(r"^(/|\./|\.\./|~/|[A-Za-z]:[\\/])\S*$")
_SQL_RE = re.compile(r"^\s*(select|insert|update|delete|create|drop|alter|with|grant)\b", re.IGNORECASE)

_PLACEHOLDER_WORDS = frozenset(
    {"changeme", "xxx", "todo", "tbd", "example", "placeholder", "dummy", "none", "null", "redacted"}
)
_PLACEHOLDER_MARKERS = ("changeme", "change_me", "change-me", "placeholder", "redacted", "your_", "your-", "yourapi")
_PLACEHOLDER_PATTERNS = (
    re.compile(r"^<.*>$", re.DOTALL),
    re.compile(r"^\$\{.*\}$", re.DOTALL),
    re.compile(r"^\{\{.*\}\}$", re.DOTALL),
    re.compile(r"^%\(.*\)s$"),
)

# Calls whose Nth positional argument is a signing key (`jwt.encode(payload, "literal")`).
_SIGNING_KEY_ARGS: dict[str, int] = {"jwt.encode": 1, "jwt.decode": 1}
_ENV_GETTERS = ("os.getenv", "os.environ.get", "environ.get", "getenv")

_DOCKERFILE = "Dockerfile"
_ANON = "<literal>"

_TITLES: dict[str, str] = {
    RULE_ASSIGN: "Hard-coded secret assigned to {name}",
    RULE_COMPARE: "Hard-coded credential compared against {name}",
    RULE_PREFIX: "Hard-coded provider credential assigned to {name}",
    RULE_DSN: "Hard-coded credentials embedded in connection string {name}",
    RULE_CONFIG: "Hard-coded secret written to config key {name}",
    RULE_ENV_DEFAULT: "Hard-coded fallback secret for environment variable {name}",
    RULE_CONFIG_FILE: "Hard-coded secret in config key {name}",
}
_ANON_TITLES: dict[str, str] = {
    RULE_PREFIX: "Hard-coded provider credential in a string literal",
    RULE_DSN: "Hard-coded credentials embedded in a connection string",
}
# Lower rank wins when two detectors land on the same (file, line, name).
_RULE_RANK = {RULE_PREFIX: 0, RULE_DSN: 1, RULE_COMPARE: 2, RULE_CONFIG: 3, RULE_ASSIGN: 4, RULE_CONFIG_FILE: 5}


@dataclass(frozen=True)
class SecretHit:
    """One hard-coded credential. `line` is 1-based; `file` is a POSIX path relative to the scan root."""

    file: str
    line: int
    name: str  # the variable, key, parameter or callee the literal is bound to (`<literal>` when unbound)
    rule_id: str
    title: str
    confidence: float
    value: str  # the literal as written
    entropy: float  # Shannon bits per character of `value`
    function: Optional[str] = None  # enclosing project function qualname; None at module/class/config level
    cwe: int = SECRET_CWE

    @property
    def redacted(self) -> str:
        """The value with all but its first three characters masked, for report evidence."""
        head = self.value[:3]
        return f"{head}{'*' * max(len(self.value) - len(head), 0)}"


@dataclass(frozen=True)
class _Rules:
    """Rule ids a detector emits, by what made the value look like a credential."""

    name: str
    prefix: str = RULE_PREFIX
    dsn: str = RULE_DSN


_PY_ASSIGN_RULES = _Rules(name=RULE_ASSIGN)
_PY_CONFIG_RULES = _Rules(name=RULE_CONFIG)
_PY_COMPARE_RULES = _Rules(name=RULE_COMPARE)
_CFG_RULES = _Rules(name=RULE_CONFIG_FILE, prefix=RULE_CONFIG_FILE, dsn=RULE_CONFIG_FILE)


def scan_secrets(
    root: Path | str,
    index: Optional[ProjectIndex] = None,
    config: Optional[SastConfig] = None,
) -> list[SecretHit]:
    """Hard-coded secrets under `root`, de-duplicated per (file, line, name) and sorted by that key.

    `index` is the project index of the same root; it is built when omitted. Python files are read
    from the index's parsed trees, every other file by extension (parse only, never imported).
    """
    cfg = config or SastConfig()
    base = Path(root).resolve()
    idx = index if index is not None else build_index(base, cfg)
    hits: list[SecretHit] = []
    for module in idx.modules.values():
        hits += _PythonSecretScan(idx, module, cfg).run()
    for path in _config_files(base, cfg):
        hits += _scan_config_file(path, base, cfg)
    return _dedupe(hits)


def shannon_entropy(value: str) -> float:
    """Shannon entropy of `value` in bits per character (0.0 for an empty string)."""
    if not value:
        return 0.0
    total = len(value)
    return -sum((n / total) * math.log2(n / total) for n in Counter(value).values())


# --------------------------------------------------------------------------- Python scan
class _PythonSecretScan:
    """Secret detectors for one parsed module. Build with the module's index and walk with `run`."""

    def __init__(self, index: ProjectIndex, module: ModuleInfo, config: SastConfig) -> None:
        self.index = index
        self.module = module
        self.cfg = config
        self.hits: list[SecretHit] = []
        self._bound: dict[int, str] = {}  # id(value node) -> the name it is bound to

    def run(self) -> list[SecretHit]:
        self._bind_names()
        for node in ast.walk(self.module.tree):
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                self._assignment(node)
            elif isinstance(node, ast.Dict):
                self._dict_literal(node)
            elif isinstance(node, ast.Call):
                self._call(node)
            elif isinstance(node, ast.Compare):
                self._comparison(node)
            elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                self._bare_literal(node)
        return self.hits

    # ------------------------------------------------------------------ detectors
    def _bind_names(self) -> None:
        """Map every value expression to the name it is bound to, so a literal can be named anywhere."""
        for node in ast.walk(self.module.tree):
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                for name, _, value in _assign_targets(node):
                    self._bound.setdefault(id(value), name)
            elif isinstance(node, ast.Dict):
                for key, value in zip(node.keys, node.values, strict=True):
                    key_name = _literal_string(key) if key is not None else None
                    if key_name:
                        self._bound.setdefault(id(value), key_name)
            elif isinstance(node, ast.Call):
                for keyword in node.keywords:
                    if keyword.arg:
                        self._bound.setdefault(id(keyword.value), keyword.arg)
            elif isinstance(node, ast.Compare):
                left = _target_name(node.left)
                if left:
                    for comparator in node.comparators:
                        self._bound.setdefault(id(comparator), left)

    def _assignment(self, node: Union[ast.Assign, ast.AnnAssign]) -> None:
        for name, is_config, value in _assign_targets(node):
            rules = _PY_CONFIG_RULES if is_config else _PY_ASSIGN_RULES
            self._report(name, value, rules, node.lineno)

    def _dict_literal(self, node: ast.Dict) -> None:
        for key, value in zip(node.keys, node.values, strict=True):
            key_name = _literal_string(key) if key is not None else None
            if key_name:
                self._report(key_name, value, _PY_CONFIG_RULES, getattr(value, "lineno", node.lineno))

    def _call(self, node: ast.Call) -> None:
        callee = self._callee(node)
        if callee in _ENV_GETTERS or (callee or "").endswith(_ENV_GETTERS):
            self._env_default(node)
            return
        for keyword in node.keywords:
            if keyword.arg:
                self._report(
                    keyword.arg, keyword.value, _PY_CONFIG_RULES, getattr(keyword.value, "lineno", node.lineno)
                )
        position = _SIGNING_KEY_ARGS.get(callee or "")
        if position is not None and len(node.args) > position:
            key_arg = node.args[position]
            label = f"{callee}()"
            found = self._classify(key_arg, _PY_ASSIGN_RULES, named=True)
            if found is not None:
                rule_id, confidence, value = found
                title = f"Hard-coded signing key passed to {label}"
                self._add(label, rule_id, title, confidence, value, getattr(key_arg, "lineno", node.lineno))

    def _env_default(self, node: ast.Call) -> None:
        """`os.getenv("X", "literal")`: the read itself is safe, a non-empty literal default is not."""
        default = node.args[1] if len(node.args) > 1 else _keyword_value(node, "default")
        if default is None:
            return
        variable = _literal_string(node.args[0]) if node.args else None
        name = self._bound.get(id(node)) or variable or _ANON
        named = _name_matches(name) or _name_matches(variable or "")
        found = self._classify(default, _PY_ASSIGN_RULES, named=named)
        if found is None:
            return
        rule_id, confidence, value = found
        if rule_id == _PY_ASSIGN_RULES.name:  # a plain literal fallback: low confidence, its own rule
            rule_id, confidence = RULE_ENV_DEFAULT, 0.5
            name = variable or name
        self._add(name, rule_id, _title(rule_id, name), confidence, value, getattr(default, "lineno", node.lineno))

    def _comparison(self, node: ast.Compare) -> None:
        if not all(isinstance(op, (ast.Eq, ast.NotEq)) for op in node.ops):
            return
        for left, right in zip([node.left, *node.comparators], node.comparators, strict=False):
            for named_side, literal_side in ((left, right), (right, left)):
                name = _target_name(named_side)
                if name and _literal_string(literal_side) is not None:
                    self._report(name, literal_side, _PY_COMPARE_RULES, node.lineno, floor=0.9)

    def _bare_literal(self, node: ast.Constant) -> None:
        """A literal anywhere with a provider prefix or embedded credentials, whatever it is bound to."""
        value = str(node.value)
        if _credential_prefix(value) is None and not _dsn_credentials(value):
            return
        name = self._bound.get(id(node), _ANON)
        self._report(name, node, _PY_ASSIGN_RULES, node.lineno)

    # ------------------------------------------------------------------ reporting
    def _report(
        self,
        name: str,
        value_node: ast.expr,
        rules: _Rules,
        line: int,
        *,
        floor: float = 0.7,
    ) -> None:
        found = self._classify(value_node, rules, named=_name_matches(name), floor=floor)
        if found is None:
            return
        rule_id, confidence, value = found
        self._add(name, rule_id, _title(rule_id, name), confidence, value, getattr(value_node, "lineno", line))

    def _classify(
        self,
        value_node: ast.expr,
        rules: _Rules,
        *,
        named: bool,
        floor: float = 0.7,
    ) -> Optional[tuple[str, float, str]]:
        value = _literal_string(value_node)
        if value is None:
            return None
        return _classify_value(value, rules, named=named, floor=floor, config=self.cfg)

    def _add(self, name: str, rule_id: str, title: str, confidence: float, value: str, line: int) -> None:
        function = self.index.function_at(self.module.file, line)
        self.hits.append(
            SecretHit(
                file=self.module.file,
                line=line,
                name=name,
                rule_id=rule_id,
                title=title,
                confidence=confidence,
                value=value,
                entropy=shannon_entropy(value),
                function=function.qualname if function is not None else None,
            )
        )

    def _callee(self, node: ast.Call) -> Optional[str]:
        """Dotted callee: the resolved project/external name when known, else the name as written."""
        return self.index.resolve_call(node, self.module) or dotted_name(node.func)


# --------------------------------------------------------------------------- config-like files
def _config_files(root: Path, config: SastConfig) -> list[Path]:
    """Config-like files under `root`, selected by extension plus the literal Dockerfile name (R6)."""
    extensions = [e for e in config.secret_file_extensions if e.lower() != ".py"]
    return text_files(root, config, extensions, extra_names=(_DOCKERFILE,))


def _scan_config_file(path: Path, root: Path, config: SastConfig) -> list[SecretHit]:
    rel = path.relative_to(root).as_posix()
    text = read_text(path, rel, config, scanner="secrets")
    if text is None:
        return []
    hits: list[SecretHit] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        for name, value in _config_pairs(path.name, line):
            found = _classify_value(value, _CFG_RULES, named=_name_matches(name), config=config)
            if found is None:
                continue
            rule_id, confidence, literal = found
            hits.append(
                SecretHit(
                    file=rel,
                    line=lineno,
                    name=name,
                    rule_id=rule_id,
                    title=_title(rule_id, name),
                    confidence=confidence,
                    value=literal,
                    entropy=shannon_entropy(literal),
                    function=None,
                )
            )
    return hits


_KEY_VALUE_RE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][\w.\-]*)\s*=\s*(.+?)\s*$")
_YAML_KEY_RE = re.compile(r"^\s*(?:-\s*)?([A-Za-z_][\w.\-]*)\s*:\s*(.+?)\s*$")
_YAML_ITEM_RE = re.compile(r"^\s*-\s*\"?([A-Za-z_][\w.\-]*)\"?\s*=\s*(.+?)\s*$")
_JSON_PAIR_RE = re.compile(r"\"([^\"]+)\"\s*:\s*\"((?:[^\"\\]|\\.)*)\"")
_DOCKER_ENV_RE = re.compile(r"^\s*(?:ENV|ARG)\s+(.+?)\s*$", re.IGNORECASE)
_DOCKER_PAIR_RE = re.compile(r"([A-Za-z_][\w.\-]*)=(\"[^\"]*\"|'[^']*'|\S+)")
_DOCKER_BARE_RE = re.compile(r"^([A-Za-z_][\w.\-]*)\s+(.+)$")


def _config_pairs(filename: str, line: str) -> list[tuple[str, str]]:
    """(key, value) pairs a single config line declares, per the file's extension."""
    stripped = line.strip()
    if not stripped or stripped.startswith(("#", ";", "//")):
        return []
    suffix = Path(filename).suffix.lower()
    if filename == _DOCKERFILE or filename.startswith(f"{_DOCKERFILE}."):
        return _dockerfile_pairs(stripped)
    if suffix == ".json":
        return [(key, value) for key, value in _JSON_PAIR_RE.findall(line) if value.strip()]
    if suffix in (".yaml", ".yml"):
        matches = [_YAML_ITEM_RE.match(line), _YAML_KEY_RE.match(line)]
        return _first_pair(matches)
    return _first_pair([_KEY_VALUE_RE.match(line)])  # .env / .ini / .cfg / .toml


def _dockerfile_pairs(stripped: str) -> list[tuple[str, str]]:
    match = _DOCKER_ENV_RE.match(stripped)
    if match is None:
        return []
    body = match.group(1)
    pairs: list[tuple[str, str]] = []
    for key, raw in _DOCKER_PAIR_RE.findall(body):
        value = _clean_value(raw)
        if value:
            pairs.append((key, value))
    if pairs:
        return pairs
    return _first_pair([_DOCKER_BARE_RE.match(body)])  # `ENV KEY value`


def _first_pair(matches: list[Optional[re.Match[str]]]) -> list[tuple[str, str]]:
    for match in matches:
        if match is None:
            continue
        value = _clean_value(match.group(2))
        if value:
            return [(match.group(1), value)]
    return []


def _clean_value(raw: str) -> Optional[str]:
    """Unquote a config value and drop an inline comment; None when nothing usable is left."""
    text = raw.strip()
    if len(text) >= 2 and text[0] in "\"'" and text[-1] == text[0]:
        return text[1:-1].strip() or None
    for marker in (" #", "\t#", " ;", "\t;"):
        cut = text.find(marker)
        if cut != -1:
            text = text[:cut]
    text = text.strip().strip("\"'").strip()
    if not text or text[0] in "&*|>[{":  # yaml anchors, aliases, block scalars and inline containers
        return None
    return text


# --------------------------------------------------------------------------- value classification
def _classify_value(
    value: str,
    rules: _Rules,
    *,
    named: bool,
    config: SastConfig,
    floor: float = 0.7,
) -> Optional[tuple[str, float, str]]:
    """(rule id, confidence, value) when `value` is a credential, else None."""
    if len(value) < config.secret_min_length or _is_placeholder(value):
        return None
    if _credential_prefix(value) is not None:
        return (rules.prefix, 0.9, value)
    if _dsn_credentials(value):
        return (rules.dsn, 0.9, value)
    if not named or _looks_benign(value):
        return None
    confidence = 0.9 if _high_entropy(value, config) else floor
    return (rules.name, max(confidence, floor), value)


def _name_matches(name: str) -> bool:
    """Whether a key name reads as a credential (spec P2-A4 pattern); an author field never does."""
    return bool(name) and bool(_NAME_RE.search(_AUTHOR_RE.sub("", name)))


def _credential_prefix(value: str) -> Optional[str]:
    """The well-known provider prefix the value starts with, or None."""
    if _PRIVATE_KEY_RE.search(value):
        return "-----BEGIN"
    for prefix in _CREDENTIAL_PREFIXES:
        if value.startswith(prefix) and len(value) > len(prefix) + 2:
            return prefix
    return None


def _dsn_credentials(value: str) -> bool:
    """Whether the value is a `scheme://user:password@host` connection string with a real password."""
    match = _DSN_RE.match(value)
    return match is not None and not _is_placeholder(match.group(1))


def _is_placeholder(value: str) -> bool:
    text = value.strip()
    if not text:
        return True
    low = text.lower()
    if len(set(low)) == 1:  # a single repeated character
        return True
    if re.sub(r"[^a-z0-9]", "", low) in _PLACEHOLDER_WORDS:
        return True
    if any(marker in low for marker in _PLACEHOLDER_MARKERS):
        return True
    return any(pattern.match(text) for pattern in _PLACEHOLDER_PATTERNS)


def _looks_benign(value: str) -> bool:
    """A credential-free URL, a filesystem path or a SQL statement is not a secret."""
    if _URL_RE.match(value) and not _dsn_credentials(value):
        return True
    return bool(_PATH_RE.match(value)) or bool(_SQL_RE.match(value))


def _high_entropy(value: str, config: SastConfig) -> bool:
    if len(value) < config.secret_entropy_min_length:
        return False
    return shannon_entropy(value) >= config.secret_entropy_bits


def _title(rule_id: str, name: str) -> str:
    if name == _ANON:
        return _ANON_TITLES.get(rule_id, "Hard-coded credential in a string literal")
    return _TITLES[rule_id].format(name=name)


def _dedupe(hits: list[SecretHit]) -> list[SecretHit]:
    """One hit per (file, line, name) - the most specific rule and highest confidence - sorted by that key."""
    order = sorted(hits, key=lambda h: (h.file, h.line, h.name, -h.confidence, _RULE_RANK.get(h.rule_id, 9)))
    best: dict[tuple[str, int, str], SecretHit] = {}
    for hit in order:
        best.setdefault((hit.file, hit.line, hit.name), hit)
    return sorted(best.values(), key=lambda h: (h.file, h.line, h.name))


# --------------------------------------------------------------------------- AST helpers
def _literal_string(node: Optional[ast.AST]) -> Optional[str]:
    """The constant string an expression evaluates to (literals and concatenations only), else None."""
    if isinstance(node, ast.Constant):
        return node.value if isinstance(node.value, str) else None
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = _literal_string(node.left), _literal_string(node.right)
        return None if left is None or right is None else left + right
    if isinstance(node, ast.JoinedStr):  # an f-string is literal only when nothing is interpolated
        parts = [_literal_string(part) for part in node.values]
        return None if any(part is None for part in parts) else "".join(parts)
    return None


def _target_name(expr: ast.AST) -> Optional[str]:
    """The name an assignment target or comparison operand binds: `x`, `o.x`, `d["x"]`, `d.get("x")`."""
    if isinstance(expr, ast.Name):
        return expr.id
    if isinstance(expr, ast.Attribute):
        return expr.attr
    if isinstance(expr, ast.Subscript):
        return _literal_string(expr.slice)
    if isinstance(expr, ast.Call) and expr.args:
        return _literal_string(expr.args[0])
    return None


def _assign_targets(node: Union[ast.Assign, ast.AnnAssign]) -> list[tuple[str, bool, ast.expr]]:
    """(bound name, is a subscript config write, value) for each target of an assignment."""
    value = node.value
    if value is None:
        return []
    targets = list(node.targets) if isinstance(node, ast.Assign) else [node.target]
    out: list[tuple[str, bool, ast.expr]] = []
    for target in targets:
        unpacking = (
            isinstance(target, (ast.Tuple, ast.List))
            and isinstance(value, (ast.Tuple, ast.List))
            and len(target.elts) == len(value.elts)
        )
        if unpacking:
            for element, item in zip(target.elts, value.elts, strict=True):  # type: ignore[union-attr]
                out += _one_target(element, item)
        else:
            out += _one_target(target, value)
    return out


def _one_target(target: ast.expr, value: ast.expr) -> list[tuple[str, bool, ast.expr]]:
    if isinstance(target, ast.Subscript):
        key = _literal_string(target.slice)
        return [(key, True, value)] if key else []
    name = _target_name(target)
    return [(name, False, value)] if name else []


def _keyword_value(node: ast.Call, name: str) -> Optional[ast.expr]:
    for keyword in node.keywords:
        if keyword.arg == name:
            return keyword.value
    return None
