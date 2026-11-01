"""Debug mode left on (CWE-489, "Active Debug Code") (Owner: A).

Parse only (R7): the already-parsed module trees are walked, nothing is imported or executed. Four
generic shapes, none of them tied to a particular app:

- a dev-server launch with a literal ``debug=True`` inside an ``if __name__ == "__main__":`` block,
  e.g. ``app.run(host=..., debug=True)``;
- a framework app constructed with ``debug=True`` (``FastAPI(debug=True)``, ``Starlette(debug=True)``);
- ``app.debug = True``, ``app.config["DEBUG"] = True`` or ``app.config.update(DEBUG=True)`` on a name
  that the same module binds to a Flask/Quart/FastAPI/Starlette app;
- a module-level ``DEBUG = True`` in a settings-style module, recognised by its *content* (it also
  defines one of ``INSTALLED_APPS``, ``ROOT_URLCONF``, ``ALLOWED_HOSTS``, ``MIDDLEWARE`` or
  ``SECRET_KEY``) and never by its file name.

Test code is skipped. Only a literal ``True`` counts: ``debug=os.environ.get(...)`` is not reported,
because it may well be off in production. The finding is code-only: CWE-489 is not a correlatable
family, and a runtime debug console is found separately by the DAST passive checks.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Optional

from FlowStopper.sast.config import SastConfig
from FlowStopper.sast.index import ModuleInfo, ProjectIndex, dotted_parts
from FlowStopper.sast.secrets import is_test_path

DEBUG_CWE = 489

RULE_RUN = "py.config.debug-run"
RULE_APP = "py.config.debug-app"
RULE_FLAG = "py.config.debug-flag"
RULE_SETTING = "py.config.debug-setting"

_TITLES: dict[str, str] = {
    RULE_RUN: "Debug mode enabled in the development-server launch ({name})",
    RULE_APP: "Debug mode enabled when the application object is created ({name})",
    RULE_FLAG: "Debug mode switched on in the application configuration ({name})",
    RULE_SETTING: "Debug mode enabled in a settings module ({name})",
}
_CONFIDENCE: dict[str, float] = {RULE_RUN: 0.9, RULE_APP: 0.9, RULE_FLAG: 0.9, RULE_SETTING: 0.8}

# Constructors whose `debug=True` keyword turns on the framework's debug responses.
_APP_CLASSES = frozenset(
    {
        "fastapi.FastAPI",
        "fastapi.applications.FastAPI",
        "starlette.applications.Starlette",
        "flask.Flask",
        "quart.Quart",
        "sanic.Sanic",
    }
)
# Names a settings-style module defines at module level (content-based detection, never file names).
_SETTINGS_MARKERS = frozenset({"INSTALLED_APPS", "ROOT_URLCONF", "ALLOWED_HOSTS", "MIDDLEWARE", "SECRET_KEY"})


@dataclass(frozen=True)
class ConfigHit:
    """One debug-mode finding. `line` is 1-based; `file` is a POSIX path relative to the scan root."""

    file: str
    line: int
    name: str  # what is switched on, e.g. "app.run(debug=True)" or "DEBUG"
    rule_id: str
    title: str
    confidence: float
    function: Optional[str] = None
    cwe: int = DEBUG_CWE


def scan_misconfig(index: ProjectIndex, config: Optional[SastConfig] = None) -> list[ConfigHit]:
    """Debug-mode findings across the project, sorted by (file, line, rule)."""
    del config  # reserved: this detector has no tunables yet
    hits: list[ConfigHit] = []
    for module in index.modules.values():
        if is_test_path(module.file):
            continue
        hits += _ModuleScan(index, module).run()
    return sorted(hits, key=lambda h: (h.file, h.line, h.rule_id))


class _ModuleScan:
    def __init__(self, index: ProjectIndex, module: ModuleInfo) -> None:
        self.index = index
        self.module = module
        self.ctx = index.context(module)
        self.hits: list[ConfigHit] = []
        self.main_guard_calls = _calls_in_main_guard(module.tree)
        self.app_names = self._framework_app_names()

    def run(self) -> list[ConfigHit]:
        for node in ast.walk(self.module.tree):
            if isinstance(node, ast.Call):
                self._call(node)
            elif isinstance(node, ast.Assign):
                self._assign(node)
        self._settings_module()
        return self.hits

    # ------------------------------------------------------------------ detectors
    def _call(self, node: ast.Call) -> None:
        if not _debug_true(node):
            if self._is_config_update(node):
                self._add(RULE_FLAG, node.lineno, f"{_text(node.func.value)}.update(DEBUG=True)")  # type: ignore[attr-defined]
            return
        callee = self.ctx.resolve(node.func)
        if callee in _APP_CLASSES:
            self._add(RULE_APP, node.lineno, f"{callee.rsplit('.', 1)[-1]}(debug=True)")
        elif isinstance(node.func, ast.Attribute) and node.func.attr == "run" and id(node) in self.main_guard_calls:
            self._add(RULE_RUN, node.lineno, f"{_text(node.func.value)}.run(debug=True)")

    def _assign(self, node: ast.Assign) -> None:
        if not _is_true(node.value):
            return
        for target in node.targets:
            if isinstance(target, ast.Attribute) and target.attr == "debug" and self._is_app(target.value):
                self._add(RULE_FLAG, node.lineno, f"{_text(target.value)}.debug")
            elif (
                isinstance(target, ast.Subscript)
                and isinstance(target.value, ast.Attribute)
                and target.value.attr == "config"
                and self._is_app(target.value.value)
                and _const_str(target.slice) == "DEBUG"
            ):
                self._add(RULE_FLAG, node.lineno, f"{_text(target.value.value)}.config['DEBUG']")

    def _is_config_update(self, node: ast.Call) -> bool:
        """`app.config.update(DEBUG=True)`."""
        func = node.func
        if not (isinstance(func, ast.Attribute) and func.attr == "update"):
            return False
        inner = func.value
        if not (isinstance(inner, ast.Attribute) and inner.attr == "config" and self._is_app(inner.value)):
            return False
        return any(kw.arg == "DEBUG" and _is_true(kw.value) for kw in node.keywords)

    def _settings_module(self) -> None:
        """Module-level `DEBUG = True` in a module that also looks like a framework settings module."""
        defined: set[str] = set()
        debug_line: Optional[int] = None
        for stmt in self.module.tree.body:
            names, value = _module_assignment(stmt)
            defined.update(names)
            if "DEBUG" in names and value is not None and _is_true(value):
                debug_line = stmt.lineno
        if debug_line is not None and defined & _SETTINGS_MARKERS:
            self._add(RULE_SETTING, debug_line, "DEBUG")

    # ------------------------------------------------------------------ helpers
    def _framework_app_names(self) -> frozenset[str]:
        """Module-level names bound to a framework application object created in this module."""
        names: set[str] = set()
        for stmt in self.module.tree.body:
            targets, value = _module_assignment(stmt)
            if isinstance(value, ast.Call) and self.ctx.resolve(value.func) in _APP_CLASSES:
                names.update(targets)
        return frozenset(names)

    def _is_app(self, expr: ast.expr) -> bool:
        return isinstance(expr, ast.Name) and expr.id in self.app_names

    def _add(self, rule_id: str, line: int, name: str) -> None:
        function = self.index.function_at(self.module.file, line)
        self.hits.append(
            ConfigHit(
                file=self.module.file,
                line=line,
                name=name,
                rule_id=rule_id,
                title=_TITLES[rule_id].format(name=name),
                confidence=_CONFIDENCE[rule_id],
                function=function.qualname if function is not None else None,
            )
        )


# --------------------------------------------------------------------------- AST helpers
def _is_true(node: Optional[ast.expr]) -> bool:
    return isinstance(node, ast.Constant) and node.value is True


def _debug_true(call: ast.Call) -> bool:
    return any(kw.arg == "debug" and _is_true(kw.value) for kw in call.keywords)


def _const_str(node: ast.expr) -> Optional[str]:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def _text(expr: ast.expr) -> str:
    parts = dotted_parts(expr)
    return ".".join(parts) if parts else "app"


def _module_assignment(stmt: ast.stmt) -> tuple[list[str], Optional[ast.expr]]:
    """Names bound by a module-level `NAME = value` / `NAME: T = value` statement, and the value."""
    if isinstance(stmt, ast.Assign):
        return [t.id for t in stmt.targets if isinstance(t, ast.Name)], stmt.value
    if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
        return [stmt.target.id], stmt.value
    return [], None


def _is_main_guard(test: ast.expr) -> bool:
    """`__name__ == "__main__"` (either order)."""
    if not (isinstance(test, ast.Compare) and len(test.ops) == 1 and isinstance(test.ops[0], ast.Eq)):
        return False
    sides = [test.left, *test.comparators]
    names = [s.id for s in sides if isinstance(s, ast.Name)]
    texts = [_const_str(s) for s in sides]
    return names == ["__name__"] and "__main__" in texts


def _calls_in_main_guard(tree: ast.Module) -> set[int]:
    """`id()` of every call inside a module-level `if __name__ == "__main__":` block."""
    found: set[int] = set()
    for stmt in tree.body:
        if isinstance(stmt, ast.If) and _is_main_guard(stmt.test):
            for sub in stmt.body:
                found.update(id(n) for n in ast.walk(sub) if isinstance(n, ast.Call))
    return found
