"""Source index (Owner: A, P1-A1): file discovery, ast parsing, symbol table, import resolution.

Never imports or executes target code (R7): every file is read as bytes, decoded, and parsed with the
standard-library `ast` module. Nothing from the scanned project is imported, compiled to bytecode or run.

Names
    Module names are dotted paths relative to the source root: `pkg/mod.py` -> `pkg.mod`,
    `pkg/__init__.py` -> `pkg`. When the root itself is a package (it has an `__init__.py` and its
    directory name is an identifier) that name prefixes every module (DECISIONS D-18).
    Qualified names follow lexical nesting: `pkg.mod.func`, `pkg.mod.Class.method`,
    `pkg.mod.outer.inner`.

Resolution
    `ProjectIndex.canonical(dotted)` follows imports, package `__init__` re-exports, star imports and
    module-level aliases to the qualname that defines a symbol. Names outside the project come back as
    their external dotted name (`os.system`, `flask.request`); builtins as `builtins.<name>`.
    `resolve_call(call, module_ctx)` resolves the callee of an `ast.Call`. Local variables, attributes
    of unknown objects and computed callees resolve to None: the index never guesses (DECISIONS D-19).
"""

from __future__ import annotations

import ast
import builtins
import io
import logging
import os
import sys
import tokenize
import warnings
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from functools import cached_property
from pathlib import Path
from typing import Optional, Union

from FlowStopper.sast.config import SastConfig

log = logging.getLogger(__name__)

FuncNode = Union[ast.FunctionDef, ast.AsyncFunctionDef]

BUILTIN_NAMES: frozenset[str] = frozenset(dir(builtins))
STDLIB_MODULES: frozenset[str] = frozenset(sys.stdlib_module_names)
_MAX_DEPTH = 16  # alias / re-export chains followed before giving up (cycle guard)


# --------------------------------------------------------------------------- AST helpers
def dotted_parts(expr: ast.AST) -> Optional[list[str]]:
    """`a.b.c` -> ["a", "b", "c"]; None unless the expression is a plain Name/Attribute chain."""
    parts: list[str] = []
    while isinstance(expr, ast.Attribute):
        parts.append(expr.attr)
        expr = expr.value
    if not isinstance(expr, ast.Name):
        return None
    parts.append(expr.id)
    parts.reverse()
    return parts


def dotted_name(expr: ast.AST) -> Optional[str]:
    """`a.b.c` -> "a.b.c"; None unless the expression is a plain Name/Attribute chain."""
    parts = dotted_parts(expr)
    return ".".join(parts) if parts else None


def decorator_name(expr: ast.expr) -> str:
    """Dotted callee of a decorator: `@app.route("/x")` -> "app.route", `@login_required` -> "login_required"."""
    target = expr.func if isinstance(expr, ast.Call) else expr
    return dotted_name(target) or ast.unparse(target)


def param_names(args: ast.arguments) -> list[str]:
    """Parameter names in declaration order (positional, *args, keyword-only, **kwargs)."""
    names = [a.arg for a in (*args.posonlyargs, *args.args)]
    if args.vararg:
        names.append(args.vararg.arg)
    names += [a.arg for a in args.kwonlyargs]
    if args.kwarg:
        names.append(args.kwarg.arg)
    return names


def child_blocks(stmt: ast.stmt) -> list[list[ast.stmt]]:
    """Statement lists nested inside a compound statement (def/class bodies are not included)."""
    if isinstance(stmt, (ast.If, ast.For, ast.AsyncFor, ast.While)):
        return [stmt.body, stmt.orelse]
    if isinstance(stmt, (ast.With, ast.AsyncWith)):
        return [stmt.body]
    if isinstance(stmt, (ast.Try, ast.TryStar)):
        return [stmt.body, *(h.body for h in stmt.handlers), stmt.orelse, stmt.finalbody]
    if isinstance(stmt, ast.Match):
        return [case.body for case in stmt.cases]
    return []


def iter_block(body: list[ast.stmt]) -> Iterator[ast.stmt]:
    """Yield the statements of a block and of its nested compound statements, without entering defs/classes."""
    for stmt in body:
        yield stmt
        for block in child_blocks(stmt):
            yield from iter_block(block)


def _last(dotted: str) -> str:
    return dotted.rsplit(".", 1)[-1]


# --------------------------------------------------------------------------- records
@dataclass
class SkippedFile:
    file: str  # POSIX path relative to the source root
    reason: str


@dataclass
class FunctionInfo:
    """A function, method or nested function defined in the project."""

    qualname: str
    name: str
    module: str
    file: str
    line_start: int  # the `def` line
    line_end: int  # last line of the body (end_lineno)
    params: list[str]
    decorators: list[str]  # dotted callee of each decorator, in source order
    node: FuncNode = field(repr=False)
    parent: Optional[str] = None  # qualname of the enclosing function or class; None at module level
    class_name: Optional[str] = None  # owning class for methods (direct children of a class body)
    is_async: bool = False
    # Scope facts used by name resolution (Python rule: a name bound anywhere in a function is local).
    local_names: frozenset[str] = frozenset()
    global_names: frozenset[str] = frozenset()
    local_imports: dict[str, str] = field(default_factory=dict, repr=False)  # local alias -> dotted target
    local_defs: dict[str, str] = field(default_factory=dict, repr=False)  # nested def/class -> qualname
    # `name = value` assignments in this function's own scope, in source order (value None = unknown)
    assignments: dict[str, list[Optional[ast.expr]]] = field(default_factory=dict, repr=False)

    @property
    def is_method(self) -> bool:
        return self.class_name is not None

    @property
    def is_staticmethod(self) -> bool:
        return any(_last(d) == "staticmethod" for d in self.decorators)

    @property
    def is_classmethod(self) -> bool:
        return any(_last(d) == "classmethod" for d in self.decorators)


@dataclass
class ClassInfo:
    qualname: str
    name: str
    module: str
    file: str
    line_start: int
    line_end: int
    decorators: list[str]
    node: ast.ClassDef = field(repr=False)
    parent: Optional[str] = None
    bases: list[str] = field(default_factory=list)  # canonical names (project or external); unresolvable omitted
    methods: dict[str, str] = field(default_factory=dict)  # name -> qualname (own methods only)
    nested_classes: dict[str, str] = field(default_factory=dict)
    attributes: dict[str, ast.expr] = field(default_factory=dict, repr=False)  # class-level NAME = value


@dataclass
class VariableInfo:
    """A module-level variable. `value` is the last assigned value (None = not statically known)."""

    qualname: str
    name: str
    module: str
    file: str
    line: int
    value: Optional[ast.expr] = field(default=None, repr=False)
    history: list[tuple[int, Optional[ast.expr]]] = field(default_factory=list, repr=False)


@dataclass
class ModuleInfo:
    name: str
    file: str
    is_package: bool
    tree: ast.Module = field(repr=False)
    source: str = field(repr=False)
    # top-level name -> (kind, target); kind is "import" | "function" | "class" | "var"
    bindings: dict[str, tuple[str, str]] = field(default_factory=dict, repr=False)
    star_imports: list[str] = field(default_factory=list)
    exports: Optional[frozenset[str]] = None  # literal __all__, when present and never modified

    @property
    def package(self) -> str:
        """The package relative imports start from."""
        return self.name if self.is_package else self.name.rpartition(".")[0]

    @cached_property
    def lines(self) -> list[str]:
        return self.source.splitlines()

    def exports_name(self, name: str) -> bool:
        if self.exports is not None:
            return name in self.exports
        return not name.startswith("_")


@dataclass(frozen=True, eq=False)
class ModuleContext:
    """What is needed to resolve a name: the index, the module, and optionally the enclosing function.

    `local_types` maps local variable names to the project class they hold an instance of (filled by the
    call graph's instantiation tracking, P1-A3).
    """

    index: ProjectIndex
    module: ModuleInfo
    scope: Optional[FunctionInfo] = None
    local_types: Optional[Mapping[str, str]] = None

    def resolve(self, expr: ast.AST) -> Optional[str]:
        return self.index.resolve_expr(expr, self.module, self.scope, self.local_types)


def resolve_call(node: ast.Call, module_ctx: ModuleContext) -> Optional[str]:
    """Qualified name of the callee of `node`, or None when it cannot be resolved statically (spec P1-A1)."""
    return module_ctx.index.resolve_call(node, module_ctx.module, module_ctx.scope, module_ctx.local_types)


# --------------------------------------------------------------------------- discovery + parsing
def discover_files(
    source_root: Path | str, config: Optional[SastConfig] = None
) -> tuple[list[Path], list[SkippedFile]]:
    """Python files under `source_root` (sorted by relative POSIX path) plus the files skipped on the way.

    Directories named in `config.exclude_dirs` are pruned at any depth; files larger than
    `config.max_file_bytes` and symlinks pointing outside the root are skipped.
    """
    cfg = config or SastConfig()
    root = Path(source_root).resolve()
    excluded = set(cfg.exclude_dirs)
    found: list[Path] = []
    skipped: list[SkippedFile] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d not in excluded)
        for fname in sorted(filenames):
            if not fname.endswith(".py"):
                continue
            path = Path(dirpath) / fname
            rel = path.relative_to(root).as_posix()
            if path.is_symlink() and not path.resolve().is_relative_to(root):
                skipped.append(_skip(rel, "symlink pointing outside the source root"))
                continue
            try:
                size = path.stat().st_size
            except OSError as exc:
                skipped.append(_skip(rel, f"unreadable: {exc.strerror or exc}"))
                continue
            if size > cfg.max_file_bytes:
                skipped.append(_skip(rel, f"larger than {cfg.max_file_bytes} bytes ({size} bytes)"))
                continue
            found.append(path)
    found.sort(key=lambda p: p.relative_to(root).as_posix())
    return found, skipped


def module_name(rel: str, root_package: Optional[str] = None) -> tuple[str, bool]:
    """Dotted module name for a relative POSIX path, and whether it is a package (`__init__.py`)."""
    parts = rel[: -len(".py")].split("/")
    is_package = parts[-1] == "__init__"
    if is_package:
        parts = parts[:-1]
    if root_package:
        parts = [root_package, *parts]
    if not parts:  # the root's own __init__.py when the root name is not usable as a package name
        return "__init__", False
    return ".".join(parts), is_package


def _skip(rel: str, reason: str) -> SkippedFile:
    log.warning("sast index: skipping %s (%s)", rel, reason)
    return SkippedFile(file=rel, reason=reason)


def _decode(raw: bytes) -> str:
    """Decode with the file's PEP 263 coding cookie / BOM; undecodable bytes become U+FFFD."""
    try:
        encoding, _ = tokenize.detect_encoding(io.BytesIO(raw).readline)
        return raw.decode(encoding, errors="replace")
    except (SyntaxError, LookupError):
        return raw.decode("utf-8", errors="replace")


def parse_source(source: str, filename: str) -> ast.Module:
    """`ast.parse` without the SyntaxWarning/DeprecationWarning noise old code produces. Parse only (R7)."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", SyntaxWarning)
        warnings.simplefilter("ignore", DeprecationWarning)
        return ast.parse(source, filename=filename)


def _parse_file(path: Path, rel: str) -> Union[tuple[str, ast.Module], SkippedFile]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        return _skip(rel, f"unreadable: {exc.strerror or exc}")
    source = _decode(raw)
    try:
        tree = parse_source(source, rel)
    except SyntaxError as exc:
        return _skip(rel, f"syntax error at line {exc.lineno}: {exc.msg}")
    except (ValueError, RecursionError, MemoryError) as exc:
        return _skip(rel, f"unparseable: {type(exc).__name__}")
    return source, tree


def build_index(source_root: Path | str, config: Optional[SastConfig] = None) -> ProjectIndex:
    """Discover, parse and index every Python file under `source_root` (parse only, never imported)."""
    cfg = config or SastConfig()
    root = Path(source_root).resolve()
    if not root.is_dir():
        raise NotADirectoryError(f"source root is not a directory: {source_root}")
    files, skipped = discover_files(root, cfg)
    index = ProjectIndex(root)
    index.files_discovered = len(files) + len(skipped)
    root_package = root.name if (root / "__init__.py").is_file() and root.name.isidentifier() else None
    for path in files:
        rel = path.relative_to(root).as_posix()
        parsed = _parse_file(path, rel)
        if isinstance(parsed, SkippedFile):
            skipped.append(parsed)
            continue
        source, tree = parsed
        name, is_package = module_name(rel, root_package)
        previous = index.modules.get(name)
        if previous is not None:
            # `pkg.py` next to `pkg/__init__.py`: Python imports the package, so the package wins.
            if previous.is_package or not is_package:
                skipped.append(_skip(rel, f"module name {name!r} already provided by {previous.file}"))
                continue
            skipped.append(_skip(previous.file, f"module name {name!r} already provided by {rel}"))
        index.modules[name] = ModuleInfo(name=name, file=rel, is_package=is_package, tree=tree, source=source)
    index.skipped = sorted(skipped, key=lambda s: s.file)
    index._finish()
    return index


# --------------------------------------------------------------------------- the index
class ProjectIndex:
    """Symbol table of one source tree. Build it with `build_index`."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.modules: dict[str, ModuleInfo] = {}
        self.functions: dict[str, FunctionInfo] = {}
        self.classes: dict[str, ClassInfo] = {}
        self.variables: dict[str, VariableInfo] = {}
        self.skipped: list[SkippedFile] = []
        self.files_discovered = 0
        self._packages: set[str] = set()  # dotted names of packages and namespace directories
        self._by_file: dict[str, ModuleInfo] = {}
        self._funcs_by_file: Optional[dict[str, list[FunctionInfo]]] = None

    # ------------------------------------------------------------------ building
    def _finish(self) -> None:
        for name, mod in self.modules.items():
            parts = name.split(".")
            self._packages.update(".".join(parts[:i]) for i in range(1, len(parts)))
            if mod.is_package:
                self._packages.add(name)
            self._by_file[mod.file] = mod
        for mod in list(self.modules.values()):
            _Collector(self, mod).collect()
        for cls in self.classes.values():
            scope = self._scope_of(cls.parent)
            bases = (self.resolve_expr(b, self.modules[cls.module], scope) for b in cls.node.bases)
            cls.bases = [b for b in bases if b is not None and b != cls.qualname]

    def _scope_of(self, parent: Optional[str]) -> Optional[FunctionInfo]:
        """Innermost function whose locals are visible from a definition with this parent."""
        while parent is not None:
            if parent in self.functions:
                return self.functions[parent]
            cls = self.classes.get(parent)
            if cls is None:
                return None
            parent = cls.parent
        return None

    def _is_project_module(self, name: str) -> bool:
        return name in self.modules or name in self._packages

    def _absolute_module(self, name: str, module: ModuleInfo) -> str:
        """Resolve an absolute import name: as written first, else relative to the importing file's packages.

        The fallback covers apps started from their own directory (`python app.py`, `flask run`), where
        sibling modules are imported as top-level names (DECISIONS D-18). Standard-library names never
        take the fallback, so `utils/email.py` does not shadow `import email`.
        """
        if not name or self._is_project_module(name) or name.split(".")[0] in STDLIB_MODULES:
            return name
        pkg = module.package.split(".") if module.package else []
        for k in range(len(pkg), 0, -1):
            candidate = ".".join([*pkg[:k], name])
            if self._is_project_module(candidate):
                return candidate
        return name

    def import_bindings(self, node: Union[ast.Import, ast.ImportFrom], module: ModuleInfo) -> list[tuple[str, str]]:
        """(local name, dotted target) pairs bound by an import statement; ("*", module) for star imports."""
        out: list[tuple[str, str]] = []
        if isinstance(node, ast.Import):
            for alias in node.names:
                target = self._absolute_module(alias.name, module)
                if alias.asname:
                    out.append((alias.asname, target))
                else:  # `import a.b.c` binds `a`
                    head = alias.name.split(".")[0]
                    prefix = target[: len(target) - len(alias.name)] if target.endswith(alias.name) else ""
                    out.append((head, prefix + head))
            return out
        if node.level:
            base = _relative_base(module, node.level, node.module)
            if base is None:
                return out
        else:
            base = self._absolute_module(node.module or "", module)
        for alias in node.names:
            if alias.name == "*":
                out.append(("*", base))
            else:
                out.append((alias.asname or alias.name, f"{base}.{alias.name}" if base else alias.name))
        return out

    # ------------------------------------------------------------------ lookups
    def module_for_file(self, file: str) -> Optional[ModuleInfo]:
        return self._by_file.get(file)

    def context(
        self,
        module: Union[str, ModuleInfo],
        scope: Union[None, str, FunctionInfo] = None,
        local_types: Optional[Mapping[str, str]] = None,
    ) -> ModuleContext:
        mod = self.modules[module] if isinstance(module, str) else module
        fn = self.functions[scope] if isinstance(scope, str) else scope
        return ModuleContext(index=self, module=mod, scope=fn, local_types=local_types)

    def is_project_symbol(self, qualname: Optional[str]) -> bool:
        return qualname is not None and (
            qualname in self.functions or qualname in self.classes or qualname in self.variables
        )

    def function_at(self, file: str, line: int) -> Optional[FunctionInfo]:
        """Innermost project function whose `def`..end span contains `line`."""
        if self._funcs_by_file is None:
            by_file: dict[str, list[FunctionInfo]] = {}
            for fn in self.functions.values():
                by_file.setdefault(fn.file, []).append(fn)
            self._funcs_by_file = by_file
        best: Optional[FunctionInfo] = None
        for fn in self._funcs_by_file.get(file, []):
            if fn.line_start <= line <= fn.line_end and (
                best is None or fn.line_end - fn.line_start < best.line_end - best.line_start
            ):
                best = fn
        return best

    def enclosing_function(self, fn: FunctionInfo) -> Optional[FunctionInfo]:
        """The function whose locals `fn` can see as free variables (class bodies are skipped)."""
        return self._scope_of(fn.parent)

    def mro(self, class_qualname: str) -> list[str]:
        """Project classes in method-resolution order (depth-first, left to right, no repeats)."""
        out: list[str] = []
        stack = [class_qualname]
        while stack:
            current = stack.pop()
            if current in out or current not in self.classes:
                continue
            out.append(current)
            stack.extend(reversed(self.classes[current].bases))
        return out

    def ancestors(self, class_qualname: str) -> list[str]:
        """Every base class name, project and external, of a project class (excluding itself), sorted."""
        out: set[str] = set()
        for cls in self.mro(class_qualname):
            out.update(self.classes[cls].bases)
        out.discard(class_qualname)
        return sorted(out)

    def find_member(self, class_qualname: str, name: str) -> Optional[str]:
        """Qualname of method or nested class `name` on a project class, searching project base classes."""
        for cls in self.mro(class_qualname):
            info = self.classes[cls]
            if name in info.methods:
                return info.methods[name]
            if name in info.nested_classes:
                return info.nested_classes[name]
        return None

    def find_method(self, class_qualname: str, name: str) -> Optional[str]:
        member = self.find_member(class_qualname, name)
        return member if member in self.functions else None

    def call_target(
        self, value: Optional[ast.expr], module: Union[str, ModuleInfo], scope: Optional[FunctionInfo] = None
    ) -> Optional[str]:
        """Canonical callee when `value` is a call expression (e.g. `Blueprint(...)` -> `flask.Blueprint`)."""
        if not isinstance(value, ast.Call):
            return None
        return self.resolve_expr(value.func, module, scope)

    # ------------------------------------------------------------------ resolution
    def canonical(self, dotted: str) -> Optional[str]:
        """Follow imports/re-exports/aliases to the defining qualname; external names are returned as is.

        None means the name points into the project but nothing defines it.
        """
        return self._canonical(dotted, 0)

    def resolve_call(
        self,
        node: ast.Call,
        module: Union[str, ModuleInfo],
        scope: Optional[FunctionInfo] = None,
        local_types: Optional[Mapping[str, str]] = None,
    ) -> Optional[str]:
        return self.resolve_expr(node.func, module, scope, local_types)

    def resolve_expr(
        self,
        expr: ast.AST,
        module: Union[str, ModuleInfo],
        scope: Optional[FunctionInfo] = None,
        local_types: Optional[Mapping[str, str]] = None,
    ) -> Optional[str]:
        """Canonical name of a Name/Attribute chain as seen from `scope` (a function) in `module`."""
        mod = self.modules[module] if isinstance(module, str) else module
        parts = dotted_parts(expr)
        if parts is None:
            return self._resolve_on_call(expr, mod, scope, local_types)
        name, tail = parts[0], parts[1:]
        fn, innermost = scope, True
        while fn is not None:
            if name in fn.global_names:
                break
            if name in fn.local_names:
                return self._resolve_local(fn, name, tail, local_types if innermost else None)
            fn, innermost = self.enclosing_function(fn), False
        return self._member(mod, parts, 0, unqualified=True)

    def _resolve_local(
        self, fn: FunctionInfo, name: str, tail: list[str], local_types: Optional[Mapping[str, str]]
    ) -> Optional[str]:
        if name in fn.local_imports:
            return self._canonical(".".join([fn.local_imports[name], *tail]), 1)
        if name in fn.local_defs:
            target = fn.local_defs[name]
            if target in self.classes:
                return self._class_member(target, tail, 1)
            return None if tail else target
        if local_types and name in local_types:
            return self._instance_member(local_types[name], tail, 1)
        if fn.class_name and fn.params and name == fn.params[0] and not fn.is_staticmethod:
            if fn.is_classmethod:
                return self._class_member(fn.class_name, tail, 1)
            return self._instance_member(fn.class_name, tail, 1)
        return None  # an ordinary local variable: its value is not known statically

    def _resolve_on_call(
        self, expr: ast.AST, mod: ModuleInfo, scope: Optional[FunctionInfo], local_types: Optional[Mapping[str, str]]
    ) -> Optional[str]:
        """`super().name` and `ProjectClass(...).name`; any other computed expression is unresolvable."""
        if not (isinstance(expr, ast.Attribute) and isinstance(expr.value, ast.Call)):
            return None
        call = expr.value
        if isinstance(call.func, ast.Name) and call.func.id == "super":
            return self._resolve_super(expr.attr, scope)
        callee = self.resolve_expr(call.func, mod, scope, local_types)
        if callee in self.classes:
            return self._instance_member(callee, [expr.attr], 1)
        return None

    def _resolve_super(self, attr: str, scope: Optional[FunctionInfo]) -> Optional[str]:
        """`super().attr` inside a method -> the first project base class defining `attr`."""
        owner = scope
        while owner is not None and owner.class_name is None:  # super() in a closure inside a method
            owner = self.enclosing_function(owner)
        if owner is None or owner.class_name is None:
            return None
        for cls in self.mro(owner.class_name)[1:]:
            info = self.classes[cls]
            if attr in info.methods:
                return info.methods[attr]
        return None

    def _canonical(self, dotted: str, depth: int) -> Optional[str]:
        if depth > _MAX_DEPTH or not dotted:
            return None
        parts = dotted.split(".")
        for i in range(len(parts), 0, -1):
            mod = self.modules.get(".".join(parts[:i]))
            if mod is not None:
                return self._member(mod, parts[i:], depth)
        if parts[0] in self._packages:
            return None  # inside a project namespace package but not defined anywhere we parsed
        return dotted

    def _member(self, mod: ModuleInfo, rest: list[str], depth: int, *, unqualified: bool = False) -> Optional[str]:
        """Resolve `rest` (name + attribute tail) inside `mod`. `unqualified` enables builtins (bare names)."""
        if depth > _MAX_DEPTH:
            return None
        if not rest:
            return mod.name
        name, tail = rest[0], rest[1:]
        binding = mod.bindings.get(name)
        if binding is None:
            if mod.is_package and self._is_project_module(f"{mod.name}.{name}"):
                return self._canonical(".".join([mod.name, *rest]), depth + 1)  # submodule as an attribute
            for star in mod.star_imports:
                star_mod = self.modules.get(star)
                if star_mod is not None and star_mod.exports_name(name):
                    found = self._member(star_mod, rest, depth + 1)
                    if found is not None:
                        return found
            if unqualified and name in BUILTIN_NAMES:
                return ".".join(["builtins", *rest])
            external = [s for s in mod.star_imports if not self._is_project_module(s)]
            if len(external) == 1:  # a bare name can then only come from that star import (or be a NameError)
                return ".".join([external[0], *rest])
            return None
        kind, target = binding
        if kind == "import":
            return self._canonical(".".join([target, *tail]), depth + 1)
        if kind == "function":
            return None if tail else target
        if kind == "class":
            return self._class_member(target, tail, depth + 1)
        var = self.variables.get(target)
        if var is None:
            return None if tail else target
        alias = dotted_parts(var.value) if var.value is not None else None
        if alias is not None:  # NAME = other.name: follow the alias
            resolved = self._member(self.modules[var.module], alias, depth + 1, unqualified=True)
            if resolved is not None:
                return self._canonical(".".join([resolved, *tail]), depth + 1) if tail else resolved
        if not tail:
            return target
        cls = self._instance_class(var, depth + 1)
        return self._instance_member(cls, tail, depth + 1) if cls else None

    def _instance_class(self, var: VariableInfo, depth: int) -> Optional[str]:
        """Project class a module-level variable holds an instance of (`svc = Service()`)."""
        if not isinstance(var.value, ast.Call):
            return None
        parts = dotted_parts(var.value.func)
        if parts is None:
            return None
        callee = self._member(self.modules[var.module], parts, depth + 1, unqualified=True)
        return callee if callee in self.classes else None

    def _class_member(self, class_qualname: str, tail: list[str], depth: int) -> Optional[str]:
        if not tail:
            return class_qualname
        if depth > _MAX_DEPTH:
            return None
        member = self.find_member(class_qualname, tail[0])
        if member is None:
            return None
        if member in self.classes:
            return self._class_member(member, tail[1:], depth + 1)
        return member if len(tail) == 1 else None

    def _instance_member(self, class_qualname: str, tail: list[str], depth: int) -> Optional[str]:
        """Attribute access on an instance of a project class (methods and nested classes)."""
        if not tail:
            return None  # the instance itself is a value, not a symbol
        return self._class_member(class_qualname, tail, depth)

    # ------------------------------------------------------------------ reporting
    def stats(self) -> dict:
        return {
            "files_discovered": self.files_discovered,
            "files_parsed": len(self.modules),
            "files_skipped": len(self.skipped),
            "skipped": [{"file": s.file, "reason": s.reason} for s in self.skipped],
            "functions": len(self.functions),
            "classes": len(self.classes),
        }


def _relative_base(module: ModuleInfo, level: int, name: Optional[str]) -> Optional[str]:
    """Absolute base of `from <level dots><name> import ...`; None if it climbs above the source root."""
    pkg = module.package.split(".") if module.package else []
    up = level - 1
    if up > len(pkg):
        return None
    parts = pkg[: len(pkg) - up]
    if name:
        parts = [*parts, *name.split(".")]
    return ".".join(parts)


# --------------------------------------------------------------------------- per-module collection
class _Collector:
    """Fills the index with one module's bindings, functions, classes and variables."""

    def __init__(self, index: ProjectIndex, module: ModuleInfo) -> None:
        self.ix = index
        self.mod = module

    def collect(self) -> None:
        self._block(self.mod.tree.body, override=True)
        var = self.ix.variables.get(f"{self.mod.name}.__all__")
        if var is not None and len(var.history) == 1 and isinstance(var.value, (ast.List, ast.Tuple)):
            names = [e.value for e in var.value.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)]
            if len(names) == len(var.value.elts):
                self.mod.exports = frozenset(names)

    # ---- module level
    def _bind(self, name: str, kind: str, target: str, override: bool) -> None:
        if override or name not in self.mod.bindings:
            self.mod.bindings[name] = (kind, target)

    def _block(self, body: list[ast.stmt], override: bool) -> None:
        for stmt in body:
            self._stmt(stmt, override)

    def _stmt(self, stmt: ast.stmt, override: bool) -> None:
        if isinstance(stmt, (ast.Import, ast.ImportFrom)):
            for name, target in self.ix.import_bindings(stmt, self.mod):
                if name != "*":
                    self._bind(name, "import", target, override)
                elif target not in self.mod.star_imports:
                    self.mod.star_imports.append(target)
        elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            fn = self._function(stmt, prefix=self.mod.name, parent=None, class_name=None)
            self._bind(stmt.name, "function", fn.qualname, override)
        elif isinstance(stmt, ast.ClassDef):
            cls = self._class(stmt, prefix=self.mod.name, parent=None)
            self._bind(stmt.name, "class", cls.qualname, override)
        elif isinstance(stmt, ast.Assign):
            for target in stmt.targets:
                self._store(target, stmt.value, stmt.lineno, override)
        elif isinstance(stmt, ast.AnnAssign):
            if stmt.value is not None:
                self._store(stmt.target, stmt.value, stmt.lineno, override)
        elif isinstance(stmt, ast.AugAssign):
            if isinstance(stmt.target, ast.Name):
                var = self.ix.variables.get(f"{self.mod.name}.{stmt.target.id}")
                if var is not None:  # value after `+=` is unknown; keep the original for allow-list checks
                    var.history.append((stmt.lineno, None))
                else:
                    self._var(stmt.target.id, None, stmt.lineno, override)
        elif isinstance(stmt, (ast.For, ast.AsyncFor)):
            self._store(stmt.target, None, stmt.lineno, override)
            self._block(stmt.body, override)
            self._block(stmt.orelse, override)
        elif isinstance(stmt, (ast.With, ast.AsyncWith)):
            for item in stmt.items:
                if item.optional_vars is not None:
                    self._store(item.optional_vars, None, stmt.lineno, override)
            self._block(stmt.body, override)
        elif isinstance(stmt, (ast.Try, ast.TryStar)):
            self._block(stmt.body, override)
            for handler in stmt.handlers:  # fallback imports/defs never shadow the try-body ones
                self._block(handler.body, override=False)
            self._block(stmt.orelse, override)
            self._block(stmt.finalbody, override)
        else:
            for block in child_blocks(stmt):  # if / while / match
                self._block(block, override)

    def _store(self, target: ast.expr, value: Optional[ast.expr], line: int, override: bool) -> None:
        if isinstance(target, ast.Name):
            self._var(target.id, value, line, override)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for elt, elt_value in zip(target.elts, _unpack(target, value), strict=True):
                self._store(elt, elt_value, line, override)
        elif isinstance(target, ast.Starred):
            self._store(target.value, None, line, override)

    def _var(self, name: str, value: Optional[ast.expr], line: int, override: bool) -> None:
        if not override and name in self.mod.bindings:
            return
        qualname = f"{self.mod.name}.{name}"
        var = self.ix.variables.get(qualname)
        if var is None:
            var = VariableInfo(qualname=qualname, name=name, module=self.mod.name, file=self.mod.file, line=line)
            self.ix.variables[qualname] = var
        var.line, var.value = line, value
        var.history.append((line, value))
        self._bind(name, "var", qualname, override)

    # ---- definitions
    def _function(self, node: FuncNode, prefix: str, parent: Optional[str], class_name: Optional[str]) -> FunctionInfo:
        qualname = f"{prefix}.{node.name}"
        scope = _ScopeScanner(self.ix, self.mod).scan(node)
        info = FunctionInfo(
            qualname=qualname,
            name=node.name,
            module=self.mod.name,
            file=self.mod.file,
            line_start=node.lineno,
            line_end=node.end_lineno or node.lineno,
            params=param_names(node.args),
            decorators=[decorator_name(d) for d in node.decorator_list],
            node=node,
            parent=parent,
            class_name=class_name,
            is_async=isinstance(node, ast.AsyncFunctionDef),
            local_names=frozenset(scope.bound - scope.globals - scope.nonlocals),
            global_names=frozenset(scope.globals),
            local_imports=scope.imports,
            assignments=scope.assignments,
        )
        self.ix.functions[qualname] = info
        for child in iter_block(node.body):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                info.local_defs[child.name] = self._function(child, qualname, qualname, None).qualname
            elif isinstance(child, ast.ClassDef):
                info.local_defs[child.name] = self._class(child, qualname, qualname).qualname
        return info

    def _class(self, node: ast.ClassDef, prefix: str, parent: Optional[str]) -> ClassInfo:
        qualname = f"{prefix}.{node.name}"
        info = ClassInfo(
            qualname=qualname,
            name=node.name,
            module=self.mod.name,
            file=self.mod.file,
            line_start=node.lineno,
            line_end=node.end_lineno or node.lineno,
            decorators=[decorator_name(d) for d in node.decorator_list],
            node=node,
            parent=parent,
        )
        self.ix.classes[qualname] = info
        for child in iter_block(node.body):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                info.methods[child.name] = self._function(child, qualname, qualname, qualname).qualname
            elif isinstance(child, ast.ClassDef):
                info.nested_classes[child.name] = self._class(child, qualname, qualname).qualname
            elif isinstance(child, ast.Assign):
                for target in child.targets:
                    if isinstance(target, ast.Name):
                        info.attributes[target.id] = child.value
            elif isinstance(child, ast.AnnAssign) and isinstance(child.target, ast.Name) and child.value is not None:
                info.attributes[child.target.id] = child.value
        return info


def _unpack(target: Union[ast.Tuple, ast.List], value: Optional[ast.expr]) -> list[Optional[ast.expr]]:
    """Per-element values for `a, b = x, y`; unknown (None) unless both sides line up without starred items."""
    if (
        isinstance(value, (ast.Tuple, ast.List))
        and len(value.elts) == len(target.elts)
        and not any(isinstance(e, ast.Starred) for e in (*target.elts, *value.elts))
    ):
        return list(value.elts)
    return [None] * len(target.elts)


class _ScopeScanner(ast.NodeVisitor):
    """Names a function binds locally (params, assignments, imports, nested defs...), plus global/nonlocal.

    Nested function, lambda, class and comprehension bodies are separate scopes and are not entered.
    """

    def __init__(self, index: ProjectIndex, module: ModuleInfo) -> None:
        self.ix = index
        self.mod = module
        self.bound: set[str] = set()
        self.globals: set[str] = set()
        self.nonlocals: set[str] = set()
        self.imports: dict[str, str] = {}
        self.assignments: dict[str, list[Optional[ast.expr]]] = {}

    def scan(self, node: FuncNode) -> _ScopeScanner:
        self.bound.update(param_names(node.args))
        for stmt in node.body:
            self.visit(stmt)
        return self

    def _defaults(self, args: ast.arguments) -> None:
        for default in (*args.defaults, *(d for d in args.kw_defaults if d is not None)):
            self.visit(default)

    def _record(self, target: ast.expr, value: Optional[ast.expr]) -> None:
        if isinstance(target, ast.Name):
            self.assignments.setdefault(target.id, []).append(value)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for elt, elt_value in zip(target.elts, _unpack(target, value), strict=True):
                self._record(elt, elt_value)
        elif isinstance(target, ast.Starred):
            self._record(target.value, None)

    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            self._record(target, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            self._record(node.target, node.value)
        self.generic_visit(node)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        self._record(node.target, None)
        self.generic_visit(node)

    def visit_For(self, node: ast.For) -> None:
        self._record(node.target, None)
        self.generic_visit(node)

    visit_AsyncFor = visit_For

    def visit_withitem(self, node: ast.withitem) -> None:
        if node.optional_vars is not None:
            self._record(node.optional_vars, None)
        self.generic_visit(node)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
        self._record(node.target, node.value)
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.bound.add(node.name)
        for deco in node.decorator_list:
            self.visit(deco)
        self._defaults(node.args)

    visit_AsyncFunctionDef = visit_FunctionDef  # type: ignore[assignment]

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.bound.add(node.name)
        for expr in (*node.bases, *(k.value for k in node.keywords), *node.decorator_list):
            self.visit(expr)

    def visit_Lambda(self, node: ast.Lambda) -> None:
        self._defaults(node.args)

    def _comprehension(self, node: Union[ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp]) -> None:
        if node.generators:  # only the first iterable is evaluated in the enclosing scope
            self.visit(node.generators[0].iter)

    visit_ListComp = visit_SetComp = visit_GeneratorExp = visit_DictComp = _comprehension

    def visit_Global(self, node: ast.Global) -> None:
        self.globals.update(node.names)

    def visit_Nonlocal(self, node: ast.Nonlocal) -> None:
        self.nonlocals.update(node.names)

    def visit_Name(self, node: ast.Name) -> None:
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            self.bound.add(node.id)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        if node.name:
            self.bound.add(node.name)
        self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> None:
        self._imports(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        self._imports(node)

    def _imports(self, node: Union[ast.Import, ast.ImportFrom]) -> None:
        for name, target in self.ix.import_bindings(node, self.mod):
            if name != "*":
                self.bound.add(name)
                self.imports[name] = target

    def visit_MatchAs(self, node: ast.MatchAs) -> None:
        if node.name:
            self.bound.add(node.name)
        self.generic_visit(node)

    def visit_MatchStar(self, node: ast.MatchStar) -> None:
        if node.name:
            self.bound.add(node.name)

    def visit_MatchMapping(self, node: ast.MatchMapping) -> None:
        if node.rest:
            self.bound.add(node.rest)
        self.generic_visit(node)
