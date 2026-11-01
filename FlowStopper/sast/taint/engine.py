"""Intraprocedural taint (Owner: A, P2-A1).

Abstract value
    `TaintValue(labels, is_constant_string, built, html_markup)`. An empty `labels` set means
    untainted; `is_constant_string` keeps parameterised SQL recognisable as safe; `built` records
    how a string was assembled (f-string, concatenation, `%`, `.format`, `.join`), which names the
    rule; `html_markup` says a constant part of the string contained markup.
    A `TaintLabel` is either a *request* label (an HTTP parameter read, projected to
    `(file, line, function)` so labels stay hashable and deterministic - DECISIONS A-06) or a
    *param* label (formal parameter `i` of the function being summarised, P2-A2). Clearance is
    per CWE (A-07), so `html.escape` hides nothing but XSS.

Walk
    `walk_function` runs one function body in statement order over `env: dict[str, TaintValue]`,
    joining environments after `if/else`, `try` and loops (loops are re-analysed
    `config.taint_loop_iterations` times, A-17), and reports every sink a tainted value reaches.
    Guards clear per A-11: the `if` body sees the guard as true, the `else` branch and the
    fall-through after an early `return/raise/abort` see it as false.

Calls to project functions are handed to the driver's `hook` (P2-A2 summaries); unknown external
calls propagate taint from any argument to the result unless the callee is a sanitiser, a safe
response wrapper or a sink (sink results are barriers, A-09). Nothing is imported or executed: the
walk only reads the AST the index already parsed (R7).
"""

from __future__ import annotations

import ast
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, replace
from typing import Optional

from FlowStopper.models import ParamLocation
from FlowStopper.sast import suppress
from FlowStopper.sast.config import SastConfig
from FlowStopper.sast.index import FunctionInfo, ModuleContext
from FlowStopper.sast.routes.resolver import const_str
from FlowStopper.sast.taint import sanitizers, sinks
from FlowStopper.sast.taint.sources import SourceRef, request_source
from FlowStopper.sast.templates import TemplateLookup

ALL_CWES = sanitizers.ALL_CWES

REQUEST = "request"  # label kind: an HTTP parameter read
PARAM = "param"  # label kind: formal parameter of the summarised function

# Methods that return a value derived from their receiver (string handling, containers).
PROPAGATOR_METHODS: frozenset[str] = frozenset(
    {
        "strip",
        "lstrip",
        "rstrip",
        "lower",
        "upper",
        "title",
        "capitalize",
        "casefold",
        "swapcase",
        "replace",
        "encode",
        "decode",
        "split",
        "rsplit",
        "splitlines",
        "partition",
        "rpartition",
        "removeprefix",
        "removesuffix",
        "center",
        "ljust",
        "rjust",
        "zfill",
        "expandtabs",
        "copy",
        "to_dict",
    }
)
CONTAINER_GETTERS: frozenset[str] = frozenset({"get", "getlist", "getall", "pop", "setdefault"})
STRING_CASTS: frozenset[str] = frozenset({"builtins.str", "builtins.bytes", "builtins.repr", "builtins.format"})
# Calls after which the rest of a block is unreachable, by resolved name only (DECISIONS A-40).
_ABORT_FUNCTIONS: frozenset[str] = frozenset(
    {
        "flask.abort",
        "flask.helpers.abort",
        "werkzeug.exceptions.abort",
        "sys.exit",
        "builtins.exit",
        "builtins.quit",
        "os._exit",
        "os.abort",
    }
)


@dataclass(frozen=True)
class TaintLabel:
    """One taint origin. `kind` is `REQUEST` (an HTTP parameter) or `PARAM` (a formal parameter)."""

    kind: str
    file: str
    line: int
    function: Optional[str] = None
    param_name: Optional[str] = None  # HTTP parameter name; None for a whole container (A-15)
    location_kind: Optional[ParamLocation] = None
    param_index: Optional[int] = None
    is_container: bool = False
    cleared: frozenset[int] = frozenset()
    sanitizers: tuple[str, ...] = ()

    @property
    def sort_key(self) -> tuple[int, str, int, str]:
        """Earliest-read order (DECISIONS A-12): source line, then file, then named before unnamed."""
        return (self.line, self.file, 0 if self.param_name else 1, self.param_name or "")

    def carry(self, cleared: frozenset[int], seen: tuple[str, ...]) -> TaintLabel:
        """This label after flowing through a callee that cleared `cleared` and applied `seen`."""
        if not cleared and not seen:
            return self
        return replace(self, cleared=self.cleared | cleared, sanitizers=_merge_names(self.sanitizers, seen))

    def refine(self, member: str) -> TaintLabel:
        """A container label narrowed to one member (`request.args` -> `request.args["q"]`), A-15."""
        return replace(self, param_name=member, is_container=False) if self.is_container else self


@dataclass(frozen=True)
class TaintValue:
    """Taint of one expression."""

    labels: frozenset[TaintLabel] = frozenset()
    is_constant_string: bool = False
    built: frozenset[str] = frozenset()
    html_markup: bool = False

    @property
    def tainted(self) -> bool:
        return bool(self.labels)

    def tainted_for(self, cwe: int) -> frozenset[TaintLabel]:
        """Labels still dangerous for `cwe` (A-07)."""
        return frozenset(label for label in self.labels if cwe not in label.cleared)

    def union(self, other: TaintValue) -> TaintValue:
        return TaintValue(
            labels=self.labels | other.labels,
            is_constant_string=self.is_constant_string and other.is_constant_string,
            built=self.built | other.built,
            html_markup=self.html_markup or other.html_markup,
        )

    def with_built(self, kind: Optional[str]) -> TaintValue:
        if kind is None or kind in self.built:
            return self
        return replace(self, built=self.built | {kind})

    def sanitize(self, name: str, cwes: frozenset[int]) -> TaintValue:
        if not self.labels:
            return self
        return replace(self, labels=frozenset(label.carry(cwes, (name,)) for label in self.labels))

    def refine(self, member: Optional[str]) -> TaintValue:
        if member is None or not self.labels:
            return self
        return replace(self, labels=frozenset(label.refine(member) for label in self.labels))

    def carry(self, cleared: frozenset[int], seen: tuple[str, ...]) -> TaintValue:
        if not self.labels:
            return self
        return replace(self, labels=frozenset(label.carry(cleared, seen) for label in self.labels))


UNTAINTED = TaintValue()
CONSTANT_STRING = TaintValue(is_constant_string=True)
TaintEnv = dict[str, TaintValue]


@dataclass(frozen=True)
class SinkReport:
    """A tainted value reaching a sink. `chain` runs from the walked function down to the sink."""

    cwe: int
    family: str
    token: str
    file: str
    line_start: int
    line_end: int
    function: Optional[str]
    chain: tuple[str, ...]
    labels: frozenset[TaintLabel]
    built: frozenset[str] = frozenset()
    html_markup: bool = False
    suppressed: bool = False
    suppress_reason: Optional[str] = None

    @property
    def rule_id(self) -> str:
        return sinks.rule_id(self.family, self.token, self.built)

    @property
    def title(self) -> str:
        return sinks.sink_title(self.family, self.token, self.built, self.suppress_reason)

    @property
    def sanitizers_seen(self) -> tuple[str, ...]:
        out: tuple[str, ...] = ()
        for label in sorted(self.labels, key=lambda lbl: lbl.sort_key):
            out = _merge_names(out, label.sanitizers)
        return out

    @property
    def dedupe_key(self) -> tuple:
        return (
            self.file,
            self.line_start,
            self.cwe,
            self.family,
            self.token,
            self.suppressed,
            tuple(sorted(self.built)),
            tuple(sorted(label.sort_key + (label.kind,) for label in self.labels)),
        )


@dataclass(frozen=True)
class CallSite:
    """A call to a project function, as the driver sees it."""

    call: ast.Call
    callee: str
    receiver: TaintValue
    args: tuple[TaintValue, ...]
    kwargs: Mapping[str, TaintValue]
    caller: str
    line: int


@dataclass(frozen=True)
class CallEffect:
    """What the driver says a project call does: its result, plus sinks reached inside it."""

    value: TaintValue = UNTAINTED
    reports: tuple[SinkReport, ...] = ()


CallHook = Callable[[CallSite], Optional[CallEffect]]


@dataclass
class WalkResult:
    env: TaintEnv
    returned: TaintValue
    reports: tuple[SinkReport, ...]
    derived_from: dict[str, frozenset[str]] = field(default_factory=dict)


def walk_function(
    ctx: ModuleContext,
    fn: FunctionInfo,
    env: Optional[TaintEnv] = None,
    config: Optional[SastConfig] = None,
    *,
    hook: Optional[CallHook] = None,
    is_handler: bool = False,
    templates: Optional[TemplateLookup] = None,
) -> WalkResult:
    """Walk `fn`'s body once with `env` as the entry environment (P2-A1).

    `hook` is asked about every call to a project function (P2-A2 applies callee summaries there).
    `is_handler` turns the function's return value into the CWE-79 response sink. `templates` is the
    P2-A5 index: with it, a render call's unescaped keyword arguments become CWE-79 sinks.
    """
    walk = _FunctionWalk(ctx, fn, config or SastConfig(), hook=hook, is_handler=is_handler, templates=templates)
    return walk.run(dict(env or {}))


def source_value(ref: SourceRef, file: str, line: int, function: Optional[str]) -> TaintValue:
    """A fresh request label for one source read."""
    label = TaintLabel(
        kind=REQUEST,
        file=file,
        line=line,
        function=function,
        param_name=ref.param_name,
        location_kind=ref.location_kind,
        is_container=ref.is_container,
        cleared=ref.cleared,
    )
    return TaintValue(labels=frozenset({label}))


def param_seed(fn: FunctionInfo) -> TaintEnv:
    """Environment that taints every formal parameter of `fn`, for the parametric summary pass."""
    return {
        name: TaintValue(
            labels=frozenset(
                {TaintLabel(kind=PARAM, file=fn.file, line=fn.line_start, function=fn.qualname, param_index=index)}
            )
        )
        for index, name in enumerate(fn.params)
    }


def join_envs(left: TaintEnv, right: TaintEnv) -> TaintEnv:
    """Union of two branch environments (A-17)."""
    out = dict(left)
    for name, value in right.items():
        current = out.get(name)
        out[name] = value if current is None else current.union(value)
    return out


# --------------------------------------------------------------------------- the walk
class _FunctionWalk:
    """Statement-order walk of one function body. Build it through `walk_function`."""

    def __init__(
        self,
        ctx: ModuleContext,
        fn: FunctionInfo,
        config: SastConfig,
        *,
        hook: Optional[CallHook],
        is_handler: bool,
        templates: Optional[TemplateLookup] = None,
    ) -> None:
        self.ctx = ctx
        self.fn = fn
        self.cfg = config
        self.hook = hook
        self.is_handler = is_handler
        self.templates = templates
        self.reports: list[SinkReport] = []
        self.derived: dict[str, frozenset[str]] = {}
        self.returned: Optional[TaintValue] = None  # None until the first `return`, so `"x"` stays constant
        self._seen: set[tuple] = set()
        self._safe_responses: set[int] = set()  # ids of response calls given a safe content type later (A-38)

    def run(self, env: TaintEnv) -> WalkResult:
        out, _ = self._block(self.fn.node.body, env)
        return WalkResult(
            env=out,
            returned=self.returned if self.returned is not None else UNTAINTED,
            reports=tuple(self.reports),
            derived_from=dict(self.derived),
        )

    # ------------------------------------------------------------------ statements
    def _block(self, body: list[ast.stmt], env: TaintEnv) -> tuple[TaintEnv, bool]:
        for i, stmt in enumerate(body):
            if self._is_retyped_response(stmt, body[i + 1 :]):
                self._safe_responses.add(id(stmt.value))
            env, exits = self._stmt(stmt, env)
            if exits:
                return env, True
        return env, False

    def _is_retyped_response(self, stmt: ast.stmt, rest: list[ast.stmt]) -> bool:
        """`resp = Response(...)` whose following straight-line statements set a safe content type (A-38)."""
        if not (isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name)):
            return False
        if not isinstance(stmt.value, ast.Call) or sinks.sink_at(stmt.value, self.ctx) is not sinks.HTML_RESPONSE:
            return False
        return sinks.later_safe_content_type(rest, stmt.targets[0].id)

    def _stmt(self, stmt: ast.stmt, env: TaintEnv) -> tuple[TaintEnv, bool]:
        if isinstance(stmt, ast.Assign):
            value = self._expr(stmt.value, env)
            for target in stmt.targets:
                self._assign(target, value, env, stmt.value)
            return env, False
        if isinstance(stmt, ast.AnnAssign):
            if stmt.value is not None:
                self._assign(stmt.target, self._expr(stmt.value, env), env, stmt.value)
            return env, False
        if isinstance(stmt, ast.AugAssign):
            value = self._expr(stmt.value, env)
            if isinstance(stmt.target, ast.Name):
                current = env.get(stmt.target.id, UNTAINTED)
                env[stmt.target.id] = current.union(value).with_built(_binop_kind(stmt.op))
                self._record_derived(stmt.target.id, stmt.value)
            else:
                self._assign(stmt.target, value, env, stmt.value)
            return env, False
        if isinstance(stmt, ast.Return):
            value = self._expr(stmt.value, env) if stmt.value is not None else UNTAINTED
            self.returned = value if self.returned is None else self.returned.union(value)
            if self.is_handler:
                self._response_sink(value, stmt)
            return env, True
        if isinstance(stmt, ast.Expr):
            self._expr(stmt.value, env)
            return env, self._is_abort(stmt.value)
        if isinstance(stmt, ast.If):
            return self._if(stmt, env)
        if isinstance(stmt, (ast.For, ast.AsyncFor)):
            return self._for(stmt, env)
        if isinstance(stmt, ast.While):
            return self._while(stmt, env)
        if isinstance(stmt, (ast.With, ast.AsyncWith)):
            return self._with(stmt, env)
        if isinstance(stmt, (ast.Try, ast.TryStar)):
            return self._try(stmt, env)
        if isinstance(stmt, ast.Match):
            return self._match(stmt, env)
        if isinstance(stmt, ast.Raise):
            for node in (stmt.exc, stmt.cause):
                if node is not None:
                    self._expr(node, env)
            return env, True
        if isinstance(stmt, (ast.Break, ast.Continue)):
            return env, True
        if isinstance(stmt, ast.Assert):
            self._expr(stmt.test, env)
            return self._apply_guards(env, stmt.test, negated=False), False
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            return env, False  # a separate scope: summarised on its own
        if isinstance(stmt, ast.Delete):
            for target in stmt.targets:
                if isinstance(target, ast.Name):
                    env.pop(target.id, None)
            return env, False
        return env, False

    def _if(self, stmt: ast.If, env: TaintEnv) -> tuple[TaintEnv, bool]:
        self._expr(stmt.test, env)
        body_env, body_exits = self._block(stmt.body, self._apply_guards(dict(env), stmt.test, negated=False))
        else_env, else_exits = self._block(stmt.orelse, self._apply_guards(dict(env), stmt.test, negated=True))
        if body_exits and else_exits:
            return env, True
        if body_exits:
            return else_env, False
        if else_exits:
            return body_env, False
        return join_envs(body_env, else_env), False

    def _for(self, stmt: ast.For | ast.AsyncFor, env: TaintEnv) -> tuple[TaintEnv, bool]:
        iterated = self._expr(stmt.iter, env)
        self._assign(stmt.target, iterated, env, stmt.iter)
        env = self._loop_body(stmt.body, env)
        return self._block(stmt.orelse, env)

    def _while(self, stmt: ast.While, env: TaintEnv) -> tuple[TaintEnv, bool]:
        self._expr(stmt.test, env)
        env = self._loop_body(stmt.body, self._apply_guards(dict(env), stmt.test, negated=False))
        return self._block(stmt.orelse, env)

    def _loop_body(self, body: list[ast.stmt], env: TaintEnv) -> TaintEnv:
        """Analyse a loop body `taint_loop_iterations` times so taint created late is seen (A-17)."""
        current = dict(env)
        for _ in range(max(self.cfg.taint_loop_iterations, 1)):
            body_env, _ = self._block(body, dict(current))
            joined = join_envs(current, body_env)
            if joined == current:
                break
            current = joined
        return current

    def _with(self, stmt: ast.With | ast.AsyncWith, env: TaintEnv) -> tuple[TaintEnv, bool]:
        for item in stmt.items:
            value = self._expr(item.context_expr, env)
            if item.optional_vars is not None:
                self._assign(item.optional_vars, value, env, item.context_expr)
        return self._block(stmt.body, env)

    def _try(self, stmt: ast.Try | ast.TryStar, env: TaintEnv) -> tuple[TaintEnv, bool]:
        start = dict(env)
        body_env, body_exits = self._block(stmt.body, dict(start))
        merged = dict(start) if body_exits else dict(body_env)
        handlers_exit = True
        for handler in stmt.handlers:
            handler_env, handler_exits = self._block(handler.body, join_envs(start, body_env))
            handlers_exit = handlers_exit and handler_exits
            if not handler_exits:
                merged = join_envs(merged, handler_env)
        orelse_env, orelse_exits = self._block(stmt.orelse, dict(merged))
        if not orelse_exits:
            merged = orelse_env
        final_env, final_exits = self._block(stmt.finalbody, dict(merged))
        return final_env, final_exits or (body_exits and handlers_exit)

    def _match(self, stmt: ast.Match, env: TaintEnv) -> tuple[TaintEnv, bool]:
        subject = self._expr(stmt.subject, env)
        merged: Optional[TaintEnv] = None
        all_exit = bool(stmt.cases)
        for case in stmt.cases:
            case_env = dict(env)
            for name in _capture_names(case.pattern):
                case_env[name] = subject
            case_env, exits = self._block(case.body, case_env)
            all_exit = all_exit and exits
            if not exits:
                merged = case_env if merged is None else join_envs(merged, case_env)
        if merged is None:
            return env, all_exit
        return join_envs(env, merged), False

    def _assign(self, target: ast.expr, value: TaintValue, env: TaintEnv, source: Optional[ast.expr]) -> None:
        if isinstance(target, ast.Name):
            env[target.id] = value
            self._record_derived(target.id, source)
            return
        if isinstance(target, (ast.Tuple, ast.List)):
            elements = _unpack(target, source)
            for element, element_source in zip(target.elts, elements, strict=True):
                element_value = value if element_source is None else self._expr(element_source, env)
                self._assign(element, element_value, env, element_source)
            return
        if isinstance(target, ast.Starred):
            self._assign(target.value, value, env, source)
            return
        if isinstance(target, ast.Subscript):
            self._header_sink(target, value)
            self._expr(target.value, env)
            return
        if isinstance(target, ast.Attribute):
            self._expr(target.value, env)

    def _record_derived(self, name: str, source: Optional[ast.expr]) -> None:
        names = sanitizers.names_in(source) - {name}
        if names:
            self.derived[name] = names
        else:
            self.derived.pop(name, None)

    def _apply_guards(self, env: TaintEnv, test: ast.expr, *, negated: bool) -> TaintEnv:
        matches = sanitizers.guard_clearance(test, self.ctx, negated=negated)
        if not matches:
            return env
        out = dict(env)
        for match in matches:
            for name in sorted(self._expand(match.names)):
                value = out.get(name)
                if value is not None and value.tainted:
                    out[name] = value.sanitize(f"guard:{match.label}", match.cwes)
        return out

    def _expand(self, names: frozenset[str]) -> set[str]:
        """Names a guard constrains, expanded through the assignments they were derived from (A-11)."""
        out, stack = set(names), list(names)
        while stack:
            for parent in self.derived.get(stack.pop(), frozenset()):
                if parent not in out:
                    out.add(parent)
                    stack.append(parent)
        return out

    def _is_abort(self, expr: ast.expr) -> bool:
        """`abort(404)` / `sys.exit()` end a block as surely as a `return` does (resolved callees only)."""
        return isinstance(expr, ast.Call) and self.ctx.resolve(expr.func) in _ABORT_FUNCTIONS

    # ------------------------------------------------------------------ expressions
    def _expr(self, node: Optional[ast.expr], env: TaintEnv) -> TaintValue:
        if node is None:
            return UNTAINTED
        handler = getattr(self, f"_e_{type(node).__name__}", None)
        if handler is None:
            return self._children(node, env)
        return handler(node, env)

    def _children(self, node: ast.AST, env: TaintEnv) -> TaintValue:
        """Visit every nested expression (so nested sinks are seen) and union what they carry."""
        value = UNTAINTED
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.expr):
                value = value.union(self._expr(child, env))
        return value

    def _e_Constant(self, node: ast.Constant, env: TaintEnv) -> TaintValue:
        if isinstance(node.value, str):
            return TaintValue(is_constant_string=True, html_markup=_has_markup(node.value))
        if isinstance(node.value, bytes):
            return CONSTANT_STRING
        return UNTAINTED

    def _e_Name(self, node: ast.Name, env: TaintEnv) -> TaintValue:
        return env.get(node.id, UNTAINTED)

    def _e_JoinedStr(self, node: ast.JoinedStr, env: TaintEnv) -> TaintValue:
        value = self._children(node, env)
        return value.with_built("fstring")

    def _e_BinOp(self, node: ast.BinOp, env: TaintEnv) -> TaintValue:
        value = self._expr(node.left, env).union(self._expr(node.right, env))
        return value.with_built(_binop_kind(node.op))

    def _e_BoolOp(self, node: ast.BoolOp, env: TaintEnv) -> TaintValue:
        value = UNTAINTED
        for operand in node.values:
            value = value.union(self._expr(operand, env))
        return value

    def _e_IfExp(self, node: ast.IfExp, env: TaintEnv) -> TaintValue:
        self._expr(node.test, env)
        body_env = self._apply_guards(dict(env), node.test, negated=False)
        else_env = self._apply_guards(dict(env), node.test, negated=True)
        return self._expr(node.body, body_env).union(self._expr(node.orelse, else_env))

    def _e_Compare(self, node: ast.Compare, env: TaintEnv) -> TaintValue:
        self._children(node, env)
        return UNTAINTED

    def _e_UnaryOp(self, node: ast.UnaryOp, env: TaintEnv) -> TaintValue:
        value = self._expr(node.operand, env)
        return UNTAINTED if isinstance(node.op, ast.Not) else value

    def _e_Lambda(self, node: ast.Lambda, env: TaintEnv) -> TaintValue:
        return UNTAINTED  # a separate scope

    def _e_Subscript(self, node: ast.Subscript, env: TaintEnv) -> TaintValue:
        source = request_source(node, self.ctx)
        if source is not None:
            self._expr(node.slice, env)
            return source_value(source, self.fn.file, node.lineno, self.fn.qualname)
        value = self._expr(node.value, env)
        self._expr(node.slice, env)
        return value.refine(const_str(node.slice))

    def _e_Attribute(self, node: ast.Attribute, env: TaintEnv) -> TaintValue:
        source = request_source(node, self.ctx)
        if source is not None:
            return source_value(source, self.fn.file, node.lineno, self.fn.qualname)
        return self._expr(node.value, env).refine(node.attr)

    def _e_Tuple(self, node: ast.Tuple, env: TaintEnv) -> TaintValue:
        return replace(self._children(node, env), is_constant_string=False)

    _e_List = _e_Tuple
    _e_Set = _e_Tuple
    _e_Dict = _e_Tuple

    def _e_ListComp(self, node: ast.ListComp, env: TaintEnv) -> TaintValue:
        return self._comprehension(node, env, (node.elt,))

    _e_SetComp = _e_ListComp
    _e_GeneratorExp = _e_ListComp

    def _e_DictComp(self, node: ast.DictComp, env: TaintEnv) -> TaintValue:
        return self._comprehension(node, env, (node.key, node.value))

    def _comprehension(self, node: ast.expr, env: TaintEnv, parts: tuple[ast.expr, ...]) -> TaintValue:
        inner = dict(env)
        for generator in getattr(node, "generators", []):
            iterated = self._expr(generator.iter, inner)
            self._assign(generator.target, iterated, inner, None)
            for condition in generator.ifs:
                self._expr(condition, inner)
                inner = self._apply_guards(inner, condition, negated=False)
        value = UNTAINTED
        for part in parts:
            value = value.union(self._expr(part, inner))
        return replace(value, is_constant_string=False)

    def _e_Starred(self, node: ast.Starred, env: TaintEnv) -> TaintValue:
        return self._expr(node.value, env)

    def _e_Await(self, node: ast.Await, env: TaintEnv) -> TaintValue:
        return self._expr(node.value, env)

    def _e_NamedExpr(self, node: ast.NamedExpr, env: TaintEnv) -> TaintValue:
        value = self._expr(node.value, env)
        self._assign(node.target, value, env, node.value)
        return value

    def _e_Call(self, node: ast.Call, env: TaintEnv) -> TaintValue:
        source = request_source(node, self.ctx)
        receiver, args, kwargs = self._call_values(node, env)
        if source is not None:
            return source_value(source, self.fn.file, node.lineno, self.fn.qualname)
        every = _union_all((receiver, *args, *kwargs.values()))

        sanitizer = sanitizers.sanitizer_at(node, self.ctx)
        if sanitizer is not None:
            if sanitizer.result_barrier:
                return UNTAINTED
            return replace(every.sanitize(sanitizer.name, sanitizer.cwes), is_constant_string=False)

        safe = sinks.safe_response_at(node, self.ctx)
        if safe is not None:
            return UNTAINTED  # jsonify / JSONResponse / a non-HTML content type: safe and a barrier
        if id(node) in self._safe_responses:
            return UNTAINTED  # its content type is set to a safe one right after construction (A-38)

        spec = sinks.sink_at(node, self.ctx)
        if spec is not None:
            if _is_make_response(node) and node.args and _is_response_tuple(node.args[0]):
                # `make_response((body, status, headers))`: only the body is HTML; header values are not
                args = (self._expr(node.args[0].elts[0], env), *args[1:])
            self._call_sink(node, spec, receiver, args, kwargs)
            return UNTAINTED if spec.result_barrier else every

        if sinks.is_template_render(node, self.ctx):
            self._template_sink(node, env)
            return UNTAINTED  # the rendered page is not the request string (A-09)

        self._maybe_header_call(node, args)
        resolved = self.ctx.resolve(node.func)
        if resolved is not None and resolved in self.ctx.index.functions:
            return self._project_call(node, resolved, receiver, args, kwargs, every)
        return self._external_call(node, receiver, args, kwargs, every, resolved)

    def _call_values(
        self, node: ast.Call, env: TaintEnv
    ) -> tuple[TaintValue, tuple[TaintValue, ...], dict[str, TaintValue]]:
        receiver = self._expr(node.func.value, env) if isinstance(node.func, ast.Attribute) else UNTAINTED
        args = tuple(self._expr(arg, env) for arg in node.args)
        kwargs: dict[str, TaintValue] = {}
        for word in node.keywords:
            value = self._expr(word.value, env)
            if word.arg is None:
                kwargs.setdefault("**", UNTAINTED)
                kwargs["**"] = kwargs["**"].union(value)
            else:
                kwargs[word.arg] = value
        return receiver, args, kwargs

    def _project_call(
        self,
        node: ast.Call,
        callee: str,
        receiver: TaintValue,
        args: tuple[TaintValue, ...],
        kwargs: dict[str, TaintValue],
        every: TaintValue,
    ) -> TaintValue:
        if self.hook is None:
            return every  # no summaries available: stay conservative
        site = CallSite(
            call=node,
            callee=callee,
            receiver=receiver,
            args=args,
            kwargs=kwargs,
            caller=self.fn.qualname,
            line=node.lineno,
        )
        effect = self.hook(site)
        if effect is None:
            return every
        for report in effect.reports:
            self._add(report)
        return effect.value

    def _external_call(
        self,
        node: ast.Call,
        receiver: TaintValue,
        args: tuple[TaintValue, ...],
        kwargs: dict[str, TaintValue],
        every: TaintValue,
        resolved: Optional[str],
    ) -> TaintValue:
        leaf = node.func.attr if isinstance(node.func, ast.Attribute) else None
        if leaf == "join":
            return replace(every.with_built("join"), is_constant_string=False)
        if leaf == "format":
            return replace(every.with_built("format"), is_constant_string=False)
        if leaf in CONTAINER_GETTERS and receiver.tainted:
            key = const_str(node.args[0]) if node.args else None
            return receiver.refine(key)
        if leaf in PROPAGATOR_METHODS:
            return replace(receiver.union(_union_all(args)), is_constant_string=receiver.is_constant_string)
        if resolved in STRING_CASTS:
            return replace(_union_all(args), is_constant_string=False)
        return replace(every, is_constant_string=False)

    # ------------------------------------------------------------------ sinks
    def _call_sink(
        self,
        node: ast.Call,
        spec: sinks.SinkSpec,
        receiver: TaintValue,
        args: tuple[TaintValue, ...],
        kwargs: dict[str, TaintValue],
    ) -> None:
        value = self._sink_value(node, spec, receiver, args, kwargs)
        if value is None:
            return
        line_end = node.end_lineno or node.lineno
        if spec.requires_string_built and value.is_constant_string:
            # A constant SQL string with tainted bind parameters is safe (spec P2-A3): kept as a
            # suppressed `safe:sql-parameterised` report so the decision is visible (A-47).
            binds = self._bind_values(spec, args, kwargs)
            if binds.tainted_for(spec.cwe):
                bound = replace(binds, built=value.built, html_markup=value.html_markup)
                self._sink_report(
                    spec, bound, node.lineno, line_end, suppressed=True, reason=suppress.SAFE_SQL_PARAMETERISED
                )
            return
        suppressed, reason = False, None
        if value.tainted_for(spec.cwe) and spec.requires_shell and not sinks.shell_true(node):
            argument = sinks.argument_node(node, spec)
            suppressed = True
            reason = sinks.SUPPRESS_LIST_NO_SHELL if sinks.is_sequence_argument(argument) else sinks.SUPPRESS_NO_SHELL
        self._sink_report(spec, value, node.lineno, line_end, suppressed=suppressed, reason=reason)

    @staticmethod
    def _bind_values(spec: sinks.SinkSpec, args: tuple[TaintValue, ...], kwargs: dict[str, TaintValue]) -> TaintValue:
        """Every argument of a sink call other than the one `spec` checks (the SQL bind parameters)."""
        positional = 0 <= spec.arg_index < len(args)
        out = UNTAINTED
        for position, value in enumerate(args):
            if not (positional and position == spec.arg_index):
                out = out.union(value)
        for name, value in kwargs.items():
            if name not in spec.arg_keywords:
                out = out.union(value)
        return out

    def _sink_report(
        self,
        spec: sinks.SinkSpec,
        value: TaintValue,
        line_start: int,
        line_end: int,
        *,
        suppressed: bool = False,
        reason: Optional[str] = None,
    ) -> None:
        """Report `value` reaching `spec`: its live labels, else its sanitised ones as suppressed (A-47).

        Labels a sanitiser or guard cleared for the sink's CWE become one suppressed
        `sanitized:<names>` report; a clearance with no sanitiser name behind it (the request URL
        and CWE-601) reports nothing.
        """
        labels = value.tainted_for(spec.cwe)
        if not labels:
            reason = suppress.sanitized_reason(value.labels, spec.cwe)
            if reason is None:
                return
            labels = frozenset(label for label in value.labels if spec.cwe in label.cleared)
            suppressed = True
        self._add(
            SinkReport(
                cwe=spec.cwe,
                family=spec.rule_family,
                token=spec.token,
                file=self.fn.file,
                line_start=line_start,
                line_end=line_end,
                function=self.fn.qualname,
                chain=(self.fn.qualname,),
                labels=labels,
                built=value.built,
                html_markup=value.html_markup,
                suppressed=suppressed,
                suppress_reason=reason,
            )
        )

    def _sink_value(
        self,
        node: ast.Call,
        spec: sinks.SinkSpec,
        receiver: TaintValue,
        args: tuple[TaintValue, ...],
        kwargs: dict[str, TaintValue],
    ) -> Optional[TaintValue]:
        if spec.arg_index == sinks.RECEIVER:
            return receiver
        if 0 <= spec.arg_index < len(args):
            return args[spec.arg_index]
        for name in sorted(spec.arg_keywords):
            if name in kwargs:
                return kwargs[name]
        return None

    def _template_sink(self, node: ast.Call, env: TaintEnv) -> None:
        """A render call is a CWE-79 sink per variable the matched template leaves unescaped (P2-A5).

        Only the kwargs the template renders unescaped are looked at, so an escaped kwarg on the
        same call reports nothing, and a `|safe` with no tainted value reports nothing (A-18).
        """
        if self.templates is None:
            return
        name = sinks.template_name(node)
        if name is None:
            return
        unescaped = self.templates.unescaped(name)
        if not unescaped:
            return
        spec = sinks.TEMPLATE_RENDER
        context = sinks.template_context(node, self._single_assignment)
        for variable in sorted(context):
            if variable not in unescaped:
                continue
            value = self._expr(context[variable], env)  # visited once already; reports de-duplicate
            self._sink_report(spec, value, node.lineno, node.end_lineno or node.lineno)

    def _single_assignment(self, name: str) -> Optional[ast.expr]:
        """The value of local `name` when it is assigned exactly once in this function, else None (A-39)."""
        values = self.fn.assignments.get(name, [])
        return values[0] if len(values) == 1 else None

    def _response_sink(self, value: TaintValue, stmt: ast.Return) -> None:
        """A route handler's return value is an HTML response (A-10)."""
        self._sink_report(sinks.HANDLER_RETURN, value, stmt.lineno, stmt.end_lineno or stmt.lineno)

    def _header_sink(self, target: ast.Subscript, value: TaintValue) -> None:
        if not (sinks.is_redirect_header(target.value) and sinks.is_redirect_header_key(target.slice)):
            return
        self._location_report(value, target.lineno, target.end_lineno or target.lineno)

    def _maybe_header_call(self, node: ast.Call, args: tuple[TaintValue, ...]) -> None:
        leaf = node.func.attr if isinstance(node.func, ast.Attribute) else None
        if leaf not in sinks.HEADER_SETTERS or len(args) < 2:
            return
        if not (sinks.is_redirect_header(node.func.value) and sinks.is_redirect_header_key(node.args[0])):
            return
        self._location_report(args[1], node.lineno, node.end_lineno or node.lineno)

    def _location_report(self, value: TaintValue, line_start: int, line_end: int) -> None:
        self._sink_report(sinks.LOCATION_HEADER, value, line_start, line_end)

    def _add(self, report: SinkReport) -> None:
        key = report.dedupe_key
        if key in self._seen:
            return
        self._seen.add(key)
        self.reports.append(report)


# --------------------------------------------------------------------------- AST helpers
def _binop_kind(op: ast.operator) -> Optional[str]:
    if isinstance(op, ast.Add):
        return "concat"
    if isinstance(op, ast.Mod):
        return "percent"
    return None


def _is_make_response(node: ast.Call) -> bool:
    func = node.func
    return (isinstance(func, ast.Name) and func.id == "make_response") or (
        isinstance(func, ast.Attribute) and func.attr == "make_response"
    )


def _is_response_tuple(node: ast.expr) -> bool:
    """A literal `(body, status_or_headers[, headers])` tuple, as Flask's `make_response` unpacks it."""
    return isinstance(node, ast.Tuple) and 2 <= len(node.elts) <= 3 and not isinstance(node.elts[0], ast.Starred)


def _union_all(values: tuple[TaintValue, ...]) -> TaintValue:
    out = UNTAINTED
    for value in values:
        out = out.union(value)
    return out


def _merge_names(left: tuple[str, ...], right: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(sorted(set(left) | set(right)))


def _has_markup(text: str) -> bool:
    start = text.find("<")
    return start >= 0 and text.find(">", start) > start


def _unpack(target: ast.Tuple | ast.List, value: Optional[ast.expr]) -> list[Optional[ast.expr]]:
    """Per-element sources for `a, b = x, y`; None when the sides do not line up."""
    if (
        isinstance(value, (ast.Tuple, ast.List))
        and len(value.elts) == len(target.elts)
        and not any(isinstance(e, ast.Starred) for e in (*target.elts, *value.elts))
    ):
        return list(value.elts)
    return [None] * len(target.elts)


def _capture_names(pattern: ast.pattern) -> set[str]:
    out: set[str] = set()
    for node in ast.walk(pattern):
        if isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name:
            out.add(node.name)
        elif isinstance(node, ast.MatchMapping) and node.rest:
            out.add(node.rest)
    return out
