# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""What report.json keys real reports carry, and which keys consumers read (#409).

Two halves, used by ``tests/test_report_reads_have_producers.py``:

* ``reduce_report`` turns a real ``report.json`` into its KEY SHAPE: every key
  path and the JSON types seen there, and nothing else. No value survives — no
  string, number, hash, address or code. Dicts whose keys are themselves data
  (pid -> command line, API name -> count, CAPE config fields) collapse to
  ``*``, so their keys do not survive either. ``tests/fixtures/
  report_key_shapes.json`` is built with it from reports read off the host.

* ``ConsumerReads`` walks consumer modules with ``ast`` and collects every key
  path read from the report: ``report.get("cape")``, ``report["cape"]``, then
  whatever is read from the variable that value was bound to, through aliases,
  ``or {}``, ``_dict(...)``, loops, comprehensions, local helper calls (by
  inlining them with the actual arguments), and the shape-checked ``_Node``
  accessors db_ingest uses. It is an abstract interpreter over a small subset of
  Python, not a regex over source text.

  What it cannot see, it says. A read with a key that is not a constant it can
  resolve, and a report value handed to a function outside the consumer set,
  are recorded in ``dynamic`` and ``handoffs`` rather than skipped, so the test
  can make each one an explicit, reviewed blind spot.

Regenerating the fixture. Copy the reports off the host read-only
(``ssh sandbox 'sudo -n cat /opt/pipeline/reports/<run>/report.json'``, the eval
corpus's ``report.json`` files, and ``report_json`` rows selected under
``default_transaction_read_only``), then::

    python -m tests.report_keys shape \\
        --era current:pipeline-run-<run name>=<report.json> ... \\
        --era older:eval-corpus-<NN>=<report.json> ... \\
        --era older:analyses-row-<YYYY-MM-DD>=<report.json> ... \\
        > tests/fixtures/report_key_shapes.json

Labels carry the run name or date only, never the sample hash; the test
enforces that. ``current`` is what the pipeline writes today; ``older`` is what
consumers still meet in stored analyses and the eval corpus.

Printing what the consumers read::

    python -m tests.report_keys reads
"""
from __future__ import annotations

import ast
import json
import re
import sys
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SHAPES = ROOT / "tests/fixtures/report_key_shapes.json"
_FILES = "ansible/roles/pipeline/files"

# ---------------------------------------------------------------------------
# Key shape of a real report
# ---------------------------------------------------------------------------

#: A list element in a key path.
ELEM = "[]"
#: Any key: a collapsed data-keyed dict in a shape, or an unknown key in a read.
ANY = "*"

#: Dicts keyed by data rather than by schema. Their keys are pids, API names,
#: category names, malware-config field names: values in all but position.
COLLAPSE = frozenset({
    ("cape", "process_cmdlines"),                       # pid -> command line
    ("cape", "detonation", "child_image_bases"),        # pid -> image base
    ("cape", "process_activity", "processes", ELEM, "apis"),        # API -> count
    ("cape", "process_activity", "processes", ELEM, "categories"),  # category -> count
    ("cape", "extracted_configs", ELEM),                # family -> CAPE config
})

#: A key that may survive into the fixture. Anything else (digits, dots,
#: spaces, slashes, colons: pids, domains, paths, addresses, Volatility and
#: Zeek column names) collapses its whole dict to ``*``. Errs towards
#: collapsing: a collapsed dict only makes the guard more lenient there.
_SCHEMA_KEY = re.compile(r"[a-z_][a-z0-9_]{0,63}")
#: Lower-case hex long enough to be a hash prefix is data, even if it parses
#: as an identifier.
_HEXISH = re.compile(r"[0-9a-f]{12,}")
#: More keys than any schema object in the pipeline has is a data-keyed dict.
_MAX_SCHEMA_KEYS = 120

_JSON_TYPES = {dict: "object", list: "array", str: "string", bool: "boolean",
               int: "integer", float: "number", type(None): "null"}


def _is_schema_key(k: Any) -> bool:
    return isinstance(k, str) and bool(_SCHEMA_KEY.fullmatch(k)) and not _HEXISH.search(k)


def reduce_report(report: Any) -> dict[tuple[str, ...], set[str]]:
    """Key path -> JSON types seen there. Values are discarded, not stored."""
    out: dict[tuple[str, ...], set[str]] = defaultdict(set)

    def walk(v: Any, path: tuple[str, ...]) -> None:
        out[path].add(_JSON_TYPES.get(type(v), "other"))
        if isinstance(v, dict):
            collapse = (path in COLLAPSE or len(v) > _MAX_SCHEMA_KEYS
                        or not all(_is_schema_key(k) for k in v))
            for k, x in v.items():
                walk(x, path + (ANY if collapse else k,))
        elif isinstance(v, list):
            for x in v:
                walk(x, path + (ELEM,))

    walk(report, ())
    out.pop((), None)
    return dict(out)


def path_str(path: Iterable[str]) -> str:
    """('cape', 'mitre_ttps', '[]', 'id') -> 'cape.mitre_ttps[].id'."""
    s = ""
    for part in path:
        s += part if part == ELEM else (f".{part}" if s else part)
    return s


def parse_path(s: str) -> tuple[str, ...]:
    out: list[str] = []
    for part in s.split("."):
        depth = 0
        while part.endswith(ELEM):
            part, depth = part[: -len(ELEM)], depth + 1
        if part:
            out.append(part)
        out += [ELEM] * depth
    return tuple(out)


class Shape:
    """The union of reduced reports, matchable with ``*`` as any key."""

    def __init__(self, paths: Iterable[tuple[str, ...]]):
        self.paths = set(paths)

    def has(self, path: tuple[str, ...]) -> bool:
        frontier = [()]
        for part in path:
            nxt = []
            for pre in frontier:
                if part == ANY:
                    nxt += [p[: len(pre) + 1] for p in self.paths
                            if len(p) > len(pre) and p[: len(pre)] == pre]
                else:
                    for cand in (pre + (part,), pre + (ANY,)):
                        if cand in self.paths:
                            nxt.append(cand)
            frontier = list(set(nxt))
            if not frontier:
                return False
        return True


def load_shapes(path: Path = SHAPES) -> dict[str, Shape]:
    """era -> Shape, from the committed fixture."""
    data = json.loads(path.read_text())
    return {era: Shape(parse_path(p) for p in body["paths"])
            for era, body in data["eras"].items()}


# ---------------------------------------------------------------------------
# Key paths consumers read
# ---------------------------------------------------------------------------

#: The consumers this guard covers, and the name the report goes by in each.
#: A function that has one of these names as a parameter, or assigns it, is
#: analysed with that name bound to the report root.
CONSUMERS: dict[str, frozenset[str]] = {
    "api/app/investigate/tools.py": frozenset({"report"}),
    "api/app/investigate/system_prompt.py": frozenset({"report_json"}),
    "api/app/flow.py": frozenset({"report"}),
    f"{_FILES}/db_ingest.py": frozenset({"report"}),
    **{f"{_FILES}/lamware_eval/{p.name}": frozenset({"report"})
       for p in sorted((ROOT / _FILES / "lamware_eval").glob("*.py"))},
}
#: Pipeline modules a consumer hands part of the report to. Not consumers in
#: their own right here (no root name): only followed when a consumer calls
#: into them, so the keys they read from what they were handed count.
FOLLOWED: tuple[str, ...] = (
    f"{_FILES}/stages/ghidra.py",            # collect_analysis_warnings (lamware_eval.metrics)
    f"{_FILES}/stages/single_shot_init.py",  # build_dotnet_init (lamware_eval.runner)
    f"{_FILES}/stages/interpret.py",         # run_interpret (lamware_eval.runner)
    f"{_FILES}/stages/dotnet_tools.py",      # is_agentic_dotnet (#646)
    f"{_FILES}/stages/dotnet_agentic.py",    # build_dotnet_interpret_init, broker_from_payload,
                                             # dotnet_input_record, is_agentic_dotnet (#646)
)

# Abstract values. Each is a hashable tuple:
#   ("path", (k1, k2, ...))   a value read from the report at that key path
#   ("const", v)              a constant (string, number, tuple of constants)
#   ("tuple", (vals, ...))    a tuple/list literal; one frozenset per position
#   ("list", vals)            a local collection holding these elements
#   ("dict", ((key, vals),))  a local dict; key None when not a constant
Val = tuple
Vals = frozenset

_EMPTY: Vals = frozenset()
_ROOT: Vals = frozenset({("path", ())})

#: Accessors that read one key from their receiver: dict.get / setdefault, and
#: db_ingest's shape-checked _Node methods.
_KEY_METHODS = frozenset({"get", "setdefault", "pop", "obj", "raw", "text", "integer",
                          "number", "flag", "timestamp", "array", "texts"})
#: Calls that return (or iterate) their first argument unchanged.
_PASSTHROUGH = frozenset({"_dict", "_list", "dict", "_Node", "copy", "deepcopy"})
_SEQUENCE_OF = frozenset({"list", "sorted", "tuple", "reversed", "set", "frozenset", "iter"})
#: Builtins and library calls that consume a value without reading a key from
#: it: a count, a type check, a serialisation of the whole value. Not blind
#: spots, because no key is chosen.
_CONSUME = frozenset({
    "len", "bool", "str", "int", "float", "isinstance", "round", "sum", "min", "max",
    "any", "all", "print", "repr", "abs", "hash", "id", "type", "range", "callable",
    "dumps", "Json", "format", "join", "debug", "info", "warning", "error", "exception",
    # String and regex operations: they take a string, and a string has no keys.
    "Path", "sub", "subn", "match", "search", "fullmatch", "findall", "finditer",
    "startswith", "endswith", "strip", "lower", "upper", "split", "rsplit", "replace",
    "encode", "decode", "fromisoformat",
})
#: Loops over a constant tuple of at most this many items are unrolled, so a
#: key taken from the loop variable is read only with the values it pairs with.
_MAX_UNROLL = 32
_MAX_DEPTH = 12
_MAX_PATH = 10


@dataclass(frozen=True)
class Site:
    file: str
    line: int
    func: str

    def __str__(self) -> str:
        return f"{self.file}:{self.line} ({self.func})"


@dataclass
class _Module:
    rel: str
    tree: ast.Module
    funcs: dict[str, ast.FunctionDef | ast.AsyncFunctionDef]
    consts: dict[str, Any]
    imports: dict[str, tuple[str, str]]  # local name -> (module rel, func name)
    roots: frozenset[str]


@dataclass
class ConsumerReads:
    """Run ``analyse()``; then read ``reads``, ``dynamic`` and ``handoffs``."""

    sources: dict[str, str]                     # rel path -> source text
    roots: dict[str, frozenset[str]]            # rel path -> root names
    reads: dict[tuple[str, ...], set[Site]] = field(default_factory=lambda: defaultdict(set))
    #: (site, path) where a key was read with a non-constant key.
    dynamic: set[tuple[Site, tuple[str, ...]]] = field(default_factory=set)
    #: (site, callee, path) where a report value went to code not analysed here.
    handoffs: set[tuple[Site, str, tuple[str, ...]]] = field(default_factory=set)

    def __post_init__(self) -> None:
        self._mods: dict[str, _Module] = {}
        by_basename: dict[str, str] = {}
        for rel, src in self.sources.items():
            tree = ast.parse(src, filename=rel)
            funcs = {n.name: n for n in tree.body
                     if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
            consts: dict[str, Any] = {}
            for n in tree.body:
                targets = (n.targets if isinstance(n, ast.Assign)
                           else [n.target] if isinstance(n, ast.AnnAssign) and n.value else [])
                for t in targets:
                    if isinstance(t, ast.Name):
                        try:
                            consts[t.id] = ast.literal_eval(n.value)
                        except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
                            pass
            self._mods[rel] = _Module(rel, tree, funcs, consts, {}, self.roots.get(rel, frozenset()))
            by_basename[Path(rel).stem] = rel
        for mod in self._mods.values():
            for n in ast.walk(mod.tree):
                if isinstance(n, ast.ImportFrom) and n.module is not None:
                    target = by_basename.get(n.module.rsplit(".", 1)[-1])
                    if target:
                        for a in n.names:
                            mod.imports[a.asname or a.name] = (target, a.name)
        self._memo: dict[tuple, Vals] = {}
        self._active: set[tuple] = set()
        self._active_names: dict[tuple[str, str], int] = defaultdict(int)

    # -- entry -------------------------------------------------------------

    def analyse(self) -> ConsumerReads:
        for mod in self._mods.values():
            if not mod.roots:
                continue
            for fn in mod.funcs.values():
                bound = {a.arg for a in _all_args(fn.args)} | _assigned_names(fn)
                if bound & mod.roots:
                    env = {name: _ROOT for name in bound & mod.roots}
                    self._call(mod, fn, env, depth=0)
        return self

    # -- functions ---------------------------------------------------------

    def _call(self, mod: _Module, fn: ast.AST, env: dict[str, Vals], depth: int) -> Vals:
        if (mod.rel, fn.name) in self._active_names:
            # Recursion over a subtree (strip_technique_ids walks every value):
            # analyse the body once more with "anything below here" and stop.
            env = {k: frozenset(("path", _child(v[1], ANY)) if v[0] == "path" else v
                                for v in vals) for k, vals in env.items()}
        key = (mod.rel, fn.name, tuple(sorted((k, v) for k, v in env.items() if v)))
        if key in self._memo:
            return self._memo[key]
        if key in self._active or depth > _MAX_DEPTH:
            return _EMPTY
        self._active.add(key)
        self._active_names[(mod.rel, fn.name)] += 1
        local = defaultdict(frozenset, env)
        for name in mod.roots & _assigned_names(fn):
            local[name] = local[name] | _ROOT
        frame = _Frame(self, mod, fn.name, local, depth)
        # Flow-insensitive apart from loop targets: a binding anywhere in the
        # body holds everywhere. Re-run until nothing new is learned.
        for _ in range(8):
            before = (dict(local), len(frame.ret))
            for stmt in fn.body:
                frame.stmt(stmt)
            if before == (dict(local), len(frame.ret)):
                break
        self._active.discard(key)
        self._active_names[(mod.rel, fn.name)] -= 1
        if not self._active_names[(mod.rel, fn.name)]:
            del self._active_names[(mod.rel, fn.name)]
        self._memo[key] = frozenset(frame.ret)
        return self._memo[key]

    def resolve(self, mod: _Module, name: str) -> tuple[_Module, ast.AST] | None:
        if name in mod.funcs:
            return mod, mod.funcs[name]
        if name in mod.imports:
            rel, fname = mod.imports[name]
            target = self._mods[rel]
            if fname in target.funcs:
                return target, target.funcs[fname]
        return None


def _all_args(a: ast.arguments) -> list[ast.arg]:
    out = [*a.posonlyargs, *a.args, *a.kwonlyargs]
    if a.vararg:
        out.append(a.vararg)
    if a.kwarg:
        out.append(a.kwarg)
    return out


def _assigned_names(fn: ast.AST) -> set[str]:
    return {n.id for n in ast.walk(fn) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store)}


def _child(path: tuple[str, ...], part: str) -> tuple[str, ...]:
    """One step down. Below ``*`` everything is ``*``: a value reached through
    an unknown key, or through recursion over a whole subtree, has no key
    path the guard can check, and growing one would never terminate."""
    if ANY in path:
        return path
    if len(path) >= _MAX_PATH:
        return path + (ANY,)
    return path + (part,)


def _const_strs(vals: Vals) -> tuple[list[str], bool]:
    """(constant string keys, whether any value was not a constant string)."""
    keys, unknown = [], False
    for v in vals:
        if v[0] == "const" and isinstance(v[1], str):
            keys.append(v[1])
        else:
            unknown = True
    return keys, unknown or not vals


def _elements(vals: Vals) -> Vals:
    out: set[Val] = set()
    for v in vals:
        kind = v[0]
        if kind == "path":
            out.add(("path", _child(v[1], ELEM)))
        elif kind == "list":
            out |= v[1]
        elif kind == "tuple":
            for item in v[1]:
                out |= item
        elif kind == "const" and isinstance(v[1], (tuple, list, frozenset, set)):
            out |= {_const(x) for x in v[1]}
        elif kind == "dict":
            out |= {_const(k) for k, _ in v[1] if k is not None}
    return frozenset(out)


def _const(x: Any) -> Val:
    if isinstance(x, list):
        x = tuple(x)
    try:
        hash(x)
    except TypeError:
        return ("const", None)
    return ("const", x)


class _Frame:
    """One analysis of one function body under one binding of its arguments."""

    def __init__(self, owner: ConsumerReads, mod: _Module, func: str,
                 env: dict[str, Vals], depth: int):
        self.o, self.mod, self.func, self.env, self.depth = owner, mod, func, env, depth
        self.ret: set[Val] = set()

    def site(self, node: ast.AST) -> Site:
        return Site(self.mod.rel, getattr(node, "lineno", 0), self.func)

    # -- reads -------------------------------------------------------------

    def access(self, vals: Vals, keys: Vals, node: ast.AST) -> Vals:
        """Subscript or .get(): read `keys` from each value in `vals`."""
        out: set[Val] = set()
        consts, unknown = _const_strs(keys)
        ints = any(k[0] == "const" and isinstance(k[1], int) for k in keys)
        for v in vals:
            kind = v[0]
            if kind == "path":
                for k in consts:
                    path = _child(v[1], k)
                    if ANY not in path:
                        self.o.reads[path].add(self.site(node))
                    out.add(("path", path))
                if ints:
                    out.add(("path", _child(v[1], ELEM)))
                elif unknown and not consts:
                    if ANY not in v[1]:
                        self.o.dynamic.add((self.site(node), v[1]))
                    out.add(("path", _child(v[1], ANY)))
            elif kind == "dict":
                for k, item in v[1]:
                    if k is None or unknown or k in consts:
                        out |= item
            elif kind == "list":
                out |= v[1]
            elif kind == "tuple":
                idx = [k[1] for k in keys if k[0] == "const" and isinstance(k[1], int)]
                if idx and all(-len(v[1]) <= i < len(v[1]) for i in idx):
                    for i in idx:
                        out |= v[1][i]
                else:
                    for item in v[1]:
                        out |= item
            elif kind == "const" and isinstance(v[1], (tuple, dict)):
                for k in keys:
                    try:
                        out.add(_const(v[1][k[1]]))
                    except (KeyError, IndexError, TypeError):
                        pass
        return frozenset(out)

    # -- statements ----------------------------------------------------------

    def bind(self, target: ast.AST, vals: Vals) -> None:
        if isinstance(target, ast.Name):
            self.env[target.id] = self.env[target.id] | vals
        elif isinstance(target, (ast.Tuple, ast.List)):
            n = len(target.elts)
            for i, elt in enumerate(target.elts):
                part: set[Val] = set()
                for v in vals:
                    if v[0] == "tuple" and len(v[1]) == n:
                        part |= v[1][i]
                    elif v[0] == "const" and isinstance(v[1], tuple) and len(v[1]) == n:
                        part.add(_const(v[1][i]))
                self.bind(elt.value if isinstance(elt, ast.Starred) else elt, frozenset(part))
        elif isinstance(target, ast.Subscript):
            self.expr(target.slice)
            if isinstance(target.value, ast.Name):
                keys, unknown = _const_strs(self.expr(target.slice))
                entries = tuple((k, vals) for k in keys) or ((None, vals),)
                if unknown and keys:
                    entries += ((None, vals),)
                self.env[target.value.id] = self.env[target.value.id] | {("dict", entries)}
            else:
                self.expr(target.value)
        elif isinstance(target, ast.Starred):
            self.bind(target.value, vals)
        else:
            self.expr(target)

    def loop(self, target: ast.AST, iterable: Vals, body: list[ast.stmt]) -> None:
        """A for loop. The target is bound to this loop's elements only (a
        name reused by two loops must not carry one loop's report section into
        the other), and a loop over a short constant tuple is unrolled, so
        ``for key in ("a", "b"): data = r.get(key)`` reads ``a`` and ``b``
        each with its own ``data``."""
        elems = _elements(iterable)
        names = {n.id for n in ast.walk(target) if isinstance(n, ast.Name)}
        assigned = names | {n.id for b in body for n in ast.walk(b)
                            if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store)}
        unroll = bool(elems) and len(elems) <= _MAX_UNROLL \
            and all(v[0] == "const" for v in iterable)
        groups = [frozenset({v}) for v in elems] if unroll else [elems]
        base = {n: self.env[n] for n in assigned}
        acc: dict[str, Vals] = defaultdict(frozenset)
        for group in groups:
            for n in (assigned if unroll else names):
                self.env[n] = _EMPTY
            self.bind(target, group)
            for b in body:
                self.stmt(b)
            for n in assigned:
                acc[n] = acc[n] | self.env[n]
        for n in assigned:
            self.env[n] = base[n] | acc[n]

    def decide(self, test: ast.expr) -> bool | None:
        """True/False when the test compares names bound only to constants,
        e.g. ``key == "dotnet_analysis"`` inside an unrolled loop; else None."""
        if isinstance(test, ast.BoolOp):
            verdicts = [self.decide(v) for v in test.values]
            if isinstance(test.op, ast.And):
                return False if False in verdicts else (True if all(verdicts) else None)
            if True in verdicts:
                return True
            return False if all(v is False for v in verdicts) else None
        if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
            v = self.decide(test.operand)
            return None if v is None else not v
        if (isinstance(test, ast.Compare) and len(test.ops) == 1
                and isinstance(test.ops[0], (ast.Eq, ast.NotEq, ast.In, ast.NotIn))):
            left, right = self._consts(test.left), self._consts(test.comparators[0])
            if left is None or right is None:
                return None
            op = test.ops[0]
            try:
                if isinstance(op, (ast.Eq, ast.NotEq)):
                    outcomes = {a == b for a in left for b in right}
                else:
                    outcomes = {a in b for a in left for b in right}
            except TypeError:
                return None
            if len(outcomes) != 1:
                return None
            (same,) = outcomes
            return same if isinstance(op, (ast.Eq, ast.In)) else not same
        return None

    def _consts(self, e: ast.expr) -> list | None:
        if not isinstance(e, (ast.Name, ast.Constant, ast.Tuple)):
            return None
        vals = self.expr(e)
        if not vals or any(v[0] != "const" for v in vals):
            return None
        return [v[1] for v in vals]

    def stmt(self, s: ast.stmt) -> None:
        if isinstance(s, ast.Assign):
            vals = self.expr(s.value)
            for t in s.targets:
                self.bind(t, vals)
        elif isinstance(s, ast.AnnAssign):
            if s.value is not None:
                self.bind(s.target, self.expr(s.value))
        elif isinstance(s, ast.AugAssign):
            self.expr(s.target if not isinstance(s.target, ast.Name)
                      else ast.Name(s.target.id, ast.Load()))
            vals = self.expr(s.value)
            if isinstance(s.target, ast.Name):
                self.bind(s.target, vals)
        elif isinstance(s, (ast.For, ast.AsyncFor)):
            self.loop(s.target, self.expr(s.iter), s.body)
            for b in s.orelse:
                self.stmt(b)
        elif isinstance(s, ast.If):
            verdict = self.decide(s.test)
            self.expr(s.test)
            if verdict is not False:
                for b in s.body:
                    self.stmt(b)
            if verdict is not True:
                for b in s.orelse:
                    self.stmt(b)
        elif isinstance(s, ast.Return):
            if s.value is not None:
                self.ret |= self.expr(s.value)
        elif isinstance(s, (ast.With, ast.AsyncWith)):
            for item in s.items:
                vals = self.expr(item.context_expr)
                if item.optional_vars is not None:
                    self.bind(item.optional_vars, vals)
            for b in s.body:
                self.stmt(b)
        elif isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            # A nested def sees the enclosing bindings (closure); its own
            # parameters are unbound.
            for b in s.body:
                self.stmt(b)
        else:
            for child in ast.iter_child_nodes(s):
                if isinstance(child, ast.stmt):
                    self.stmt(child)
                elif isinstance(child, ast.expr):
                    self.expr(child)
                elif isinstance(child, ast.excepthandler):
                    for b in child.body:
                        self.stmt(b)
                elif isinstance(child, ast.match_case):
                    for b in child.body:
                        self.stmt(b)

    # -- expressions ---------------------------------------------------------

    def expr(self, e: ast.expr | None) -> Vals:
        if e is None:
            return _EMPTY
        method = getattr(self, f"_{type(e).__name__}", None)
        if method is not None:
            return method(e)
        for child in ast.iter_child_nodes(e):
            if isinstance(child, ast.expr):
                self.expr(child)
        return _EMPTY

    def _Name(self, e: ast.Name) -> Vals:
        if e.id in self.env and self.env[e.id]:
            return self.env[e.id]
        if e.id in self.mod.consts:
            return frozenset({_const(self.mod.consts[e.id])})
        # `from stages.ghidra import ROUTED_FLAGS`: a constant defined in another
        # covered module. Without this a loop over an imported constant tuple
        # reads as a non-constant key (lamware_eval/runner.py init_payload_for).
        imported = self.mod.imports.get(e.id)
        if imported is not None:
            target = self.o._mods.get(imported[0])
            if target is not None and imported[1] in target.consts:
                return frozenset({_const(target.consts[imported[1]])})
        return _EMPTY

    def _Constant(self, e: ast.Constant) -> Vals:
        return frozenset({_const(e.value)})

    def _tuple_like(self, e: ast.Tuple | ast.List | ast.Set) -> Vals:
        items = tuple(self.expr(x) for x in e.elts)
        if all(len(i) == 1 and next(iter(i))[0] == "const" for i in items):
            return frozenset({_const(tuple(next(iter(i))[1] for i in items))})
        return frozenset({("tuple", items)})

    _Tuple = _List = _Set = _tuple_like

    def _Dict(self, e: ast.Dict) -> Vals:
        entries = []
        for k, v in zip(e.keys, e.values, strict=True):
            vals = self.expr(v)
            if k is None:  # {**other}
                entries.append((None, frozenset(x for d in vals if d[0] == "dict"
                                                for _, item in d[1] for x in item)))
                continue
            keys, unknown = _const_strs(self.expr(k))
            entries += [(key, vals) for key in keys]
            if unknown:
                entries.append((None, vals))
        return frozenset({("dict", tuple(entries))})

    def _BoolOp(self, e: ast.BoolOp) -> Vals:
        out: Vals = _EMPTY
        stop = not isinstance(e.op, ast.And)
        for v in e.values:
            out = out | self.expr(v)
            if self.decide(v) is stop:
                break  # short-circuits here; the rest is never evaluated
        return out

    def _IfExp(self, e: ast.IfExp) -> Vals:
        verdict = self.decide(e.test)
        self.expr(e.test)
        out: Vals = _EMPTY
        if verdict is not False:
            out = out | self.expr(e.body)
        if verdict is not True:
            out = out | self.expr(e.orelse)
        return out

    def _NamedExpr(self, e: ast.NamedExpr) -> Vals:
        vals = self.expr(e.value)
        self.bind(e.target, vals)
        return vals

    def _Starred(self, e: ast.Starred) -> Vals:
        return self.expr(e.value)

    def _Await(self, e: ast.Await) -> Vals:
        return self.expr(e.value)

    def _Compare(self, e: ast.Compare) -> Vals:
        left = self.expr(e.left)
        for op, right in zip(e.ops, e.comparators, strict=True):
            rvals = self.expr(right)
            if isinstance(op, (ast.In, ast.NotIn)):
                # `"key" in report_section` reads whether the key is there.
                # `":" in dst` is a substring test on a string: not a key.
                keys = frozenset(v for v in left if v[0] == "const"
                                 and isinstance(v[1], str) and _is_schema_key(v[1]))
                if keys:
                    self.access(frozenset(v for v in rvals if v[0] == "path"), keys, e)
        return _EMPTY

    def _Subscript(self, e: ast.Subscript) -> Vals:
        vals = self.expr(e.value)
        if isinstance(e.slice, ast.Slice):
            for part in (e.slice.lower, e.slice.upper, e.slice.step):
                self.expr(part)
            return vals
        return self.access(vals, self.expr(e.slice), e)

    def _Attribute(self, e: ast.Attribute) -> Vals:
        vals = self.expr(e.value)
        # _Node.data is the dict the node wraps.
        return frozenset(v for v in vals if v[0] == "path") if e.attr == "data" else _EMPTY

    def _comprehension(self, e: ast.ListComp | ast.SetComp | ast.GeneratorExp | ast.DictComp,
                       elt: list[ast.expr]) -> list[Vals]:
        names = {n.id for g in e.generators for n in ast.walk(g.target)
                 if isinstance(n, ast.Name)}
        saved = {n: self.env[n] for n in names}
        for g in e.generators:
            for n in (x.id for x in ast.walk(g.target) if isinstance(x, ast.Name)):
                self.env[n] = _EMPTY
            self.bind(g.target, _elements(self.expr(g.iter)))
            for cond in g.ifs:
                self.expr(cond)
        out = [self.expr(x) for x in elt]
        for n, vals in saved.items():  # comprehension variables do not leak
            self.env[n] = vals
        return out

    def _ListComp(self, e: ast.ListComp) -> Vals:
        (vals,) = self._comprehension(e, [e.elt])
        return frozenset({("list", vals)})

    _SetComp = _GeneratorExp = _ListComp

    def _DictComp(self, e: ast.DictComp) -> Vals:
        _k, vals = self._comprehension(e, [e.key, e.value])
        return frozenset({("dict", ((None, vals),))})

    def _Lambda(self, e: ast.Lambda) -> Vals:
        self.expr(e.body)
        return _EMPTY

    def _Call(self, e: ast.Call) -> Vals:
        args = [self.expr(a) for a in e.args]
        kwargs = {k.arg: self.expr(k.value) for k in e.keywords}
        f = e.func
        if isinstance(f, ast.Attribute):
            return self._method(e, f, args, kwargs)
        name = f.id if isinstance(f, ast.Name) else None
        if name is None:
            self.expr(f)
            return _EMPTY
        target = self.o.resolve(self.mod, name)
        if target is not None:
            mod, fn = target
            return self.o._call(mod, fn, self._bind_args(fn, args, kwargs), self.depth + 1)
        first = args[0] if args else _EMPTY
        if name in _PASSTHROUGH:
            return first
        if name in _SEQUENCE_OF:
            return frozenset({("list", _elements(first))})
        if name == "next":
            return _elements(first) | (args[1] if len(args) > 1 else _EMPTY)
        if name == "enumerate":
            return frozenset({("list", frozenset({("tuple", (_EMPTY, _elements(first)))}))})
        if name == "zip":
            return frozenset({("list", frozenset({("tuple", tuple(_elements(a) for a in args))}))})
        if name in _CONSUME:
            return _EMPTY
        self._handoff(e, name, args, kwargs)
        return _EMPTY

    def _bind_args(self, fn: ast.AST, args: list[Vals], kwargs: dict[str | None, Vals]) -> dict:
        a = fn.args
        positional = [*a.posonlyargs, *a.args]
        env: dict[str, Vals] = {}
        for i, vals in enumerate(args):
            if i < len(positional):
                env[positional[i].arg] = vals
            elif a.vararg is not None:
                env[a.vararg.arg] = env.get(a.vararg.arg, _EMPTY) | {("list", vals)}
        names = {x.arg for x in [*positional, *a.kwonlyargs]}
        for k, vals in kwargs.items():
            if k in names:
                env[k] = vals
            elif a.kwarg is not None:
                env[a.kwarg.arg] = env.get(a.kwarg.arg, _EMPTY) | {("dict", ((k, vals),))}
        return env

    def _method(self, e: ast.Call, f: ast.Attribute, args: list[Vals],
                kwargs: dict[str | None, Vals]) -> Vals:
        recv = self.expr(f.value)
        tracked = frozenset(v for v in recv if v[0] in ("path", "dict", "list", "tuple"))
        m = f.attr
        if m in _KEY_METHODS and args and tracked:
            default = args[1] if len(args) > 1 else kwargs.get("default", _EMPTY)
            return self.access(tracked, args[0], e) | default
        if m == "pop" and tracked:
            return _elements(tracked)
        if m == "required_texts" and tracked:
            for a in args:
                self.access(tracked, a, e)
            return _EMPTY
        if m == "items" and tracked:
            if args:  # _Node.items(key): the object elements of a list
                return self.access(tracked, args[0], e)
            out: set[Val] = set()
            for v in tracked:
                if v[0] == "path":
                    out.add(("tuple", (_EMPTY, frozenset({("path", _child(v[1], ANY))}))))
                elif v[0] == "dict":
                    for k, item in v[1]:
                        out.add(("tuple", (frozenset({_const(k)}) if k else _EMPTY, item)))
            return frozenset({("list", frozenset(out))})
        if m == "values" and tracked:
            out = set()
            for v in tracked:
                if v[0] == "path":
                    out.add(("path", _child(v[1], ANY)))
                elif v[0] == "dict":
                    for _, item in v[1]:
                        out |= item
            return frozenset({("list", frozenset(out))})
        if m == "copy":
            return tracked
        # Collections built up in place.
        if isinstance(f.value, ast.Name) and m in ("append", "add", "extend", "insert", "update"):
            vals = args[-1] if args else _EMPTY
            if m == "extend":
                vals = _elements(vals)
            new = ("dict", ((None, frozenset(x for d in vals if d[0] == "dict"
                                              for _, i in d[1] for x in i)),)) \
                if m == "update" else ("list", vals)
            self.env[f.value.id] = self.env[f.value.id] | {new}
            return _EMPTY
        if (m == "append" and isinstance(f.value, ast.Call)
                and isinstance(f.value.func, ast.Attribute)
                and f.value.func.attr == "setdefault"
                and isinstance(f.value.func.value, ast.Name)):
            # d.setdefault(k, []).append(v)
            d = f.value.func.value.id
            self.env[d] = self.env[d] | {("dict", ((None, frozenset({("list", args[0])})),))}
            return _EMPTY
        if not tracked and m not in _CONSUME and m not in _KEY_METHODS:
            self._handoff(e, ast.unparse(f), args, kwargs)
        return _EMPTY

    def _handoff(self, e: ast.Call, callee: str, args: list[Vals],
                 kwargs: dict[str | None, Vals]) -> None:
        for vals in (*args, *kwargs.values()):
            for v in vals:
                if v[0] == "path" and ANY not in v[1]:
                    self.o.handoffs.add((self.site(e), callee, v[1]))


def consumer_reads(sources: dict[str, str] | None = None,
                   roots: dict[str, frozenset[str]] | None = None) -> ConsumerReads:
    """Analyse the real consumers, or the given sources (for the guard's own tests)."""
    if sources is None:
        sources = {rel: (ROOT / rel).read_text() for rel in (*CONSUMERS, *FOLLOWED)}
        roots = CONSUMERS
    return ConsumerReads(sources, roots or {}).analyse()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _cmd_shape(argv: list[str]) -> None:
    eras: dict[str, dict] = {}
    it = iter(argv)
    for flag in it:
        if flag != "--era":
            raise SystemExit(f"unexpected argument {flag!r}")
        era, rest = next(it).split(":", 1)
        label, path = rest.split("=", 1)
        body = eras.setdefault(era, {"sources": [], "paths": defaultdict(set)})
        body["sources"].append(label)
        for p, types in reduce_report(json.loads(Path(path).read_text())).items():
            body["paths"][path_str(p)] |= types
    out = {
        "_about": ("Key shape of real report.json files (#409): key paths and JSON types "
                   "only, no values. Built by tests/report_keys.py from reports read "
                   "off the host; '*' is a data-keyed dict, '[]' a list element."),
        "eras": {era: {"sources": body["sources"],
                       "paths": {p: sorted(t) for p, t in sorted(body["paths"].items())}}
                 for era, body in eras.items()},
    }
    json.dump(out, sys.stdout, indent=1, sort_keys=False)
    sys.stdout.write("\n")


def _cmd_reads() -> None:
    r = consumer_reads()
    for path in sorted(r.reads, key=path_str):
        print(path_str(path), "  ", sorted(str(s) for s in r.reads[path])[0])
    print("\n# dynamic keys")
    for site, path in sorted(r.dynamic, key=str):
        print(site, path_str(path))
    print("\n# handoffs")
    for site, callee, path in sorted(r.handoffs, key=str):
        print(site, callee, path_str(path) or "<report>")


if __name__ == "__main__":
    if sys.argv[1:2] == ["shape"]:
        _cmd_shape(sys.argv[2:])
    elif sys.argv[1:2] == ["reads"]:
        _cmd_reads()
    else:
        raise SystemExit(__doc__)
