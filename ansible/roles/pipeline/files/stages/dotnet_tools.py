# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Agentic .NET analysis: an index over ILSpy's C# and the tools that read it (#646).

WHY THIS EXISTS. The .NET interpret path was one request: strings, 50 class
summaries and up to 100,000 characters of decompiled C#, sent at once. On the
CPU-only host that is 38-58k tokens of prefill — 45 to 90 minutes for ONE call,
which the stage budget cannot interrupt because nothing is written to stdout
until it returns. quasarrat and warzonerat ran past the budget (redet644,
2026-09-27). formbook finished and was fooled: 95k characters of a Uzbek card
game, and six lines in one method that build a byte list from bitmap pixels and
load it with `LateBinding.LateGet(Thread.GetDomain(), null, "Load", ...)` — a
grep for `Assembly.Load` finds nothing.

The native Ghidra path already works on this hardware because it is AGENTIC:
a small first message and tools to pull code on demand, in short turns. This
module gives .NET the same shape:

  * `CSharpIndex` parses the decompiled source into namespaces, types and
    members with exact spans, so a method can be fetched by name.
  * `scan_suspicious_constructs` lists the places a reader should look first
    (reflection by string name, assembly loading, byte building, P/Invoke,
    crypto, process/registry/network APIs), by `Class.Method`.
  * `build_dotnet_agentic_init` builds the init payload: assembly metadata, a
    bounded table of contents, strings of interest and the construct list —
    and the full source, which the ORCHESTRATOR keeps (`agent_payload` in
    stages/interpret.py strips it before the container sees the payload).
  * `DotnetToolbox.call` serves the tools from that source.

WHERE THE TOOLS RUN — the orchestrator, not the interpret container. The source
could be served in-process by the container, but then no tool call would ever
cross the stdin/stdout protocol, and that protocol is the only way the pipeline
can stop a run: the container reads stdin only while waiting for a tool result,
so `force_final` and the synthesis reserve (#240, #663) are delivered as the
answer to a tool call. In-process tools would leave a run the budget cannot
reach, which is the defect this change exists to remove. Brokering also puts
every call in the same audit log and turn trail as a Ghidra call, which the
eval grounds claims against. The interpret container keeps --network=none and
gains nothing new to reach.

NOTHING IS DROPPED. Every result is bounded, and every bound says so: source is
paged (`page`/`pages`), lists carry `total` and `truncated`. Everything the
analyser stored stays reachable through `search_source`, `get_source_lines`
and the paged getters. What the analyser did NOT store (it keeps the first
100,000 characters of a larger decompilation, `source_truncated_by_analyser`)
is outside this index, and the payload says so.

THE SOURCE IS ATTACKER-CONTROLLED. Nothing here executes it. Results are
returned as data; the container wraps every tool result in the UNTRUSTED_DATA
fence with `neutralize_delimiters` like any Ghidra result. The one
model-supplied regex (`search_source`) runs in a child process with a timeout,
because Python's `re` has none and a catastrophic pattern over 100k characters
would otherwise hang the pipeline process itself.
"""
from __future__ import annotations

import bisect
import json
import re
import subprocess
import sys
from dataclasses import dataclass, field

from stages.single_shot_init import _source_provenance, build_dotnet_init

# --- Result bounds -----------------------------------------------------------
#
# A page of source. The native local path caps a Ghidra result at 12,000 chars
# (TOOL_RESULT_CHAR_CAP); a C# page is smaller because the per-turn limit (3
# calls) multiplies it and C# tokenizes worse than Ghidra pseudocode on this
# model (~2.5 chars/token measured on the redet644 prompts, below). 6,000 chars
# x 3 calls bounds a turn at ~7k tokens of new context.
SOURCE_PAGE_CHARS = 6_000
#: Search hits returned at most per call, and the default.
SEARCH_MAX_HITS = 50
SEARCH_DEFAULT_HITS = 20
#: One hit's line, centred on the match.
SEARCH_LINE_CHARS = 240
#: Lines `get_source_lines` returns at most.
LINES_MAX = 150
#: Entries `list_methods` / `list_classes` return at most.
LIST_MAX = 150
#: Seconds a model-supplied regex may run before the search is abandoned.
SEARCH_TIMEOUT_S = 10.0
#: Longest pattern accepted.
PATTERN_MAX = 200

# --- Initial-message bounds (what the agent sees before any tool call) --------
TOC_MAX_CLASSES = 200
TOC_MAX_METHODS = 220
CONSTRUCT_MAX_LOCATIONS = 40
USINGS_MAX = 60

#: The phrase every negative answer carries. The eval counts a tool error as a
#: broken TOOL LAYER unless it recognises the error as the tool answering "no"
#: (llm_ab_re._SEMANTIC_TOOL_ERRORS); this is the marker it recognises.
NOT_FOUND = "not found in the decompiled source"

DOTNET_TOOL_NAMES = ("list_classes", "list_methods", "get_method_source",
                     "get_class_source", "search_source", "get_source_lines")


# --- Masking: strings and comments out, so braces can be counted -------------

def mask_source(src: str) -> str:
    """`src` with comments and string contents blanked; see `mask_with_comments`."""
    return mask_with_comments(src)[0]


def mask_with_comments(src: str) -> tuple[str, list[tuple[int, int]]]:
    """(`src` with the CONTENTS of comments, strings and chars replaced by spaces.

    Same length, newlines kept, so every offset and line number in the masked
    text is the offset and line number in the original. Brace matching and
    declaration parsing run on this; names and source text are read from the
    original.

    Handles `//` and `/* */` comments, regular, verbatim (`@"..."`, `""`
    escape) and interpolated (`$"..."`, `$@`/`@$`) strings — including
    interpolation holes, which are code and may contain strings of their own —
    and char literals. A sample can put a `}` in any of these; counting it
    would shift every span after it.

    The second element lists comment spans: the construct scan must skip a hit
    inside a comment (a sample can write any API name there to steer a reader)
    and must NOT skip one inside a string (`"Load"` is the formbook signal), and
    both are blank in the masked text.
    """
    out = list(src)
    n = len(src)
    comments: list[tuple[int, int]] = []

    def blank(a: int, b: int) -> None:
        for k in range(a, min(b, n)):
            if out[k] != "\n":
                out[k] = " "

    def scan_string(i: int, verbatim: bool, interp: bool) -> int:
        """i is at the opening quote; return the index after the closing one."""
        j = i + 1
        while j < n:
            c = src[j]
            if verbatim and c == '"':
                if j + 1 < n and src[j + 1] == '"':
                    blank(j, j + 2)
                    j += 2
                    continue
                return j + 1
            if not verbatim and c == "\\":
                blank(j, j + 2)
                j += 2
                continue
            if not verbatim and c == '"':
                return j + 1
            if not verbatim and c == "\n":
                return j            # unterminated: do not swallow the file
            if interp and c == "{":
                if j + 1 < n and src[j + 1] == "{":
                    blank(j, j + 2)
                    j += 2
                    continue
                # A hole: code, masked as code would be, then blanked so its
                # braces never reach the structural parser.
                start = j
                j = scan_code(j + 1, stop_at_close=True)
                blank(start, j)
                continue
            if interp and c == "}" and j + 1 < n and src[j + 1] == "}":
                blank(j, j + 2)
                j += 2
                continue
            blank(j, j + 1)
            j += 1
        return j

    def scan_code(i: int, stop_at_close: bool = False) -> int:
        depth = 0
        while i < n:
            c = src[i]
            if c == "/" and i + 1 < n and src[i + 1] == "/":
                end = src.find("\n", i)
                end = n if end < 0 else end
                blank(i, end)
                comments.append((i, end))
                i = end
                continue
            if c == "/" and i + 1 < n and src[i + 1] == "*":
                end = src.find("*/", i + 2)
                end = n if end < 0 else end + 2
                blank(i, end)
                comments.append((i, end))
                i = end
                continue
            if c in "$@" and i + 1 < n and src[i + 1] in '"$@':
                # $"  @"  $@"  @$"
                k = i
                verbatim = interp = False
                while k < n and src[k] in "$@":
                    verbatim |= src[k] == "@"
                    interp |= src[k] == "$"
                    k += 1
                if k < n and src[k] == '"':
                    i = scan_string(k, verbatim, interp)
                    continue
                i += 1
                continue
            if c == '"':
                i = scan_string(i, False, False)
                continue
            if c == "'":
                # Char literal: 'x', '\'', 'A'. Bounded so a stray quote
                # (none in valid C#) cannot blank a long run.
                m = re.match(r"'(?:\\.|\\u[0-9A-Fa-f]{4}|[^'\\\n])'", src[i:i + 8])
                if m:
                    blank(i + 1, i + m.end() - 1)
                    i += m.end()
                    continue
                i += 1
                continue
            if stop_at_close:
                if c == "{":
                    depth += 1
                elif c == "}":
                    if depth == 0:
                        return i + 1
                    depth -= 1
            i += 1
        return i

    scan_code(0)
    return "".join(out), comments


# --- Declarations ------------------------------------------------------------

# Names admit `<` and `>`: ILSpy writes compiler-generated types as `<Module>`,
# `<PrivateImplementationDetails>`, `<>c__DisplayClass1_0`, and obfuscators put
# their whole payload in `<Module>` (quasarrat's stored source is ONLY that
# class). A name pattern of plain identifiers parsed that file as zero types.
_TYPE_RE = re.compile(
    r"\b(class|struct|interface|enum|record(?:\s+(?:class|struct))?)\s+(@?[A-Za-z_<][\w<>`]*)")
_NAMESPACE_RE = re.compile(r"\A\s*namespace\s+([\w.@]+)\s*\Z")
_OPERATOR_RE = re.compile(r"\boperator\s*(\S+)\s*\Z")
_MODIFIERS = frozenset({
    "public", "private", "protected", "internal", "static", "virtual", "override",
    "abstract", "sealed", "extern", "unsafe", "async", "new", "readonly", "partial",
    "volatile", "const", "implicit", "explicit", "fixed", "ref", "required"})


def _plain_name(name: str) -> str:
    """`Foo` from `Foo<T>`; `<Module>` and `<>c` stay whole (the brackets ARE
    the name); a leading `@` (verbatim identifier) dropped."""
    name = name.lstrip("@")
    k = name.find("<")
    return name[:k] if k > 0 and not name.startswith("~<") else name


def _member_name(before_paren: str) -> str | None:
    """The member name in the text before its parameter list.

    `void M<T, U>` -> `M` (generic arguments dropped, and they may contain
    spaces); `static <Module>` -> `<Module>` (a static constructor of a
    compiler-named type: the brackets are the name, not generic arguments).
    """
    s = before_paren.rstrip()
    if s.endswith(">"):
        depth, k = 0, len(s) - 1
        while k >= 0:
            if s[k] == ">":
                depth += 1
            elif s[k] == "<":
                depth -= 1
                if depth == 0:
                    break
            k -= 1
        if k > 0 and (s[k - 1].isalnum() or s[k - 1] in "_`"):
            s = s[:k]                      # generic arguments of a named method
    tokens = s.split()
    if not tokens:
        return None
    name = tokens[-1].lstrip("@")
    return name if re.fullmatch(r"~?[A-Za-z_<][\w<>`.]*", name) else None


def _strip_attributes(header: str) -> tuple[str, str]:
    """(attributes, rest). Leading `[...]` blocks, bracket-balanced."""
    i, n = 0, len(header)
    attrs: list[str] = []
    while True:
        while i < n and header[i].isspace():
            i += 1
        if i >= n or header[i] != "[":
            break
        depth, j = 0, i
        while j < n:
            if header[j] == "[":
                depth += 1
            elif header[j] == "]":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        attrs.append(header[i:j + 1])
        i = j + 1
    return " ".join(attrs), header[i:]


def _top_level(text: str, ch: str) -> int:
    """Index of the first `ch` outside (), [], <> nesting, or -1."""
    depth = 0
    for k, c in enumerate(text):
        if c in "([<":
            depth += 1
        elif c in ")]>":
            depth = max(0, depth - 1)
        elif c == ch and depth == 0:
            return k
    return -1


def _split_params(params: str) -> list[str]:
    out, depth, cur = [], 0, []
    for c in params:
        if c in "([<{":
            depth += 1
        elif c in ")]>}":
            depth -= 1
        if c == "," and depth == 0:
            out.append("".join(cur))
            cur = []
        else:
            cur.append(c)
    if "".join(cur).strip():
        out.append("".join(cur))
    return out


def compact_signature(header: str) -> str:
    """`List<byte> Anneal(Bitmap, int)` from a full declaration header.

    Modifiers, attributes, parameter names and default values dropped: the
    table of contents is the agent's map, and every character in it is paid
    for on every turn. `list_methods` returns the full header.
    """
    _, rest = _strip_attributes(header)
    rest = " ".join(rest.split())
    p = rest.find("(")
    if p < 0:
        words = [w for w in rest.split() if w not in _MODIFIERS]
        return " ".join(words)[:160]
    close, depth = -1, 0
    for k in range(p, len(rest)):
        if rest[k] == "(":
            depth += 1
        elif rest[k] == ")":
            depth -= 1
            if depth == 0:
                close = k
                break
    head = [w for w in rest[:p].split() if w not in _MODIFIERS]
    params = rest[p + 1:close if close > 0 else len(rest)]
    types = []
    for prm in _split_params(params):
        prm = prm.split("=", 1)[0].strip()
        _, prm = _strip_attributes(prm)
        words = [w for w in prm.split() if w not in ("this", "params", "in", "out", "ref")]
        types.append(" ".join(words[:-1]) if len(words) > 1 else " ".join(words))
    return (" ".join(head) + "(" + ", ".join(types) + ")")[:200]


@dataclass
class Member:
    name: str
    kind: str              # method | ctor | property | operator | extern | expression
    header: str            # full declaration, whitespace-collapsed, attributes kept
    signature: str         # compact
    start: int
    end: int
    line_start: int
    line_end: int

    @property
    def chars(self) -> int:
        return self.end - self.start


@dataclass
class TypeDecl:
    qualname: str
    name: str
    kind: str
    bases: str
    start: int
    end: int
    line_start: int
    line_end: int
    members: list[Member] = field(default_factory=list)

    @property
    def chars(self) -> int:
        return self.end - self.start


class CSharpIndex:
    """Namespaces, types and members of one decompiled source, with exact spans.

    A structural parse, not a compiler: it counts braces on the masked source
    and classifies the text before each `{` (and each type-level `;`, for
    extern and expression-bodied members). ILSpy's output is regular — one
    declaration per header, Allman braces — and the parse only has to find
    spans, never meaning. A header it cannot classify becomes an anonymous
    block inside its parent, so its text is still inside the parent's span.
    """

    def __init__(self, source: str) -> None:
        self.source = source or ""
        self.masked, self._comments = mask_with_comments(self.source)
        self._comment_starts = [a for a, _ in self._comments]
        self._line_starts = [0] + [m.end() for m in re.finditer("\n", self.source)]
        self.types: list[TypeDecl] = []
        self.namespaces: list[str] = []
        self._parse()
        self.types.sort(key=lambda t: t.start)
        # (start, end, label) for every member, sorted, for offset -> location.
        self._spans = sorted(
            ((m.start, m.end, f"{t.qualname}.{m.name}") for t in self.types for m in t.members),
            key=lambda s: s[0])
        self._span_starts = [s[0] for s in self._spans]

    # -- positions --
    def in_comment(self, offset: int) -> bool:
        k = bisect.bisect_right(self._comment_starts, offset) - 1
        return k >= 0 and self._comments[k][0] <= offset < self._comments[k][1]

    def line_start_of(self, offset: int) -> int:
        """Offset of the start of the line holding `offset`, so a fetched
        member keeps its first line's indentation."""
        return self._line_starts[self.line_of(offset) - 1]

    def line_of(self, offset: int) -> int:
        """1-based line number of `offset`."""
        return bisect.bisect_right(self._line_starts, offset)

    @property
    def line_count(self) -> int:
        return len(self._line_starts)

    def location_of(self, offset: int) -> str:
        """`Namespace.Class.Method` containing `offset`, else the innermost type,
        else `<assembly>` (usings and assembly attributes)."""
        # Member spans are disjoint (members do not nest; a nested type's
        # members sit inside the outer TYPE, not inside an outer member), so
        # only the nearest span starting at or before `offset` can contain it.
        k = bisect.bisect_right(self._span_starts, offset) - 1
        if k >= 0 and self._spans[k][0] <= offset < self._spans[k][1]:
            return self._spans[k][2]
        inner = None
        for t in self.types:
            if t.start <= offset < t.end and (inner is None or t.start >= inner.start):
                inner = t
        return inner.qualname if inner else "<assembly>"

    # -- parse --
    def _parse(self) -> None:
        src, masked = self.source, self.masked
        # Frame: (kind, name, start, type_index or None)
        stack: list[dict] = [{"kind": "root", "ns": [], "type": None}]
        boundary = 0
        for i, c in enumerate(masked):
            if c not in "{};":
                continue
            frame = stack[-1]
            if c == "{":
                raw_header = src[boundary:i]
                header_masked = masked[boundary:i]
                lead = len(header_masked) - len(header_masked.lstrip())
                hstart = boundary + lead
                new = self._classify(frame, header_masked.strip(), raw_header.strip(), hstart, i)
                stack.append(new)
                boundary = i + 1
            elif c == "}":
                if len(stack) > 1:
                    done = stack.pop()
                    end = i + 1
                    if done["kind"] == "type":
                        t = self.types[done["type"]]
                        t.end, t.line_end = end, self.line_of(i)
                    elif done["kind"] == "member":
                        m = done["member"]
                        m.end, m.line_end = end, self.line_of(i)
                boundary = i + 1
            else:  # ';'
                if frame["kind"] == "type":
                    stmt_masked = masked[boundary:i]
                    lead = len(stmt_masked) - len(stmt_masked.lstrip())
                    self._type_level_statement(frame, stmt_masked.strip(),
                                               src[boundary:i].strip(), boundary + lead, i + 1)
                boundary = i + 1
        # Unclosed frames (a truncated source ends mid-class): close at EOF so
        # the partial class and method are still fetchable.
        end = len(src)
        for done in stack[1:]:
            if done["kind"] == "type":
                t = self.types[done["type"]]
                t.end, t.line_end = end, self.line_of(end - 1)
            elif done["kind"] == "member":
                m = done["member"]
                m.end, m.line_end = end, self.line_of(end - 1)

    def _ns_of(self, frame: dict) -> list[str]:
        return frame.get("ns", [])

    def _classify(self, frame: dict, header: str, raw: str, hstart: int, brace: int) -> dict:
        kind = frame["kind"]
        if kind in ("member", "block"):
            return {"kind": "block", "ns": frame.get("ns", []), "type": frame.get("type")}
        _, body = _strip_attributes(header)
        body = body.strip()
        m = _NAMESPACE_RE.match(body)
        if m and kind in ("root", "namespace"):
            ns = self._ns_of(frame) + [m.group(1)]
            full = ".".join(ns)
            if full not in self.namespaces:
                self.namespaces.append(full)
            return {"kind": "namespace", "ns": ns, "type": None}
        paren = body.find("(")
        tm = _TYPE_RE.search(body if paren < 0 else body[:paren])
        if tm and "=" not in (body if paren < 0 else body[:paren]):
            name = _plain_name(tm.group(2))
            if kind == "type":
                parent = self.types[frame["type"]]
                qual = f"{parent.qualname}.{name}"
            else:
                qual = ".".join(self._ns_of(frame) + [name])
            after = body[tm.end():]
            colon = _top_level(after, ":")
            bases = " ".join(after[colon + 1:].split())[:160] if colon >= 0 else ""
            bases = re.split(r"\bwhere\b", bases)[0].strip()
            t = TypeDecl(qual, name, tm.group(1).split()[0], bases, hstart, len(self.source),
                         self.line_of(hstart), self.line_count)
            self.types.append(t)
            return {"kind": "type", "ns": self._ns_of(frame), "type": len(self.types) - 1}
        if kind != "type":
            return {"kind": "block", "ns": self._ns_of(frame), "type": None}
        # A member of a type. A top-level `=` is a field or property initializer
        # (`int[] x = new int[] { 1 }`, `X { get; } = new()`), not a declaration.
        if _top_level(body, "=") >= 0 and "=>" not in body and "operator" not in body:
            return {"kind": "block", "ns": self._ns_of(frame), "type": frame["type"]}
        member = self._member(body, raw, hstart)
        if member is None:
            return {"kind": "block", "ns": self._ns_of(frame), "type": frame["type"]}
        self.types[frame["type"]].members.append(member)
        return {"kind": "member", "ns": self._ns_of(frame), "type": frame["type"],
                "member": member}

    def _member(self, body: str, raw: str, hstart: int, end: int | None = None,
                expression: str | None = None) -> Member | None:
        """A member from its declaration header. `expression` is set for a
        `;`-terminated declaration: "arrow" for an expression-bodied member,
        "none" for one with no body at all (extern, abstract, interface)."""
        paren = body.find("(")
        if paren >= 0 and (body.find("[") < 0 or body.find("[") > paren):
            before = body[:paren]
            om = _OPERATOR_RE.search(before)
            if om:
                name, kind = f"operator {om.group(1)}", "operator"
            else:
                name = _member_name(before)
                if not name:
                    return None
                words = before.split()
                kind = "ctor" if len([w for w in words if w not in _MODIFIERS]) == 1 else "method"
                if name.startswith("~"):
                    kind = "ctor"
        elif "this[" in body.replace(" ", ""):
            name, kind = "this[]", "property"
        else:
            words = re.findall(r"@?[A-Za-z_]\w*", body)
            if not words:
                return None
            name, kind = words[-1].lstrip("@"), "property"
        if expression and kind != "property":
            kind = ("extern" if re.search(r"\bextern\b", body)
                    else "expression" if expression == "arrow" else "bodiless")
        header = " ".join(raw.split())
        start = hstart
        return Member(name, kind, header[:400], compact_signature(body), start,
                      end if end is not None else len(self.source),
                      self.line_of(start), self.line_of(end - 1) if end else self.line_count)

    def _type_level_statement(self, frame: dict, stmt: str, raw: str, start: int, end: int) -> None:
        """A `;`-terminated declaration directly inside a type.

        Fields are skipped (they are in the class source). Kept: P/Invoke
        (`[DllImport] static extern ...;`), abstract/interface methods and
        expression-bodied members, which have no braces and would otherwise be
        invisible to `get_method_source`.
        """
        if not stmt or ("(" not in stmt and "=>" not in stmt):
            return
        _, body = _strip_attributes(stmt)
        body = body.strip()
        arrow = body.find("=>")
        head = body[:arrow] if arrow >= 0 else body
        if _top_level(head, "=") >= 0 and "operator" not in head:
            return                           # a field with an initializer
        if "(" not in head and arrow < 0:
            return                           # a plain field or event
        if "(" not in head:
            # `int X => y;` — an expression-bodied property.
            words = re.findall(r"@?[A-Za-z_]\w*", head)
            if not words:
                return
            m = Member(words[-1].lstrip("@"), "property", " ".join(raw.split())[:400],
                       compact_signature(head), start, end, self.line_of(start),
                       self.line_of(end - 1))
            self.types[frame["type"]].members.append(m)
            return
        m = self._member(head.strip(), raw, start, end=end,
                         expression="arrow" if arrow >= 0 else "none")
        if m is not None:
            self.types[frame["type"]].members.append(m)

    # -- lookup --
    def find_types(self, name: str) -> list[TypeDecl]:
        """Types matching `name`: exact qualified name, else a dotted suffix
        (`BattleForm`, `Formalar.BattleForm`), case-sensitive first, then not."""
        name = (name or "").strip().lstrip("@")
        exact = [t for t in self.types if t.qualname == name]
        if exact:
            return exact
        suffix = [t for t in self.types if t.qualname.endswith("." + name) or t.qualname == name]
        if suffix:
            return suffix
        low = name.lower()
        return [t for t in self.types
                if t.qualname.lower() == low or t.qualname.lower().endswith("." + low)]


# --- Suspicious constructs -----------------------------------------------------
#
# (category, weight, pattern). Weight ranks a LOCATION by what it contains; the
# list is a reading order, not a verdict, and says so in the message.
#
# Reflection by STRING NAME is its own category, and the heaviest: the formbook
# loader calls `LateBinding.LateGet(Thread.GetDomain(), null, "Load", ...)`, so
# nothing that looks for the identifier `Assembly.Load` sees it. The name of a
# sensitive member as a string literal is the signal.
_SENSITIVE_MEMBER_NAMES = (
    "Load", "LoadFile", "LoadFrom", "LoadWithPartialName", "UnsafeLoadFrom", "Invoke",
    "InvokeMember", "EntryPoint", "GetMethod", "GetMethods", "GetType", "GetTypes",
    "GetExportedTypes", "CreateInstance", "CreateDelegate", "DynamicInvoke",
    "FromBase64String", "GetDomain", "CurrentDomain", "GetManifestResourceStream",
    "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "WriteProcessMemory",
    "CreateRemoteThread", "NtUnmapViewOfSection", "ZwUnmapViewOfSection",
    "SetThreadContext", "Wow64SetThreadContext", "ResumeThread", "GetProcAddress",
    "LoadLibrary", "LoadLibraryA", "LoadLibraryW", "CreateProcess", "CreateProcessA",
    "CreateProcessW")

CONSTRUCT_PATTERNS: tuple[tuple[str, int, str], ...] = (
    ("reflection_by_name", 6,
     r'"(?:' + "|".join(_SENSITIVE_MEMBER_NAMES) + r')"'),
    ("assembly_load", 6,
     r"\bAssembly\s*\.\s*(?:Load\w*|UnsafeLoadFrom)\s*\(|\bAppDomain\s*\.\s*CurrentDomain\s*\.\s*Load\b"
     r"|\bThread\s*\.\s*GetDomain\s*\(|\.EntryPoint\b|\bGetExportedTypes\s*\("),
    ("late_binding", 5,
     r"\b(?:New)?LateBinding\s*\.\s*\w+|\bNewLateBinding\b|\bCallByName\s*\(|\bInvokeMember\s*\("),
    ("dynamic_code", 5,
     r"\b(?:CSharpCodeProvider|VBCodeProvider|CompileAssemblyFrom\w+|ILGenerator|AssemblyBuilder"
     r"|DynamicMethod|TypeBuilder)\b"),
    ("native_injection_api", 5,
     r"\b(?:VirtualAlloc(?:Ex)?|VirtualProtect(?:Ex)?|WriteProcessMemory|ReadProcessMemory"
     r"|CreateRemoteThread|(?:Nt|Zw)UnmapViewOfSection|(?:Wow64)?SetThreadContext"
     r"|(?:Wow64)?GetThreadContext|ResumeThread|QueueUserAPC|NtCreateThreadEx"
     r"|RtlMoveMemory|CallWindowProc|EnumWindows|GetDelegateForFunctionPointer)\b"),
    ("reflection", 3,
     r"\bActivator\s*\.\s*CreateInstance\b|\.\s*GetMethod\s*\(|\.\s*GetMethods\s*\(\s*\)"
     r"|\bType\s*\.\s*GetType\s*\(|\.\s*GetType\s*\(\s*\"|\bMethodInfo\b|\.\s*DynamicInvoke\s*\("
     r"|\bDelegate\s*\.\s*CreateDelegate\b|\.\s*GetTypes\s*\(\s*\)"),
    ("pinvoke", 4,
     r"\[\s*DllImport\s*\(|\bstatic\s+extern\b|\bGetProcAddress\b|\bLoadLibrary\w*\b"
     r"|\bMarshal\s*\.\s*(?:Copy|AllocHGlobal|ReadIntPtr|WriteIntPtr|PtrToStructure)\b"),
    ("byte_building", 2,
     r"\bList\s*<\s*byte\s*>|\bnew\s+byte\s*\[|\bBuffer\s*\.\s*BlockCopy\b|\bArray\s*\.\s*Reverse\b"),
    ("encoding", 3,
     r"\bConvert\s*\.\s*FromBase64(?:String|CharArray)\b|\bFromHex\w*\b|\bStrReverse\b"
     r"|\bConvert\s*\.\s*ToByte\s*\([^;]*,\s*16\s*\)"),
    ("compression", 2, r"\b(?:GZipStream|DeflateStream|ZipArchive|Decompress)\b"),
    ("resources_and_pixels", 3,
     r"\bGetManifestResource(?:Stream|Names)\b|\bResourceManager\b|\.\s*GetObject\s*\("
     r"|\.\s*GetPixel\s*\(|\bLockBits\b"
     # `Resources.X` is a resource read; `System.Resources.Tools` is the
     # generated-code attribute every designer class carries, and is not.
     r"|\bResources\s*\.\s*(?!Tools\b|ResourceManager\b)[A-Za-z_]\w*"),
    ("crypto", 3,
     r"\b(?:RijndaelManaged|Rijndael\s*\.\s*Create|Aes(?:Managed|CryptoServiceProvider)"
     r"|Aes\s*\.\s*Create|(?:Triple)?DESCryptoServiceProvider|(?:Triple)?DES\s*\.\s*Create"
     r"|RSACryptoServiceProvider|RSA\s*\.\s*Create|MD5CryptoServiceProvider|MD5\s*\.\s*Create"
     r"|SHA(?:1|256|384|512)(?:Managed|CryptoServiceProvider)|SHA(?:1|256|384|512)\s*\.\s*Create"
     r"|HMACSHA\d+|HMACMD5|Rfc2898DeriveBytes|PasswordDeriveBytes|CreateDecryptor|CreateEncryptor"
     r"|TransformFinalBlock|ProtectedData\s*\.\s*Unprotect)\b"),
    ("process", 3,
     r"\bProcess\s*\.\s*Start\b|\bProcessStartInfo\b|\bProcess\s*\.\s*GetProcess\w*\b"
     r"|\bInteraction\s*\.\s*Shell\b|cmd\.exe|powershell|schtasks|\bWScript\.Shell\b"),
    ("registry", 3,
     r"\bRegistry\s*\.\s*\w+|\bRegistryKey\b|\.\s*OpenSubKey\s*\(|\.\s*CreateSubKey\s*\("
     r"|CurrentVersion\\\\Run"),
    ("network", 3,
     r"\b(?:TcpClient|TcpListener|UdpClient|Socket|WebClient|HttpWebRequest|HttpClient|SmtpClient"
     r"|FtpWebRequest|SslStream|NetworkStream|ServicePointManager)\b|\bWebRequest\s*\.\s*Create\b"
     r"|\b(?:Download|Upload)(?:String|Data|File|Values)\w*\b|\bDns\s*\.\s*\w+"
     r"|api\.telegram\.org|discord(?:app)?\.com/api/webhooks"),
    ("anti_analysis", 3,
     r"\bDebugger\s*\.\s*IsAttached\b|\bIsDebuggerPresent\b|\bCheckRemoteDebuggerPresent\b"
     r"|\bManagementObjectSearcher\b|Win32_(?:ComputerSystem|BIOS|DiskDrive|VideoController)"
     r"|VirtualBox|VBox\w*|vmware|SbieDll|\bThread\s*\.\s*Sleep\s*\("),
    ("collection", 3,
     r"\bGetAsyncKeyState\b|\bSetWindowsHookEx\w*\b|\bClipboard\s*\.\s*\w+|\bCopyFromScreen\b"
     r"|Login Data|\bwallet\b|Mozilla\\\\Firefox|User Data"),
    ("filesystem", 1,
     r"\bFile\s*\.\s*(?:WriteAllBytes|WriteAllText|Copy|Move|Delete|SetAttributes)\b"
     r"|\bEnvironment\s*\.\s*GetFolderPath\b|\bSpecialFolder\s*\.\s*\w+|\\\\Startup\\\\"),
)
_COMPILED = tuple((cat, w, re.compile(p, re.IGNORECASE if cat in ("process", "anti_analysis",
                                                                     "collection") else 0))
                  for cat, w, p in CONSTRUCT_PATTERNS)


def scan_suspicious_constructs(index: CSharpIndex,
                               max_locations: int = CONSTRUCT_MAX_LOCATIONS) -> dict:
    """Where to read first: suspicious constructs grouped by `Class.Method`.

    Patterns run on the ORIGINAL source (string literals are the point of
    `reflection_by_name`) but a hit inside a comment is skipped — a sample can
    write any API name in a comment to steer the reader.

    Locations are ranked by the summed weight of DISTINCT categories they hit,
    so a short method that builds bytes AND loads them by reflection outranks a
    long UI method that merely touches a resource many times. Bounded, with
    the total and the per-category counts reported, so the agent knows what
    the list omits and can `search_source` for the rest.
    """
    src = index.source
    by_loc: dict[str, dict] = {}
    cat_totals: dict[str, int] = {}
    for cat, weight, rx in _COMPILED:
        for m in rx.finditer(src):
            pos = m.start()
            if index.in_comment(pos):
                continue
            loc = index.location_of(pos)
            entry = by_loc.setdefault(loc, {"location": loc, "findings": {}, "first": pos})
            f = entry["findings"].setdefault(cat, {"category": cat, "weight": weight,
                                                  "count": 0, "line": index.line_of(pos),
                                                  "match": m.group(0)[:60]})
            f["count"] += 1
            entry["first"] = min(entry["first"], pos)
            cat_totals[cat] = cat_totals.get(cat, 0) + 1
    ranked = []
    for loc, entry in by_loc.items():
        findings = sorted(entry["findings"].values(), key=lambda f: (-f["weight"], f["line"]))
        score = sum(f["weight"] for f in findings)
        span = _span_for(index, loc)
        top = findings[0]
        line_text = _line_text(index, top["line"])
        ranked.append({
            "location": loc,
            "score": score,
            "lines": f"{span[0]}-{span[1]}" if span else None,
            "chars": span[2] if span else None,
            "findings": [{k: f[k] for k in ("category", "count", "line", "match")}
                         for f in findings],
            "example_line": top["line"],
            "example": _clip(line_text.strip(), 160),
        })
    ranked.sort(key=lambda e: (-e["score"], e["example_line"]))
    return {
        "locations": ranked[:max_locations],
        "locations_total": len(ranked),
        "truncated": len(ranked) > max_locations,
        "category_totals": dict(sorted(cat_totals.items(), key=lambda kv: -kv[1])),
    }


def _span_for(index: CSharpIndex, loc: str) -> tuple[int, int, int] | None:
    tname, _, mname = loc.rpartition(".")
    for t in index.types:
        if t.qualname == tname:
            for m in t.members:
                if m.name == mname:
                    return (m.line_start, m.line_end, m.chars)
        if t.qualname == loc:
            return (t.line_start, t.line_end, t.chars)
    return None


def _line_text(index: CSharpIndex, line: int) -> str:
    starts = index._line_starts
    a = starts[line - 1]
    b = starts[line] - 1 if line < len(starts) else len(index.source)
    return index.source[a:b]


def _clip(text: str, n: int) -> str:
    return text if len(text) <= n else text[:n] + "…"


# --- Assembly metadata and table of contents -----------------------------------

_ASSEMBLY_ATTR_RE = re.compile(r'^\[assembly:\s*(\w+)\s*\((.*)\)\]\s*$', re.M)
_KEEP_ATTRS = ("AssemblyTitle", "AssemblyDescription", "AssemblyCompany", "AssemblyProduct",
               "AssemblyCopyright", "AssemblyTrademark", "AssemblyFileVersion",
               "AssemblyVersion", "Guid", "TargetFramework", "AssemblyInformationalVersion",
               "InternalsVisibleTo")


def assembly_metadata(index: CSharpIndex) -> dict:
    """What the assembly says about itself, plus its entry points and imports."""
    attrs = {}
    for m in _ASSEMBLY_ATTR_RE.finditer(index.source):
        # Empty values ("") are skipped: ILSpy writes every attribute the
        # project template declared, and blank ones say nothing.
        if (m.group(1) in _KEEP_ATTRS and m.group(1) not in attrs
                and m.group(2).strip().strip('"')):
            attrs[m.group(1)] = _clip(m.group(2).strip(), 160)
    usings = re.findall(r"^using\s+([\w.]+(?:\s*=\s*[\w.<>]+)?)\s*;", index.source, re.M)
    entry = [f"{t.qualname}.{m.name}" for t in index.types for m in t.members
             if m.name == "Main" and re.search(r"\bstatic\b", m.header)]
    return {
        "attributes": attrs,
        "usings": usings[:USINGS_MAX],
        "usings_total": len(usings),
        "entry_points": entry,
        "namespaces": index.namespaces[:50],
        "type_count": len(index.types),
        "method_count": sum(len(t.members) for t in index.types),
        "line_count": index.line_count,
    }


def table_of_contents(index: CSharpIndex, priority: list[str] | None = None,
                      max_classes: int = TOC_MAX_CLASSES,
                      max_methods: int = TOC_MAX_METHODS) -> dict:
    """Types in source order with sizes; method signatures within a budget.

    Every type (up to `max_classes`) is listed with its member count and size.
    Member signatures are spent on the types in `priority` first (those with
    suspicious constructs), then in source order, until `max_methods` — so on
    a large assembly the budget lands where the scan pointed, and a type whose
    members were not listed says so (`methods_listed < methods`).
    """
    priority = priority or []
    order = sorted(range(len(index.types)), key=lambda k: (
        0 if index.types[k].qualname in priority else 1,
        priority.index(index.types[k].qualname) if index.types[k].qualname in priority else 0,
        index.types[k].start))
    budget = max_methods
    listed: dict[int, list[dict]] = {}
    for k in order:
        t = index.types[k]
        take = t.members[:max(0, budget)]
        budget -= len(take)
        listed[k] = [{"name": m.name, "sig": m.signature, "line": m.line_start,
                      "chars": m.chars} for m in take]
    classes = []
    for k, t in enumerate(index.types[:max_classes]):
        classes.append({
            "class": t.qualname, "kind": t.kind, "bases": t.bases,
            "lines": f"{t.line_start}-{t.line_end}", "chars": t.chars,
            "methods": len(t.members), "methods_listed": len(listed.get(k, [])),
            "members": listed.get(k, []),
        })
    total_methods = sum(len(t.members) for t in index.types)
    shown_methods = sum(c["methods_listed"] for c in classes)
    return {
        "classes": classes,
        "classes_total": len(index.types),
        "methods_total": total_methods,
        "methods_listed": shown_methods,
        "truncated": len(index.types) > max_classes or shown_methods < total_methods,
    }


def _class_priority(constructs: dict) -> list[str]:
    seen: list[str] = []
    for loc in constructs.get("locations", []):
        owner = loc["location"].rpartition(".")[0] or loc["location"]
        if owner not in seen:
            seen.append(owner)
    return seen


# --- The init payload ------------------------------------------------------------

DOTNET_MODES = ("agentic", "single_shot")


def build_dotnet_agentic_init(dotnet_data: dict, llm_context: dict,
                              cape_sigs: list[str]) -> dict:
    """The agentic .NET init payload.

    Carries `decompiled_source` IN FULL, for the orchestrator: `run_interpret`
    builds the tool index from it and `agent_payload` removes it before the
    payload reaches the container. Everything else here is what the agent sees
    in its first message.
    """
    decompilation = dotnet_data.get("decompilation", {}) or {}
    source = decompilation.get("source", "") or ""
    index = CSharpIndex(source)
    constructs = scan_suspicious_constructs(index)
    extraction_source = dotnet_data.get("extraction_source")
    deob = dotnet_data.get("deobfuscation") or {}
    return {
        **llm_context,
        "analysis_type": "dotnet",
        "dotnet_mode": "agentic",
        "source_language": "csharp",
        "decompiled_source": source,
        "source_bytes_indexed": len(source),
        **_source_provenance(decompilation),
        "blob_bytes_elided": decompilation.get("blob_bytes_elided"),
        "deobfuscated": bool(deob.get("deobfuscated")),
        "assembly": assembly_metadata(index),
        "table_of_contents": table_of_contents(index, _class_priority(constructs)),
        "suspicious_constructs": constructs,
        "strings_of_interest": dotnet_data.get("strings_of_interest", []),
        "analysis_success": True,
        "origin": "extraction" if extraction_source else "original",
        "extraction_context": {
            "source_dir": extraction_source["source_dir"],
            "sha256": extraction_source["sha256"],
            "cape_signatures": cape_sigs[:10],
        } if extraction_source else None,
    }


def build_dotnet_interpret_init(dotnet_data: dict, llm_context: dict,
                                cape_sigs: list[str], mode: str) -> dict:
    """The .NET init payload for `mode` — the ONE place the choice is made.

    run-pipeline.py and the eval harness both call this, so the eval measures
    what production sends for the same `dotnet_mode` (#380, #667).
    """
    if mode == "single_shot":
        return build_dotnet_init(dotnet_data, llm_context, cape_sigs)
    if mode != "agentic":
        raise ValueError(f"dotnet_mode must be one of {DOTNET_MODES}, got {mode!r}")
    return build_dotnet_agentic_init(dotnet_data, llm_context, cape_sigs)


def is_agentic_dotnet(payload: dict) -> bool:
    return (isinstance(payload, dict) and payload.get("analysis_type") == "dotnet"
            and payload.get("dotnet_mode") == "agentic")


# --- The tools -------------------------------------------------------------------

def _int_arg(args: dict, key: str, default: int, lo: int, hi: int) -> int:
    v = args.get(key, default)
    if v is None or v == "":
        return default
    if isinstance(v, bool):
        raise ValueError(f"{key} must be an integer")
    try:
        v = int(v)
    except (TypeError, ValueError):
        raise ValueError(f"{key} must be an integer") from None
    if not lo <= v <= hi:
        raise ValueError(f"{key} must be between {lo} and {hi}")
    return v


def _name_arg(args: dict, key: str, required: bool = True) -> str:
    v = args.get(key, "")
    if v is None:
        v = ""
    if not isinstance(v, str):
        raise ValueError(f"{key} must be a string")
    v = v.strip()
    if required and not v:
        raise ValueError(f"{key} is required")
    if len(v) > 200 or any(ord(c) < 32 for c in v):
        raise ValueError(f"{key} must be at most 200 printable characters")
    return v


def validate_dotnet_args(tool: str, args: dict) -> str | None:
    """Argument check for a .NET tool call, before anything runs. None if valid."""
    if tool not in DOTNET_TOOL_NAMES:
        return f"Unknown tool: {tool}"
    if not isinstance(args, dict):
        return "arguments must be an object"
    try:
        if tool == "list_classes":
            _name_arg(args, "filter", required=False)
        elif tool == "list_methods":
            _name_arg(args, "class_name")
        elif tool == "get_method_source":
            _name_arg(args, "class_name")
            _name_arg(args, "method_name")
            _int_arg(args, "page", 0, 0, 100_000)
        elif tool == "get_class_source":
            _name_arg(args, "class_name")
            _int_arg(args, "page", 0, 0, 100_000)
        elif tool == "search_source":
            p = args.get("pattern")
            if not isinstance(p, str) or not p or len(p) > PATTERN_MAX:
                return f"pattern must be a non-empty string of at most {PATTERN_MAX} characters"
            _int_arg(args, "max_hits", SEARCH_DEFAULT_HITS, 1, SEARCH_MAX_HITS)
            _int_arg(args, "context_lines", 0, 0, 3)
        elif tool == "get_source_lines":
            _int_arg(args, "start_line", 1, 1, 10_000_000)
            _int_arg(args, "end_line", 1, 1, 10_000_000)
    except ValueError as e:
        return str(e)
    return None


def _page(text: str, page: int, page_chars: int = SOURCE_PAGE_CHARS) -> dict:
    """One page of `text`, cut at a line boundary where one is near."""
    total = len(text)
    # Page boundaries computed by walking, so a page never splits a line unless
    # one line alone exceeds the page.
    bounds = [0]
    while bounds[-1] < total:
        a = bounds[-1]
        b = min(total, a + page_chars)
        if b < total:
            nl = text.rfind("\n", a + page_chars // 2, b)
            if nl > a:
                b = nl + 1
        bounds.append(b)
    pages = max(1, len(bounds) - 1)
    if page >= pages:
        return {"page": page, "pages": pages, "total_chars": total, "source": "",
                "truncated": False,
                "note": f"page {page} does not exist; pages are 0..{pages - 1}"}
    a, b = bounds[page], bounds[page + 1] if page + 1 < len(bounds) else total
    out = {"page": page, "pages": pages, "total_chars": total, "source": text[a:b],
           "truncated": pages > 1}
    if page + 1 < pages:
        out["note"] = (f"TRUNCATED: page {page} of 0..{pages - 1} ({b - a:,} of {total:,} "
                       f"chars). Call again with page={page + 1} for the next part.")
    elif pages > 1:
        out["note"] = f"last page ({page} of 0..{pages - 1})"
    return out


class DotnetToolbox:
    """Serves the .NET tools from one decompiled source. Orchestrator-side."""

    def __init__(self, source: str, analyser_truncated: bool = False,
                 source_bytes_total: int | None = None) -> None:
        self.index = CSharpIndex(source)
        self.analyser_truncated = analyser_truncated
        self.source_bytes_total = source_bytes_total

    @classmethod
    def from_payload(cls, payload: dict) -> DotnetToolbox:
        return cls(payload.get("decompiled_source", "") or "",
                   bool(payload.get("source_truncated_by_analyser")),
                   payload.get("source_bytes_total"))

    def call(self, tool: str, args: dict) -> dict:
        """Run one tool. Arguments must already have passed validate_dotnet_args."""
        args = args or {}
        fn = getattr(self, f"_t_{tool}", None)
        if fn is None or tool not in DOTNET_TOOL_NAMES:
            return {"error": f"Unknown tool: {tool}"}
        try:
            return fn(args)
        except ValueError as e:
            return {"error": str(e)}

    # Each result says when the index itself is partial, so "not found" is never
    # read as "absent from the program" when the analyser cut the source.
    def _coverage(self, out: dict) -> dict:
        if self.analyser_truncated:
            out["coverage_note"] = (
                f"The analyser stored only the first {len(self.index.source):,} of "
                f"{self.source_bytes_total or 0:,} characters of decompiled source; code "
                f"beyond that is not searchable here.")
        return out

    def _resolve(self, class_name: str) -> tuple[TypeDecl | None, dict | None]:
        found = self.index.find_types(class_name)
        if not found:
            close = [t.qualname for t in self.index.types
                     if class_name.lower().split(".")[-1] in t.qualname.lower()][:10]
            return None, self._coverage({
                "error": f"Class {class_name!r} {NOT_FOUND}.",
                "similar": close})
        if len(found) > 1:
            exact = [t for t in found if t.name == class_name.split(".")[-1]]
            if len(exact) == 1:
                return exact[0], None
            return None, {"error": f"Class name {class_name!r} is ambiguous; use the full name.",
                          "candidates": [t.qualname for t in found[:20]]}
        return found[0], None

    def _t_list_classes(self, args: dict) -> dict:
        flt = _name_arg(args, "filter", required=False).lower()
        rows = [{"class": t.qualname, "kind": t.kind, "bases": t.bases,
                 "methods": len(t.members), "chars": t.chars,
                 "lines": f"{t.line_start}-{t.line_end}"}
                for t in self.index.types if not flt or flt in t.qualname.lower()]
        return self._coverage({"total": len(rows), "classes": rows[:LIST_MAX],
                               "truncated": len(rows) > LIST_MAX})

    def _t_list_methods(self, args: dict) -> dict:
        t, err = self._resolve(_name_arg(args, "class_name"))
        if err:
            return err
        rows = [{"name": m.name, "kind": m.kind, "declaration": _clip(m.header, 240),
                 "lines": f"{m.line_start}-{m.line_end}", "chars": m.chars}
                for m in t.members]
        return {"class": t.qualname, "total": len(rows), "methods": rows[:LIST_MAX],
                "truncated": len(rows) > LIST_MAX}

    def _t_get_method_source(self, args: dict) -> dict:
        t, err = self._resolve(_name_arg(args, "class_name"))
        if err:
            return err
        name = _name_arg(args, "method_name")
        # `Class.Method` passed as the method name is a common shape; accept it.
        bare = name.rpartition(".")[2] if "." in name and not name.startswith("operator") else name
        found = [m for m in t.members if m.name == bare] or \
                [m for m in t.members if m.name.lower() == bare.lower()]
        if not found:
            return self._coverage({
                "error": f"Method {name!r} {NOT_FOUND} in class {t.qualname}.",
                "methods_in_class": [m.name for m in t.members][:60]})
        parts = []
        for k, m in enumerate(found):
            label = (f"// overload {k + 1} of {len(found)}, " if len(found) > 1 else "// ")
            parts.append(f"{label}lines {m.line_start}-{m.line_end}\n"
                         + self.index.source[self.index.line_start_of(m.start):m.end])
        text = "\n\n".join(parts)
        out = {"class": t.qualname, "method": found[0].name, "overloads": len(found),
               "lines": [f"{m.line_start}-{m.line_end}" for m in found]}
        out.update(_page(text, _int_arg(args, "page", 0, 0, 100_000)))
        return out

    def _t_get_class_source(self, args: dict) -> dict:
        t, err = self._resolve(_name_arg(args, "class_name"))
        if err:
            return err
        out = {"class": t.qualname, "lines": f"{t.line_start}-{t.line_end}",
               "methods": len(t.members)}
        out.update(_page(self.index.source[self.index.line_start_of(t.start):t.end],
                         _int_arg(args, "page", 0, 0, 100_000)))
        return out

    def _t_get_source_lines(self, args: dict) -> dict:
        a = _int_arg(args, "start_line", 1, 1, 10_000_000)
        b = _int_arg(args, "end_line", a + 40, 1, 10_000_000)
        if b < a:
            raise ValueError("end_line must be >= start_line")
        total = self.index.line_count
        if a > total:
            return self._coverage({"error": f"Line {a} {NOT_FOUND}; it has {total} lines."})
        want_b = b
        b = min(b, total, a + LINES_MAX - 1)
        starts = self.index._line_starts
        lo = starts[a - 1]
        hi = starts[b] if b < total else len(self.index.source)
        text = self.index.source[lo:hi]
        truncated = b < want_b
        if len(text) > SOURCE_PAGE_CHARS:
            text = text[:SOURCE_PAGE_CHARS]
            truncated = True
        out = {"start_line": a, "end_line": b, "total_lines": total,
               "location": self.index.location_of(lo), "source": text,
               "truncated": truncated}
        if truncated:
            out["note"] = (f"TRUNCATED at {LINES_MAX} lines / {SOURCE_PAGE_CHARS:,} chars; "
                           f"request the next range to continue.")
        return out

    def _t_search_source(self, args: dict) -> dict:
        pattern = args.get("pattern", "")
        max_hits = _int_arg(args, "max_hits", SEARCH_DEFAULT_HITS, 1, SEARCH_MAX_HITS)
        ctx = _int_arg(args, "context_lines", 0, 0, 3)
        try:
            re.compile(pattern)
        except re.error as e:
            return {"error": f"Invalid search pattern: {e}. Escape regex metacharacters "
                             f"such as ( ) [ ] . * + ? with a backslash."}
        try:
            raw = _run_search(self.index.source, pattern, max_hits)
        except subprocess.TimeoutExpired:
            return {"error": f"Invalid search pattern: it ran longer than "
                             f"{SEARCH_TIMEOUT_S:.0f}s and was stopped. Use a simpler pattern."}
        hits = []
        lines = self.index.source.split("\n")
        budget = SOURCE_PAGE_CHARS
        shown = 0
        for line_no, col, length in raw["hits"]:
            text = lines[line_no - 1]
            a = max(0, col - SEARCH_LINE_CHARS // 2)
            snippet = text[a:a + SEARCH_LINE_CHARS]
            hit = {"line": line_no, "location": self.index.location_of(
                self.index._line_starts[line_no - 1] + col), "text": snippet.strip()}
            if ctx:
                hit["context"] = [_clip(lines[k - 1].rstrip(), SEARCH_LINE_CHARS)
                                  for k in range(max(1, line_no - ctx),
                                                 min(len(lines), line_no + ctx) + 1)]
            cost = len(json.dumps(hit))
            if cost > budget:
                break
            budget -= cost
            hits.append(hit)
            shown += 1
        out = {"pattern": pattern, "total_hits": raw["total"], "hits": hits,
               "truncated": raw["total"] > shown}
        if out["truncated"]:
            out["note"] = (f"TRUNCATED: showing {shown} of {raw['total']} matching lines. "
                           f"Narrow the pattern to see the rest.")
        return self._coverage(out)


# The search runs in a child process: Python's `re` cannot be interrupted, the
# pattern comes from the model (and the model reads attacker-controlled text),
# and a catastrophic pattern over 100k characters would otherwise wedge the
# pipeline process that brokers every other stage. A plain interpreter with -c,
# rather than multiprocessing: no re-import of run-pipeline.py as __main__, no
# fork of a process that is running reader threads.
_SEARCH_CHILD = r"""
import json, re, sys
req = json.load(sys.stdin)
rx = re.compile(req["pattern"])
hits, total = [], 0
for n, line in enumerate(req["source"].split("\n"), 1):
    m = rx.search(line)
    if m:
        total += 1
        if len(hits) < req["max_hits"]:
            hits.append([n, m.start(), m.end() - m.start()])
json.dump({"hits": hits, "total": total}, sys.stdout)
"""


def _run_search(source: str, pattern: str, max_hits: int) -> dict:
    proc = subprocess.run(
        [sys.executable, "-I", "-c", _SEARCH_CHILD],
        input=json.dumps({"source": source, "pattern": pattern, "max_hits": max_hits}),
        capture_output=True, text=True, timeout=SEARCH_TIMEOUT_S)
    if proc.returncode != 0:
        raise ValueError(f"search failed: {proc.stderr.strip()[-200:]}")
    return json.loads(proc.stdout)
