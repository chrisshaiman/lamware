# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""A report nested deeper than its consumers can walk is cut, and says so (#702).

The guest sets how deep parts of the report nest. windows.pstree is the plain
case: a process that spawns a child that spawns a child is one level per
process, two containers each (the row object and its ``__children`` array).
#701 made the Volatility parse fail closed at the decoder's limit (4,998
processes deep on Python 3.12.13), but a tree that parses was still too deep
for what came after it. Measured on origin/main 6025344, Python 3.12.13, a
pstree chain in ``report["volatility"]["plugins"]["pstree"]``:

    db_ingest._Cleaner (recursive)              RecursionError from 247 levels:
                                                the analyses row was rolled back
    write_json_atomic (json.dump, indent=2:     RecursionError from 495 levels:
      the pure-Python encoder)                  report.json was never written
    json.dumps compact / psycopg2 Json          RecursionError from 4,997 levels
    json.loads of the plugin output             RecursionError from 4,999 levels

The last two are why falling back to a compact dump would not have been
enough: a tree 4,997 or 4,998 deep parses and then cannot be serialised by
anything in the standard library.

So the report is bounded instead. Every container nested more than
MAX_REPORT_DEPTH levels below the report root is replaced, in place, by the
string MARKER, and the report gains a ``depth_truncated`` record naming the
section it happened in, how many subtrees were removed and how deep the
deepest one went. Nothing deeper than the bound reaches report.json, the
database row, or any consumer that reads either.

Why 128: a real host pstree is at most 9 processes deep (#702), which is 21
container levels counted from the report root; the deepest fixture in the
test suite is 17. 128 is six times the deepest observed, and leaves every
recursive consumer more than 800 frames of the default 1,000 (the indent
encoder uses one frame per container level).

Everything here is iterative: a bound that recursed would fail on exactly the
input it exists for.

What is NOT lost: Volatility's insights (stages/volatility.py) and the
correlation rules read the plugin output iteratively, and the insights are
computed before the report is bounded. The raw tree beyond the bound is not
kept anywhere else; ``depth_truncated`` is the record that it existed.
"""
from __future__ import annotations

import re

#: Container levels below the report root that are kept. The root is level 0;
#: ``report["volatility"]`` is level 1.
MAX_REPORT_DEPTH = 128

#: Stands in for each removed subtree. A string, so every reader that
#: shape-checks a field (db_ingest._Node, plugin_rows.Row) sees a wrong-typed
#: value and skips it with a warning, the same as any other malformed field.
MARKER = f"[removed: nested deeper than {MAX_REPORT_DEPTH} levels (#702), see depth_truncated]"

#: The report key the record goes under.
RECORD_KEY = "depth_truncated"

#: How many leading path steps name a section: "volatility.plugins.pstree".
#: An array step is written "[]" (the index is not useful across subtrees).
_SECTION_KEYS = 3

#: Only key names of this shape are copied into the record. The first three
#: levels of the report are the pipeline's own keys today, but nothing
#: guarantees that, and a key below them can be guest-chosen text.
_SAFE_KEY = re.compile(r"[A-Za-z0-9_.-]{1,64}")

_CONTAINERS = (dict, list, tuple)


def _segment(key) -> str:
    if isinstance(key, int):
        return "[]"
    if isinstance(key, str) and _SAFE_KEY.fullmatch(key):
        return key
    return "?"


def _deepest(value, level: int) -> int:
    """The deepest container level inside ``value``, which sits at ``level``."""
    deepest = level
    stack = [(value, level)]
    while stack:
        node, at = stack.pop()
        deepest = max(deepest, at)
        children = node.values() if isinstance(node, dict) else node
        stack.extend((c, at + 1) for c in children if isinstance(c, _CONTAINERS))
    return deepest


def bound_report_depth(report, max_depth: int = MAX_REPORT_DEPTH) -> dict | None:
    """Cut every container nested deeper than ``max_depth``, in place.

    Returns None when nothing was cut, and the report is then untouched. When
    something was, each removed subtree is replaced by MARKER, and
    ``report["depth_truncated"]`` records it::

        {"max_depth": 128,
         "sections": [{"section": "volatility.plugins.pstree",
                       "subtrees_removed": 1, "deepest_level": 1203}]}

    A second call on the same report finds nothing more to cut; a call that
    does cut adds to the counts already recorded, so the record covers every
    call. A tuple holding a subtree to cut is replaced by a list in its parent:
    it would be written as a JSON array either way.
    """
    if not isinstance(report, dict):
        return None
    cuts: dict[str, list[int]] = {}

    # (container, its level, its parent, its key in the parent, section path)
    stack = [(report, 0, None, None, ())]
    while stack:
        node, level, parent, key, section = stack.pop()
        if isinstance(node, dict):
            items = list(node.items())
        else:
            items = list(enumerate(node))
        for k, child in items:
            if not isinstance(child, _CONTAINERS):
                continue
            child_section = section + (_segment(k),) if len(section) < _SECTION_KEYS else section
            if level + 1 <= max_depth:
                stack.append((child, level + 1, node, k, child_section))
                continue
            if isinstance(node, tuple):
                node = list(node)
                parent[key] = node
            node[k] = MARKER
            entry = cuts.setdefault(".".join(child_section) or "?", [0, 0])
            entry[0] += 1
            entry[1] = max(entry[1], _deepest(child, level + 1))

    if not cuts:
        return None
    record = report.get(RECORD_KEY)
    if not (isinstance(record, dict) and isinstance(record.get("sections"), list)):
        record = {"max_depth": max_depth, "sections": []}
    by_section = {s.get("section"): s for s in record["sections"] if isinstance(s, dict)}
    for name, (removed, deepest) in sorted(cuts.items()):
        known = by_section.get(name)
        if known is None:
            record["sections"].append({"section": name, "subtrees_removed": removed,
                                       "deepest_level": deepest})
            continue
        known["subtrees_removed"] = int(known.get("subtrees_removed") or 0) + removed
        known["deepest_level"] = max(int(known.get("deepest_level") or 0), deepest)
    report[RECORD_KEY] = record
    return record


def describe(record: dict | None) -> str | None:
    """One log/warning line for a record, built from section names and counts."""
    if not record:
        return None
    parts = [f"{s['section']} ({s['subtrees_removed']} subtree(s), "
             f"deepest level {s['deepest_level']})"
             for s in record.get("sections", []) if isinstance(s, dict)]
    return (f"report nested deeper than {record.get('max_depth')} levels; removed in: "
            + ", ".join(parts))
