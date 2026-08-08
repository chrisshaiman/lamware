# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Tool descriptions must disambiguate confusable pairs, and their references
must resolve.

The tool set uses a scope convention — `search_*` works across all analyses,
`get_*` works on one analysis the caller already has the id for — and the schemas
enforce it with disjoint required parameters (`search_iocs` needs `value`,
`get_iocs` needs `analysis_id`).

That prevents a MALFORMED call. It does not help the model pick the right tool in
the first place, which happens before any schema is checked. Descriptions are the
only signal at selection time, and a wrong pick costs a tool call in a loop where
budget exhaustion is an observed failure mode (claude-sonnet-5 on amadey stopped
with "not yet decompiled/traced due to tool budget exhaustion").

Parsed from source rather than imported: tools.py pulls in sqlmodel, the app
config and the DB engine, none of which this needs.
"""
import ast
import re
from pathlib import Path

TOOLS_PY = (Path(__file__).resolve().parent.parent / "app" / "investigate"
            / "tools.py")


def _const_str(node) -> str | None:
    """Flatten a string node: plain, implicitly concatenated, or an f-string.

    `run_python`'s description is an f-string, so `ast.literal_eval` on the whole
    TOOL_DEFINITIONS list raises. Only the literal segments matter here.
    """
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        return "".join(v.value for v in node.values
                       if isinstance(v, ast.Constant) and isinstance(v.value, str))
    return None


def _tool_descriptions() -> dict[str, str]:
    tree = ast.parse(TOOLS_PY.read_text(encoding="utf-8"))
    out: dict[str, str] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Dict):
            continue
        keys = {k.value for k in node.keys
                if isinstance(k, ast.Constant) and isinstance(k.value, str)}
        if not {"name", "description"} <= keys:
            continue
        entry = {}
        for k, v in zip(node.keys, node.values):
            if isinstance(k, ast.Constant) and k.value in ("name", "description"):
                entry[k.value] = _const_str(v)
        if entry.get("name") and entry.get("description"):
            out[entry["name"]] = entry["description"]
    return out


DESCRIPTIONS = _tool_descriptions()
NAMES = set(DESCRIPTIONS)

# Pairs where picking the wrong one is plausible and the cost is a wasted call.
CONFUSABLE = [
    ("search_iocs", "get_iocs"),          # corpus-wide vs single analysis
    ("get_xrefs_to", "get_xrefs_from"),   # opposite directions
]

# Ordered pairs: the first lists what the second consumes.
SEQUENTIAL = [
    ("get_cape_payloads", "read_payload"),
    ("list_functions", "decompile_function"),
]


def test_the_parser_found_the_tools():
    """Guards the guard: a parser returning {} makes every test below vacuous."""
    assert len(NAMES) >= 15, f"only parsed {sorted(NAMES)}"
    for expected in ("search_iocs", "get_iocs", "get_xrefs_to", "run_python"):
        assert expected in NAMES, f"{expected} missing — parser is wrong"
    assert "sandbox" in DESCRIPTIONS["run_python"], (
        "the f-string description must flatten to its literal segments")


def test_every_tool_referenced_in_a_description_exists():
    """THE durable check. A rename that leaves 'use get_iocs instead' pointing at
    nothing is worse than no cross-reference: it sends the model somewhere real
    tools are not."""
    dangling = []
    for name, desc in DESCRIPTIONS.items():
        for ref in re.findall(r"\buse ([a-z][a-z0-9_]{3,})\b", desc):
            if ref not in NAMES:
                dangling.append(f"{name} -> {ref}")
    assert not dangling, (
        f"descriptions reference tools that do not exist: {dangling}")


def test_confusable_pairs_point_at_each_other():
    """Both directions. A one-sided cross-reference only helps the model that
    already landed on the documented side."""
    for a, b in CONFUSABLE:
        assert b in DESCRIPTIONS[a], f"{a} must mention {b}"
        assert a in DESCRIPTIONS[b], f"{b} must mention {a}"


def test_sequential_pairs_name_their_successor():
    """One direction only — these are ordered, not alternatives. Knowing to list
    before reading is useful; the reverse is noise."""
    for first, second in SEQUENTIAL:
        assert second in DESCRIPTIONS[first], (
            f"{first} should point at {second}, which consumes its output")


def test_the_scope_distinction_is_stated_not_implied():
    """`search_` vs `get_` is a convention the model has to infer. The pair that
    actually collides should say it outright."""
    assert "ACROSS ALL" in DESCRIPTIONS["search_iocs"]
    assert "ONE analysis" in DESCRIPTIONS["get_iocs"]


def test_the_xref_directions_are_unambiguous():
    """'callers' and 'callees' differ by two letters and disambiguate only for a
    reader who already has the distinction straight."""
    assert "CALLERS" in DESCRIPTIONS["get_xrefs_to"]
    assert "CALLEES" in DESCRIPTIONS["get_xrefs_from"]
    assert "what invokes this" in DESCRIPTIONS["get_xrefs_to"]
    assert "what does this call" in DESCRIPTIONS["get_xrefs_from"]


def test_no_tool_references_itself():
    """A self-reference reads as a cross-reference and resolves to nowhere useful."""
    for name, desc in DESCRIPTIONS.items():
        for ref in re.findall(r"\buse ([a-z][a-z0-9_]{3,})\b", desc):
            assert ref != name, f"{name} tells the caller to use itself"
