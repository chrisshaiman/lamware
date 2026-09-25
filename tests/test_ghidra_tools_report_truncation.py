# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""A capped Ghidra result must say it was capped (#633).

`GhidraTool.java` caps every result set. `decompile_function` said so — it
appends `// [truncated: ...]`. The other three did not: they stopped at the cap
and reported the capped size as `count`, which is the number RETURNED presented
as the number that EXISTS.

Measured against two corpus projects before the fix:

    amadey        report: 434 functions    list_functions({}) -> count: 200
    cobaltstrike  report: 1227 functions   list_functions({}) -> count: 200

A 434-function binary and a 1227-function binary were indistinguishable to the
agent. The dangerous consequence is not the missing entries: an agent that
believes it enumerated everything can conclude "this binary contains no network
code" from a listing that stopped at 200 of 1227, and the GROUNDING CHECK WILL
NOT CATCH IT, because the claim is consistent with the evidence it was shown.

These assertions are structural, on the template source. The Java is compiled by
Ghidra inside a container at run time, so there is no build step here to hook —
behavioural verification happens on the host before merge (#636). Structural is
therefore the weaker check, and it is written to fail for the right reason: it
requires the count to come from a separate total, not from the returned list.
"""
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = (ROOT / "ansible" / "roles" / "ghidra" / "templates"
            / "GhidraTool.java.j2").read_text()

# (java method, the list it builds) for every tool that caps its results.
CAPPED_TOOLS = [
    ("runListFunctions", "funcEntries"),
    ("runGetXrefsTo", "xrefEntries"),
    ("runGetXrefsFrom", "xrefEntries"),
    ("runGetStringsAt", "stringEntries"),
]


def _method_body(name: str) -> str:
    start = TEMPLATE.index(f"private void {name}(")
    nxt = TEMPLATE.find("\n    private void ", start + 1)
    return TEMPLATE[start: nxt if nxt != -1 else len(TEMPLATE)]


def test_the_tools_under_test_exist():
    """Guards the guard: a renamed method would make every test below vacuous."""
    for name, _ in CAPPED_TOOLS:
        assert f"private void {name}(" in TEMPLATE, f"{name} not found"


@pytest.mark.parametrize("method,listname", CAPPED_TOOLS, ids=[m for m, _ in CAPPED_TOOLS])
def test_every_capped_tool_emits_total_count_and_truncated(method, listname):
    body = _method_body(method)
    # The quotes are escaped in the Java source: json.append("\\"total_count\\": ")
    assert "total_count" in body, f"{method} does not report a true total"
    assert "truncated" in body, f"{method} does not report whether it capped"


@pytest.mark.parametrize("method,listname", CAPPED_TOOLS, ids=[m for m, _ in CAPPED_TOOLS])
def test_the_total_is_not_just_the_returned_count(method, listname):
    """The defect restated: `total_count` taken from the entry list is the same
    number as `count` and reports nothing. It must come from a counter that keeps
    incrementing past the cap."""
    body = _method_body(method)
    # Anchored on the emitting statement, not the word: the explanatory comment
    # above the loop also says "total_count", and matching prose is how a guard
    # passes while the code it guards is wrong.
    total_line = next(ln for ln in body.splitlines()
                      if "total_count" in ln and "json.append" in ln)
    assert f"{listname}.size()" not in total_line, (
        f"{method} derives total_count from the returned list: {total_line.strip()}")
    assert "totalMatches" in total_line


@pytest.mark.parametrize("method,listname", CAPPED_TOOLS, ids=[m for m, _ in CAPPED_TOOLS])
def test_truncated_compares_the_total_against_what_was_returned(method, listname):
    body = _method_body(method)
    line = next(ln for ln in body.splitlines() if "truncated" in ln and "append" in ln)
    assert "totalMatches >" in line and f"{listname}.size()" in line, line


@pytest.mark.parametrize("method,listname", CAPPED_TOOLS, ids=[m for m, _ in CAPPED_TOOLS])
def test_the_loop_no_longer_stops_at_the_cap(method, listname):
    """Counting has to continue past the cap or the total is the cap. The old
    shape was `while (it.hasNext() && entries.size() < MAX_...)`."""
    body = _method_body(method)
    # Checked line by line rather than with one regex: `[^)]*` cannot cross the
    # `)` in `hasNext()`, so a pattern like that silently matches nothing and the
    # guard passes against the very shape it exists to reject.
    offenders = [ln.strip() for ln in body.splitlines()
                 if "while (" in ln and "MAX_" in ln]
    assert not offenders, (
        f"{method} still terminates its loop at the cap, so totalMatches cannot "
        f"exceed it: {offenders}")


def test_decompile_functions_existing_notice_is_untouched():
    """It already did the right thing; this change must not disturb it."""
    assert "// [truncated: " in TEMPLATE


@pytest.mark.parametrize("path,needle", [
    ("ansible/roles/interpret/files/interpret-ghidra.py", "truncated"),
    ("api/app/investigate/tools.py", "truncated"),
])
def test_both_tool_descriptions_explain_truncation(path, needle):
    """Two copies of the schema exist (#380). A field the model is never told
    about is a field the model will not use — it has to know that `truncated`
    means 'say at least N'."""
    text = (ROOT / path).read_text()
    block = text[text.index("List functions in the binary"):][:900]
    assert needle in block, f"{path} does not explain truncation to the model"
    assert "at least" in block


def test_the_filter_description_no_longer_promises_everything():
    """`Omit to list all` was false above 200 and is plausibly what taught the
    model to trust a capped listing."""
    text = (ROOT / "ansible" / "roles" / "interpret" / "files" / "interpret-ghidra.py").read_text()
    assert "Omit to list all." not in text
