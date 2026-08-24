# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
r"""No Ghidra argument pattern may accept a value with a trailing newline.

Python's `$` matches at the end of the string OR immediately before a final
newline, so `re.match(r"^0x[0-9a-fA-F]{1,16}$", "0x401000\n")` succeeds and every
pattern in `GHIDRA_ARG_VALIDATORS` accepted a value it was written to reject.

Fixed at the CONSUMER — `validate_ghidra_args` calls `re.fullmatch` — rather than
by rewriting eight patterns, so a pattern added to the table later cannot
reintroduce it. That is also why these tests go through the real validator rather
than inspecting the patterns: the property belongs to the pair, not to either half.

Lives in shared/tests rather than beside the repo-wide sweep in
tests/test_regex_end_anchors.py because only this job installs the package.

See tests/test_regex_end_anchors.py for the structural half — the check that no
NEW `re.match`/`re.compile` whole-string pattern anywhere in the tree is anchored
with a bare `$`.
"""
import pytest

# --- the Ghidra argument table, which the structural check cannot see -------

@pytest.mark.parametrize("tool,arg,value", [
    ("decompile_function", "name", "DecryptConfig"),
    ("get_xrefs_to", "name", "DecryptConfig"),
    ("get_xrefs_from", "name", "DecryptConfig"),
    ("get_strings_at", "address", "0x00401000"),
    ("get_strings_at", "range", "4096"),
    ("list_functions", "filter", "Decrypt*"),
    ("get_data_at", "address", "0x00401000"),
    ("get_data_at", "length", "512"),
])
def test_no_ghidra_arg_accepts_a_trailing_newline(tool, arg, value):
    """These patterns keep their `^...$` anchors; the fix is that their consumer
    uses `re.fullmatch`. Asserted through the real validator, so it holds however
    the table is written."""
    from lamware_shared.tool_validators import validate_ghidra_args

    assert validate_ghidra_args(tool, {arg: value}) is None, (
        "precondition: this value must be accepted, or the test below proves nothing")
    assert validate_ghidra_args(tool, {arg: value + "\n"}) is not None, (
        f"{tool}.{arg} accepts {value + chr(10)!r}")


def test_every_pattern_in_the_table_is_covered_above():
    """A pattern added to the table without a case here would be untested, and
    the parametrize list is the kind of thing that quietly falls behind."""
    from lamware_shared.tool_validators import GHIDRA_ARG_VALIDATORS

    declared = {(tool, arg) for tool, args in GHIDRA_ARG_VALIDATORS.items() for arg in args}
    covered = {
        ("decompile_function", "name"), ("get_xrefs_to", "name"),
        ("get_xrefs_from", "name"), ("get_strings_at", "address"),
        ("get_strings_at", "range"), ("list_functions", "filter"),
        ("get_data_at", "address"), ("get_data_at", "length"),
    }
    assert declared == covered, f"uncovered: {sorted(declared - covered)}"
