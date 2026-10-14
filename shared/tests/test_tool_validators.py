# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Tests for the single shared Ghidra arg validator (normal import)."""

import pytest
from lamware_shared.tool_validators import GHIDRA_ARG_VALIDATORS, validate_ghidra_args

_GHIDRA_TOOLS = {
    "decompile_function", "get_xrefs_to", "get_xrefs_from",
    "get_strings_at", "list_functions", "get_data_at",
}


def test_dict_covers_exactly_the_ghidra_tools():
    assert set(GHIDRA_ARG_VALIDATORS) == _GHIDRA_TOOLS


def test_non_ghidra_tool_returns_none():
    # Not a Ghidra tool -> nothing to check here (api's generic layer handles it).
    assert validate_ghidra_args("search_analyses", {"query": "x"}) is None


def test_valid_address_and_name_accepted():
    assert validate_ghidra_args("decompile_function", {"name": "main"}) is None
    assert validate_ghidra_args("get_strings_at", {"address": "0x00401000"}) is None


def test_bad_address_rejected():
    err = validate_ghidra_args("get_strings_at", {"address": "0x401000; rm -rf /"})
    assert err is not None and "address" in err


def test_over_length_name_rejected():
    assert validate_ghidra_args("decompile_function", {"name": "x" * 300}) is not None


def test_range_bound_enforced():
    assert validate_ghidra_args("get_strings_at", {"address": "0x1", "range": 99999}) is not None


def test_length_bound_enforced():
    assert validate_ghidra_args("get_data_at", {"address": "0x1", "length": 999999}) is not None


def test_filter_metachars_rejected():
    assert validate_ghidra_args("list_functions", {"filter": "*; cat /etc/shadow"}) is not None


@pytest.mark.parametrize("args", ["main", ["main"], None, 42])
@pytest.mark.parametrize("tool", ["decompile_function", "not_a_ghidra_tool"])
def test_non_object_args_are_a_tool_error_not_a_crash(tool, args):
    """#734: `"args": "..."` from the model raised AttributeError out of the
    interpret stage. It must come back as an error the model can correct."""
    err = validate_ghidra_args(tool, args)
    assert err is not None and "expected an object" in err
