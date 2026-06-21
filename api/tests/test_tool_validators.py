# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Tests for the investigation-agent tool-argument validator.

tool_validators.py is pure stdlib, so we exec its source directly — no app-package import,
no sys.modules stubs. validate_tool_args takes the schema lookup as a parameter, so we pass a
hand-built schema covering the tools under test.
"""
from pathlib import Path

import pytest

_TV_SRC = (
    Path(__file__).resolve().parent.parent / "app" / "investigate" / "tool_validators.py"
)
_ns: dict = {}
exec(_TV_SRC.read_text(encoding="utf-8"), _ns)  # noqa: S102
validate_tool_args = _ns["validate_tool_args"]
GHIDRA_ARG_VALIDATORS = _ns["GHIDRA_ARG_VALIDATORS"]

# Minimal schema_by_name mirroring the real input_schemas for the tools under test.
SCHEMAS = {
    "decompile_function": {
        "type": "object",
        "properties": {"name": {"type": "string"}},
        "required": ["name"],
    },
    "get_strings_at": {
        "type": "object",
        "properties": {
            "address": {"type": "string"},
            "range": {"type": "integer"},
        },
        "required": ["address"],
    },
    "get_data_at": {
        "type": "object",
        "properties": {
            "address": {"type": "string"},
            "length": {"type": "integer"},
        },
        "required": ["address"],
    },
    "list_functions": {
        "type": "object",
        "properties": {"filter": {"type": "string"}},
    },
    "search_iocs": {
        "type": "object",
        "properties": {
            "value": {"type": "string"},
            "type": {"type": "string"},
        },
        "required": ["value"],
    },
    "get_signatures": {
        "type": "object",
        "properties": {"analysis_id": {"type": "integer"}},
        "required": ["analysis_id"],
    },
}


def v(tool, args):
    return validate_tool_args(tool, args, SCHEMAS)


# --- accept ---------------------------------------------------------------

def test_accept_decompile_valid_name():
    assert v("decompile_function", {"name": "main"}) is None


def test_accept_get_strings_at_valid():
    assert v("get_strings_at", {"address": "0x00401000", "range": 256}) is None


def test_accept_get_data_at_valid():
    assert v("get_data_at", {"address": "0x401000", "length": 64}) is None


def test_accept_list_functions_wildcard():
    assert v("list_functions", {"filter": "*crypt*"}) is None


def test_accept_search_iocs_valid():
    assert v("search_iocs", {"value": "1.2.3.4", "type": "ipv4-addr"}) is None


def test_accept_get_signatures_valid():
    assert v("get_signatures", {"analysis_id": 5}) is None


# --- reject ---------------------------------------------------------------

def test_reject_unknown_tool():
    assert "Unknown tool" in v("not_a_tool", {"x": 1})


def test_reject_missing_required():
    assert "Missing required argument" in v("decompile_function", {})
    assert "Missing required argument" in v("search_iocs", {})


@pytest.mark.parametrize(
    "addr",
    ["401000", "0xZZ", "0x401000; rm -rf /", "$(id)", "`whoami`", "../../etc/passwd"],
)
def test_reject_bad_address(addr):
    assert v("get_strings_at", {"address": addr}) is not None


def test_reject_overlong_name():
    assert v("decompile_function", {"name": "x" * 201}) is not None


def test_reject_range_too_large():
    # int 5000 passes type + regex (4 digits) but exceeds the 4096 bound.
    assert v("get_strings_at", {"address": "0x401000", "range": 5000}) == "range must be <= 4096"


def test_reject_length_too_large():
    assert v("get_data_at", {"address": "0x401000", "length": 70000}) == "length must be <= 65536"


def test_reject_filter_bad_chars():
    assert v("list_functions", {"filter": "*; rm*"}) is not None


@pytest.mark.parametrize("bad", ["abc", {}, True])
def test_reject_wrong_type_integer(bad):
    assert "expected integer" in v("get_signatures", {"analysis_id": bad})


# --- drift guard ----------------------------------------------------------

def test_ghidra_validator_names():
    assert set(GHIDRA_ARG_VALIDATORS) == {
        "decompile_function",
        "get_xrefs_to",
        "get_xrefs_from",
        "get_strings_at",
        "list_functions",
        "get_data_at",
    }
