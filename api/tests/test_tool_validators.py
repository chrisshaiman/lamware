# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Tests for the agent arg-validation wrapper (generic schema + shared Ghidra core).

Normal import: tool_validators imports only lamware_shared, so no DB/app
stack is needed once lamware_shared is installed.
"""

from app.investigate.tool_validators import validate_tool_args

_SCHEMA = {
    "decompile_function": {
        "type": "object",
        "properties": {"name": {"type": "string"}},
        "required": ["name"],
    },
    "get_strings_at": {
        "type": "object",
        "properties": {"address": {"type": "string"}, "range": {"type": "integer"}},
        "required": ["address"],
    },
}


def test_unknown_tool_rejected():
    assert validate_tool_args("nope", {}, _SCHEMA) is not None


def test_missing_required_rejected():
    assert validate_tool_args("decompile_function", {}, _SCHEMA) is not None


def test_wrong_type_rejected():
    assert validate_tool_args("get_strings_at", {"address": 123}, _SCHEMA) is not None


def test_valid_passes():
    assert validate_tool_args("decompile_function", {"name": "main"}, _SCHEMA) is None


def test_ghidra_core_delegated_bad_address():
    err = validate_tool_args("get_strings_at", {"address": "$(id)"}, _SCHEMA)
    assert err is not None and "address" in err
