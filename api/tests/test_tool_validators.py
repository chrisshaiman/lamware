# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Tests for the agent arg-validation wrapper (generic schema + shared Ghidra core).

Normal import: tool_validators imports only lamware_shared, so no DB/app
stack is needed once lamware_shared is installed.

sys.modules cleanup: other test files (test_orchestrator.py, test_system_prompt.py)
register stub ModuleType objects for app.investigate so their exec()-loaded sources
resolve against fakes instead of the real DB/FastAPI stack.  Those stubs must be
evicted before we attempt a genuine import here, otherwise Python resolves
`app.investigate` to the bare ModuleType and cannot find tool_validators under it.
"""

import sys

# Evict any stub registrations for the app.investigate namespace so that our
# normal import below gets the real module from the filesystem.
for _key in list(sys.modules):
    if _key.startswith("app.investigate"):
        del sys.modules[_key]

from app.investigate.tool_validators import validate_tool_args  # noqa: E402

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
