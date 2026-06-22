# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Argument validation for investigation-agent tool calls.

Fail-closed shape/format checks applied at the execute_tool dispatch boundary before any
tool runs, so an injected LLM cannot drive a tool with malformed arguments. Generic
JSON-schema layer (required + type) handled here; Ghidra-specific regex/bounds delegated
to the shared canonical module (lamware_shared.tool_validators), which is the single
source of truth shared with the pipeline.

Author: Christopher Shaiman
License: Apache 2.0
"""
from lamware_shared.tool_validators import GHIDRA_ARG_VALIDATORS, validate_ghidra_args  # noqa: F401

# JSON Schema type -> acceptable Python type(s). Strict: no coercion.
_JSON_TYPE_MAP = {
    "string": str,
    "integer": int,
    "number": (int, float),
    "boolean": bool,
    "object": dict,
    "array": list,
}


def validate_tool_args(tool_name: str, args: dict, schema_by_name: dict) -> str | None:
    """Validate a tool call's arguments. Return an error string, or None if valid.

    schema_by_name: {tool_name: input_schema} from the tool definitions.
    """
    schema = schema_by_name.get(tool_name)
    if schema is None:
        return f"Unknown tool: {tool_name}"

    properties = schema.get("properties", {})
    required = schema.get("required", [])

    # Generic: required fields present.
    for field in required:
        if field not in args:
            return f"Missing required argument: {field}"

    # Generic: declared-type match (strict; reject bool where a number is expected).
    for key, value in args.items():
        prop = properties.get(key)
        if prop is None:
            continue  # forward-compatible: ignore args not in the schema
        jtype = prop.get("type")
        py_type = _JSON_TYPE_MAP.get(jtype)
        if py_type is None:
            continue
        if jtype in ("integer", "number") and isinstance(value, bool):
            return f"Invalid {key}: expected {jtype}"
        if not isinstance(value, py_type):
            return f"Invalid {key}: expected {jtype}"

    # Ghidra-specific regex + bounds (shared with the pipeline).
    err = validate_ghidra_args(tool_name, args)
    if err:
        return err

    return None
