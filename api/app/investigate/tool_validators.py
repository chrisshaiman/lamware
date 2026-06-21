# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Argument validation for investigation-agent tool calls.

Fail-closed shape/format checks applied at the execute_tool dispatch boundary before any
tool runs, so an injected LLM cannot drive a tool with malformed arguments. Pure stdlib +
dependency-injected schema (the caller passes the tool input_schemas) — no imports from
tools.py, so there is no circular import and this is trivially unit-testable.

GHIDRA_ARG_VALIDATORS mirrors TOOL_ARG_VALIDATORS in
ansible/roles/pipeline/templates/stages/interpret.py.j2 — keep the two in sync by hand
(cross-deploy-unit; no shared import until the pipeline is de-templated).

Author: Christopher Shaiman
License: Apache 2.0
"""
import re

# Regex/bounds for the 6 Ghidra tools whose free-form args reach the Ghidra subprocess.
# Ported verbatim from the pipeline's TOOL_ARG_VALIDATORS.
GHIDRA_ARG_VALIDATORS = {
    "decompile_function": {"name": r"^.{1,200}$"},
    "get_xrefs_to": {"name": r"^.{1,200}$"},
    "get_xrefs_from": {"name": r"^.{1,200}$"},
    "get_strings_at": {"address": r"^0x[0-9a-fA-F]{1,16}$", "range": r"^[0-9]{1,6}$"},
    "list_functions": {"filter": r"^[A-Za-z0-9_*?]{0,100}$"},
    "get_data_at": {"address": r"^0x[0-9a-fA-F]{1,16}$", "length": r"^[0-9]{1,5}$"},
}

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

    # Ghidra-specific: regex + numeric bounds.
    validators = GHIDRA_ARG_VALIDATORS.get(tool_name)
    if validators:
        for arg_name, pattern in validators.items():
            if arg_name in args and not re.match(pattern, str(args[arg_name])):
                return f"Invalid {arg_name}: must match {pattern}"
        if "range" in args:
            try:
                if int(args["range"]) > 4096:
                    return "range must be <= 4096"
            except (ValueError, TypeError):
                return "range must be numeric"
        if "length" in args:
            try:
                if int(args["length"]) > 65536:
                    return "length must be <= 65536"
            except (ValueError, TypeError):
                return "length must be numeric"

    return None
