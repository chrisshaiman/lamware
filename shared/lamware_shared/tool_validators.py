# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Canonical Ghidra tool-argument validators — the single source of truth.

Imported by BOTH the investigation agent (api/app/investigate/tool_validators.py)
and the pipeline interpret stage (ansible/.../stages/interpret.py.j2). There is
exactly one copy; the previous cross-copy drift guard is therefore retired.
"""
import re

# Regex per Ghidra tool whose free-form args reach the Ghidra subprocess.
GHIDRA_ARG_VALIDATORS = {
    "decompile_function": {"name": r"^.{1,200}$"},
    "get_xrefs_to": {"name": r"^.{1,200}$"},
    "get_xrefs_from": {"name": r"^.{1,200}$"},
    "get_strings_at": {"address": r"^0x[0-9a-fA-F]{1,16}$", "range": r"^[0-9]{1,6}$"},
    "list_functions": {"filter": r"^[A-Za-z0-9_*?]{0,100}$"},
    "get_data_at": {"address": r"^0x[0-9a-fA-F]{1,16}$", "length": r"^[0-9]{1,5}$"},
}


def validate_ghidra_args(tool_name: str, args: dict) -> str | None:
    """Regex + numeric-bounds check for a Ghidra tool call's args.

    Returns an error string, or None if the args are valid OR the tool is not a
    Ghidra tool (callers layer their own generic validation on top).
    """
    validators = GHIDRA_ARG_VALIDATORS.get(tool_name)
    if validators is None:
        return None
    for arg_name, arg_value in args.items():
        pattern = validators.get(arg_name)
        if pattern is None:
            continue
        if not re.match(pattern, str(arg_value)):
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
