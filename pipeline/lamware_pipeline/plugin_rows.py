# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Typed reads of tool output that describes the guest (#171, #686).

Volatility plugin rows and Cape's per-process data describe whatever the sample
made them: process names, command lines, DLL paths, PIDs. They used to be read
with ``entry.get("Args", "").lower()``, and ``dict.get(k, default)`` returns the
default only when k is ABSENT, so a row that was not an object, or a field
present with the wrong type, raised.

Every read goes through Row instead, the same rule as db_ingest's _Node:
  - absent              -> the caller's default (exactly what .get gave)
  - null                -> None where the value is only copied into the output
                           (as before); the default where the code operates on
                           it (null used to raise there)
  - present, right type -> the value, unchanged
  - present, wrong type -> the default, AND a warning naming the path
A row that is not an object is skipped with a warning. A well-formed output
produces no warnings.

Lives here, not in stages/volatility.py where #685 wrote it, because the import
only goes one way: the stage modules deploy flat to /opt/pipeline/stages and
import the installed lamware_pipeline package, which cannot import them back.
correlation_rules.py (in this package) and stages/volatility.py both read the
same plugin rows, so both import this one reader rather than keep two copies.

_Node itself is not used: db_ingest loads PipelineConfig and psycopg2 at import
and its integer() enforces int4 column ranges, neither of which means anything
for plugin output.
"""
from __future__ import annotations

#: 60k handle rows of junk are one problem, not 60k.
MAX_PARSE_WARNINGS = 50


def type_name(value) -> str:
    """The JSON name of a value's type, for a warning."""
    return {dict: "object", list: "array", str: "string", bool: "boolean",
            int: "integer", float: "number", type(None): "null"}.get(
                type(value), type(value).__name__)


class Row:
    """One object in a tool's JSON output, with typed reads that never raise.

    `path` is built from plugin names, our own key names and list indices —
    never from tool output — so a warning cannot carry guest-chosen text.
    """

    __slots__ = ("data", "path", "warnings")

    def __init__(self, data: dict, path: str, warnings: list[str]):
        self.data = data
        self.path = path
        self.warnings = warnings

    def _read(self, key: str, default, nullable: bool, ok, expected: str):
        if key not in self.data:
            return default
        value = self.data[key]
        if value is None:
            return None if nullable else default
        if ok(value):
            return value
        self.warnings.append(
            f"{self.path}.{key}: expected {expected}, got {type_name(value)} — not read")
        return default

    def text(self, key: str, default: str | None = "", nullable: bool = True) -> str | None:
        return self._read(key, default, nullable, lambda v: isinstance(v, str), "string")

    def integer(self, key: str, default: int | None = 0, nullable: bool = True) -> int | None:
        """An int. bool is not one here, though Python says it is."""
        return self._read(key, default, nullable, lambda v: type(v) is int, "integer")

    def array(self, key: str, default: list | None = None) -> list | None:
        return self._read(key, default, True, lambda v: isinstance(v, list), "array")


def rows(output, name: str, warnings: list[str]) -> list[Row]:
    """The object rows of one plugin's (or one list field's) output.

    A dict is run_single_plugin's {"error": ...} and null means the plugin did
    not run; both are skipped silently (the failure is already recorded in
    volatility.plugins, and correlation_warnings reports it per rule). Any other
    non-list, and any row that is not an object, is skipped with a warning.
    """
    if output is None or isinstance(output, dict):
        return []
    if not isinstance(output, list):
        warnings.append(f"{name}: expected array, got {type_name(output)} — not read")
        return []
    out = []
    for i, item in enumerate(output):
        if isinstance(item, dict):
            out.append(Row(item, f"{name}[{i}]", warnings))
        else:
            warnings.append(f"{name}[{i}]: expected object, got {type_name(item)} — row skipped")
    return out


def capped(warnings: list[str], limit: int = MAX_PARSE_WARNINGS) -> list[str]:
    """At most `limit` warnings, then one line saying how many more there were."""
    if len(warnings) <= limit:
        return list(warnings)
    return warnings[:limit] + [f"... and {len(warnings) - limit} more"]
