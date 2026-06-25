# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Tests for the psycopg2.sql query builders (lamware_pipeline.db).

These prove the builders use sql composition (not f-strings) and emit one
placeholder per value + safely-quoted identifiers — no DB connection needed.
"""
from psycopg2 import sql

from lamware_pipeline.db import build_insert, build_update


def _leaves(composable):
    """Flatten a psycopg2.sql.Composed tree into its leaf Composables."""
    if isinstance(composable, sql.Composed):
        out = []
        for part in composable.seq:
            out.extend(_leaves(part))
        return out
    return [composable]


def test_build_insert_is_composed_not_a_string():
    stmt = build_insert("analyses", ["a", "b", "report_json"])
    assert isinstance(stmt, sql.Composed)  # composition, never an f-string


def test_build_insert_counts():
    stmt = build_insert("analyses", ["a", "b", "c"])
    leaves = _leaves(stmt)
    assert sum(isinstance(x, sql.Placeholder) for x in leaves) == 3   # one %s per column
    assert sum(isinstance(x, sql.Identifier) for x in leaves) == 4    # table + 3 columns


def test_build_update_is_composed_and_counts():
    stmt = build_update("analyses", ["a", "b"], "id")
    assert isinstance(stmt, sql.Composed)
    leaves = _leaves(stmt)
    assert sum(isinstance(x, sql.Placeholder) for x in leaves) == 3   # 2 SET values + 1 WHERE key
    assert sum(isinstance(x, sql.Identifier) for x in leaves) == 4    # table + 2 columns + key column
