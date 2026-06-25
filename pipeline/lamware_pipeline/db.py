# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Safe dynamic-SQL builders using psycopg2.sql composition.

Building a dynamic column list requires assembling SQL identifiers in code
(psycopg2 %s placeholders bind VALUES, not identifiers). Using sql.Identifier /
sql.Placeholder keeps identifiers safely quoted and values parameterized, so the
result is injection-proof even if a column name were ever derived from input —
and there is no f-string for bandit B608 to flag.
"""
from psycopg2 import sql


def build_insert(table: str, columns: list[str]) -> sql.Composed:
    """INSERT INTO <table> (<cols>) VALUES (<%s...>) RETURNING id."""
    return sql.SQL("INSERT INTO {table} ({cols}) VALUES ({vals}) RETURNING id").format(
        table=sql.Identifier(table),
        cols=sql.SQL(", ").join(sql.Identifier(c) for c in columns),
        vals=sql.SQL(", ").join(sql.Placeholder() for _ in columns),
    )


def build_update(table: str, columns: list[str], key_column: str) -> sql.Composed:
    """UPDATE <table> SET <col = %s, ...> WHERE <key_column> = %s."""
    return sql.SQL("UPDATE {table} SET {assignments} WHERE {key} = {key_ph}").format(
        table=sql.Identifier(table),
        assignments=sql.SQL(", ").join(
            sql.SQL("{} = {}").format(sql.Identifier(c), sql.Placeholder()) for c in columns
        ),
        key=sql.Identifier(key_column),
        key_ph=sql.Placeholder(),
    )
