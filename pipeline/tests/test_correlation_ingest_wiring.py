# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The ingest has to write correlations idempotently, and stamp that it ran.

Three properties that need PostgreSQL to exercise directly, asserted here
against the parsed source instead — the alternative is no coverage at all, which
is how `cross_correlations` went unwritten for 998 analyses in the first place.

  1. Delete-then-insert, not append. Every other child table in db_ingest
     appends, and `--replay` (#405) re-runs the whole ingest — so a replayed
     analysis would double its findings. For IOCs that is untidy; for
     correlations it corrupts the one number these tables exist to produce.

  2. Warnings are written to `analyses.correlation_warnings`, ALWAYS — the
     empty list included, because setting the column is what records that
     correlation ran. Leaving it NULL on a clean analysis would make that
     analysis indistinguishable from the 998 that predate persistence.

  3. That write happens LAST. Set before the inserts, a failure between the two
     would leave an analysis claiming it had been correlated when nothing was
     written.
"""
import ast
from pathlib import Path

import pytest

SRC_PATH = (Path(__file__).resolve().parents[2]
            / "ansible" / "roles" / "pipeline" / "files" / "db_ingest.py")
SOURCE = SRC_PATH.read_text(encoding="utf-8")
TREE = ast.parse(SOURCE)


def _sql_literals() -> list[tuple[int, str]]:
    """(lineno, sql) for every string constant passed to a `cur.execute` call.

    Parsed, not grepped: this file's comments discuss DELETE, replay and the
    timestamp at length, and a text search would find all three whether or not
    the statements survive.
    """
    out = []
    for node in ast.walk(TREE):
        if not isinstance(node, ast.Call):
            continue
        fn = node.func
        if not isinstance(fn, ast.Attribute) or fn.attr != "execute":
            continue
        if not node.args or not isinstance(node.args[0], ast.Constant):
            continue
        value = node.args[0].value
        if isinstance(value, str):
            out.append((node.lineno, " ".join(value.split())))
    return out


def test_the_ingest_inserts_findings():
    inserts = [s for _, s in _sql_literals() if s.upper().startswith("INSERT INTO CORRELATIONS")]
    assert inserts, "nothing inserts into correlations"


@pytest.mark.parametrize("table", ["correlations"])
def test_prior_rows_are_deleted_before_reinsert(table):
    """Property 1. Without this, `--replay` doubles the findings."""
    deletes = [
        s for _, s in _sql_literals()
        if s.upper().startswith(f"DELETE FROM {table.upper()}")
        and "ANALYSIS_ID = %S" in s.upper()
    ]
    assert deletes, (
        f"{table} is appended to without a scoped DELETE, so a replayed "
        f"analysis accumulates duplicate rows and the base rate is wrong")


@pytest.mark.parametrize("table", ["correlations"])
def test_the_delete_precedes_the_insert(table):
    d = min(ln for ln, s in _sql_literals() if s.upper().startswith(f"DELETE FROM {table.upper()}"))
    i = min(ln for ln, s in _sql_literals() if s.upper().startswith(f"INSERT INTO {table.upper()}"))
    assert d < i, f"{table}: the DELETE at line {d} runs after the INSERT at {i}"


def test_warnings_are_not_written_into_the_findings_table():
    """Property 2. A warning is not a finding; putting one in the findings table
    makes a zero unreadable, which is the defect #411 fixed one layer up."""
    for _, sql in _sql_literals():
        if sql.upper().startswith("INSERT INTO CORRELATIONS"):
            assert "warning" not in sql.lower()
    assert not [s for _, s in _sql_literals()
                if "INSERT INTO CORRELATION_WARNINGS" in s.upper()], (
        "correlation_warnings is a column on analyses, not a table")


def test_the_warnings_column_is_written():
    """Property 2. Without this write every analysis stays NULL, which means
    'never recorded' — so correlation would look like it had never run."""
    writes = [s for _, s in _sql_literals()
              if s.upper().startswith("UPDATE ANALYSES") and "correlation_warnings" in s]
    assert writes, "nothing records that correlation ran for this analysis"


def test_the_warnings_write_is_unconditional():
    """An empty list must still be written. Guarding the UPDATE behind
    `if warnings:` would leave a clean analysis NULL — indistinguishable from
    one that predates persistence, which is the state this column exists to
    rule out."""
    tree = ast.parse(SOURCE)
    for node in ast.walk(tree):
        if not isinstance(node, ast.If):
            continue
        body = ast.dump(ast.Module(body=node.body, type_ignores=[]))
        assert "correlation_warnings = %s" not in body, (
            "the warnings write sits inside a conditional; a clean analysis "
            "would be left NULL")


def test_the_warnings_write_comes_after_the_inserts():
    """A write before the inserts would claim correlation was recorded for an
    analysis whose findings then failed to land."""
    write = min(ln for ln, s in _sql_literals()
                if s.upper().startswith("UPDATE ANALYSES") and "correlation_warnings" in s)
    last = max(ln for ln, s in _sql_literals()
               if s.upper().startswith("INSERT INTO CORRELATIONS"))
    assert write > last, (
        f"correlation_warnings is written at line {write}, before the last "
        f"findings insert at {last}")


def test_the_warnings_write_is_inside_the_committed_transaction():
    """It must share a commit with the rows, or a crash between them leaves the
    column and the findings disagreeing."""
    commits = [n.lineno for n in ast.walk(TREE)
               if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
               and n.func.attr == "commit"]
    write = min(ln for ln, s in _sql_literals()
                if s.upper().startswith("UPDATE ANALYSES") and "correlation_warnings" in s)
    assert any(c > write for c in commits), "no commit follows the warnings write"


def test_the_shaping_helper_is_used_rather_than_a_second_mapping():
    """One place decides the row shape. A hand-written tuple here would drift
    from CORRELATION_COLUMNS silently, since the ingest zips positionally."""
    imported = {
        alias.name for n in ast.walk(TREE) if isinstance(n, ast.ImportFrom)
        and n.module == "lamware_pipeline.correlation_rules"
        for alias in n.names
    }
    assert "correlation_rows" in imported


# --- the INSERT has to be satisfiable against the schema it targets ---------

MIGRATION = (Path(__file__).resolve().parents[2] / "api" / "alembic" / "versions"
             / "0003_persist_correlation_findings.py").read_text(encoding="utf-8")


def _required_columns_without_a_default(table: str) -> set[str]:
    """NOT NULL columns of `table` that the database will not fill in itself.

    SERIAL primary keys are excluded: alembic renders `sa.Integer()` under a
    PrimaryKeyConstraint as SERIAL, which supplies its own value.
    """
    tree = ast.parse(MIGRATION)
    create = next(
        n for n in ast.walk(tree)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
        and n.func.attr == "create_table" and n.args
        and isinstance(n.args[0], ast.Constant) and n.args[0].value == table)
    required = set()
    for arg in create.args[1:]:
        if not (isinstance(arg, ast.Call) and isinstance(arg.func, ast.Attribute)
                and arg.func.attr == "Column" and arg.args):
            continue
        name = arg.args[0].value
        kw = {k.arg: k.value for k in arg.keywords}
        nullable = kw.get("nullable")
        is_nullable = isinstance(nullable, ast.Constant) and nullable.value is True
        if is_nullable or "server_default" in kw or name == "id":
            continue
        required.add(name)
    return required


def _insert_columns(table: str) -> set[str]:
    sql = next(s for _, s in _sql_literals()
               if s.upper().startswith(f"INSERT INTO {table.upper()}"))
    inside = sql[sql.index("(") + 1:sql.index(")")]
    return {c.strip() for c in inside.split(",")}


def test_the_insert_supplies_every_column_the_schema_demands():
    """The bug this caught: `created_at` was NOT NULL with no server_default and
    the INSERT did not name it, so every correlation insert would have raised
    NotNullViolation — and db_ingest's blanket `except Exception: rollback`
    turns that into a LOST ANALYSIS, IOCs and techniques included, not merely
    lost correlations.

    It survived a run against real PostgreSQL because the verification script
    hand-wrote its own INSERT with created_at included, rather than using the
    statement db_ingest actually issues. This test compares the two directly.
    """
    required = _required_columns_without_a_default("correlations")
    supplied = _insert_columns("correlations")
    missing = required - supplied
    assert not missing, (
        f"the INSERT omits NOT NULL column(s) {sorted(missing)} that have no "
        f"server_default — every insert would fail and roll back the analysis")


def test_the_insert_names_no_column_the_table_lacks():
    """The mirror: a renamed column would otherwise fail only in production."""
    tree = ast.parse(MIGRATION)
    create = next(
        n for n in ast.walk(tree)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
        and n.func.attr == "create_table" and n.args
        and isinstance(n.args[0], ast.Constant) and n.args[0].value == "correlations")
    declared = {
        a.args[0].value for a in create.args[1:]
        if isinstance(a, ast.Call) and isinstance(a.func, ast.Attribute)
        and a.func.attr == "Column" and a.args
    }
    assert _insert_columns("correlations") <= declared


def test_created_at_matches_the_convention_used_by_every_other_table():
    """`timestamp with time zone DEFAULT now()` throughout the baseline. A naive
    DateTime here would store local time next to twelve timezone-aware columns."""
    assert "sa.DateTime(timezone=True)" in MIGRATION
    assert 'server_default=sa.text("now()")' in MIGRATION
