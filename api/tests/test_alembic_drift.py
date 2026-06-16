# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Drift sentinel: SQLModel.metadata must match the DB built by `alembic upgrade head`.

SKIPPED unless LAMWARE_MIGRATION_TEST_URL points at a THROWAWAY PostgreSQL DB
(it DROPs/recreates the public schema). Scope = tables + columns + nullability
(matches the include_object policy); types/server_defaults/indexes/constraints are
not compared.
"""
import os
import subprocess
from pathlib import Path

import pytest

MIGRATION_URL = os.environ.get("LAMWARE_MIGRATION_TEST_URL", "")
API_DIR = Path(__file__).resolve().parents[1]
RELEVANT_OPS = {
    "add_table",
    "remove_table",
    "add_column",
    "remove_column",
    "modify_nullable",
}


def _op_name(diff) -> str:
    # compare_metadata yields either a tuple (op, ...) or a list of such tuples
    if isinstance(diff, list):
        return diff[0][0] if diff and isinstance(diff[0], tuple) else ""
    return diff[0] if isinstance(diff, tuple) else ""


@pytest.fixture
def built_engine():
    if not MIGRATION_URL:
        pytest.skip("LAMWARE_MIGRATION_TEST_URL not set")
    import sqlalchemy as sa

    engine = sa.create_engine(MIGRATION_URL)
    with engine.begin() as conn:
        conn.execute(sa.text("DROP SCHEMA public CASCADE"))
        conn.execute(sa.text("CREATE SCHEMA public"))
    result = subprocess.run(
        ["alembic", "upgrade", "head"],
        cwd=API_DIR,
        env={**os.environ, "ALEMBIC_DATABASE_URL": MIGRATION_URL},
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, f"alembic upgrade failed:\n{result.stderr}"
    return engine


def test_models_match_db(built_engine):
    import app.models  # noqa: F401 — register tables on metadata
    from alembic.autogenerate import compare_metadata
    from alembic.runtime.migration import MigrationContext
    from sqlmodel import SQLModel

    from app.schema_meta import include_object

    with built_engine.connect() as conn:
        ctx = MigrationContext.configure(
            conn, opts={"include_object": include_object, "compare_type": False}
        )
        diffs = compare_metadata(ctx, SQLModel.metadata)

    relevant = [d for d in diffs if _op_name(d) in RELEVANT_OPS]
    assert not relevant, "model/DB drift (tables/columns/nullability):\n" + "\n".join(
        repr(d) for d in relevant
    )
