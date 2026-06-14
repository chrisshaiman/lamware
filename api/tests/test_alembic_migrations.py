# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Round-trip test: `alembic upgrade head` builds the expected schema.

SKIPPED unless LAMWARE_MIGRATION_TEST_URL points at a THROWAWAY PostgreSQL
database. The test DROPs and recreates the public schema in that database, then
runs migrations into it. NEVER point this at production.

Run it like:
    LAMWARE_MIGRATION_TEST_URL=postgresql+psycopg2://user:pw@localhost/alembic_test \
        pytest api/tests/test_alembic_migrations.py -v
"""
import os
import subprocess
from pathlib import Path

import pytest

MIGRATION_URL = os.environ.get("LAMWARE_MIGRATION_TEST_URL", "")
API_DIR = Path(__file__).resolve().parents[1]

# The 20 data tables (19 from schema.sql + audit_log from migration_002) plus
# Alembic's own bookkeeping table.
EXPECTED_TABLES = {
    "samples", "sample_relationships", "analyses", "ioc_values", "analysis_iocs",
    "technique_values", "analysis_techniques", "capabilities", "signatures",
    "network_events", "tags", "analysis_tags", "ioc_tags", "sample_tags",
    "ioc_technique_mappings", "pipeline_stage_events", "audit_log",
    "investigation_sessions", "investigation_messages", "investigation_pins",
    "alembic_version",
}


@pytest.fixture
def fresh_engine():
    if not MIGRATION_URL:
        pytest.skip("LAMWARE_MIGRATION_TEST_URL not set")
    import sqlalchemy as sa

    engine = sa.create_engine(MIGRATION_URL)
    with engine.begin() as conn:
        conn.execute(sa.text("DROP SCHEMA public CASCADE"))
        conn.execute(sa.text("CREATE SCHEMA public"))
    return engine


def test_upgrade_head_creates_expected_tables(fresh_engine):
    import sqlalchemy as sa

    result = subprocess.run(
        ["alembic", "upgrade", "head"],
        cwd=API_DIR,
        env={**os.environ, "ALEMBIC_DATABASE_URL": MIGRATION_URL},
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, f"alembic upgrade failed:\n{result.stderr}"

    tables = set(sa.inspect(fresh_engine).get_table_names())
    missing = EXPECTED_TABLES - tables
    assert not missing, f"missing tables after upgrade: {sorted(missing)}"


def test_upgrade_head_is_idempotent(fresh_engine):
    import sqlalchemy as sa

    base_env = {**os.environ, "ALEMBIC_DATABASE_URL": MIGRATION_URL}
    first = subprocess.run(
        ["alembic", "upgrade", "head"], cwd=API_DIR, env=base_env,
        capture_output=True, text=True,
    )
    assert first.returncode == 0, first.stderr
    second = subprocess.run(
        ["alembic", "upgrade", "head"], cwd=API_DIR, env=base_env,
        capture_output=True, text=True,
    )
    assert second.returncode == 0, f"second upgrade not a clean no-op:\n{second.stderr}"

    with sa.create_engine(MIGRATION_URL).connect() as conn:
        version = conn.execute(
            sa.text("SELECT version_num FROM alembic_version")
        ).scalar_one()
    assert version == "0001"
