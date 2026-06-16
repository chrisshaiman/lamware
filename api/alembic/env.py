# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
#
# Alembic environment.
#
# Phase A: migrations-only. target_metadata is None so autogenerate is DISABLED.
# The ORM models cover only ~13 of 19 tables; autogenerate against that partial
# metadata would emit destructive op.drop_table(...) calls for the unmodeled
# tables. Spec 2 completes the models and sets target_metadata = SQLModel.metadata.
#
# The database URL comes EXCLUSIVELY from ALEMBIC_DATABASE_URL. There is no
# fallback to application settings: migrations need a DDL-capable connection, and
# silently using the runtime (DML-only) credentials would fail confusingly.
import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Spec 2: populate metadata from the ORM models where the app package is importable
# (dev / host reconciliation). The deployed runner at /opt/lamware-migrations has
# only the alembic project and no `app` package / sqlmodel, so fall back to None —
# upgrade/stamp don't need metadata, and this keeps the runner working.
try:
    import app.models  # noqa: F401 — registers all tables on SQLModel.metadata
    from sqlmodel import SQLModel

    from app.schema_meta import include_object

    target_metadata = SQLModel.metadata
except ModuleNotFoundError:
    target_metadata = None
    include_object = None


def _database_url() -> str:
    url = os.environ.get("ALEMBIC_DATABASE_URL")
    if not url:
        raise RuntimeError(
            "ALEMBIC_DATABASE_URL is not set. Alembic migrations require a "
            "DDL-capable database URL (e.g. the postgres superuser via peer "
            "auth: postgresql+psycopg2:///malware_analysis). Refusing to fall "
            "back to application credentials."
        )
    return url


def run_migrations_offline() -> None:
    """Run migrations without a DB-API connection (emits SQL)."""
    context.configure(
        url=_database_url(),
        target_metadata=target_metadata,
        include_object=include_object,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations against a live connection."""
    section = config.get_section(config.config_ini_section, {})
    section["sqlalchemy.url"] = _database_url()
    connectable = engine_from_config(
        section,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            include_object=include_object,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
