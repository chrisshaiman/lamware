# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
#
# Alembic environment.
#
# Spec 2 (active): autogenerate is ENABLED when the `app` package is importable
# (dev / host reconciliation) — target_metadata = SQLModel.metadata. The deployed
# runner has no `app`/sqlmodel, so it falls back to None and runs upgrade/stamp
# only. Autogenerate scope is tables + columns + nullability (see app/schema_meta).
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

# Populate metadata from the ORM models where importable (dev/host); the app-less
# deployed runner keeps these as None (defaults below) and runs upgrade/stamp only.
#
# INVARIANT: app.models must NOT transitively import app.database or app.config —
# those build the SQLAlchemy engine from LAMWARE_* env vars at import time, which
# are absent in the alembic runner. Use TYPE_CHECKING / lazy imports if a model
# ever needs a DB reference.
target_metadata = None
include_object = None
try:
    import app.models  # noqa: F401 — registers all tables on SQLModel.metadata
    from sqlmodel import SQLModel

    from app.schema_meta import include_object  # noqa: F811 — rebinds the None default

    target_metadata = SQLModel.metadata
except ModuleNotFoundError:
    pass


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
