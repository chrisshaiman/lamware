# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
#
# Database — SQLModel engine and session dependency.
# DATABASE_URL is assembled from settings at import time.
# pool_pre_ping=True drops stale connections before reuse, which matters for a
# long-running uvicorn process that may outlive a PostgreSQL restart.

from collections.abc import Generator
from urllib.parse import quote

from sqlmodel import Session, create_engine

from app.config import settings


def build_pg_dsn(driver: str = "postgresql") -> str:
    """PostgreSQL DSN with every interpolated component percent-encoded.

    The credentials come from the vault, and a password containing `@`, `:`, `/`
    or `#` produced a DSN that parsed as something else entirely — a `@` splits
    userinfo from host, so the connection would be attempted against a host
    named from the tail of the password. Nothing validated the assembled string,
    so the symptom was a connection error blamed on the database.

    The WebSocket listener fails softer and therefore worse: `_pg_listener`
    retries every 5 seconds at `log.warning`, so live pipeline events simply
    stop reaching the dashboard and no error surfaces.

    `safe=""` matters — `quote` leaves `/` alone by default, which is one of the
    characters that has to be encoded here.
    """
    user = quote(settings.db_user, safe="")
    password = quote(settings.db_password, safe="")
    name = quote(settings.db_name, safe="")
    return f"{driver}://{user}:{password}@{settings.db_host}:{settings.db_port}/{name}"


DATABASE_URL = build_pg_dsn()

engine = create_engine(DATABASE_URL, pool_pre_ping=True)


def get_session() -> Generator[Session, None, None]:
    """FastAPI dependency — yields a database session per request."""
    with Session(engine) as session:
        yield session
