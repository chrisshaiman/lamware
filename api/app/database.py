# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
#
# Database — SQLModel engine and session dependency.
# DATABASE_URL is assembled from settings at import time.
# pool_pre_ping=True drops stale connections before reuse, which matters for a
# long-running uvicorn process that may outlive a PostgreSQL restart.

from collections.abc import Generator

from sqlmodel import Session, create_engine

from app.config import settings

DATABASE_URL = (
    f"postgresql://{settings.db_user}:{settings.db_password}"
    f"@{settings.db_host}:{settings.db_port}/{settings.db_name}"
)

engine = create_engine(DATABASE_URL, pool_pre_ping=True)


def get_session() -> Generator[Session, None, None]:
    """FastAPI dependency — yields a database session per request."""
    with Session(engine) as session:
        yield session
