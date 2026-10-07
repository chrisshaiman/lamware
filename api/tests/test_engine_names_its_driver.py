"""The API engine names its PostgreSQL driver instead of taking SQLAlchemy's default.

SQLAlchemy 2.1 resolves a bare `postgresql://` to psycopg (3), which the API does
not install; CI picked up 2.1.3 on 2026-10-07 and every database-touching test
failed to import. The URL's drivername is asserted rather than the resolved
dialect driver, because on SQLAlchemy 2.0 the default IS psycopg2 and a check
of the resolved driver would pass on the broken code.
"""

from urllib.parse import urlsplit

from app import database as db


def test_the_engine_url_names_psycopg2():
    assert db.engine.url.drivername == "postgresql+psycopg2"


def test_the_engine_resolves_the_installed_driver():
    assert db.engine.dialect.driver == "psycopg2"


def test_the_asyncpg_dsn_keeps_the_bare_scheme():
    """routers/ws.py hands build_pg_dsn() to asyncpg, which rejects '+driver'."""
    assert urlsplit(db.build_pg_dsn()).scheme == "postgresql"
