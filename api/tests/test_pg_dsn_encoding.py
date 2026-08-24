# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""A vault password with a URL-special character must not silently redirect the DSN.

`postgresql://{user}:{password}@{host}:{port}/{name}` was assembled by f-string
in two places. A password containing `@` splits userinfo from host, so the
connection is attempted against a host named from the tail of the password —
the string parses fine, it just means something else.

The WebSocket listener is where this hides best: `_pg_listener` retries every
five seconds at `log.warning`, so live pipeline events stop reaching the
dashboard and nothing surfaces as an error.

Assertions parse the result with `urllib.parse.urlsplit` and check the decoded
components. Asserting on the string would pass for a DSN that merely contains
the right characters in the wrong places, which is the entire bug.
"""
from urllib.parse import unquote, urlsplit

import app.database as db
import pytest

#: Characters that change how a DSN parses. `/` is called out because
#: urllib.parse.quote leaves it alone unless safe="" is passed.
HOSTILE = ["p@ss", "pa:ss", "pa/ss", "pa#ss", "pa?ss", "p@ss:/#?word", "pä ss"]


@pytest.fixture
def settings(monkeypatch):
    monkeypatch.setattr(db.settings, "db_user", "lamware", raising=False)
    monkeypatch.setattr(db.settings, "db_host", "10.200.0.1", raising=False)
    monkeypatch.setattr(db.settings, "db_port", 5432, raising=False)
    monkeypatch.setattr(db.settings, "db_name", "lamware", raising=False)
    return db.settings


@pytest.mark.parametrize("password", HOSTILE)
def test_the_host_survives_a_hostile_password(password, settings, monkeypatch):
    """THE bug. With `p@ss`, the unencoded DSN pointed at host `ss`."""
    monkeypatch.setattr(settings, "db_password", password, raising=False)
    parts = urlsplit(db.build_pg_dsn())
    assert parts.hostname == "10.200.0.1", (
        f"password {password!r} moved the connection to {parts.hostname!r}")
    assert parts.port == 5432


@pytest.mark.parametrize("password", HOSTILE)
def test_the_password_round_trips_unchanged(password, settings, monkeypatch):
    """Encoding must be reversible — the server has to receive the real one."""
    monkeypatch.setattr(settings, "db_password", password, raising=False)
    parts = urlsplit(db.build_pg_dsn())
    assert unquote(parts.password) == password


@pytest.mark.parametrize("field,value", [
    ("db_user", "la@mware"),
    ("db_user", "la:mware"),
    ("db_name", "lam/ware"),
    ("db_name", "lam?ware"),
])
def test_user_and_database_name_are_encoded_too(field, value, settings, monkeypatch):
    """Not just the password: all three are interpolated, all three are vault
    values, and `/` in a database name terminates the path component."""
    monkeypatch.setattr(settings, "db_password", "plain", raising=False)
    monkeypatch.setattr(settings, field, value, raising=False)
    parts = urlsplit(db.build_pg_dsn())
    assert parts.hostname == "10.200.0.1"
    got = unquote(parts.username) if field == "db_user" else unquote(parts.path.lstrip("/"))
    assert got == value


def test_an_ordinary_password_is_left_alone(settings, monkeypatch):
    """No gratuitous encoding — the common case must stay readable in logs."""
    monkeypatch.setattr(settings, "db_password", "s3cret", raising=False)
    assert db.build_pg_dsn() == "postgresql://lamware:s3cret@10.200.0.1:5432/lamware"


def test_the_websocket_listener_uses_the_same_builder():
    """The two DSNs drifted apart once already — ws.py was the reported site and
    database.py had the identical bug unreported. One builder, both callers."""
    import ast
    from pathlib import Path

    src = Path(db.__file__).resolve().parent / "routers" / "ws.py"
    tree = ast.parse(src.read_text(encoding="utf-8"))
    called = {
        node.func.id for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    assert "build_pg_dsn" in called, "ws.py assembles its own DSN again"

    joined = [
        node for node in ast.walk(tree)
        if isinstance(node, ast.JoinedStr)
        and "postgresql://" in "".join(
            v.value for v in node.values if isinstance(v, ast.Constant)
            and isinstance(v.value, str))
    ]
    assert not joined, "ws.py still has an f-string DSN"
