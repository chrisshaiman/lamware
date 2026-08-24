# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""One account must not be able to hold unbounded WebSocket connections.

`broadcast` iterates the entire connection pool on every pipeline event, so an
unbounded socket count is unbounded work per event. There was no cap.

Low severity — authentication is required and this is a single-team deployment —
which is why the limit is generous rather than tight. Several dashboard tabs is
the normal case; this is a runaway guard, not a quota.
"""
import asyncio

import pytest
from app.ws_manager import MAX_CONNECTIONS_PER_PRINCIPAL, ConnectionManager


class _Socket:
    """Stand-in for a WebSocket. Records what it was sent and whether it closed."""

    def __init__(self):
        self.sent: list[str] = []
        self.accepted = False

    async def accept(self):
        self.accepted = True

    async def send_text(self, payload):
        self.sent.append(payload)


@pytest.fixture
def mgr():
    return ConnectionManager()


def test_a_principal_can_hold_up_to_the_limit(mgr):
    accepted = [mgr.track(_Socket(), principal="analyst")
                for _ in range(MAX_CONNECTIONS_PER_PRINCIPAL)]
    assert all(accepted)
    assert mgr.connections_for("analyst") == MAX_CONNECTIONS_PER_PRINCIPAL


def test_the_next_one_is_refused(mgr):
    """THE bug: this used to be unbounded."""
    for _ in range(MAX_CONNECTIONS_PER_PRINCIPAL):
        mgr.track(_Socket(), principal="analyst")

    extra = _Socket()
    assert mgr.track(extra, principal="analyst") is False
    assert extra not in mgr.active_connections, (
        "a refused socket must not join the broadcast pool")
    assert mgr.connections_for("analyst") == MAX_CONNECTIONS_PER_PRINCIPAL


def test_a_refused_socket_receives_no_broadcasts(mgr):
    """The consequence of the assertion above, stated as behaviour."""
    for _ in range(MAX_CONNECTIONS_PER_PRINCIPAL):
        mgr.track(_Socket(), principal="analyst")
    extra = _Socket()
    mgr.track(extra, principal="analyst")

    asyncio.run(mgr.broadcast({"event": "x"}))
    assert extra.sent == []


def test_the_limit_is_per_principal_not_global(mgr):
    """A busy analyst must not lock everyone else out — that would turn a
    runaway guard into a denial of service against the rest of the team."""
    for _ in range(MAX_CONNECTIONS_PER_PRINCIPAL):
        mgr.track(_Socket(), principal="analyst-a")

    assert mgr.track(_Socket(), principal="analyst-b") is True
    assert mgr.connections_for("analyst-b") == 1


def test_disconnecting_frees_a_slot(mgr):
    """Otherwise the cap is a lifetime budget and a long-lived process
    eventually refuses everyone."""
    sockets = [_Socket() for _ in range(MAX_CONNECTIONS_PER_PRINCIPAL)]
    for s in sockets:
        mgr.track(s, principal="analyst")
    assert mgr.track(_Socket(), principal="analyst") is False

    mgr.disconnect(sockets[0])
    assert mgr.track(_Socket(), principal="analyst") is True


def test_a_dead_client_reaped_by_broadcast_frees_a_slot(mgr):
    """broadcast removes sockets whose send fails, and it must remove them from
    the principal map too — otherwise the count leaks and the cap tightens
    silently over time."""
    class _Dead(_Socket):
        async def send_text(self, payload):
            raise ConnectionResetError

    for _ in range(MAX_CONNECTIONS_PER_PRINCIPAL - 1):
        mgr.track(_Socket(), principal="analyst")
    mgr.track(_Dead(), principal="analyst")
    assert mgr.connections_for("analyst") == MAX_CONNECTIONS_PER_PRINCIPAL

    asyncio.run(mgr.broadcast({"event": "x"}))
    assert mgr.connections_for("analyst") == MAX_CONNECTIONS_PER_PRINCIPAL - 1
    assert mgr.track(_Socket(), principal="analyst") is True


def test_connect_reports_the_refusal_too(mgr):
    """`connect` accepts then tracks; its return value has to carry the refusal
    or a caller using it would leave an accepted socket untracked and silent."""
    for _ in range(MAX_CONNECTIONS_PER_PRINCIPAL):
        mgr.track(_Socket(), principal="analyst")

    extra = _Socket()
    assert asyncio.run(mgr.connect(extra, principal="analyst")) is False
    assert extra.accepted, "the socket is accepted before the limit is known"


def test_the_router_closes_a_refused_connection():
    """The manager refuses; the router has to act on it. 1013 "try again later"
    rather than an auth code — the credentials were fine."""
    import ast
    from pathlib import Path

    import app.routers.ws as ws_router

    tree = ast.parse(Path(ws_router.__file__).read_text(encoding="utf-8"))
    guarded = [
        n for n in ast.walk(tree)
        if isinstance(n, ast.If) and isinstance(n.test, ast.UnaryOp)
        and isinstance(n.test.op, ast.Not)
        and isinstance(n.test.operand, ast.Call)
        and isinstance(n.test.operand.func, ast.Attribute)
        and n.test.operand.func.attr == "track"
    ]
    assert guarded, "manager.track()'s return value is discarded — the cap does nothing"

    body = ast.dump(ast.Module(body=guarded[0].body, type_ignores=[]))
    assert "close" in body, "a refused connection must be closed, not left open"
    assert "1013" in body, "expected close code 1013 (try again later)"
    assert any(isinstance(n, ast.Return) for n in ast.walk(guarded[0])), (
        "the handler must return, or a refused socket falls through to the loop")
