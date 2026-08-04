# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The WebSocket auth boundary, at parity with REST (#208).

The pre-existing WS tests cover only REJECTION paths — every one asserts that a bad
first message closes the socket. None ever authenticated successfully, which is how
`await _validate_jwt(...)` sat there with its result discarded: the connection carried
no principal, nothing on the channel was attributable, and no test noticed because no
test ever got past the auth gate.

So these tests drive the AUTHENTICATED path. That is the half that was unobserved, and
the half where all six defects in #208 lived.

Auth is stubbed at `app.auth._validate_jwt` rather than by minting real JWTs: the
subject here is what the ENDPOINT does with a validated principal (bind it, bound the
session by its expiry, log rejections), not JWT verification itself, which
test_auth.py already covers against real signatures.
"""
import json
import logging
import time
from dataclasses import dataclass, field

import pytest
from app.main import app
from fastapi.testclient import TestClient


@dataclass
class _Ctx:
    """Stand-in for AuthContext with the fields the endpoint consumes."""
    user_id: str = "user-abc"
    email: str = "analyst@example.com"
    name: str = "Analyst"
    roles: list[str] = field(default_factory=lambda: ["analyst"])
    auth_method: str = "jwt"
    exp: int | None = None


@pytest.fixture()
def authed(monkeypatch):
    """Make _validate_jwt succeed, returning a principal with a far-future expiry."""
    def _apply(exp_offset: float = 3600.0, **kw):
        ctx = _Ctx(exp=int(time.time() + exp_offset), **kw)

        async def _fake(token: str):
            return ctx

        monkeypatch.setattr("app.auth._validate_jwt", _fake)
        return ctx
    return _apply


def _auth_frame(token="good.jwt.token"):
    return json.dumps({"type": "auth", "token": token})


# --- the principal must reach the connection -------------------------------


def test_authenticated_connection_binds_the_principal(authed):
    """The core regression: the validated principal must reach the manager.

    Previously `await _validate_jwt(...)` was called and its return value thrown away,
    so a connection was authenticated but anonymous.
    """
    ctx = authed()
    from app.ws_manager import manager

    seen: dict = {}
    original = manager.track

    def _spy(websocket, principal="anonymous"):
        seen["principal"] = principal
        return original(websocket, principal=principal)

    manager.track = _spy
    try:
        client = TestClient(app)
        with client.websocket_connect("/ws/pipeline") as ws:
            ws.send_text(_auth_frame())
            ws.receive_json()  # initial state — proves we got past the gate
    finally:
        manager.track = original

    assert seen.get("principal") == ctx.user_id, (
        "the connection must carry the authenticated principal, not 'anonymous' — "
        "without it nothing on the channel is attributable to a user")


def test_manager_forgets_the_principal_on_disconnect(authed):
    """A principal map that only grows is a slow leak on a 24h-timeout socket."""
    authed()
    from app.ws_manager import manager

    client = TestClient(app)
    with client.websocket_connect("/ws/pipeline") as ws:
        ws.send_text(_auth_frame())
        ws.receive_json()
    assert manager.principals == {}, f"principals leaked: {manager.principals}"


# --- every rejection path must be logged -----------------------------------


@pytest.mark.parametrize("frame,label", [
    (json.dumps({"type": "subscribe"}), "not an auth frame"),
    (json.dumps({"type": "auth"}), "auth frame with no token"),
    ("}{ not json", "malformed json"),
])
def test_rejections_are_logged(frame, label, caplog):
    """REST logged failed auth; all three WS rejection paths logged nothing.

    That made credential stuffing against /ws/ invisible — the point of the log line
    is that somebody can see the attempt, so its absence is the vulnerability.
    """
    client = TestClient(app)
    with caplog.at_level(logging.WARNING):
        with client.websocket_connect("/ws/pipeline") as ws:
            ws.send_text(frame)
            with pytest.raises(Exception):
                ws.receive_json()

    assert any("Auth failed" in r.message or "Auth failed" in r.getMessage()
               for r in caplog.records), (
        f"WS rejection ({label}) produced no failed-auth log line; "
        f"got {[r.getMessage() for r in caplog.records]}")


def test_a_rejected_token_is_logged(monkeypatch, caplog):
    async def _reject(token: str):
        raise ValueError("bad signature")

    monkeypatch.setattr("app.auth._validate_jwt", _reject)
    client = TestClient(app)
    with caplog.at_level(logging.WARNING):
        with client.websocket_connect("/ws/pipeline") as ws:
            ws.send_text(_auth_frame("forged"))
            with pytest.raises(Exception):
                ws.receive_json()

    assert any("Auth failed" in r.getMessage() for r in caplog.records)


# --- session lifetime ------------------------------------------------------


def test_session_closes_when_the_token_expires(authed):
    """nginx sets proxy_read_timeout 86400 on /ws/, so a socket could outlive a
    ~5-minute Keycloak token by a full day. Disabling a user would not disconnect
    them — the connection was authorized exactly once, at open.

    An already-past expiry is used so the deadline fires immediately rather than
    making the suite wait on a real clock.
    """
    authed(exp_offset=-60.0)
    client = TestClient(app)
    with client.websocket_connect("/ws/pipeline") as ws:
        ws.send_text(_auth_frame())
        ws.receive_json()          # initial state is still delivered
        with pytest.raises(Exception):
            # Already past the deadline, so the server closes instead of serving on.
            ws.receive_json()


def test_a_token_without_exp_does_not_grant_an_unbounded_session():
    """A missing `exp` must not read as 'never expires'."""
    from app.routers.ws import _MAX_WS_SESSION_S
    assert _MAX_WS_SESSION_S <= 3600, (
        "the absolute session ceiling must stay well under nginx's 86400s read "
        "timeout, or a token with no exp reinstates the bug this bounds")


# --- the GC defect ---------------------------------------------------------


def test_broadcast_tasks_are_strongly_referenced():
    """asyncio.create_task returns the only strong reference; the loop holds a weak
    one. Dropping it lets a broadcast be collected mid-flight, so notifications
    vanish silently under load — exactly when they matter."""
    import asyncio

    from app.routers import ws as ws_mod

    async def _drive():
        ws_mod._broadcast_tasks.clear()
        ws_mod._on_notification(None, 0, "pipeline_events", json.dumps({"x": 1}))
        assert ws_mod._broadcast_tasks, (
            "the broadcast task must be retained until it completes")
        await asyncio.sleep(0)
        await asyncio.gather(*list(ws_mod._broadcast_tasks), return_exceptions=True)

    asyncio.run(_drive())


def test_malformed_notify_payload_creates_no_task():
    from app.routers import ws as ws_mod
    ws_mod._broadcast_tasks.clear()
    ws_mod._on_notification(None, 0, "pipeline_events", "}{ not json")
    assert not ws_mod._broadcast_tasks


# --- parity with REST ------------------------------------------------------


def test_failed_auth_logger_accepts_a_websocket():
    """The WS path logs through the SAME function as REST, not a copy.

    Both Request and WebSocket derive from Starlette's HTTPConnection, which carries
    every attribute the logger touches. Sharing it is what stops the two paths
    drifting in what they record — the asymmetry #208 is about.
    """
    import inspect

    from app.auth import _log_failed_auth
    from starlette.requests import HTTPConnection
    from starlette.websockets import WebSocket

    assert HTTPConnection in WebSocket.__mro__
    hint = inspect.signature(_log_failed_auth).parameters["request"].annotation
    assert hint in (HTTPConnection, "HTTPConnection"), (
        f"_log_failed_auth is typed {hint!r}; it must accept HTTPConnection so the "
        f"WebSocket path shares it rather than growing a parallel logger")


def test_auth_context_carries_expiry():
    """REST re-validates every request, so only the WS path needs `exp` — which is
    why it was missing."""
    from app.auth import AuthContext
    assert "exp" in AuthContext.__dataclass_fields__
    assert AuthContext(user_id="u", email="e", name="n").exp is None
