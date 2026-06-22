# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
#
# WebSocket auth tests — JWT via first message.

import json

import pytest
from app.main import app
from fastapi.testclient import TestClient


def test_ws_closes_without_auth_message():
    """WebSocket should close if no auth message sent within timeout."""
    client = TestClient(app)
    with client.websocket_connect("/ws/pipeline") as ws:
        # Don't send auth — server should close with 4001
        with pytest.raises(Exception):
            ws.receive_json()


def test_ws_rejects_invalid_message_type():
    """WebSocket should close if first message type is not 'auth'."""
    client = TestClient(app)
    with client.websocket_connect("/ws/pipeline") as ws:
        ws.send_text(json.dumps({"type": "subscribe"}))
        with pytest.raises(Exception):
            ws.receive_json()


def test_ws_rejects_auth_without_token():
    """WebSocket should close if auth message has no token."""
    client = TestClient(app)
    with client.websocket_connect("/ws/pipeline") as ws:
        ws.send_text(json.dumps({"type": "auth"}))
        with pytest.raises(Exception):
            ws.receive_json()


def test_ws_rejects_invalid_jwt():
    """WebSocket should close if JWT is invalid."""
    client = TestClient(app)
    with client.websocket_connect("/ws/pipeline") as ws:
        ws.send_text(json.dumps({"type": "auth", "token": "invalid.jwt.token"}))
        with pytest.raises(Exception):
            ws.receive_json()
