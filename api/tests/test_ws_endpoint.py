# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.config import settings


@pytest.fixture(autouse=True)
def _set_api_key(monkeypatch):
    monkeypatch.setattr(settings, "api_key", "test-key-123")


def test_ws_rejects_missing_api_key():
    client = TestClient(app)
    with pytest.raises(Exception):
        with client.websocket_connect("/ws/pipeline"):
            pass


def test_ws_rejects_wrong_api_key():
    client = TestClient(app)
    with pytest.raises(Exception):
        with client.websocket_connect("/ws/pipeline?api_key=wrong"):
            pass


def test_ws_accepts_valid_api_key():
    client = TestClient(app)
    with client.websocket_connect("/ws/pipeline?api_key=test-key-123") as ws:
        # Should receive initial state on connect
        data = ws.receive_json()
        assert "running" in data
        assert "recent_completed" in data


def test_ws_allows_any_key_in_dev_mode(monkeypatch):
    monkeypatch.setattr(settings, "api_key", "")
    client = TestClient(app)
    with client.websocket_connect("/ws/pipeline") as ws:
        data = ws.receive_json()
        assert "running" in data
