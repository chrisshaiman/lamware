# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0

import json
from unittest.mock import AsyncMock

import pytest
from app.ws_manager import ConnectionManager


@pytest.fixture
def manager():
    return ConnectionManager()


def _mock_ws():
    ws = AsyncMock()
    ws.send_text = AsyncMock()
    return ws


@pytest.mark.asyncio
async def test_connect_adds_to_set(manager):
    ws = _mock_ws()
    await manager.connect(ws)
    assert ws in manager.active_connections


@pytest.mark.asyncio
async def test_disconnect_removes_from_set(manager):
    ws = _mock_ws()
    await manager.connect(ws)
    manager.disconnect(ws)
    assert ws not in manager.active_connections


@pytest.mark.asyncio
async def test_disconnect_ignores_unknown(manager):
    ws = _mock_ws()
    manager.disconnect(ws)  # should not raise


@pytest.mark.asyncio
async def test_broadcast_sends_to_all(manager):
    ws1 = _mock_ws()
    ws2 = _mock_ws()
    await manager.connect(ws1)
    await manager.connect(ws2)

    msg = {"event": "stage_update", "analysis_id": 1}
    await manager.broadcast(msg)

    expected = json.dumps(msg)
    ws1.send_text.assert_called_once_with(expected)
    ws2.send_text.assert_called_once_with(expected)


@pytest.mark.asyncio
async def test_broadcast_removes_dead_client(manager):
    ws_alive = _mock_ws()
    ws_dead = _mock_ws()
    ws_dead.send_text.side_effect = Exception("connection closed")

    await manager.connect(ws_alive)
    await manager.connect(ws_dead)

    await manager.broadcast({"event": "test"})

    assert ws_alive in manager.active_connections
    assert ws_dead not in manager.active_connections
