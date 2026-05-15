# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
#
# WebSocket connection manager — tracks connected clients and broadcasts
# pipeline events. Dead clients are removed silently on send failure.

import json
import logging

from fastapi import WebSocket

log = logging.getLogger(__name__)


class ConnectionManager:
    """Manages active WebSocket connections and broadcasts messages."""

    def __init__(self) -> None:
        self.active_connections: set[WebSocket] = set()

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self.active_connections.add(websocket)
        log.info("WebSocket client connected (%d total)", len(self.active_connections))

    def disconnect(self, websocket: WebSocket) -> None:
        self.active_connections.discard(websocket)
        log.info("WebSocket client disconnected (%d total)", len(self.active_connections))

    async def broadcast(self, message: dict) -> None:
        """Send a JSON message to all connected clients.

        Dead clients (send fails) are removed from the set silently.
        """
        payload = json.dumps(message)
        dead: list[WebSocket] = []

        for ws in self.active_connections:
            try:
                await ws.send_text(payload)
            except Exception:
                dead.append(ws)

        for ws in dead:
            self.active_connections.discard(ws)
            log.info("Removed dead WebSocket client (%d total)", len(self.active_connections))


# Singleton — imported by ws router and pg listener
manager = ConnectionManager()
