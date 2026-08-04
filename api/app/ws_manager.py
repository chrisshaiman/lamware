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
        # Connection -> authenticated principal. Kept alongside rather than inside the
        # set because the set is the broadcast fan-out and must stay cheap to iterate.
        # Without this, nothing on a WebSocket channel was attributable to a user (#208).
        self.principals: dict[WebSocket, str] = {}

    async def connect(self, websocket: WebSocket, principal: str = "anonymous") -> None:
        await websocket.accept()
        self.track(websocket, principal=principal)

    def track(self, websocket: WebSocket, principal: str = "anonymous") -> None:
        """Add an already-accepted, AUTHENTICATED WebSocket to the broadcast pool."""
        self.active_connections.add(websocket)
        self.principals[websocket] = principal
        log.info(
            "WebSocket client tracked: %s (%d total)", principal, len(self.active_connections)
        )

    def disconnect(self, websocket: WebSocket) -> None:
        self.active_connections.discard(websocket)
        principal = self.principals.pop(websocket, "unknown")
        log.info(
            "WebSocket client disconnected: %s (%d total)",
            principal, len(self.active_connections),
        )

    async def broadcast(self, message: dict) -> None:
        """Send a JSON message to all connected clients.

        Dead clients (send fails) are removed from the set silently.
        """
        payload = json.dumps(message)
        dead: list[WebSocket] = []

        # Iterate a snapshot: a send that fails can trigger disconnect() on the same
        # loop, and mutating active_connections mid-iteration raises RuntimeError.
        for ws in list(self.active_connections):
            try:
                await ws.send_text(payload)
            except Exception:
                dead.append(ws)

        for ws in dead:
            self.active_connections.discard(ws)
            self.principals.pop(ws, None)
            log.info("Removed dead WebSocket client (%d total)", len(self.active_connections))


# Singleton — imported by ws router and pg listener
manager = ConnectionManager()
