# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
#
# WebSocket connection manager — tracks connected clients and broadcasts
# pipeline events. Dead clients are removed silently on send failure.

import json
import logging

from fastapi import WebSocket

log = logging.getLogger(__name__)

#: Concurrent WebSocket connections one authenticated principal may hold.
#:
#: There was no cap, so one account could hold unbounded sockets — every one of
#: them a target of `broadcast`, which iterates the whole pool per event. Low
#: severity while this is a single-team deployment behind authentication, which
#: is why the number is generous rather than tight: it is a runaway guard, not a
#: quota. A dashboard open in several tabs is the normal case, and 4 does not
#: cover a browser that reconnects before the old socket is reaped.
MAX_CONNECTIONS_PER_PRINCIPAL = 16


class ConnectionManager:
    """Manages active WebSocket connections and broadcasts messages."""

    def __init__(self) -> None:
        self.active_connections: set[WebSocket] = set()
        # Connection -> authenticated principal. Kept alongside rather than inside the
        # set because the set is the broadcast fan-out and must stay cheap to iterate.
        # Without this, nothing on a WebSocket channel was attributable to a user (#208).
        self.principals: dict[WebSocket, str] = {}

    async def connect(self, websocket: WebSocket, principal: str = "anonymous") -> bool:
        await websocket.accept()
        return self.track(websocket, principal=principal)

    def connections_for(self, principal: str) -> int:
        """How many sockets this principal currently holds."""
        return sum(1 for p in self.principals.values() if p == principal)

    def track(self, websocket: WebSocket, principal: str = "anonymous") -> bool:
        """Add an already-accepted, AUTHENTICATED WebSocket to the broadcast pool.

        Returns False and adds nothing when the principal is already at
        MAX_CONNECTIONS_PER_PRINCIPAL. The caller closes the socket; refusing
        here rather than in the router keeps the count and the limit in one
        place, so a second entry point cannot bypass it.
        """
        if self.connections_for(principal) >= MAX_CONNECTIONS_PER_PRINCIPAL:
            log.warning(
                "WebSocket refused for %s: already holding %d connections (limit %d)",
                principal, self.connections_for(principal), MAX_CONNECTIONS_PER_PRINCIPAL,
            )
            return False
        self.active_connections.add(websocket)
        self.principals[websocket] = principal
        log.info(
            "WebSocket client tracked: %s (%d total)", principal, len(self.active_connections)
        )
        return True

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
