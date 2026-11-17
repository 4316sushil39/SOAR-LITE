"""WebSocket Connection Manager for streaming real-time security events to dashboard clients."""

import asyncio
import logging
from typing import Any

from fastapi import WebSocket

logger = logging.getLogger(__name__)


class ConnectionManager:
    """Manages active dashboard WebSocket subscribers and broadcasts live telemetry."""

    def __init__(self) -> None:
        self.active_connections: list[WebSocket] = []
        self._loop: asyncio.AbstractEventLoop | None = None

    def set_event_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        """Store the running asyncio loop for thread-safe cross-thread broadcasting."""
        self._loop = loop

    async def connect(self, websocket: WebSocket) -> None:
        """Accept and register new WebSocket client."""
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info("Dashboard WebSocket client connected. Active connections: %d", len(self.active_connections))

    def disconnect(self, websocket: WebSocket) -> None:
        """Unregister disconnected WebSocket client."""
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            logger.info("Dashboard WebSocket client disconnected. Remaining: %d", len(self.active_connections))

    async def broadcast(self, message: dict[str, Any]) -> None:
        """Broadcast JSON message to all connected clients."""
        for connection in list(self.active_connections):
            try:
                await connection.send_json(message)
            except Exception as exc:
                logger.debug("Failed sending to client, removing: %s", exc)
                self.disconnect(connection)

    def broadcast_threadsafe(self, message: dict[str, Any]) -> None:
        """Thread-safe broadcast invocation callable from background collector threads."""
        if not self.active_connections:
            return

        try:
            loop = self._loop
            if loop and loop.is_running():
                asyncio.run_coroutine_threadsafe(self.broadcast(message), loop)
            else:
                # Fallback if loop not captured yet
                cur_loop = asyncio.get_event_loop()
                if cur_loop.is_running():
                    cur_loop.create_task(self.broadcast(message))
        except Exception as exc:
            logger.debug("Threadsafe broadcast notice: %s", exc)


ws_manager = ConnectionManager()
