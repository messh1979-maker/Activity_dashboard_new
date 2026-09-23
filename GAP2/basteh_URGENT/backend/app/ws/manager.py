"""Connection manager for chat/notification WebSockets (architecture 8.1).

Connections are kept in-process per worker; room messages are fanned out
through Redis pub/sub so multiple workers deliver to the same room.
Redis is optional: when unreachable the in-memory broker on this process
is used, which is exactly right for local development and testing.
"""

from __future__ import annotations

import asyncio
import itertools
import json
import logging
from typing import Any, Awaitable, Callable, Optional
from uuid import UUID

from fastapi import WebSocket

from app.core.redis import get_redis_broker

logger = logging.getLogger("ws.manager")

_counter = itertools.count(1)

MSG_BUFFER_LIMIT = 512


class _RoomConnection:
    """One accepted socket in a room."""

    def __init__(self, ws: WebSocket, user_id: UUID, socket_id: int) -> None:
        self.ws = ws
        self.user_id = user_id
        self.socket_id = socket_id
        self.queue: asyncio.Queue = asyncio.Queue(maxsize=MSG_BUFFER_LIMIT)


class ConnectionManager:
    """In-process socket registry + Redis pub/sub bridge per room.

    ``join`` adds the socket to ``_rooms`` and registers a per-socket
    writer task that drains messages broadcast on the room channel.
    ``publish_room`` writes to Redis ``room:{room_id}`` which every worker
    subscribed for that room relays to its local sockets.
    """

    def __init__(self) -> None:
        self._rooms: dict[str, dict[str, _RoomConnection]] = {}
        self._lock = asyncio.Lock()
        self._sub_tasks: dict[str, asyncio.Task] = {}
        self._broker = get_redis_broker()

    @staticmethod
    def _channel(room_id: UUID) -> str:
        return f"room:{room_id}"

    async def join(self, room_id: UUID, ws: WebSocket, user_id: UUID) -> None:
        """Register an accepted socket on a room and relay room broadcasts."""
        key = self._channel(room_id)
        socket_id = next(_counter)
        conn = _RoomConnection(ws, user_id, socket_id)
        async with self._lock:
            self._rooms.setdefault(key, {})[str(socket_id)] = conn
            if key not in self._sub_tasks:
                task = asyncio.create_task(self._relay_loop(key))
                self._sub_tasks[key] = task

    async def leave(self, room_id: UUID, ws: WebSocket) -> None:
        key = self._channel(room_id)
        async with self._lock:
            bucket = self._rooms.get(key)
            if bucket is None:
                return
            for socket_id in list(bucket):
                if bucket[socket_id].ws is ws:
                    bucket.pop(socket_id, None)
            if not bucket:
                self._rooms.pop(key, None)
                task = self._sub_tasks.pop(key, None)
                if task is not None:
                    task.cancel()

    async def broadcast(self, room_id: UUID, payload: dict) -> None:
        """Publish a message to a room channel for every worker to relay.

        Each worker's ``_relay_loop`` subscription delivers the payload to
        the local sockets connected to that room (single delivery only).
        """
        raw = json.dumps(payload, ensure_ascii=False, default=str)
        await self.publish_room(room_id, raw)

    async def publish_room(self, room_id: UUID, raw: str) -> None:
        """Redis pub/sub for cross-worker delivery into ``room:{room_id}``."""
        await self._broker.publish(self._channel(room_id), raw)

    async def _relay_loop(self, key: str) -> None:
        """Subscribe to a room channel and relay messages to local sockets."""
        room_id = key.split(":", 1)[1]
        try:
            async for message in self._broker.subscribe(key):
                async with self._lock:
                    bucket = list(self._rooms.get(key, {}).values())
                for conn in bucket:
                    try:
                        conn.queue.put_nowait(message)
                    except asyncio.QueueFull:
                        pass
        except asyncio.CancelledError:
            return
        except Exception as exc:  # publisher gone between publish and subscribe
            logger.warning("relay loop for %s stopped: %s", key, exc)

    async def drain_to(self, room_id: UUID, ws: WebSocket) -> None:
        """Writer task: drain this socket's queue into the wire connection."""
        # Shared writer owned by the endpoint; see routes/chat.py
        key = self._channel(room_id)
        socket_id = None
        async with self._lock:
            bucket = self._rooms.get(key, {})
            for sid, c in bucket.items():
                if c.ws is ws:
                    socket_id = sid
                    break
        if socket_id is None:
            return
        conn = bucket[socket_id]
        while True:
            raw = await conn.queue.get()
            try:
                await ws.send_text(raw)
            except Exception:
                return


# --- process-wide singleton (initialized in app lifespan) ---

_manager: Optional[ConnectionManager] = None


def get_connection_manager() -> ConnectionManager:
    global _manager
    if _manager is None:
        _manager = ConnectionManager()
    return _manager


def reset_connection_manager() -> None:
    """Testing helper."""
    global _manager
    _manager = None