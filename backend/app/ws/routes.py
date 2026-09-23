"""WebSocket endpoints (architecture 1.4 / 5.5 / 12.8).

* ``/ws/chat``           - live chat: join + message frames, per-socket rate
                           limiting (20 msg/min), idle timeout (300 s),
                           message size cap (8192 bytes), re-validation of
                           the access token every 60 s (close 4401).
* ``/ws/notifications``  - live push of unread-count + inbox events.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from uuid import UUID

from fastapi import APIRouter, Query, WebSocket, WebSocketDisconnect

from app.core.config import settings
from app.core.database import async_session_context
from app.core.redis import get_redis_broker
from app.core.security import verify_hmac_signature
from app.ws.manager import get_connection_manager

logger = logging.getLogger("ws.routes")

router = APIRouter(tags=["websocket"])

WS_CHAT: str = "/ws/chat"
WS_NOTIFICATIONS: str = "/ws/notifications"

MSG_MAX_BYTES = 8192
IDLE_TIMEOUT_S = 300
REVALIDATE_INTERVAL_S = 60
CHAT_RATE_LIMIT = 20  # messages per minute per socket

# --- shared token verification -------------------------------------------------


def _is_allowed_origin(headers) -> bool:
    allowed = settings.ws_allowed_origins
    if not allowed or "*" in allowed:
        return True
    origin = headers.get("origin") if hasattr(headers, "get") else None
    return origin in allowed


async def _verify_access_token(token: str) -> UUID | None:
    from jose import JWTError, jwt as jose_jwt

    if not token:
        return None
    try:
        claims = jose_jwt.decode(
            token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM]
        )
        sub = claims.get("sub")
        if not sub:
            return None
        return UUID(sub)
    except (JWTError, ValueError, TypeError):
        return None


async def _user_is_active(user_id: UUID) -> bool:
    from sqlalchemy import text

    async with async_session_context() as session:
        row = (await session.execute(
            text("SELECT is_active FROM auth.users WHERE id = :uid"),
            {"uid": str(user_id)},
        )).mappings().first()
    return bool(row and row["is_active"])


# --- chat gateway -----------------------------------------------------------------


@router.websocket(WS_CHAT)
async def chat_gateway(websocket: WebSocket):
    token = websocket.query_params.get("token", "")
    manager = get_connection_manager()

    await websocket.accept()

    if not _is_allowed_origin(websocket.headers):
        await websocket.close(code=4403)
        return

    user_id = await _verify_access_token(token)
    if user_id is None or not await _user_is_active(user_id):
        await websocket.close(code=4401, reason="invalid or expired token")
        return

    sw = _SlidingWindow(CHAT_RATE_LIMIT, 60)
    joined_room: UUID | None = None
    revalidate_ok = True

    async def revalidate_task():
        nonlocal revalidate_ok
        while True:
            await asyncio.sleep(REVALIDATE_INTERVAL_S)
            if not await _user_is_active(user_id):
                revalidate_ok = False
                try:
                    await websocket.close(code=4401, reason="token expired")
                except Exception:
                    pass
                return

    reval = asyncio.create_task(revalidate_task())
    writer: asyncio.Task | None = None

    try:
        while True:
            if not revalidate_ok:
                break
            try:
                raw = await asyncio.wait_for(websocket.receive_text(), timeout=IDLE_TIMEOUT_S)
            except asyncio.TimeoutError:
                await websocket.close(code=4408, reason="idle timeout")
                break

            if len(raw.encode("utf-8")) > MSG_MAX_BYTES:
                await websocket.send_json({"type": "error", "code": "MESSAGE_TOO_LARGE"})
                await websocket.close(code=1009)
                break

            try:
                frame = json.loads(raw)
            except (json.JSONDecodeError, TypeError):
                await websocket.send_json({"type": "error", "code": "INVALID_FRAME"})
                continue

            ftype = frame.get("type")
            if ftype == "join":
                try:
                    room_id = UUID(str(frame.get("room_id")))
                except (ValueError, TypeError):
                    await websocket.send_json({"type": "error", "code": "BAD_ROOM"})
                    continue
                if not await _is_member(room_id, user_id):
                    await websocket.send_json({"type": "error", "code": "NOT_A_MEMBER"})
                    continue
                if joined_room is not None and joined_room != room_id:
                    await manager.leave(joined_room, websocket)
                joined_room = room_id
                await manager.join(room_id, websocket, user_id)
                if writer is not None:
                    writer.cancel()
                writer = asyncio.create_task(_write_loop(manager, room_id, websocket, user_id))
                await websocket.send_json(
                    {"type": "connected", "room_id": str(room_id)}
                )
                continue

            if ftype == "message":
                if joined_room is None:
                    await websocket.send_json({"type": "error", "code": "NOT_JOINED"})
                    continue
                if not sw.allow():
                    await websocket.send_json({"type": "error", "code": "RATE_LIMITED"})
                    continue
                body = str(frame.get("body", ""))[:4000]
                if not body.strip():
                    await websocket.send_json({"type": "error", "code": "EMPTY_MESSAGE"})
                    continue
                body = _sanitize_html(body)
                if not body:
                    await websocket.send_json({"type": "error", "code": "EMPTY_MESSAGE"})
                    continue
                room_id = joined_room
                if not await _is_member(room_id, user_id):
                    await websocket.send_json({"type": "error", "code": "NOT_A_MEMBER"})
                    continue
                saved = await _persist_message(room_id, user_id, body)
                await manager.broadcast(
                    room_id,
                    {
                        "type": "message",
                        "room_id": str(room_id),
                        "sender_id": str(user_id),
                        "body": body,
                        "id": str(saved.get("id")),
                        "created_at": saved.get("created_at"),
                    },
                )
                continue

            if ftype == "leave":
                if joined_room is not None:
                    await manager.leave(joined_room, websocket)
                    joined_room = None
                    await websocket.send_json({"type": "left"})
                continue

            if ftype == "ping":
                await websocket.send_json({"type": "pong"})
                continue

            await websocket.send_json({"type": "error", "code": "UNKNOWN_FRAME"})

    except WebSocketDisconnect:
        pass
    finally:
        reval.cancel()
        if writer is not None:
            writer.cancel()
        if joined_room is not None:
            await manager.leave(joined_room, websocket)


# --- notifications gateway ----------------------------------------------------------


@router.websocket(WS_NOTIFICATIONS)
async def notifications_gateway(websocket: WebSocket):
    token = websocket.query_params.get("token", "")

    await websocket.accept()

    if not _is_allowed_origin(websocket.headers):
        await websocket.close(code=4403)
        return

    user_id = await _verify_access_token(token)
    if user_id is None or not await _user_is_active(user_id):
        await websocket.close(code=4401, reason="invalid or expired token")
        return

    broker = get_redis_broker()
    channel = f"notifications:{user_id}"

    async def push_unread():
        await websocket.send_json({"type": "unread_count", "count": await _unread_count(user_id)})

    await push_unread()

    async def redis_loop():
        async for message in broker.subscribe(channel):
            try:
                await websocket.send_text(message)
            except Exception:
                return
            # also refresh the headline count after an event
            await push_unread()

    task = asyncio.create_task(redis_loop())
    try:
        while True:
            try:
                raw = await asyncio.wait_for(websocket.receive_text(), timeout=IDLE_TIMEOUT_S)
            except asyncio.TimeoutError:
                await websocket.close(code=4408, reason="idle timeout")
                break
            if len(raw.encode("utf-8")) > MSG_MAX_BYTES:
                await websocket.close(code=1009)
                break
            try:
                frame = json.loads(raw)
            except (json.JSONDecodeError, TypeError):
                continue
            if frame.get("type") == "ping":
                await websocket.send_json({"type": "pong"})
            elif frame.get("type") == "unread_count":
                await push_unread()
    except WebSocketDisconnect:
        pass
    finally:
        task.cancel()


# --- helpers -------------------------------------------------------------------------


class _SlidingWindow:
    """Simple 20/min sliding window per socket (WS-only, independent of REST)."""

    def __init__(self, limit: int, window: int) -> None:
        self._limit = limit
        self._window = window
        self._hits: list[float] = []

    def allow(self) -> bool:
        now = time.monotonic()
        self._hits = [t for t in self._hits if now - t < self._window]
        if len(self._hits) >= self._limit:
            return False
        self._hits.append(now)
        return True


async def _write_loop(manager, room_id: UUID, websocket: WebSocket, user_id: UUID) -> None:
    """Drain this socket's outgoing queue into the wire (broadcast fan-out)."""
    await manager.drain_to(room_id, websocket)


async def _is_member(room_id: UUID, user_id: UUID) -> bool:
    from sqlalchemy import text

    async with async_session_context() as session:
        row = (await session.execute(
            text("""
                SELECT 1 FROM chat.room_members
                 WHERE room_id = :rid AND user_id = :uid AND left_at IS NULL
            """),
            {"rid": str(room_id), "uid": str(user_id)},
        )).first()
    return row is not None


async def _persist_message(room_id: UUID, sender_id: UUID, body: str) -> dict:
    from datetime import datetime, timezone
    from sqlalchemy import text

    async with async_session_context() as session:
        row = (await session.execute(
            text("""
                INSERT INTO chat.messages (room_id, sender_id, body, message_type, is_edited)
                VALUES (:rid, :uid, :body, 'text', FALSE)
                RETURNING id, created_at
            """),
            {"rid": str(room_id), "uid": str(sender_id), "body": body},
        )).mappings().first()
        await session.commit()
    return {
        "id": str(row["id"]),
        "created_at": row["created_at"].isoformat() if isinstance(row["created_at"], datetime) else str(row["created_at"]),
    }


def _sanitize_html(body: str) -> str:
    """Strip angle-bracket markup from message bodies (arch 8.1)."""
    import re

    return re.sub(r"<[^>]*>", "", body).strip()


async def _unread_count(user_id: UUID) -> int:
    from sqlalchemy import text

    async with async_session_context() as session:
        row = (await session.execute(
            text("""
                SELECT count(*) AS n FROM notification.notifications
                 WHERE user_id = :uid AND is_read = FALSE
            """),
            {"uid": str(user_id)},
        )).mappings().first()
    return row["n"] if row else 0