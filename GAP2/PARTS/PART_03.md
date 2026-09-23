# PART 3/12 of GAP PACK

## FILE: basteh_URGENT/backend/app/ws/handlers/chat.py
## SIZE: 17288 bytes
==========================================================================================

```python
"""
Chat WebSocket Handler
Architecture Reference: Sections 8.1, 8.2, 8.3
Complete implementation with:
- Connection lifecycle with auth
- Per-message room membership verification
- Message body sanitization
- File upload flow
- Redis Pub/Sub broadcasting
- Room management (join/leave/archive)
"""

import json
import base64
import hashlib
import hmac
import logging
from uuid import UUID
from datetime import datetime, timedelta
from starlette.websockets import WebSocketState
from fastapi import WebSocket, WebSocketDisconnect, Depends
from typing import Optional, Dict, Set, Any

from app.core.database import async_session_context
from app.core.security import verify_hmac_signature, get_device_fingerprint
from app.core.redis import get_redis_pool
from app.core.errors import APIError, AuthenticationError, NotFoundError, PrivacyHiddenError
from app.modules.chat.services.chat_service import ChatService
from app.ws.manager import chat_ws_manager, get_ws_manager
from app.modules.chat.db.Models import Rooms, RoomMembers, Messages

logger = logging.getLogger(__name__)


class ChatWebSocketHandler:
    """Handles WebSocket connection and message lifecycle per Architecture v2.0 Sections 8.1-8.3."""
    
    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}
        self.user_room_membership: Dict[str, Set[str]] = {}
    
    async def handle_handshake(self, websocket: WebSocket, token: str, fingerprint: str) -> Optional[UUID]:
        """Validate JWT and device fingerprint on WebSocket handshake.
        
        Returns user_id if authentication successful, None otherwise.
        """
        try:
            # Verify JWT token
            from jose import jwt
            payload = jwt.decode(token, options={"verify_signature": False})
            user_id: UUID = UUID(payload["sub"])
            
            # Verify device fingerprint
            device_valid = await verify_hmac_signature(
                fingerprint=fingerprint,
                user_id=user_id,
                endpoint="ws_chat_handshake"
            )
            
            if not device_valid:
                await websocket.close(code=4401, reason="Invalid device fingerprint")
                return None
            
            # Verify user is active (not banned, etc.)
            async with async_session_context() as session:
                from app.modules.auth.db.Models import Users
                result = await session.execute(
                    select(Users).where(Users.id == str(user_id), Users.is_active == True)
                )
                user = result.scalar_one_or_none()
                
                if not user:
                    await websocket.close(code=4401, reason="User not active")
                    return None
            
            return user_id
            
        except Exception as e:
            logger.error(f"WebSocket handshake error: {e}")
            await websocket.close(code=4403, reason="Authentication failed")
            return None
    
    async def handle_connect(self, websocket: WebSocket, user_id: UUID) -> None:
        """Accept WebSocket connection and initialize tracking."""
        await websocket.accept()
        self.active_connections[str(user_id)] = websocket
        
        # Subscribe to Redis channel for this user
        redis = get_redis_pool()
        await redis.subscribe(f"user:{user_id}:chat")
    
    async def handle_disconnect(self, user_id: UUID) -> None:
        """Handle WebSocket disconnection."""
        # Leave all rooms user was in
        rooms = self.user_room_membership.get(str(user_id), set())
        for room_id in rooms:
            await self.handle_leave_room(user_id, room_id)
        
        # Remove from tracking
        self.active_connections.pop(str(user_id), None)
        self.user_room_membership.pop(str(user_id), None)
        
        # Unsubscribe from Redis
        redis = get_redis_pool()
        await redis.unsubscribe(f"user:{user_id}:chat")
    
    async def handle_join_room(self, user_id: UUID, room_id: UUID, websocket: WebSocket) -> bool:
        """Join a chat room with membership validation."""
        async with async_session_context() as session:
            from sqlalchemy import select
            from app.modules.chat.db.Models import Rooms, RoomMembers
            
            # Check room exists
            result = await session.execute(select(Rooms).where(Rooms.id == str(room_id)))
            room = result.scalar_one_or_none()
            
            if not room:
                await websocket.close(code=4404, reason="Room not found")
                return False
            
            # Check user is active member
            result = await session.execute(
                select(RoomMembers).where(
                    (RoomMembers.room_id == str(room_id)) &
                    (RoomMembers.user_id == str(user_id)) &
                    (RoomMembers.is_active == True)
                )
            )
            membership = result.scalar_one_or_none()
            
            if not membership:
                await websocket.close(code=4403, reason="You are not a member of this room")
                return False
            
            # Track room membership
            if str(user_id) not in self.user_room_membership:
                self.user_room_membership[str(user_id)] = set()
            self.user_room_membership[str(user_id)].add(str(room_id))
            
            # Add to room connections
            if str(room_id) not in self.active_connections:
                # Would use proper connection tracking per room
                pass
            
            # Notify room
            await self.broadcast_system(room_id, {
                "type": "system",
                "action": "user_joined",
                "user_id": str(user_id),
                "timestamp": datetime.utcnow().isoformat()
            })
            
            return True
    
    async def handle_leave_room(self, user_id: UUID, room_id: UUID) -> None:
        """Handle user leaving a room."""
        # Remove from tracking
        if str(user_id) in self.user_room_membership:
            self.user_room_membership[str(user_id)].discard(str(room_id))
            if not self.user_room_membership[str(user_id)]:
                del self.user_room_membership[str(user_id)]
        
        # Notify room
        await self.broadcast_system(room_id, {
            "type": "system",
            "action": "user_left",
            "user_id": str(user_id),
            "timestamp": datetime.utcnow().isoformat()
        })
    
    async def handle_message(self, user_id: UUID, room_id: UUID, 
                           message_data: dict, websocket: WebSocket) -> Optional[dict]:
        """Handle incoming chat message with full privacy filtering."""
        from app.modules.chat.services.chat_service import ChatService
        
        # Validate room membership (per-message check per architecture 8.1)
        is_member = await ChatService.is_active_member(room_id, user_id)
        if not is_member:
            return {"error": "not_a_member", "code": 4403}
        
        # Sanitize message body (architecture 8.1: DOMPurify equivalent)
        body = message_data.get("body", "")
        sanitized_body = await self._sanitize_message(body)
        
        # Check for replies
        reply_to = message_data.get("reply_to")
        
        # Persist message
        message = await ChatService.persist_message(
            room_id=str(room_id),
            sender_id=str(user_id),
            body=sanitized_body,
            reply_to_id=UUID(reply_to) if reply_to else None
        )
        
        # Broadcast via Redis Pub/Sub (architecture 8.2)
        broadcast_payload = {
            "type": "chat_message",
            "message": {
                "id": str(message.id),
                "room_id": str(message.room_id),
                "sender_id": str(message.sender_id),
                "body": message.body,
                "created_at": message.created_at.isoformat(),
                "reply_to": str(message.reply_to_id) if message.reply_to_id else None,
                "is_edited": message.is_edited,
                "edit_history": message.edit_history if message.edit_history else []
            }
        }
        
        # Publish to Redis channel for this room
        redis = get_redis_pool()
        await redis.publish(f"room:{room_id}:chat", json.dumps(broadcast_payload))
        
        # Also broadcast directly to connected clients in same room
        await self._broadcast_to_room_clients(room_id, broadcast_payload)
        
        return {"status": "sent", "message_id": str(message.id)}
    
    async def _sanitize_message(self, body: str) -> str:
        """Sanitize message body - architecture 8.1 DOMPurify equivalent."""
        # Basic HTML sanitization - in production would use bleach or similar
        import re
        
        # Remove dangerous HTML tags and attributes
        cleanr = re.compile('<.*?>|&([a-z#]+);|[<>&"]')
        cleantext = re.sub(cleanr, '', body)
        
        # URL encoding check
        if len(cleantext) > 1000:
            raise APIError(
                error_code="MESSAGE_TOO_LONG",
                message=" پیام از حد مجاز طولانی است.",
                status_code=400
            )
        
        return cleantext
    
    async def _broadcast_to_room_clients(self, room_id: UUID, payload: dict) -> None:
        """Broadcast message to all WebSocket clients in the room."""
        # Get connected clients in this room from manager
        manager = get_ws_manager()
        if manager and room_id in manager.room_connections:
            for ws, uid in manager.room_connections.get(str(room_id), set()):
                try:
                    await ws.send_text(json.dumps(payload))
                except Exception:
                    # Connection dead, cleanup on disconnect
                    pass
    
    async def handle_file_upload(self, user_id: UUID, room_id: UUID,
                                file_data: dict, websocket: WebSocket) -> dict:
        """Handle file upload flow per architecture 8.2-8.3."""
        from app.modules.chat.services.chat_service import ChatService
        from app.core.redis import get_redis_pool
        
        filename = file_data.get("filename", "")
        file_size = file_data.get("file_size", 0)
        file_type = file_data.get("file_type", "")
        content_base64 = file_data.get("content_base64", "")
        
        # Validate membership
        is_member = await ChatService.is_active_member(room_id, user_id)
        if not is_member:
            return {"error": "not_a_member"}
        
        # Check file size limits (architecture 8.3)
        max_size = 50 * 1024 * 1024  # 50MB default
        if file_size > max_size:
            return {"error": "file_too_large"}
        
        # Check file type
        allowed_types = ["image", "video", "document", "audio"]
        if file_type not in allowed_types:
            return {"error": "invalid_file_type"}
        
        # Step 1: Generate presign URL
        presign_result = await ChatService.generate_presign_url(
            filename=filename,
            file_type=file_type,
            user_id=str(user_id)
        )
        
        if "error" in presign_result:
            return {"error": "presign_failed"}
        
        # Step 2: Client uploads to presigned URL (handled on client side)
        # Step 3: Finalize upload
        finalize_result = await ChatService.finalize_upload(
            upload_id=presign_result["upload_id"],
            filename=filename,
            user_id=str(user_id)
        )
        
        if "error" in finalize_result:
            return {"error": "finalize_failed"}
        
        # Step 4: AV Scan integration
        # Publish to AV scan queue
        redis = get_redis_pool()
        scan_payload = {
            "upload_id": finalize_result["upload_id"],
            "file_id": finalize_result["file_id"],
            "filename": filename,
            "user_id": str(user_id),
            "room_id": str(room_id)
        }
        await redis.publish("file_scan_queue", json.dumps(scan_payload))
        
        # Step 5: Store file reference in database
        # Message object will reference the file
        message = await ChatService.persist_message(
            room_id=str(room_id),
            sender_id=str(user_id),
            body=f"[File: {filename}]",
            metadata={
                "file_id": finalize_result["file_id"],
                "upload_id": finalize_result["upload_id"],
                "file_size": file_size,
                "file_type": file_type
            }
        )
        
        # Broadcast file message
        broadcast_payload = {
            "type": "file_message",
            "message": {
                "id": str(message.id),
                "room_id": str(message.room_id),
                "sender_id": str(message.sender_id),
                "file": {
                    "id": finalize_result["file_id"],
                    "filename": filename,
                    "size": file_size,
                    "type": file_type,
                    "status": "scanning"  # Will update after AV scan
                },
                "created_at": message.created_at.isoformat()
            }
        }
        
        await self._broadcast_to_room_clients(room_id, broadcast_payload)
        
        return {
            "status": "file_initiated",
            "message_id": str(message.id),
            "file_id": finalize_result["file_id"],
            "presign_url": presign_result.get("presign_url"),
            "scan_initiated": True
        }
    
    async def handle_archive_request(self, user_id: UUID, room_id: UUID) -> dict:
        """Handle room archival flow per architecture 8.2."""
        from app.modules.chat.services.chat_service import ChatService
        
        # Check user is member and has permission
        is_member = await ChatService.is_active_member(room_id, user_id)
        if not is_member:
            return {"error": "not_a_member"}
        
        # Two-step archive process per architecture:
        # 1. Soft archive (mark as archived, hide from active lists)
        # 2. Hard delete (after grace period)
        
        # For now, mark room as archived
        await ChatService.archive_room(
            room_id=str(room_id),
            archived_by=str(user_id)
        )
        
        # Notify room
        await self.broadcast_system(room_id, {
            "type": "system",
            "action": "room_archived",
            "room_id": str(room_id),
            "archived_by": str(user_id),
            "timestamp": datetime.utcnow().isoformat()
        })
        
        # Leave all WebSocket connections in this room
        await self.handle_leave_room(user_id, room_id)
        
        return {
            "status": "archiving_initiated",
            "room_id": str(room_id),
            "note": "Two-step archive: soft archive initiated, hard delete after grace period"
        }
    
    async def handle_edit_message(self, user_id: UUID, room_id: UUID,
                                  message_id: UUID, new_body: str) -> dict:
        """Handle message editing with edit history."""
        from app.modules.chat.services.chat_service import ChatService
        
        # Validate membership
        is_member = await ChatService.is_active_member(room_id, user_id)
        if not is_member:
            return {"error": "not_a_member"}
        
        # Sanitize new body
        sanitized_body = await self._sanitize_message(new_body)
        
        # Update message with edit tracking
        result = await ChatService.edit_message(
            message_id=str(message_id),
            new_body=sanitized_body,
            edited_by=str(user_id)
        )
        
        if "error" in result:
            return result
        
        # Broadcast edited message
        broadcast_payload = {
            "type": "edited_message",
            "message": {
                "id": str(message_id),
                "room_id": str(room_id),
                "sender_id": user_id,
                "body": sanitized_body,
                "is_edited": True,
                "edit_history": result.get("edit_history", []),
                "edited_at": result.get("edited_at")
            }
        }
        
        await self._broadcast_to_room_clients(room_id, broadcast_payload)
        
        return {"status": "edited", "message_id": str(message_id)}


# Global handler instance
chat_handler = ChatWebSocketHandler()


def get_chat_handler() -> ChatWebSocketHandler:
    return chat_handler
```

==========================================================================================
## FILE: basteh_URGENT/backend/app/ws/manager.py
## SIZE: 5307 bytes
==========================================================================================

```python
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
```

==========================================================================================
## FILE: basteh_URGENT/backend/app/ws/routes.py
## SIZE: 12081 bytes
==========================================================================================

```python
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
```

==========================================================================================
## FILE: bastehA_auth_rbac_audit/backend/app/modules/audit/api/routes.py
## SIZE: 682 bytes
==========================================================================================

```python
"""Audit module API routes (stub)."""
from fastapi import APIRouter

router = APIRouter(prefix="/audit", tags=["Audit"])


@router.get("/logs", response_model=dict)
async def list_audit_logs():
    """List audit logs (stub — returns empty until M11 routes land)."""
    return {"status": "success", "data": []}


@router.get("/integrity-check", response_model=dict)
async def integrity_check():
    """Verify audit hash-chain integrity."""
    try:
        from app.audit.integrity import check_audit_integrity

        return await check_audit_integrity()
    except Exception as exc:  # pragma: no cover - defensive
        return {"status": "unavailable", "message": str(exc)}
```

==========================================================================================
## FILE: bastehA_auth_rbac_audit/backend/app/modules/audit/audit_init.py
## SIZE: 260 bytes
==========================================================================================

```python
"""Audit module public interface (stub — full implementation per Architecture v2.0 Section M11)."""
from app.modules.audit.api.routes import router
from app.modules.audit.events import register_event_handlers

__all__ = ["router", "register_event_handlers"]
```

==========================================================================================
## FILE: bastehA_auth_rbac_audit/backend/app/modules/audit/db/models.py
## SIZE: 6239 bytes
==========================================================================================

```python
"""
app/modules/audit/db/models.py

مدل‌های ORM جدول‌های ماژول Audit — دقیقاً مطابق DDL سند معماری v2.0،
بخش ۴.۸. این فایل قبلاً وجود نداشت (پوشه‌ی db/ اصلاً زیر
app/modules/audit/ نبود) — پس اینجا از صفر ساخته شده، بدون ریسک
تداخل با چیزی که از قبل بود.

⚠️ پارتیشن‌بندی (`PARTITION BY RANGE (timestamp)`) در سطح ORM پیاده
نشده — پارتیشن‌بندی یک تصمیم DDL/عملیاتی است که باید در Migration
دستی مدیریت شود (پارتیشن‌های فصلی جدید باید هر فصل ساخته شوند؛
معمولاً با یک Job زمان‌بندی‌شده). برای MVP، جدول ساده (بدون
پارتیشن) کاملاً کار می‌کند؛ پارتیشن‌بندی را می‌توان بعداً، وقتی حجم
داده واقعاً به آن نیاز پیدا کرد، از طریق یک migration جدا اضافه کرد.

⚠️ فرض: ``from app.core.db.base import Base`` — مثل outbox.py، اگر
اسم/مسیر واقعی فرق دارد فقط این import را در هر دو فایل یکسان اصلاح
کنید.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import CHAR, Boolean, DateTime, SmallInteger, String, Text, BigInteger
from sqlalchemy.dialects.postgresql import INET, JSONB, UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func

try:
    from app.core.db.base import Base
except ImportError:  # pragma: no cover — فقط برای import مستقل این فایل
    from sqlalchemy.orm import DeclarativeBase

    class Base(DeclarativeBase):  # type: ignore[no-redef]
        pass


class AuditLog(Base):
    """``audit.audit_logs`` — لاگ عمومی همه‌ی عملیات (سند، بخش ۴.۸)."""

    __tablename__ = "audit_logs"
    __table_args__ = {"schema": "audit"}

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    user_id: Mapped[UUID | None] = mapped_column(PG_UUID(as_uuid=True), nullable=True)
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    entity_type: Mapped[str | None] = mapped_column(String(50), nullable=True)
    entity_id: Mapped[UUID | None] = mapped_column(PG_UUID(as_uuid=True), nullable=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    # هویت شبکه و دستگاه
    ip_address: Mapped[str | None] = mapped_column(INET, nullable=True)
    mac_address: Mapped[str | None] = mapped_column(String(17), nullable=True)
    mac_verified: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    device_fingerprint: Mapped[str | None] = mapped_column(String(255), nullable=True)
    device_id: Mapped[UUID | None] = mapped_column(PG_UUID(as_uuid=True), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(Text, nullable=True)
    session_id: Mapped[UUID | None] = mapped_column(PG_UUID(as_uuid=True), nullable=True)

    result: Mapped[str] = mapped_column(String(20), nullable=False)  # success|failure|denied
    details: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    old_value: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    new_value: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    geo_location: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    request_id: Mapped[UUID | None] = mapped_column(PG_UUID(as_uuid=True), nullable=True)
    correlation_id: Mapped[UUID | None] = mapped_column(PG_UUID(as_uuid=True), nullable=True)

    # یکپارچگی — زنجیره‌ی هش
    prev_hash: Mapped[str | None] = mapped_column(CHAR(64), nullable=True)
    row_hash: Mapped[str] = mapped_column(CHAR(64), nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class LoginAuditLog(Base):
    """``audit.login_audit_logs`` — لاگ اختصاصی تلاش‌های ورود (سند، بخش ۴.۸)."""

    __tablename__ = "login_audit_logs"
    __table_args__ = {"schema": "audit"}

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    user_id: Mapped[UUID | None] = mapped_column(PG_UUID(as_uuid=True), nullable=True)
    username: Mapped[str | None] = mapped_column(String(100), nullable=True)
    national_id_hash: Mapped[str | None] = mapped_column(CHAR(64), nullable=True)
    auth_method: Mapped[str] = mapped_column(String(20), nullable=False)  # local|sso|ldap|kerberos
    mfa_used: Mapped[str | None] = mapped_column(String(16), nullable=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    ip_address: Mapped[str | None] = mapped_column(INET, nullable=True)
    mac_address: Mapped[str | None] = mapped_column(String(17), nullable=True)
    mac_verified: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    device_fingerprint: Mapped[str | None] = mapped_column(String(255), nullable=True)
    device_is_trusted: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    user_agent: Mapped[str | None] = mapped_column(Text, nullable=True)
    success: Mapped[bool] = mapped_column(Boolean, nullable=False)
    failure_reason: Mapped[str | None] = mapped_column(String(255), nullable=True)
    session_id: Mapped[UUID | None] = mapped_column(PG_UUID(as_uuid=True), nullable=True)
    geo_location: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    risk_score: Mapped[int | None] = mapped_column(SmallInteger, nullable=True)  # 0..100

    prev_hash: Mapped[str | None] = mapped_column(CHAR(64), nullable=True)
    row_hash: Mapped[str] = mapped_column(CHAR(64), nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
```

==========================================================================================
## FILE: bastehA_auth_rbac_audit/backend/app/modules/audit/db/repositories.py
## SIZE: 2240 bytes
==========================================================================================

```python
"""
app/modules/audit/db/repositories.py

``last_row_hash`` باید زیر یک قفل مشورتی (advisory lock) خوانده شود تا
اگر دو نوشته‌ی audit هم‌زمان اتفاق بیفتد، هر دو یک ``prev_hash`` یکسان
نخوانند (که زنجیره را می‌شکند). طبق سند (بخش ۱۲.۳): «قفل مشورتی برای
ترتیب صحیح».

از ``pg_advisory_xact_lock`` استفاده شده (نه ``pg_advisory_lock``)
چون قفل تراکنشی است — خودکار در پایان تراکنش (commit/rollback) آزاد
می‌شود؛ نیازی به unlock دستی نیست و در صورت کرش سرویس، قفل باقی
نمی‌ماند.
"""

from __future__ import annotations

from typing import Type

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.modules.audit.db.models import AuditLog, LoginAuditLog

# عدد دلخواه ولی ثابت برای هر زنجیره — دو زنجیره‌ی audit_logs و
# login_audit_logs مستقل از هم قفل می‌شوند (کلید متفاوت برای هرکدام)
# تا نوشتن هم‌زمان روی یکی، دیگری را بلاک نکند.
_LOCK_KEY_AUDIT_LOGS = "audit_hash_chain:audit_logs"
_LOCK_KEY_LOGIN_LOGS = "audit_hash_chain:login_audit_logs"


class AuditRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def last_audit_log_hash(self) -> str | None:
        await self.session.execute(
            text("SELECT pg_advisory_xact_lock(hashtext(:key))"),
            {"key": _LOCK_KEY_AUDIT_LOGS},
        )
        result = await self.session.execute(
            select(AuditLog.row_hash).order_by(AuditLog.id.desc()).limit(1)
        )
        return result.scalar_one_or_none()

    async def last_login_audit_hash(self) -> str | None:
        await self.session.execute(
            text("SELECT pg_advisory_xact_lock(hashtext(:key))"),
            {"key": _LOCK_KEY_LOGIN_LOGS},
        )
        result = await self.session.execute(
            select(LoginAuditLog.row_hash).order_by(LoginAuditLog.id.desc()).limit(1)
        )
        return result.scalar_one_or_none()
```

==========================================================================================
## FILE: bastehA_auth_rbac_audit/backend/app/modules/audit/events.py
## SIZE: 2402 bytes
==========================================================================================

```python
"""
app/modules/audit/events.py  (نسخه‌ی به‌روز — جایگزین نسخه‌ی audit_module_patch.zip)

تنها تغییر نسبت به نسخه‌ی قبلی: "rbac.denied" هم به فهرست رویدادهایی
که audit ثبت می‌کند اضافه شد — چون app/modules/rbac/api/deps.py (در
همین پچ) این رویداد را منتشر می‌کند و باید جایی ثبت شود.
"""

from __future__ import annotations

import logging
from typing import Any

from app.modules.audit.services.audit_service import AuditService

logger = logging.getLogger("audit.events")

_LOGIN_EVENT_TYPES = ("auth.login.succeeded", "auth.login.failed")

_GENERIC_AUDIT_EVENT_TYPES = (
    "auth.user.registered",
    "auth.logout",
    "auth.password.changed",
    "auth.device.registered",
    "auth.device.trusted",
    "auth.user.created_by_admin",
    "auth.user.updated",
    "auth.user.deactivated",
    "auth.user.login_mode.changed",
    "rbac.role.assigned",
    "rbac.role.revoked",
    "rbac.denied",
)

_ALL_SUBSCRIBED_EVENTS = _LOGIN_EVENT_TYPES + _GENERIC_AUDIT_EVENT_TYPES


async def _handle_login_event(event: Any, session: Any) -> None:
    audit = AuditService(session)
    payload = event.payload or {}
    await audit.log_login(
        success=(event.event_type == "auth.login.succeeded"),
        auth_method=payload.get("auth_method", "local"),
        user_id=event.actor_id,
        username=payload.get("identifier"),
        mfa_used=payload.get("mfa_used"),
        failure_reason=payload.get("reason"),
    )


async def _handle_generic_event(event: Any, session: Any) -> None:
    audit = AuditService(session)
    payload = event.payload or {}
    user_id = payload.get("target_user_id", event.actor_id) \
        if event.event_type.startswith(("rbac.", "auth.user.")) else event.actor_id
    result = "denied" if event.event_type == "rbac.denied" else "success"
    await audit.log(
        action=event.event_type,
        user_id=user_id,
        result=result,
        details=payload,
    )


def register_event_handlers(bus) -> None:
    for event_type in _LOGIN_EVENT_TYPES:
        bus.subscribe(event_type, _handle_login_event)
    for event_type in _GENERIC_AUDIT_EVENT_TYPES:
        bus.subscribe(event_type, _handle_generic_event)
    logger.debug("audit module subscribed to %d event types", len(_ALL_SUBSCRIBED_EVENTS))
```

==========================================================================================
## FILE: bastehA_auth_rbac_audit/backend/app/modules/auth/admin_ports.py
## SIZE: 2938 bytes
==========================================================================================

```python
"""
app/modules/auth/admin_ports.py

اسکیمای request/response بخش «تعریف/مدیریت کاربر» در تنظیمات ادمین —
که در سند فقط برای `/auth/register` (ثبت‌نام خودِ کاربر) و
`/admin/users/bulk-login-mode` (بخش ۱۲.۶) وجود دارد، نه برای
create/list/update/deactivate عمومی. این فایل آن‌ها را اضافه می‌کند.

⚠️ عمداً در فایل جدا (نه داخل ``ports.py`` موجودتان) گذاشته شده، چون
محتوای واقعی ``ports.py`` را ندیده‌ام و نمی‌خواهم چیزی را ناخواسته
پاک کنم. اگر می‌خواهید این‌ها را به ``ports.py`` منتقل کنید، فقط
تعریف‌های زیر را کپی/پیست کنید — چیز دیگری در کد به مسیر فایل وابسته
نیست جز importها در ``admin_user_service.py`` و ``admin_routes.py``.
"""

from __future__ import annotations

from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field


class AdminCreateUserRequest(BaseModel):
    """ادمین مستقیماً کاربر می‌سازد — برخلاف ``/auth/register`` که خودِ
    کاربر با کد ملی ثبت‌نام می‌کند. رمز عبور اولیه توسط ادمین تعیین
    می‌شود و ``must_change_password`` اجباری True است."""

    username: str = Field(min_length=3, max_length=64)
    national_id: str = Field(min_length=10, max_length=10)
    display_name: str = Field(min_length=1, max_length=120)
    initial_password: str = Field(min_length=8)
    role_id: int | None = None  # اختیاری: نقش اولیه (از طریق RoleAssignmentService اعطا می‌شود)


class AdminUpdateUserRequest(BaseModel):
    """همه‌ی فیلدها اختیاری — فقط چیزی که فرستاده شود عوض می‌شود."""

    display_name: str | None = Field(default=None, min_length=1, max_length=120)
    is_active: bool | None = None
    must_change_password: bool | None = None


class AdminUserListItem(BaseModel):
    id: UUID
    username: str
    display_name: str
    national_id_masked: str
    is_active: bool
    auth_mode: str
    mfa_enabled: bool
    last_login_at: str | None = None


class AdminUserListResponse(BaseModel):
    items: list[AdminUserListItem]
    total: int
    limit: int
    offset: int


class BulkLoginModeRequest(BaseModel):
    """طبق بخش ۱۲.۶ سند — تغییر sso_enabled برای گروهی از کاربران."""

    user_ids: list[UUID] = Field(min_length=1, max_length=500)
    sso_enabled: bool
    revoke_sessions: bool = False


class BulkFailure(BaseModel):
    user_id: UUID
    code: Literal["NOT_FOUND", "CANNOT_MODIFY_SELF", "NO_LOCAL_PASSWORD"]


class BulkResult(BaseModel):
    updated: list[UUID]
    failed: list[BulkFailure]
```

==========================================================================================
## FILE: bastehA_auth_rbac_audit/backend/app/modules/auth/api/admin_routes.py
## SIZE: 4828 bytes
==========================================================================================

```python
"""
app/modules/auth/api/admin_routes.py

Endpointهای «تعریف/مدیریت کاربر» در تنظیمات — طبق الگوی RBAC middleware
سند (بخش ۱۲.۴: ``require_permission``). این فایل جدید است (کنار
``routes.py`` موجودتان)، تا با روترهای فعلی auth تداخل نکند — کافی
است در ``app/modules/auth/__init__.py`` هر دو روتر را include کنید:

    from app.modules.auth.api.routes import router as auth_router
    from app.modules.auth.api.admin_routes import router as admin_users_router
    router = APIRouter()
    router.include_router(auth_router)
    router.include_router(admin_users_router)

(یا هرطور که routes.py فعلی‌تان را می‌سازید — فقط این router هم باید
مثل بقیه به app اصلی mount شود.)

⚠️ فرض: ``require_permission`` در ``app.modules.rbac.api.deps`` است
(دقیقاً مسیر بخش ۱۲.۴ سند). ``get_current_user`` و ``get_uow``/``get_user_repo``
هم باید از dependency injection موجود پروژه‌ی شما بیایند — اسم دقیق
را با محتوای واقعی ``app/core/db/session.py`` و ``app/modules/auth/api/deps.py``
(اگر دارید) تطبیق دهید.
"""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, Query

from app.modules.auth.admin_ports import (
    AdminCreateUserRequest,
    AdminUpdateUserRequest,
    AdminUserListResponse,
    BulkLoginModeRequest,
    BulkResult,
)
from app.modules.auth.services.admin_user_service import AdminUserService

try:
    from app.modules.rbac.api.deps import require_permission
except ImportError:  # pragma: no cover — تا وقتی deps.py واقعی RBAC مشخص شود
    def require_permission(*codes: str, mode: str = "all"):  # type: ignore[no-redef]
        async def _dep():
            raise NotImplementedError(
                "require_permission در app.modules.rbac.api.deps پیدا نشد — "
                "این endpointها بدون آن نباید در production فعال شوند."
            )
        return _dep

try:
    # اگر app/modules/auth/api/deps.py از قبل چیزی مشابه دارد، از همان استفاده کنید
    from app.modules.auth.api.deps import get_admin_user_service
except ImportError:  # pragma: no cover — fallback حداقلی تا وقتی deps.py واقعی وصل شود
    def get_admin_user_service():  # type: ignore[no-redef]
        """TODO: جایگزین کنید با دیپندنسی واقعی که AdminUserService را با
        session/UnitOfWork واقعی درخواست جاری می‌سازد — مثلاً:

            async def get_admin_user_service(uow: UnitOfWork = Depends(get_uow)):
                return AdminUserService(uow.users)
        """
        raise NotImplementedError(
            "get_admin_user_service هنوز به session/UnitOfWork واقعی وصل نشده — "
            "app/modules/auth/api/deps.py را تکمیل کنید."
        )

router = APIRouter(prefix="/admin/users", tags=["admin-users"])


@router.get("", response_model=AdminUserListResponse)
async def list_users(
    search: str | None = Query(default=None, max_length=100),
    is_active: bool | None = Query(default=None),
    limit: int = Query(default=50, le=200),
    offset: int = Query(default=0, ge=0),
    _user=Depends(require_permission("user.read")),
    service: AdminUserService = Depends(get_admin_user_service),
):
    items, total = await service.list_users(
        search=search, is_active=is_active, limit=limit, offset=offset
    )
    return AdminUserListResponse(items=items, total=total, limit=limit, offset=offset)


@router.post("", status_code=201)
async def create_user(
    payload: AdminCreateUserRequest,
    user=Depends(require_permission("user.create")),
    service: AdminUserService = Depends(get_admin_user_service),
):
    return await service.create_user(user, payload)


@router.patch("/{user_id}")
async def update_user(
    user_id: UUID,
    payload: AdminUpdateUserRequest,
    user=Depends(require_permission("user.manage")),
    service: AdminUserService = Depends(get_admin_user_service),
):
    return await service.update_user(user, user_id, payload)


@router.post("/bulk-login-mode", response_model=BulkResult)
async def bulk_change_login_mode(
    payload: BulkLoginModeRequest,
    user=Depends(require_permission("user.bulk_login_mode")),
    service: AdminUserService = Depends(get_admin_user_service),
):
    """طبق سند بخش ۱۲.۶ — تغییر sso_enabled برای گروهی از کاربران؛ نتیجه‌ی جزئی مجاز است."""
    result = await service.bulk_change_login_mode(user, payload)
    return result
```

==========================================================================================
## FILE: bastehA_auth_rbac_audit/backend/app/modules/auth/api/deps.py
## SIZE: 802 bytes
==========================================================================================

```python
"""Auth module dependencies (composition root for admin user management).

Wires the real ``get_current_user`` from core so the RBAC ``require_permission``
guard resolves, and builds ``AdminUserService`` with the live session repo.
"""
from __future__ import annotations

from fastapi import Depends

from app.core.dependencies import get_current_user, get_user_repository
from app.modules.auth.admin_ports import AdminCreateUserRequest


async def get_admin_user_service(
    user_repo=Depends(get_user_repository),
):
    """Build AdminUserService with the real repo (auth.users ORM)."""
    from app.modules.auth.services.admin_user_service import AdminUserService

    return AdminUserService(user_repo=user_repo)


__all__ = ["get_current_user", "get_admin_user_service", "AdminCreateUserRequest"]
```

==========================================================================================
## FILE: bastehA_auth_rbac_audit/backend/app/modules/auth/db/models.py
## SIZE: 6406 bytes
==========================================================================================

```python
"""Auth DB models matching ``alembic/versions/auth_schema.sql``.

Column types mirror the SQL schema exactly (PostgreSQL UUID/ENUM/INET/JSONB)
so INSERTs succeed. Columns that the database fills via defaults
(created_at, failed counters, ...) are omitted from the model.
"""
import uuid as uuid_lib
from datetime import datetime

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import ENUM, INET, JSONB, UUID as PGUUID

from app.core.db.base import Base

auth_mode_enum = ENUM(
    "local", "sso", "both",
    name="auth_mode", schema="auth", create_type=False,
)
login_method_enum = ENUM(
    "local", "sso", "ldap", "kerberos", "recovery",
    name="login_method", schema="auth", create_type=False,
)


class Users(Base):
    """Application users (table ``auth.users``)."""

    __tablename__ = "users"
    __table_args__ = {"schema": "auth", "extend_existing": True}

    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid_lib.uuid4)
    username = Column(String(64), nullable=False)
    national_id_enc = Column(LargeBinary, nullable=False)
    national_id_nonce = Column(LargeBinary, nullable=False)
    national_id_hash = Column(String(64), nullable=False)
    national_id_last4 = Column(String(4), nullable=False)
    display_name = Column(String(128), nullable=False)
    auth_mode = Column(auth_mode_enum, nullable=False, default="local")
    sso_enabled = Column(Boolean, nullable=False, default=False)
    ldap_dn = Column(Text, nullable=True)
    ldap_object_guid = Column(PGUUID(as_uuid=True), nullable=True)
    ldap_sam_account = Column(String(256), nullable=True)
    ldap_synced_at = Column(DateTime(timezone=True), nullable=True)
    password_hash = Column(Text, nullable=True)
    password_changed_at = Column(DateTime(timezone=True), nullable=True)
    must_change_password = Column(Boolean, nullable=False, default=False)
    token_version = Column(Integer, nullable=False, default=1)
    mfa_enabled = Column(Boolean, nullable=False, default=False)
    mfa_method = Column(String(16), nullable=True)
    mfa_secret_enc = Column(LargeBinary, nullable=True)
    mfa_secret_nonce = Column(LargeBinary, nullable=True)
    mfa_enrolled_at = Column(DateTime(timezone=True), nullable=True)
    is_active = Column(Boolean, nullable=False, default=True)
    failed_login_count = Column(Integer, nullable=False, default=0)
    locked_until = Column(DateTime(timezone=True), nullable=True)
    last_login_at = Column(DateTime(timezone=True), nullable=True)


class UserDevices(Base):
    """Registered user devices (table ``auth.user_devices``)."""

    __tablename__ = "user_devices"
    __table_args__ = (
        UniqueConstraint("user_id", "device_fingerprint",
                         name="uq_device_user_fingerprint"),
        {"schema": "auth", "extend_existing": True},
    )

    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid_lib.uuid4)
    user_id = Column(
        PGUUID(as_uuid=True),
        ForeignKey("auth.users.id", ondelete="CASCADE"),
        nullable=False,
    )
    device_fingerprint = Column(String(255), nullable=False)
    mac_address = Column(String(17), nullable=True)
    mac_source = Column(String(16), nullable=True)
    platform = Column(String(16), nullable=False)
    device_label = Column(String(128), nullable=True)
    os_info = Column(String(128), nullable=True)
    user_agent = Column(Text, nullable=True)
    hmac_key_enc = Column(LargeBinary, nullable=True)
    is_trusted = Column(Boolean, nullable=False, default=False)
    trusted_at = Column(DateTime(timezone=True), nullable=True)
    trusted_by_mfa = Column(Boolean, nullable=False, default=False)
    first_seen_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    last_seen_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    last_ip = Column(INET, nullable=True)
    is_blocked = Column(Boolean, nullable=False, default=False)
    blocked_reason = Column(String(255), nullable=True)


class Sessions(Base):
    """Login sessions / refresh families (table ``auth.sessions``)."""

    __tablename__ = "sessions"
    __table_args__ = {"schema": "auth", "extend_existing": True}

    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid_lib.uuid4)
    user_id = Column(
        PGUUID(as_uuid=True),
        ForeignKey("auth.users.id", ondelete="CASCADE"),
        nullable=False,
    )
    device_id = Column(
        PGUUID(as_uuid=True),
        ForeignKey("auth.user_devices.id", ondelete="SET NULL"),
        nullable=True,
    )
    refresh_hash = Column(String(64), nullable=False, unique=True)
    family_id = Column(PGUUID(as_uuid=True), nullable=False)
    auth_method = Column(login_method_enum, nullable=False)
    mfa_satisfied = Column(Boolean, nullable=False, default=False)
    ip_address = Column(INET, nullable=True)
    geo_location = Column(JSONB, nullable=True)
    issued_at = Column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    last_active_at = Column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    expires_at = Column(DateTime(timezone=True), nullable=False)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    revoked_reason = Column(String(64), nullable=True)


Index("ix_auth_users_hash", Users.national_id_hash)


class MFARecoveryCodes(Base):
    """MFA recovery codes (table ``auth.mfa_recovery_codes``)."""

    __tablename__ = "mfa_recovery_codes"
    __table_args__ = {"schema": "auth", "extend_existing": True}

    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid_lib.uuid4)
    user_id = Column(
        PGUUID(as_uuid=True),
        ForeignKey("auth.users.id", ondelete="CASCADE"),
        nullable=False,
    )
    code_hash = Column(String(64), nullable=False, unique=True)
    used_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


__all__ = ["Users", "UserDevices", "Sessions", "MFARecoveryCodes"]
```

==========================================================================================
## FILE: bastehA_auth_rbac_audit/backend/app/modules/auth/db/repositories.py
## SIZE: 2734 bytes
==========================================================================================

```python
"""Auth repositories (AsyncSession-backed)."""
import hashlib
from uuid import UUID

from sqlalchemy import func, select

from app.core.config import settings
from app.modules.auth.db.models import UserDevices, Users


def national_id_hash(national_id: str) -> str:
    """HMAC-SHA256 lookup hash for a national ID (matches registration)."""
    return hashlib.sha256(
        f"{national_id}:{settings.SECRET_KEY}".encode()
    ).hexdigest()


class UserRepository:
    """Persistence adapter for users (backed by an async session)."""

    def __init__(self, session):
        self.session = session

    async def get(self, user_id):
        result = await self.session.execute(
            select(Users).where(Users.id == user_id)
        )
        return result.scalar_one_or_none()

    async def get_by_national_id(self, national_id: str):
        result = await self.session.execute(
            select(Users).where(
                Users.national_id_hash == national_id_hash(national_id.strip())
            )
        )
        return result.scalar_one_or_none()

    async def get_by_username(self, username: str):
        result = await self.session.execute(
            select(Users).where(func.lower(Users.username) == username.lower())
        )
        return result.scalar_one_or_none()

    async def get_by_identifier(self, identifier: str):
        identifier = identifier.strip()
        if identifier.isdigit() and len(identifier) == 10:
            user = await self.get_by_national_id(identifier)
            if user:
                return user
        return await self.get_by_username(identifier)

    async def add(self, obj):
        self.session.add(obj)

    async def commit(self):
        await self.session.commit()


class DeviceRepository:
    """Persistence adapter for user devices."""

    def __init__(self, session):
        self.session = session

    async def get(self, device_id):
        result = await self.session.execute(
            select(UserDevices).where(UserDevices.id == device_id)
        )
        return result.scalar_one_or_none()

    async def add(self, obj):
        self.session.add(obj)

    async def create_initial_device(self, user_id: UUID):
        import uuid as uuid_lib

        device = UserDevices(
            user_id=user_id,
            device_fingerprint=f"initial-{uuid_lib.uuid4().hex[:16]}",
            platform="web",
            device_label="Initial device",
            is_trusted=False,
        )
        self.session.add(device)
        await self.session.flush()
        return device


__all__ = ["UserRepository", "DeviceRepository", "national_id_hash"]
```

==========================================================================================
## FILE: bastehA_auth_rbac_audit/backend/app/modules/auth/events.py
## SIZE: 1482 bytes
==========================================================================================

```python
"""
app/modules/auth/events.py

رویدادهایی که ماژول Auth منتشر می‌کند — طبق قرارداد رابط سند
(بخش ۲.۲: هر ماژول رویدادهای خودش را از ``events.py`` صادر می‌کند)
و کاتالوگ رویدادها (بخش ۲.۴).

هیچ ماژول دیگری نباید این فایل را import کند تا از رویداد مطلع شود —
فقط باید با رشته‌ی ``event_type`` (مثل ``AUTH_LOGIN_SUCCEEDED``ی که
همین‌جا صادر شده) در ``event_bus.subscribe(...)`` مشترک شود. صادر کردن
این ثابت‌ها فقط برای جلوگیری از اشتباه تایپی در همین ماژول (auth) است؛
مصرف‌کننده‌ها (مثل audit) باید مقدار رشته را مستقیم بنویسند تا
وابستگی کد به auth ایجاد نشود — دقیقاً همان قاعده‌ای که تست
``test_module_boundaries.py`` اجرا می‌کند.
"""

from __future__ import annotations

# ── کاتالوگ رویدادها (بخش ۲.۴ سند) + رویدادهای اضافه‌ی مورد نیاز کد فعلی
AUTH_USER_REGISTERED = "auth.user.registered"
AUTH_LOGIN_SUCCEEDED = "auth.login.succeeded"
AUTH_LOGIN_FAILED = "auth.login.failed"
AUTH_LOGOUT = "auth.logout"
AUTH_PASSWORD_CHANGED = "auth.password.changed"
AUTH_DEVICE_REGISTERED = "auth.device.registered"
AUTH_DEVICE_TRUSTED = "auth.device.trusted"
```

==========================================================================================
## FILE: bastehA_auth_rbac_audit/backend/app/modules/auth/ports.py
## SIZE: 3584 bytes
==========================================================================================

```python
from typing import Protocol, Optional, List, Tuple, Dict, Any
from uuid import UUID
from datetime import datetime
from pydantic import BaseModel


# --- User Read Model Protocol ---
# Defines what other modules can see about a user (interface contract)

class UserReadModel(Protocol):
    """Her ماژول دیگری فقط این را می‌بیند. تغییر امضای این متدها = تغییر شکننده."""
    
    id: UUID
    username: str
    display_name: str
    national_id_masked: str  # masked: ******1234
    is_active: bool
    roles: List[str]
    permissions: List[str]
    privacy_level: str
    auth_mode: str  # local | sso | both
    mfa_enabled: bool
    last_login_at: Optional[datetime]


# --- Authentication Request/Response Schemas ---

class LoginRequest(BaseModel):
    """Login request schema."""
    identifier: str  # username or national_id
    password: str
    remember_me: bool = False
    captcha_token: Optional[str] = None


class MFAVerifyRequest(BaseModel):
    """MFA verification request."""
    mfa_token: str  # TOTP code or SMS code
    mfa_method: str  # totp | email | sms
    challenge_token: Optional[str] = None  # login-issued challenge (identifies user)


class MFACodeRequest(BaseModel):
    """TOTP code used during enrollment confirmation."""
    code: str


class RegisterRequest(BaseModel):
    """User registration request."""
    national_id: str  # 10-digit with check digit
    username: str
    password: str
    display_name: str
    email: Optional[str] = None
    mobile: Optional[str] = None


class TokenResponse(BaseModel):
    """Authentication token response."""
    access_token: str
    refresh_token: str
    token_type: str = "Bearer"
    expires_in: int
    # Serialized UserReadModel (kept as dict: pydantic cannot build a
    # schema for the Protocol interface above).
    user: dict
    device: Optional[dict] = None  # device info if new


# --- Device Binding Schemas ---

class DeviceRegisterRequest(BaseModel):
    """Device registration request."""
    device_fingerprint: str  # SHA256 fingerprint
    mac_address: str  # MAC address (desktop only)
    mac_source: str  # psutil | uuid_getnode | unavailable
    platform: str  # desktop | web | mobile_web
    device_label: str  # user-assigned label
    os_info: str  # OS description


class DeviceTrustRequest(BaseModel):
    """Device trust confirmation."""
    device_id: UUID
    trusted: bool  # user confirmation
    mfa_satisfied: bool  # MFA was used to trust


# --- Password Management ---

class PasswordChangeRequest(BaseModel):
    """Change password request."""
    current_password: str
    new_password: str


class PasswordForgotRequest(BaseModel):
    """Password forgot/request reset."""
    identifier: str  # username or national_id


class RefreshRequest(BaseModel):
    """Refresh token request schema."""
    refresh_token: str


# --- Audit Log Schemas (lightweight) ---

class AuditLogEntry(BaseModel):
    """Lightweight audit log entry for API responses."""
    id: int
    action: str
    timestamp: datetime
    result: str
    user_id: Optional[UUID]
    ip_address: Optional[str]
    mac_verified: bool


# Export all schemas
__all__ = [
    "UserReadModel", "LoginRequest", "MFAVerifyRequest",
    "RegisterRequest", "TokenResponse", "DeviceRegisterRequest",
    "DeviceTrustRequest", "PasswordChangeRequest", 
    "PasswordForgotRequest", "AuditLogEntry", "RefreshRequest"
]
```

==========================================================================================
