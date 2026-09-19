"""
Chat WebSocket Complete Flow Implementation
Architecture Reference: Sections 8.1, 8.2, 8.3
"""

import json
import asyncio
from typing import Dict, Set, Optional, Any
from uuid import UUID
from datetime import datetime, timedelta
from fastapi import WebSocket, WebSocketDisconnect
from starlette.websockets import State

from app.core.database import async_session_context
from app.modules.chat.services.chat_service import ChatService
from app.modules.chat.db.Models import Rooms, RoomMembers, Messages
from app.core.errors import APIError, NotFoundError, PrivacyHiddenError


class ChatWebSocketManager:
    """Manages WebSocket connections and message broadcasting."""
    
    def __init__(self, chat_service: ChatService):
        self.chat_service = chat_service
        # Connection tracking: room_id -> set of (websocket, user_id)
        self.room_connections: Dict[str, Set[tuple]] = {}
        # User tracking: user_id -> set of room_ids
        self.user_rooms: Dict[str, Set[str]] = {}
        # Message handlers by type
        self.message_handlers: Dict[str, Any] = {}
    
    async def connect(self, websocket: WebSocket, user_id: UUID, room_id: UUID) -> bool:
        """Connect a user to a chat room.
        
        Returns True if connection successful, False if should reject.
        """
        # Accept connection
        await websocket.accept()
        
        # Join room (validates membership)
        joined = await self.join_room(room_id, user_id, websocket)
        if not joined:
            await websocket.close(code=4403)  # Not a member
            return False
        
        # Track connection
        if room_id not in self.room_connections:
            self.room_connections[room_id] = set()
        self.room_connections[room_id].add((websocket, user_id))
        
        if user_id not in self.user_rooms:
            self.user_rooms[user_id] = set()
        self.user_rooms[user_id].add(room_id)
        
        # Notify room
        await self.broadcast_system(room_id, {
            "type": "system",
            "action": "user_joined",
            "user_id": str(user_id),
            "timestamp": datetime.utcnow().isoformat()
        })
        
        return True
    
    async def disconnect(self, websocket: WebSocket, user_id: UUID) -> None:
        """Handle user disconnection."""
        # Leave all rooms
        rooms = self.user_rooms.get(user_id, set())
        for room_id in rooms:
            await self.leave_room(room_id, user_id, websocket)
        
        # Remove tracking
        if user_id in self.user_rooms:
            del self.user_rooms[user_id]
        
        # Cleanup empty room connections
        for room_id, connections in self.room_connections.items():
            self.room_connections[room_id] = {
                c for c in connections if c[1] != user_id
            }
            if not self.room_connections[room_id]:
                del self.room_connections[room_id]
    
    async def join_room(self, room_id: UUID, user_id: UUID, websocket: WebSocket) -> bool:
        """Validate and join a room."""
        # Check if room exists and user is member
        is_member = await self.chat_service.is_active_member(room_id, user_id)
        if not is_member:
            return False
        
        # Add to room tracking
        if room_id not in self.room_connections:
            self.room_connections[room_id] = set()
        self.room_connections[room_id].add((websocket, user_id))
        
        if user_id not in self.user_rooms:
            self.user_rooms[user_id] = set()
        self.user_rooms[user_id].add(room_id)
        
        return True
    
    async def leave_room(self, room_id: UUID, user_id: UUID) -> None:
        """Handle user leaving a room."""
        # Remove from tracking
        if room_id in self.room_connections:
            self.room_connections[room_id] = {
                c for c in self.room_connections[room_id] if c[1] != user_id
            }
            if not self.room_connections[room_id]:
                del self.room_connections[room_id]
        
        if user_id in self.user_rooms:
            self.user_rooms[user_id].discard(room_id)
            if not self.user_rooms[user_id]:
                del self.user_rooms[user_id]
    
    async def send_message(self, room_id: UUID, sender_id: UUID, message: str, 
                          reply_to: Optional[UUID] = None) -> Optional[Messages]:
        """Send a message to a room."""
        # Validate membership (re-check)
        is_member = await self.chat_service.is_active_member(room_id, sender_id)
        if not is_member:
            return None
        
        # Persist message
        message_obj = await self.chat_service.persist(
            room_id=room_id,
            sender_id=sender_id,
            body=message,
            reply_to_id=reply_to
        )
        
        # Broadcast to all connected clients in room
        if room_id in self.room_connections:
            broadcast_data = message_obj.to_event()
            for ws, uid in self.room_connections[room_id]:
                try:
                    await ws.send_text(json.dumps(broadcast_data))
                except Exception:
                    # Connection lost, will cleanup on disconnect
                    pass
        
        # Audit log
        await self.chat_service.audit_log(
            action="chat.message.sent",
            entity_type="chat_message",
            entity_id=message_obj.id,
            user_id=sender_id,
            result="success"
        )
        
        return message_obj
    
    async def broadcast_system(self, room_id: UUID, message: dict) -> None:
        """Broadcast a system message to all in room."""
        if room_id in self.room_connections:
            for ws, uid in self.room_connections[room_id]:
                try:
                    await ws.send_text(json.dumps(message))
                except Exception:
                    pass
    
    def register_handler(self, message_type: str, handler: Any) -> None:
        """Register a handler for a message type."""
        self.message_handlers[message_type] = handler


# Global manager instance (initialized during app startup)
chat_ws_manager: Optional[ChatWebSocketManager] = None


def init_chat_websocket_manager(chat_service: Any) -> None:
    """Initialize the WebSocket manager."""
    global chat_ws_manager
    chat_ws_manager = ChatWebSocketManager(chat_service)


# Dependency to get manager
def get_ws_manager() -> ChatWebSocketManager:
    return chat_ws_manager