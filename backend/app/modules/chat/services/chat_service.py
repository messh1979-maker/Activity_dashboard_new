from typing import Optional, List, Tuple, Dict, Any
from uuid import UUID
from datetime import datetime

from sqlalchemy import select, func, delete, insert, update
from sqlalchemy.orm import Session

from app.core.errors import APIError, NotFoundError
from app.modules.chat.ports import (
    RoomCreate, RoomUpdate, MessageCreate, MessageResponse,
    MemberCreate, ChatExport
)
from app.modules.chat.db.Models import Rooms, RoomMembers, Messages


class ChatService:
    """Service layer for Chat module operations."""
    
    def __init__(self, session: Session):
        self.session = session
    
    # --- Room CRUD ---
    
    async def create_room(
        self, title: str, linked_type: Optional[str],
        linked_id: Optional[UUID], owner_id: UUID
    ) -> Rooms:
        """Create a new chat room."""
        room = Rooms(
            title=title,
            owner_id=owner_id,
            linked_type=linked_type,
            linked_id=str(linked_id) if linked_id else None,
        )
        
        self.session.add(room)
        await self.session.flush()
        return room
    
    async def list_rooms(self, user_id: UUID) -> List[dict]:
        """List rooms user is member of."""
        query = select(Rooms).join(RoomMembers).where(
            RoomMembers.user_id == str(user_id),
            Rooms.is_archived == False
        )
        results = (await self.session.execute(query)).scalars().all()
        
        rooms = []
        for room in results:
            rooms.append({
                "id": str(room.id),
                "title": room.title,
                "is_archived": room.is_archived,
                "member_count": 0,  # Would query members
                "owner_id": str(room.owner_id),
            })
        
        return rooms
    
    async def get_room(self, room_id: UUID, user_id: UUID) -> Optional[dict]:
        """Get room with membership check."""
        result = await self.session.execute(
            select(Rooms).where(Rooms.id == str(room_id))
        )
        room = result.scalar_one_or_none()
        
        if not room:
            return None
        
        # Check membership
        member_result = await self.session.execute(
            select(RoomMembers).where(
                (RoomMembers.room_id == str(room_id)) &
                (RoomMembers.user_id == str(user_id))
            )
        )
        is_member = member_result.scalar_one_or_none() is not None
        
        if not is_member:
            # Check if room is public or user has permission
            # Simplified: return None
            return None
        
        # Get member count
        count_result = await self.session.execute(
            select(func.count()).select_from(RoomMembers).where(
                RoomMembers.room_id == str(room_id),
                RoomMembers.is_active == True
            )
        )
        member_count = count_result.scalar() or 0
        
        return {
            "id": str(room.id),
            "title": room.title,
            "description": room.description,
            "is_archived": room.is_archived,
            "member_count": member_count,
            "owner_id": str(room.owner_id),
            "linked_type": room.linked_type,
            "linked_id": room.linked_id,
        }
    
    # --- Member Management ---
    
    async def add_member(self, room_id: UUID, user_id: UUID, role: str,
                        added_by: UUID) -> dict:
        """Add member to room."""
        # Verify room exists
        result = await self.session.execute(
            select(Rooms).where(Rooms.id == str(room_id))
        )
        room = result.scalar_one_or_none()
        
        if not room:
            raise APIError(
                error_code="ROOM_NOT_FOUND",
                message="اتاق یافت نشد.",
                status_code=404
            )
        
        # Check if user already a member
        existing_result = await self.session.execute(
            select(RoomMembers).where(
                (RoomMembers.room_id == str(room_id)) &
                (RoomMembers.user_id == str(user_id))
            )
        )
        if existing_result.scalar_one_or_none():
            return {"status": "already_member", "message": "کاربر déjà member اتاق است."}
        
        # Add member
        member = RoomMembers(
            room_id=str(room_id),
            user_id=str(user_id),
            role=role,
            source="manual",
        )
        
        self.session.add(member)
        await self.session.flush()
        
        return {"status": "added", "member_id": str(member.id)}
    
    # --- Message Operations ---
    
    async def send_message(self, room_id: UUID, body: str, sender_id: UUID) -> Messages:
        """Send a chat message."""
        # Verify room exists and user is member
        result = await self.session.execute(
            select(Rooms).where(Rooms.id == str(room_id))
        )
        room = result.scalar_one_or_none()
        
        if not room:
            raise APIError(
                error_code="ROOM_NOT_FOUND",
                message="اتاق یافت نشد.",
                status_code=404
            )
        
        # Check membership
        member_result = await self.session.execute(
            select(RoomMembers).where(
                (RoomMembers.room_id == str(room_id)) &
                (RoomMembers.user_id == str(sender_id))
            )
        )
        is_member = member_result.scalar_one_or_none() is not None
        
        if not is_member:
            raise APIError(
                error_code="NOT_MEMBER",
                message="شما_member این اتاق نیستید.",
                status_code=403
            )
        
        # Check if room is archived
        if room.is_archived:
            # Check if user can view archived messages
            # Simplified: allow if owner
            if room.owner_id != sender_id:
                raise APIError(
                    error_code="ROOM_ARCHIVED",
                    message="اتاق آرشیو شده است.",
                    status_code=403
                )
        
        # Check body length
        if len(body) > 4000:
            raise APIError(
                error_code="MESSAGE_TOO_LONG",
                message="متن پیام بیش از حد مجاز است.",
                status_code=400
            )
        
        # Create message
        message = Messages(
            room_id=str(room_id),
            sender_id=str(sender_id),
            body=body,
            message_type="text",
        )
        
        self.session.add(message)
        await self.session.flush()
        
        # Update room last activity (simplified)
        # room.updated_at = datetime.utcnow()
        
        return message
    
    async def get_messages(self, room_id: UUID, viewer_id: UUID) -> List[dict]:
        """Get messages for a room."""
        # Verify membership
        member_result = await self.session.execute(
            select(RoomMembers).where(
                (RoomMembers.room_id == str(room_id)) &
                (RoomMembers.user_id == str(viewer_id))
            )
        )
        is_member = member_result.scalar_one_or_none() is not None
        
        if not is_member:
            return []
        
        # Get messages
        query = select(Messages).where(Messages.room_id == str(room_id))
        results = (await self.session.execute(query)).scalars().all()
        
        messages = []
        for msg in results:
            messages.append({
                "id": str(msg.id),
                "room_id": str(msg.room_id),
                "sender_id": str(msg.sender_id),
                "body": msg.body,
                "sender_name": "sender",  # Would fetch user details
                "created_at": msg.created_at.isoformat() if msg.created_at else None,
                "message_type": msg.message_type,
                "is_edited": msg.is_edited,
            })
        
        # Sort by created_at ascending (oldest first)
        messages.sort(key=lambda m: m["created_at"])
        
        return messages
    
    # --- Archive Room ---
    
    async def archive_room(self, room_id: UUID, archived_by: UUID) -> dict:
        """Archive a chat room."""
        result = await self.session.execute(
            select(Rooms).where(Rooms.id == str(room_id))
        )
        room = result.scalar_one_or_none()
        
        if not room:
            raise APIError(
                error_code="ROOM_NOT_FOUND",
                message="اتاق یافت نشد.",
                status_code=404
            )
        
        # Check permission (owner or admin)
        is_owner = room.owner_id == archived_by
        
        if not is_owner:
            raise APIError(
                error_code="PERMISSION_DENIED",
                message="شما اجازه آرشیو این اتاق را ندارید.",
                status_code=403
            )
        
        # Archive the room
        await self.session.execute(
            update(Rooms).where(Rooms.id == str(room_id)).values(
                is_archived=True,
                archived_at=datetime.utcnow()
            )
        )
        await self.session.flush()
        
        return {"status": "archived", "archived_at": datetime.utcnow().isoformat()}