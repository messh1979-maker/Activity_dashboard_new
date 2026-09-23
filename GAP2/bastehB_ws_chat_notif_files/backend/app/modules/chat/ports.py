from typing import Protocol, Optional, List, Tuple, Dict, Any
from uuid import UUID
from datetime import datetime
from pydantic import BaseModel, Field


# --- Chat Room Protocols ---

class RoomReadModel(Protocol):
    """Read model for chat rooms visible to other modules."""
    id: UUID
    title: str
    owner_id: UUID
    is_archived: bool
    member_count: int
    privacy_level: str  # from groups module


# --- Chat Message Protocols ---

class MessageReadModel(Protocol):
    """Read model for chat messages."""
    id: UUID
    room_id: UUID
    sender_id: UUID
    body: str
    sender_name: str
    created_at: datetime
    message_type: str  # 'text' | 'file' | 'system'
    is_edited: bool
    edited_at: Optional[datetime]


# --- Chat Schemas ---

class RoomCreate(BaseModel):
    """Create room request."""
    title: str = Field(..., min_length=1, max_length=160)
    linked_type: Optional[str] = Field(
        None,
        pattern="^(task|meeting|goal|null)$"
    )
    linked_id: Optional[UUID] = Field(None, description="ID of linked entity")


class RoomUpdate(BaseModel):
    """Update room request."""
    title: Optional[str] = Field(None, min_length=1, max_length=160)
    is_archived: Optional[bool] = Field(None)


class MessageCreate(BaseModel):
    """Create message request."""
    room_id: UUID = Field(...)
    body: str = Field(..., min_length=1, max_length=4000)
    reply_to: Optional[UUID] = Field(None, description="Message ID to reply to")


class MessageResponse(BaseModel):
    """Message response."""
    id: UUID
    room_id: UUID
    sender_id: UUID
    body: str
    sender_name: str
    created_at: datetime
    message_type: str
    is_edited: bool
    edit_history: List[dict] = Field(default_factory=list)


# --- Room Membership ---

class MemberCreate(BaseModel):
    """Add member to room."""
    user_id: UUID
    role: str = "member"  # 'member' | 'moderator' | 'owner'


# --- Export ---

class ChatExport(BaseModel):
    """Chat export format."""
    room_id: UUID
    room_title: str
    messages: List[MessageResponse]
    exported_at: datetime


# Export all
__all__ = [
    "RoomReadModel", "MessageReadModel", "RoomCreate", "RoomUpdate",
    "MessageCreate", "MessageResponse", "MemberCreate", "ChatExport"
]