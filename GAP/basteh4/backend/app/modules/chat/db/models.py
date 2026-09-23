import uuid
from uuid import UUID
from datetime import datetime
from sqlalchemy import func

from sqlalchemy import (
    Column, String, Integer, Boolean, DateTime,
    ForeignKey, Text, JSON, Index, UniqueConstraint, Table
)
from sqlalchemy.orm import relationship

from app.core.db.base import AuditMixin, BaseModel


# --- Rooms Table ---

class Rooms(BaseModel, AuditMixin):
    """Chat room entity."""
    
    __tablename__ = "rooms"
    __table_args__ = (
        Index("ix_rooms_linked", "linked_type", "linked_id"),
        Index("ix_rooms_owner", "owner_id"),
    )
    
    # Primary key inherited
    title = Column(String(160), nullable=False)
    description = Column(Text, nullable=True)
    
    # Linkage to other entities
    linked_type = Column(
        String(32),
        nullable=True,
        comment="task | meeting | goal | null (free room)"
    )
    linked_id = Column(String(36), nullable=True, index=True)
    
    # Ownership
    owner_id = Column(
        String(36),
        ForeignKey("auth.users.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    
    # Privacy & Archive
    is_archived = Column(Boolean, nullable=False, default=False)
    archived_at = Column(DateTime(timezone=True), nullable=True)
    archive_object_key = Column(String(512), nullable=True)  # S3 path
    retention_days = Column(
        Integer,
        nullable=False,
        default=365,
        comment="Message retention in days"
    )
    
    # Timestamps inherited
    # created_at, updated_at, deleted_at, version, created_by, updated_by
    
    # Relationships
    # members = relationship("RoomMembers", back_populates="room")
    # messages = relationship("Messages", back_populates="room", cascade="all, delete-orphan")


# --- Room Members ---

class RoomMembers(BaseModel, AuditMixin):
    """Room membership."""
    
    __tablename__ = "room_members"
    __table_args__ = (
        UniqueConstraint("room_id", "user_id", name="uq_room_member"),
        Index("ix_room_members_room", "room_id"),
    )
    
    # Primary key components
    room_id = Column(
        String(36),
        ForeignKey("rooms.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    user_id = Column(
        String(36),
        ForeignKey("auth.users.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    
    # Member role
    role = Column(
        String(16),
        nullable=False,
        default="member",
        comment="owner | moderator | member | readonly"
    )
    
    # Status
    is_muted = Column(Boolean, nullable=False, default=False)
    muted_until = Column(DateTime(timezone=True), nullable=True)
    left_at = Column(DateTime(timezone=True), nullable=True)
    
    # Timestamps inherited
    # created_at inherited from AuditMixin


# --- Messages Table ---

class Messages(BaseModel, AuditMixin):
    """Chat message entity."""
    
    __tablename__ = "messages"
    __table_args__ = (
        Index("ix_messages_room", "room_id", "created_at"),
        Index("ix_messages_sender", "sender_id"),
        Index("ix_messages_search", "search_vector"),
    )
    
    # Primary key inherited
    room_id = Column(
        String(36),
        ForeignKey("rooms.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    sender_id = Column(
        String(36),
        ForeignKey("auth.users.id", ondelete="SET NULL"),
        nullable=True,
        index=True
    )
    
    # Message content
    body = Column(Text, nullable=False)
    body_html = Column(Text, nullable=True)  # Sanitized HTML
    reply_to_id = Column(String(36), nullable=True)
    
    # Message type
    message_type = Column(
        String(16),
        nullable=False,
        server_default="text",
        comment="text | file | system"
    )
    
    # Edit tracking
    is_edited = Column(Boolean, nullable=False, default=False)
    edited_at = Column(DateTime(timezone=True), nullable=True)
    edit_history = Column(JSON, nullable=True, default={})
    
    # Search vector (PostgreSQL)
    search_vector = Column(
        Text,
        nullable=True,
        comment="GIN index for full-text search"
    )
    
    # Timestamps inherited from AuditMixin
    
    # Relationships
    # room = relationship("Rooms", back_populates="messages")
    # sender = relationship("Users", foreign_keys=[sender_id])
    # reply_to = relationship("Messages", remote_messages.id, remote_side=[id])


# --- Export all ---
__all__ = ["Rooms", "RoomMembers", "Messages"]