import uuid
from uuid import UUID
from datetime import datetime
from sqlalchemy import func

from sqlalchemy import (
    Column, String, Integer, Boolean, DateTime,
    ForeignKey, Text, JSON, UniqueConstraint, Index
)
from sqlalchemy.orm import relationship

from app.core.db.base import AuditMixin, BaseModel


# --- Inbox Items ---

class InboxItems(BaseModel, AuditMixin):
    """Inbox item entity."""
    
    __tablename__ = "inbox_items"
    __table_args__ = (
        UniqueConstraint("id", name="uq_inbox_item_id"),
        Index("ix_inbox_recipient", "recipient_id", "action_state"),
        Index("ix_inbox_sender", "sender_id"),
        Index("ix_inbox_deferred", "defer_until"),
    )
    
    # Primary key
    id = Column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4())
    )
    
    # Sender and recipient
    sender_id = Column(
        String(36),
        ForeignKey("auth.users.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    recipient_id = Column(
        String(36),
        ForeignKey("auth.users.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    
    # Item classification
    item_type = Column(
        String(32),
        nullable=False,
        comment="meeting_invite | share_request | task_assignment | chat_invoice | approval"
    )
    entity_type = Column(String(32), nullable=True)
    entity_id = Column(String(36), nullable=True)
    
    # Content
    title = Column(String(200), nullable=False)
    message = Column(Text, nullable=True)
    
    # Status
    priority = Column(
        String(16),
        nullable=False,
        default="normal",
        comment="normal | high | low"
    )
    action_state = Column(
        String(16),
        nullable=False,
        default="pending",
        comment="pending | accepted | rejected | deferred | expired"
    )
    receipt_state = Column(
        String(16),
        nullable=False,
        default="sent",
        comment="sent | seen | acted"
    )
    
    # Timeline
    due_at = Column(DateTime(timezone=True), nullable=True)
    expires_at = Column(DateTime(timezone=True), nullable=True)
    defer_until = Column(DateTime(timezone=True), nullable=True)
    
    # Notes
    response_note = Column(Text, nullable=True)
    
    # Timestamps inherited from AuditMixin
    
    # Relationships
    # sender = relationship("Users", foreign_keys=[sender_id])
    # recipient = relationship("Users", foreign_keys=[recipient_id])


# --- Read Receipts ---

class Receipts(BaseModel, AuditMixin):
    """Read receipt tracking."""
    
    __tablename__ = "receipts"
    __table_args__ = (
        UniqueConstraint("item_id", "user_id", name="uq_receipt"),
        Index("ix_receipt_item", "item_id"),
        Index("ix_receipt_user", "user_id"),
    )
    
    # Primary key components
    item_id = Column(
        String(36),
        ForeignKey("inbox_items.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    user_id = Column(
        String(36),
        ForeignKey("auth.users.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    
    # State tracking
    state = Column(
        String(16),
        nullable=False,
        default="sent",
        comment="sent | seen | acted"
    )
    acted_at = Column(DateTime(timezone=True), nullable=True)
    note = Column(Text, nullable=True)
    
    # Timestamps inherited


# --- Outbox Items ---

class OutboxItems(BaseModel, AuditMixin):
    """Outbox item entity."""
    
    __tablename__ = "outbox_items"
    __table_args__ = (
        Index("ix_outbox_recipient", "recipient_id", "created_at"),
    )
    
    # Primary key
    id = Column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4())
    )
    
    # Sender
    sender_id = Column(
        String(36),
        ForeignKey("auth.users.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    
    # Recipient
    recipient_id = Column(
        String(36),
        ForeignKey("auth.users.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    
    # Content
    item_type = Column(
        String(32),
        nullable=False,
        comment="meeting_invite | share_request | task_assignment | chat_invoice | approval"
    )
    entity_type = Column(String(32), nullable=True)
    entity_id = Column(String(36), nullable=True)
    title = Column(String(200), nullable=False)
    message = Column(Text, nullable=True)
    
    # Status
    read_receipt = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    # sender = relationship("Users", foreign_keys=[sender_id])
    # recipient = relationship("Users", foreign_keys=[recipient_id])


# --- Export all ---
__all__ = ["InboxItems", "Receipts", "OutboxItems"]