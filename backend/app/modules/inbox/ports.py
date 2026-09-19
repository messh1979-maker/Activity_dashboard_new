from typing import Protocol, Optional, List, Tuple
from uuid import UUID
from datetime import datetime
from pydantic import BaseModel, Field


# --- Inbox Item Types ---

class InboxItemType(BaseModel):
    """Inbox item type enum."""
    value: str
    label: str
    description: str = ""


INBOX_ITEM_TYPES = [
    InboxItemType(value="meeting_invite", label="مهموتیه"),
    InboxItemType(value="share_request", label="درخواست دسترسی"),
    InboxItemType(value="task_assignment", label="تعیین تسک"),
    InboxItemType(value="chat_invite", label="دعوت به چت"),
    InboxItemType(value="approval", label=" تأیید درخواست"),
]


# --- Inbox Item Schemas ---

class InboxItemCreate(BaseModel):
    """Create inbox item request."""
    recipient_id: UUID = Field(...)
    item_type: str = Field(..., pattern="^(meeting_invite|share_request|task_assignment|chat_invite|approval)$")
    entity_type: Optional[str] = Field(None, max_length=32)
    entity_id: Optional[UUID] = Field(None)
    title: str = Field(..., min_length=1, max_length=200)
    message: Optional[str] = Field(None, max_length=500)
    priority: str = Field(default="normal", pattern="^(normal|high|low)$")
    due_at: Optional[datetime] = Field(None)
    expires_at: Optional[datetime] = Field(None)


class InboxItemUpdate(BaseModel):
    """Update inbox item status."""
    action: str = Field(..., pattern="^(accepted|rejected|deferred)$")
    note: Optional[str] = Field(None, max_length=500)


class InboxItemResponse(BaseModel):
    """Inbox item response."""
    id: UUID
    sender_id: UUID
    recipient_id: UUID
    item_type: str
    entity_type: Optional[str]
    entity_id: Optional[UUID]
    title: str
    message: Optional[str] = None
    priority: str = "normal"
    action_state: str = "pending"  # 'pending' | 'accepted' | 'rejected' | 'deferred' | 'expired'
    receipt_state: str = "sent"  # 'sent' | 'seen' | 'acted'
    seen_at: Optional[datetime] = None
    acted_at: Optional[datetime] = None
    defer_until: Optional[datetime] = None
    response_note: Optional[str] = None
    due_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    created_at: datetime


# --- Outbox Item ---

class OutboxItemCreate(BaseModel):
    """Create outbox item request."""
    recipient_id: UUID = Field(...)
    item_type: str = Field(..., pattern="^(meeting_invite|share_request|task_assignment|chat_invite|approval)$")
    entity_type: Optional[str] = Field(None, max_length=32)
    entity_id: Optional[UUID] = Field(None)
    title: str = Field(..., min_length=1, max_length=200)
    message: Optional[str] = None


# --- Read Receipt ---

class ReceiptState(BaseModel):
    """Read receipt state."""
    state: str  # 'sent' | 'seen' | 'acted'
    acted_at: Optional[datetime] = None
    note: Optional[str] = None


# --- Export ---

class InboxExport(BaseModel):
    """Inbox export format."""
    user_id: UUID
    items: List[InboxItemResponse]
    exported_at: datetime


# Export all
__all__ = [
    "InboxItemCreate", "InboxItemUpdate", "InboxItemResponse",
    "OutboxItemCreate", "ReceiptState", "InboxExport",
    "INBOX_ITEM_TYPES"
]