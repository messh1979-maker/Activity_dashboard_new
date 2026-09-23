"""Notification module ports — request/response Pydantic schemas (real DDL)."""

from __future__ import annotations

from datetime import datetime, time
from typing import Optional, List
from uuid import UUID

from pydantic import BaseModel, Field


class NotificationCreate(BaseModel):
    user_id: UUID
    type: str = Field(..., max_length=50)
    title: str = Field(..., max_length=255)
    message: Optional[str] = None
    data: Optional[dict] = None
    action_url: Optional[str] = Field(None, max_length=255)
    action_text: Optional[str] = Field(None, max_length=100)
    related_entity_type: Optional[str] = Field(None, max_length=50)
    related_entity_id: Optional[UUID] = None
    priority: str = Field("normal", pattern="^(low|normal|high|urgent)$")
    expires_at: Optional[datetime] = None


class NotificationResponse(BaseModel):
    id: UUID
    user_id: UUID
    type: str
    title: str
    message: Optional[str]
    data: Optional[dict]
    is_read: bool
    action_url: Optional[str]
    action_text: Optional[str]
    priority: str
    created_at: datetime
    read_at: Optional[datetime]


class PreferencesUpdate(BaseModel):
    email_enabled: Optional[bool] = None
    push_enabled: Optional[bool] = None
    inbox_enabled: Optional[bool] = None
    types: Optional[dict] = None
    quiet_hours_start: Optional[time] = None
    quiet_hours_end: Optional[time] = None


class PreferencesResponse(BaseModel):
    user_id: UUID
    email_enabled: bool
    push_enabled: bool
    inbox_enabled: bool
    types: dict
    quiet_hours_start: Optional[time] = None
    quiet_hours_end: Optional[time] = None


class NotificationCount(BaseModel):
    unread: int


__all__ = [
    "NotificationCreate", "NotificationResponse", "PreferencesUpdate",
    "PreferencesResponse", "NotificationCount",
]