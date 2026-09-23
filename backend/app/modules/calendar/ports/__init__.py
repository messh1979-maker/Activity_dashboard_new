"""Calendar module ports — request/response Pydantic schemas (real DDL).

Architecture Reference: Sections 9.3, 10.4 (calendar.events/attendees/notes).
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional, Literal
from uuid import UUID

from pydantic import BaseModel, Field


# --- Event payload / status enums ---

class EventCreate(BaseModel):
    """Create a new calendar event."""
    title: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    privacy_level: Literal['public', 'team_only', 'private'] = 'team_only'
    start_time: datetime
    end_time: datetime
    all_day: bool = False
    recurrence_rule: Optional[str] = None  # iCalendar RRULE
    status: Literal['active', 'cancelled', 'rescheduled'] = 'active'


class EventUpdate(BaseModel):
    """Patch an existing event."""
    title: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None
    privacy_level: Optional[Literal['public', 'team_only', 'private']] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    all_day: Optional[bool] = None
    recurrence_rule: Optional[str] = None
    status: Optional[Literal['active', 'cancelled', 'rescheduled']] = None


class AttendeeLink(BaseModel):
    """Add or update an attendee on an event."""
    user_id: UUID
    response_status: Literal['pending', 'accepted', 'declined', 'tentative'] = 'pending'
    rsvp: bool = False


class AttendeeResponse(BaseModel):
    user_id: UUID
    response_status: str
    notified_at: Optional[datetime] = None
    rsvp: bool


class NoteCreate(BaseModel):
    """Add a meeting note to an event."""
    content: str
    author_id: Optional[UUID] = None


# --- Row-level response schemas ---

class _EventBase(BaseModel):
    id: UUID
    title: str
    description: Optional[str] = None
    owner_id: UUID
    privacy_level: str
    start_time: datetime
    end_time: datetime
    all_day: bool
    recurrence_rule: Optional[str] = None
    status: str
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    deleted_at: Optional[datetime] = None


class EventResponse(_EventBase):
    """Full event payload returned by list/detail endpoints."""
    attendees: list[AttendeeResponse] = []
    notes_count: int = 0


class EventListItem(_EventBase):
    """Lightweight event row for list views."""
    attendees: list[UUID] = []


class NoteResponse(BaseModel):
    id: UUID
    event_id: UUID
    author_id: UUID
    content: str
    created_at: datetime
    updated_at: datetime


class CalendarSummary(BaseModel):
    """Aggregate counts returned by the summary endpoint."""
    events_total: int
    events_active: int
    events_cancelled: int
    attendees_total: int
    notes_total: int


__all__ = [
    "EventCreate", "EventUpdate", "AttendeeLink",
    "AttendeeResponse", "NoteCreate", "EventResponse",
    "EventListItem", "NoteResponse", "CalendarSummary",
]