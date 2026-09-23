# BUNDLE: basteh3
# Source: GAP\basteh3
================================================================================

================================================================================
## FILE: backend/app/modules/calendar/__init__.py
================================================================================

```python
"""Calendar module public interface (real DDL)."""
from app.modules.calendar.api.routes import router

__all__ = ["router"]
```

================================================================================
## FILE: backend/app/modules/calendar/services/calendar_service.py
================================================================================

```python
"""Calendar service — real DDL (M5).

Raw SQL against schema ``calendar``: events, attendees, notes.
Mirrors the inbox pattern (raw ``sa.text``, ``SimpleNamespace``,
``_row_serialize``) so the ORM drift between code and the DDL
is handled consistently.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Optional
from uuid import UUID
from types import SimpleNamespace

from sqlalchemy import text

from app.core.errors import APIError, NotFoundError


def _iso(v) -> Optional[str]:
    return v.isoformat() if isinstance(v, datetime) else v


def _row_serialize(r) -> dict:
    d = dict(r)
    for k, v in list(d.items()):
        if v is not None and isinstance(v, datetime):
            d[k] = _iso(v)
    return d


class CalendarStateMachine:
    """Manages calendar events, attendees and notes (real DDL)."""

    def __init__(self, session):
        self.session = session

    async def create_event(self, owner_id: UUID, payload: dict) -> SimpleNamespace:
        """Insert a new event and return its identity + state."""
        row = (await self.session.execute(text("""
            INSERT INTO calendar.events (
                title, description, owner_id, privacy_level,
                start_time, end_time, all_day, recurrence_rule, status
            )
            VALUES (:title, :desc, :owner, :privacy, :start, :end,
                    :all_day, :recur, :status)
            RETURNING id, title, status, created_at
        """), {
            "title": payload["title"],
            "desc": payload.get("description"),
            "owner": str(owner_id),
            "privacy": payload.get("privacy_level", "team_only"),
            "start": payload["start_time"],
            "end": payload["end_time"],
            "all_day": payload.get("all_day", False),
            "recur": payload.get("recurrence_rule"),
            "status": payload.get("status", "active"),
        })).mappings().first()
        await self.session.commit()
        return SimpleNamespace(
            id=row["id"], title=row["title"], status=row["status"],
            created_at=_iso(row["created_at"]),
        )

    async def list_events(self, user_id: UUID,
                          date_from: Optional[datetime] = None,
                          date_to: Optional[datetime] = None,
                          status: Optional[str] = None) -> list[dict]:
        """List events the user owns or attends, with safe filtering."""
        conds = ["(e.owner_id = :uid OR EXISTS (SELECT 1 FROM calendar.attendees a WHERE a.event_id = e.id AND a.user_id = :uid))"]
        params: dict = {"uid": str(user_id)}
        if date_from:
            conds.append("e.start_time >= :from")
            params["from"] = date_from
        if date_to:
            conds.append("e.end_time <= :to")
            params["to"] = date_to
        if status:
            conds.append("e.status::text = :st")
            params["st"] = status

        rows = (await self.session.execute(text(f"""
            SELECT e.id, e.title, e.description, e.owner_id, e.privacy_level,
                   e.start_time, e.end_time, e.all_day, e.recurrence_rule,
                   e.status, e.created_at, e.updated_at, e.deleted_at
              FROM calendar.events e
             WHERE {" AND ".join(conds)}
             ORDER BY e.start_time ASC
        """), params)).mappings().all()
        return [_row_serialize(r) for r in rows]

    async def get_event(self, event_id: UUID,
                        user_id: UUID) -> dict:
        """Fetch a single event with its attendees and note count."""
        row = (await self.session.execute(text("""
            SELECT e.id, e.title, e.description, e.owner_id, e.privacy_level,
                   e.start_time, e.end_time, e.all_day, e.recurrence_rule,
                   e.status, e.created_at, e.updated_at, e.deleted_at
              FROM calendar.events e
             WHERE e.id = :eid AND (e.owner_id = :uid OR EXISTS (
                SELECT 1 FROM calendar.attendees a WHERE a.event_id = e.id AND a.user_id = :uid
             ))
        """), {"eid": str(event_id), "uid": str(user_id)})).mappings().first()
        if not row:
            raise NotFoundError(resource="calendar event")
        event = _row_serialize(row)

        attendees = (await self.session.execute(text("""
            SELECT a.user_id, a.response_status, a.notified_at, a.rsvp
              FROM calendar.attendees a WHERE a.event_id = :eid
        """), {"eid": str(event_id)})).mappings().all()
        event["attendees"] = [
            {"user_id": str(a["user_id"]), "response_status": a["response_status"],
             "notified_at": _iso(a["notified_at"]), "rsvp": a["rsvp"]}
            for a in attendees
        ]
        note_row = (await self.session.execute(text("""
            SELECT count(*) AS n FROM calendar.notes WHERE event_id = :eid
        """), {"eid": str(event_id)})).mappings().first()
        event["notes_count"] = note_row["n"] or 0
        return event

    async def update_event(self, event_id: UUID, user_id: UUID,
                           patch: dict) -> SimpleNamespace:
        """Patch event fields; returns updated identity."""
        set_parts, params = [], {"eid": str(event_id), "uid": str(user_id)}
        for col, key in (("title", "title"), ("description", "description"),
                         ("privacy_level", "privacy"), ("start_time", "start"),
                         ("end_time", "end"), ("all_day", "all_day"),
                         ("recurrence_rule", "recur"), ("status", "st")):
            if key in patch and patch[key] is not None:
                set_parts.append(f"{col} = :{key}")
                params[key] = patch[key]
        if not set_parts:
            raise APIError(error_code="NO_CHANGE",
                           message="هیچ فیلدی برای بروزرسانی داده نشد.",
                           status_code=400)
        set_parts.append("updated_at = now()")
        result = (await self.session.execute(text(f"""
            UPDATE calendar.events
               SET {" , ".join(set_parts)}
             WHERE id = :eid AND owner_id = :uid
         RETURNING id, title, status, updated_at
        """), params)).mappings().first()
        await self.session.commit()
        if not result:
            raise NotFoundError(resource="calendar event")
        return SimpleNamespace(id=result["id"], title=result["title"],
                               status=result["status"],
                               updated_at=_iso(result["updated_at"]))

    async def delete_event(self, event_id: UUID, user_id: UUID) -> SimpleNamespace:
        """Soft-delete an event (sets deleted_at)."""
        result = (await self.session.execute(text("""
            UPDATE calendar.events SET deleted_at = now()
             WHERE id = :eid AND owner_id = :uid
         RETURNING id
        """), {"eid": str(event_id), "uid": str(user_id)})).mappings().first()
        await self.session.commit()
        if not result:
            raise NotFoundError(resource="calendar event")
        return SimpleNamespace(id=result["id"])

    # --- Attendees ---

    async def add_attendee(self, event_id: UUID, user_id: UUID) -> SimpleNamespace:
        """Add attendee to an event (UPSERT)."""
        row = (await self.session.execute(text("""
            INSERT INTO calendar.attendees (event_id, user_id)
            VALUES (:eid, :uid)
            ON CONFLICT (event_id, user_id) DO NOTHING
            RETURNING event_id, user_id, response_status, rsvp
        """), {"eid": str(event_id), "uid": str(user_id)})).mappings().first()
        await self.session.commit()
        if not row:
            row = (await self.session.execute(text("""
                SELECT event_id, user_id, response_status, rsvp
                  FROM calendar.attendees
                 WHERE event_id = :eid AND user_id = :uid
            """), {"eid": str(event_id), "uid": str(user_id)})).mappings().first()
        return SimpleNamespace(event_id=row["event_id"],
                               user_id=row["user_id"],
                               response_status=row["response_status"],
                               rsvp=row["rsvp"])

    async def list_attendees(self, event_id: UUID) -> list[dict]:
        """List all attendees for an event."""
        rows = (await self.session.execute(text("""
            SELECT a.user_id, a.response_status, a.notified_at, a.rsvp
              FROM calendar.attendees a WHERE a.event_id = :eid
        """), {"eid": str(event_id)})).mappings().all()
        return [{"user_id": str(a["user_id"]), "response_status": a["response_status"],
                 "notified_at": _iso(a["notified_at"]), "rsvp": a["rsvp"]} for a in rows]

    async def set_response(self, event_id: UUID, user_id: UUID,
                           status: str) -> SimpleNamespace:
        """RSVP an attendee (pending/accepted/declined/tentative)."""
        valid = {"pending", "accepted", "declined", "tentative"}
        if status not in valid:
            raise APIError(error_code="INVALID_RESPONSE",
                           message="وضعیت پاسخ نامعتبر.", status_code=400)
        result = (await self.session.execute(text("""
            UPDATE calendar.attendees SET response_status = :st, notified_at = now()
             WHERE event_id = :eid AND user_id = :uid
         RETURNING event_id, user_id, response_status
        """), {"st": status, "eid": str(event_id), "uid": str(user_id)})).mappings().first()
        await self.session.commit()
        if not result:
            raise NotFoundError(resource="calendar attendee")
        return SimpleNamespace(event_id=result["event_id"],
                               user_id=result["user_id"],
                               response_status=result["response_status"])

    # --- Notes ---

    async def add_note(self, event_id: UUID, author_id: UUID,
                       content: str) -> SimpleNamespace:
        """Append a note to an event."""
        row = (await self.session.execute(text("""
            INSERT INTO calendar.notes (event_id, author_id, content)
            VALUES (:eid, :aid, :content)
            RETURNING id, content, created_at
        """), {"eid": str(event_id), "aid": str(author_id),
              "content": content})).mappings().first()
        await self.session.commit()
        return SimpleNamespace(id=row["id"], content=row["content"],
                               created_at=_iso(row["created_at"]))


CalendarService = CalendarStateMachine
```

================================================================================
## FILE: backend/app/modules/goals/__init__.py
================================================================================

```python
"""Goals module public interface."""
from app.modules.goals.api.routes import router

__all__ = ["router"]
```

================================================================================
## FILE: backend/app/modules/goals/db/models.py
================================================================================

```python
import uuid
from typing import Dict
from uuid import UUID
from datetime import datetime
from sqlalchemy import (
    Column, String, Integer, DateTime, Boolean, Text,
    ForeignKey, CheckConstraint, UniqueConstraint, Index, Table
)
from sqlalchemy.sql import func

from app.core.db.base import BaseModel, AuditMixin


# --- Goals Table ---

class Goals(BaseModel, AuditMixin):
    """Goal entity with privacy-aware fields."""
    
    __tablename__ = "goals"
    __table_args__ = (
        CheckConstraint("progress_pct >= 0 AND progress_pct <= 100"),
        {},
    )
    
    # Primary key inherited from BaseModel (UUID)
    
    # Goal identity
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    
    # Ownership & Privacy
    owner_id = Column(
        String(36),  # UUID as string
        nullable=False,
        index=True
    )
    privacy_level = Column(
        String(20), 
        nullable=False,
        default="team_only",
        comment="fully_private | team_only | selected | fully_transparent"
    )
    
    # Progress tracking
    progress_pct = Column(
        Integer, 
        nullable=False,
        server_default="0",
        comment="0-100"
    )
    
    # Timeline
    status = Column(
        String(16), 
        nullable=False,
        server_default="active",
        comment="active | completed | archived"
    )
    start_date = Column(DateTime(timezone=True), nullable=True)
    due_date = Column(DateTime(timezone=True), nullable=True)
    
    # Timestamps (inherited from BaseModel)
    # created_at, updated_at, deleted_at, version, created_by, updated_by
    
    # Relationships (lazy loading)
    # tags = relationship("GoalTags", back_populates="goal", cascade="all, delete-orphan")
    # tasks = relationship("Tasks", back_populates="goal", cascade="all, delete-orphan")
    
    def is_visible_to(self, viewer_id: UUID, privacy_level: str) -> bool:
        """Check if goal is visible to a viewer based on privacy settings."""
        if privacy_level == "fully_transparent":
            return True
        elif privacy_level == "team_only":
            # Team members can see - determined by ACL
            return True  # simplified
        elif privacy_level == "selected":
            # Only specific viewers allowed
            return False  # determined by privacy_exceptions
        elif privacy_level == "fully_private":
            # Only owner can see
            return False  # determined by owner check
        return False
    
    def get_privacy_decision(self, owner_id: UUID, viewer_id: UUID) -> dict:
        """Get privacy decision for a viewer."""
        # This would query groups.privacy_settings and groups.privacy_exceptions
        # For now, simplified logic
        is_owner = owner_id == viewer_id
        
        if is_owner:
            return {"level": "full", "redaction": None}
        else:
            # Check privacy level from goal
            level = self.privacy_level
            if level == "fully_private":
                return {"level": "hidden", "redaction": "full_content"}
            elif level == "team_only":
                # Would check if viewer is team member
                return {"level": "aggregate_only", "redaction": "status_only"}
            elif level == "selected":
                # Would check privacy_exceptions
                return {"level": "hidden", "redaction": "full_content"}
            elif level == "fully_transparent":
                return {"level": "full", "redaction": None}
        
        return {"level": "hidden", "redaction": "full_content"}


# --- Tasks Table ---

class Tasks(BaseModel, AuditMixin):
    """Task entity linked to a goal."""
    
    __tablename__ = "tasks"
    __table_args__ = (
        UniqueConstraint("goal_id", "title", name="uq_goal_task_title"),
    )
    
    # Primary key inherited
    goal_id = Column(
        String(36),  # UUID
        ForeignKey("goals.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    
    # Task identity
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    
    # Assignment
    assignee_id = Column(
        String(36),
        ForeignKey("auth.users.id"),
        nullable=True,
        index=True
    )
    owner_id = Column(
        String(36),
        nullable=False,
        comment="Goal owner who created the task"
    )
    
    # Task tracking
    privacy_level = Column(
        String(20),
        nullable=False,
        default="team_only",
        comment="inherited from goal or overridden"
    )
    status = Column(
        String(16),
        nullable=False,
        server_default="pending",
        comment="pending | in_progress | completed | deferred"
    )
    priority = Column(
        String(16),
        nullable=False,
        server_default="normal",
        comment="normal | high | low"
    )
    progress_pct = Column(
        Integer,
        nullable=False,
        server_default="0",
        comment="0-100 for task progress"
    )
    
    # Timeline
    due_date = Column(DateTime(timezone=True), nullable=True)
    
    # Timestamps inherited
    # created_at, updated_at, deleted_at, version, created_by, updated_by
    
    # Relationships
    # goal = relationship("Goals", back_populates="tasks")
    # assignee = relationship("Users", foreign_keys=[assignee_id])
    
    def is_visible_to(self, viewer_id: UUID, goal_privacy: str) -> bool:
        """Check if task is visible to viewer based on privacy."""
        # Tasks inherit privacy from goal, with possible overrides
        if goal_privacy == "fully_transparent":
            return True
        elif goal_privacy == "fully_private" and viewer_id != self.owner_id:
            return False
        elif goal_privacy == "team_only":
            # Team members can see basic info
            return True  # simplified - would check ACL
        elif goal_privacy == "selected":
            # Would check privacy_exceptions
            return False  # simplified
        return False
    
    def get_privacy_decision(self, goal_privacy: str, viewer_id: UUID) -> dict:
        """Get privacy decision for task viewer."""
        is_owner = viewer_id is not None and hasattr(self, 'owner_id') and self.owner_id == viewer_id
        
        if is_owner:
            return {"level": "full", "redaction": None}
        
        if goal_privacy == "fully_private":
            return {"level": "hidden", "redaction": "full_content"}
        elif goal_privacy == "team_only":
            return {"level": "aggregate_only", "redaction": "status_and_progress"}
        elif goal_privacy == "selected":
            return {"level": "hidden", "redaction": "full_content"}
        elif goal_privacy == "fully_transparent":
            return {"level": "full", "redaction": None}
        
        return {"level": "hidden", "redaction": "full_content"}


# --- Tags Table ---

class Tags(BaseModel, AuditMixin):
    """Tag entity for multi-goal labeling."""
    
    __tablename__ = "tags"
    __table_args__ = (
        UniqueConstraint("name", name="uq_tag_name"),
    )
    
    # Primary key inherited
    name = Column(String(64), nullable=False, unique=True)
    color = Column(
        String(7),
        nullable=False,
        default="#3B82F6",
        comment="#RRGGBB format"
    )
    
    # Timestamps inherited
    # created_at, updated_at, deleted_at, version, created_by, updated_by
    
    # Relationships
    # goal_tags = relationship("GoalTags", back_populates="tag", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<Tag name='{self.name}' color='{self.color}'>"


# --- Goal-Tag Junction Table ---

class GoalTags(BaseModel, AuditMixin):
    """Junction table for many-to-many Goal-Tag relationship."""
    
    __tablename__ = "goal_tags"
    __table_args__ = (
        UniqueConstraint("goal_id", "tag_id", name="uq_goal_tag"),
    )
    
    # Primary key inherited
    goal_id = Column(
        String(36),
        ForeignKey("goals.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    tag_id = Column(
        String(36),
        ForeignKey("tags.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    
    # Composite primary key (goal_id, tag_id)
    
    # Relationships
    # goal = relationship("Goals", back_populates="goal_tags")
    # tag = relationship("Tags", back_populates="goal_tags")
```

================================================================================
## FILE: backend/app/modules/groups/__init__.py
================================================================================

```python
"""Groups module public interface."""
from app.modules.groups.api.routes import router

__all__ = ["router"]
```

================================================================================
## FILE: backend/app/modules/groups/db/models.py
================================================================================

```python
import uuid
from typing import List
from uuid import UUID
from datetime import datetime
from sqlalchemy import func

from sqlalchemy import (
    Column, String, Integer, Boolean, DateTime,
    ForeignKey, Table, UniqueConstraint, Index, Text
)
from sqlalchemy.orm import relationship

from app.core.db.base import AuditMixin, BaseModel


# --- Groups Table ---

class Groups(BaseModel, AuditMixin):
    """Group entity with hierarchical structure and privacy."""
    
    __tablename__ = "groups"
    __table_args__ = (
        UniqueConstraint("path", name="uq_group_path"),
        Index("ix_groups_owner", "owner_id"),
        Index("ix_groups_parent", "parent_id"),
    )
    
    # Primary key inherited from BaseModel
    title = Column(String(128), nullable=False)
    description = Column(Text, nullable=True)
    
    # Hierarchical structure
    parent_id = Column(
        String(36),
        ForeignKey("groups.id", ondelete="CASCADE"),
        nullable=True,
        index=True
    )
    path = Column(String, nullable=True)  # LTREE path
    
    # Ownership
    owner_id = Column(
        String(36),
        ForeignKey("auth.users.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    
    # Privacy
    privacy_level = Column(
        String(20),
        nullable=False,
        default="team_only",
        comment="fully_private | team_only | selected | fully_transparent"
    )
    
    # Status
    is_active = Column(Boolean, nullable=False, server_default="True")
    
    # Timestamps inherited from BaseModel/AuditMixin
    # created_at, updated_at, deleted_at, version, created_by, updated_by
    
    # Relationships
    # parent = relationship("Groups", remote_side=[id], backref="children")
    # members = relationship("GroupMembers", back_populates="group")
    # goals = relationship("Goals", back_populates="group")
    
    def get_path(self) -> str:
        """Get the full path for this group."""
        return self.path or ""
    
    def is_descendant_of(self, ancestor_id: UUID) -> bool:
        """Check if this group is a descendant of another."""
        if not self.path:
            return False
        # In real implementation, use LTREE operations
        return True  # simplified
    
    def get_ancestors(self) -> List[UUID]:
        """Get ancestor group IDs."""
        # Real implementation would parse LTREE path
        return []  # simplified


# --- Group Members Table ---

class GroupMembers(BaseModel, AuditMixin):
    """Group membership with roles."""
    
    __tablename__ = "group_members"
    __table_args__ = (
        UniqueConstraint("group_id", "user_id", name="uq_group_member"),
        Index("ix_group_members_user", "user_id"),
    )
    
    # Primary key components
    group_id = Column(
        String(36),
        ForeignKey("groups.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    user_id = Column(
        String(36),
        ForeignKey("auth.users.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    
    # Membership roles
    is_manager = Column(Boolean, nullable=False, default=False)
    role = Column(String(16), nullable=False, default="member")
    
    # Timestamps
    joined_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    # group = relationship("Groups", back_populates="members")
    # user = relationship("Users", foreign_keys=[user_id])


# --- Privacy Exceptions ---

class PrivacyExceptions(BaseModel, AuditMixin):
    """Privacy exceptions for 'selected' level groups."""
    
    __tablename__ = "privacy_exceptions"
    __table_args__ = (
        UniqueConstraint("group_id", "viewer_id", name="uq_privacy_exception"),
    )
    
    # Primary key components
    group_id = Column(
        String(36),
        ForeignKey("groups.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    owner_id = Column(
        String(36),
        nullable=False,
        comment="Group owner who set the exception"
    )
    viewer_id = Column(
        String(36),
        nullable=False,
        comment="User who has exception access"
    )
    
    # Exception settings
    can_comment = Column(Boolean, nullable=False, default=False)
    granted_at = Column(DateTime(timezone=True), server_default=func.now())
    expires_at = Column(DateTime(timezone=True), nullable=True)
    
    # Relationships
    # group = relationship("Groups", back_populates="exceptions")


# --- Export all ---
__all__ = ["Groups", "GroupMembers", "PrivacyExceptions"]
```

================================================================================
## FILE: backend/app/modules/inbox/__init__.py
================================================================================

```python
"""Inbox module public interface."""
from app.modules.inbox.api.routes import router

__all__ = ["router"]
```

================================================================================
## FILE: backend/app/modules/inbox/db/models.py
================================================================================

```python
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
```

================================================================================
## FILE: backend/app/modules/inbox/services/inbox_service.py
================================================================================

```python
"""
Inbox State Machine Implementation (real DDL).

Architecture Reference: Sections 9.1, 9.2, 11.1.
State Machine: pending -> accepted/rejected/deferred/expired
Read Receipt: sent -> seen -> acted

Raw SQL against schema ``inbox``; the ORM models drifted from the DDL.
"""

from uuid import UUID
from datetime import datetime, timedelta
from typing import Optional, Literal
from types import SimpleNamespace

from sqlalchemy import text

from app.core.errors import APIError, NotFoundError
from app.modules.inbox.ports import INBOX_ITEM_TYPES


def _iso(v):
    return v.isoformat() if isinstance(v, datetime) else v


def _row_serialize(r) -> dict:
    d = dict(r)
    for k in (k for k in d if d[k] is not None):
        if isinstance(d[k], datetime):
            d[k] = _iso(d[k])
    return d


class InboxStateMachine:
    """Manages inbox item state transitions and read receipts (real DDL)."""

    def __init__(self, session):
        self.session = session

    async def create_item(self, sender_id: UUID, recipient_id: UUID,
                          item_type: str, entity_type: Optional[str],
                          entity_id: Optional[UUID], title: str,
                          message: Optional[str], priority: str,
                          due_at: Optional[datetime], expires_at: Optional[datetime]
                          ) -> SimpleNamespace:
        """Create a new inbox item with initial state."""
        valid_types = [t.value for t in INBOX_ITEM_TYPES]
        if item_type not in valid_types:
            raise APIError(error_code="INVALID_ITEM_TYPE",
                           message="نوع آیتم نامعتبر.", status_code=400)
        row = (await self.session.execute(text("""
            INSERT INTO inbox.items (sender_id, recipient_id, item_type,
                                     entity_type, entity_id, title, message,
                                     priority, action_state, receipt_state,
                                     due_at, expires_at)
            VALUES (:sid, :rid, :itype, :etype, :eid, :title, :msg,
                    :prio, 'pending', 'sent', :due, :exp)
            RETURNING id, action_state, receipt_state
        """), {
            "sid": str(sender_id), "rid": str(recipient_id),
            "itype": item_type, "etype": entity_type,
            "eid": str(entity_id) if entity_id else None,
            "title": title, "msg": message, "prio": priority,
            "due": due_at, "exp": expires_at,
        })).mappings().first()
        await self.session.execute(text("""
            INSERT INTO inbox.receipts (item_id, user_id, state)
            VALUES (:iid, :uid, 'sent')
        """), {"iid": row["id"], "uid": str(recipient_id)})
        await self.session.commit()
        return SimpleNamespace(id=row["id"], action_state=row["action_state"],
                               receipt_state=row["receipt_state"])

    async def list_items(self, user_id: UUID, state: Optional[str] = None) -> list:
        """List inbox items for a recipient."""
        conds, params = ["recipient_id = :uid"], {"uid": str(user_id)}
        if state:
            conds.append("action_state::text = :st"); params["st"] = state
        rows = (await self.session.execute(text(f"""
            SELECT id, sender_id, recipient_id, item_type, entity_type,
                   entity_id, title, message, priority,
                   action_state::text AS action_state, receipt_state::text AS receipt_state,
                   seen_at, acted_at, defer_until, response_note, due_at, expires_at, created_at
              FROM inbox.items WHERE {" AND ".join(conds)}
             ORDER BY created_at DESC
        """), params)).mappings().all()
        return [_row_serialize(r) for r in rows]

    async def list_outbox(self, user_id: UUID) -> list:
        """List outbox items sent by a user."""
        rows = (await self.session.execute(text("""
            SELECT id, sender_id, recipient_id, item_type, entity_type,
                   entity_id, title, message, read_receipt, created_at,
                   recipient_acknowledged_at, recipient_acknowledged_note
              FROM inbox.outbox WHERE sender_id = :uid
             ORDER BY created_at DESC
        """), {"uid": str(user_id)})).mappings().all()
        return [_row_serialize(r) for r in rows]

    async def act_on_item(self, item_id: UUID, action: Literal["accepted", "rejected", "deferred"],
                          note: Optional[str], actor_id: UUID) -> SimpleNamespace:
        """Handle item action (accept, reject, defer)."""
        item = (await self.session.execute(text("""
            SELECT id, recipient_id, action_state::text AS action_state FROM inbox.items
             WHERE id = :iid
        """), {"iid": str(item_id)})).mappings().first()
        if not item:
            raise APIError(error_code="ITEM_NOT_FOUND",
                           message="آیتم یافت نشد.", status_code=404)
        if str(item["recipient_id"]) != str(actor_id):
            raise APIError(error_code="PERMISSION_DENIED",
                           message="شما اجازه عملکرد بر این آیتم را ندارید.",
                           status_code=403)
        now = datetime.utcnow()
        valid = {"accepted", "rejected", "deferred"}
        if action not in valid:
            raise APIError(error_code="INVALID_ACTION",
                           message="عملیات نامعتبر.", status_code=400)
        new_state = action
        defer_until = (now + timedelta(hours=48)) if action == "deferred" else None
        await self.session.execute(text("""
            UPDATE inbox.items
               SET action_state = :st, receipt_state = 'acted',
                   acted_at = now(), defer_until = :defer, response_note = :note
             WHERE id = :iid
        """), {"st": new_state, "defer": defer_until, "note": note,
               "iid": str(item_id)})
        await self.session.execute(text("""
            INSERT INTO inbox.receipts (item_id, user_id, state, acted_at, note)
            VALUES (:iid, :uid, 'acted', now(), :note)
            ON CONFLICT DO NOTHING
        """), {"iid": str(item_id), "uid": str(actor_id), "note": note})
        await self.session.commit()
        return SimpleNamespace(action_state=new_state, receipt_state="acted",
                               acted_at=now, note=note)

    async def mark_read(self, item_id: UUID, reader_id: UUID) -> SimpleNamespace:
        """Mark inbox item as read."""
        item = (await self.session.execute(text("""
            SELECT recipient_id FROM inbox.items WHERE id = :iid
        """), {"iid": str(item_id)})).mappings().first()
        if not item:
            raise APIError(error_code="ITEM_NOT_FOUND",
                           message="آیتم یافت نشد.", status_code=404)
        if str(item["recipient_id"]) != str(reader_id):
            raise APIError(error_code="PERMISSION_DENIED",
                           message="شما اجازه خواندن این آیتم را ندارید.",
                           status_code=403)
        await self.session.execute(text("""
            UPDATE inbox.items SET receipt_state = 'seen', seen_at = now()
             WHERE id = :iid
        """), {"iid": str(item_id)})
        await self.session.execute(text("""
            INSERT INTO inbox.receipts (item_id, user_id, state, seen_at)
            VALUES (:iid, :uid, 'seen', now())
            ON CONFLICT DO NOTHING
        """), {"iid": str(item_id), "uid": str(reader_id)})
        await self.session.commit()
        return SimpleNamespace(receipt_state="seen")

    async def create_outbox(self, sender_id: UUID, recipient_id: UUID,
                            item_type: str, entity_type: Optional[str],
                            entity_id: Optional[UUID], title: str,
                            message: Optional[str]) -> SimpleNamespace:
        """Create outbox item (sent item)."""
        row = (await self.session.execute(text("""
            INSERT INTO inbox.outbox (sender_id, recipient_id, item_type,
                                      entity_type, entity_id, title, message, read_receipt)
            VALUES (:sid, :rid, :itype, :etype, :eid, :title, :msg, FALSE)
            RETURNING id
        """), {
            "sid": str(sender_id), "rid": str(recipient_id),
            "itype": item_type, "etype": entity_type,
            "eid": str(entity_id) if entity_id else None,
            "title": title, "msg": message,
        })).mappings().first()
        await self.session.commit()
        return SimpleNamespace(id=row["id"])

    async def check_expiries(self) -> dict:
        """Check and process expired items."""
        result = await self.session.execute(text("""
            UPDATE inbox.items SET action_state = 'expired', receipt_state = 'acted',
                                   acted_at = now()
             WHERE action_state = 'pending' AND expires_at IS NOT NULL AND expires_at < now()
            RETURNING id
        """))
        expired = result.rowcount or 0
        await self.session.commit()
        return {"expired_count": expired, "processed": True}


# Name used by the API layer (routes import ``InboxService``).
InboxService = InboxStateMachine
```

================================================================================
## FILE: backend/app/modules/reporting/__init__.py
================================================================================

```python
"""Reporting module public interface."""
from app.modules.reporting.api.routes import router
from app.modules.reporting.api.dashboard import dashboard_router

router.include_router(dashboard_router)

__all__ = ["router"]
```

================================================================================
## FILE: backend/app/modules/sharing/__init__.py
================================================================================

```python
"""Sharing module public interface."""
from app.modules.sharing.api.routes import router

__all__ = ["router"]
```

================================================================================
## FILE: backend/app/modules/sharing/db/models.py
================================================================================

```python
import uuid
from uuid import UUID
from datetime import datetime
from sqlalchemy import func

from sqlalchemy import (
    Column, String, Integer, Boolean, DateTime,
    ForeignKey, Table, UniqueConstraint, Index
)
from sqlalchemy.orm import relationship

from app.core.db.base import AuditMixin, BaseModel


# --- Shares Table ---

class Shares(BaseModel, AuditMixin):
    """Share entity for ACL and permission sharing."""
    
    __tablename__ = "shares"
    __table_args__ = (
        UniqueConstraint("share_code", name="uq_share_code"),
        Index("ix_shares_entity", "entity_type", "entity_id"),
        Index("ix_shares_recipient", "recipient_id"),
    )
    
    # Primary key inherited
    share_code = Column(
        String(32),
        unique=True,
        nullable=False,
        index=True
    )
    # Unique code for recipient access (time-limited)
    
    entity_type = Column(String(32), nullable=False)
    # 'goal' | 'task' | 'group' | 'document'
    
    entity_id = Column(String(36), nullable=False, index=True)
    # ID of the shared entity
    
    recipient_id = Column(String(36), nullable=False, index=True)
    # ID of the user who received the share
    
    granted_by = Column(String(36), nullable=True)
    # ID of who granted the share
    
    permission_level = Column(
        String(16),
        nullable=False,
        default="read",
        comment="read | write | manage"
    )
    
    allow_comment = Column(Boolean, nullable=False, default=False)
    
    expires_at = Column(DateTime(timezone=True), nullable=True)
    # Expiration time for the share
    
    granted_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    # granter = relationship("Users", foreign_keys=[granted_by])


# --- ACL View ---

class ACLView(BaseModel, AuditMixin):
    """ACL view for an entity."""
    
    __tablename__ = "acl_views"
    __table_args__ = (
        UniqueConstraint("entity_id", "viewer_id", name="uq_acl_view"),
    )
    
    # Primary key components
    entity_id = Column(
        String(36),
        nullable=False,
        index=True
    )
    viewer_id = Column(
        String(36),
        nullable=False,
        index=True
    )
    
    effective_permission = Column(
        String(16),
        nullable=False,
        default="read",
        comment="read | write | manage"
    )
    
    is_denied = Column(Boolean, nullable=False, default=False)
    granted_at = Column(DateTime(timezone=True), server_default=func.now())
    expires_at = Column(DateTime(timezone=True), nullable=True)
    
    # Relationships
    # entity = relationship("Shares", foreign_keys=[entity_id])


# --- Export all ---
__all__ = ["Shares", "ACLView"]
```

================================================================================
## FILE: backend/app/modules/sharing/services/sharing_service.py
================================================================================

```python
"""Sharing service — raw SQL against the real DDL (schema ``sharing``).

Architecture Reference: Sections 4.6, 8.2, 11.1.
Note: the DDL has no ``share_code`` column; the share ``id`` is used as
the public code (routes keep the ``share_code`` interface).
"""
from typing import Optional, List
from types import SimpleNamespace
from uuid import UUID
from datetime import datetime

from sqlalchemy import text

from app.core.errors import APIError, NotFoundError

VALID_LEVELS = {"read", "write", "manage"}


def _iso(v):
    return v.isoformat() if isinstance(v, datetime) else v


class SharingService:
    """Service layer for Sharing module operations (real DDL)."""

    def __init__(self, session):
        self.session = session

    async def create_share(self, entity_type: str, entity_id: UUID,
                           recipient_id: UUID, permission_level: str,
                           allow_comment: bool, granted_by: UUID) -> SimpleNamespace:
        """Create a new share."""
        if permission_level not in VALID_LEVELS:
            raise APIError(error_code="INVALID_PERMISSION_LEVEL",
                           message="سطح دسترسی نامعتبر.", status_code=400)
        # sharing.shares has no unique constraint on the triple; upsert manually.
        existing = (await self.session.execute(text("""
            SELECT id FROM sharing.shares
             WHERE entity_type = :etype AND entity_id = :eid
               AND recipient_id = :rid AND revoked_at IS NULL
        """), {"etype": entity_type, "eid": str(entity_id),
               "rid": str(recipient_id)})).mappings().first()
        if existing:
            id_ = existing["id"]
            await self.session.execute(text("""
                UPDATE sharing.shares
                   SET permission_level = :lvl, allow_comment = :can,
                       granted_by = :by, granted_at = now(),
                       revoked_at = NULL, revoked_reason = NULL
                 WHERE id = :id
            """), {"id": str(id_), "lvl": permission_level,
                   "can": bool(allow_comment), "by": str(granted_by)})
        else:
            row = (await self.session.execute(text("""
                INSERT INTO sharing.shares (entity_type, entity_id, recipient_id,
                                            granted_by, permission_level, allow_comment)
                VALUES (:etype, :eid, :rid, :by, :lvl, :can)
                RETURNING id
            """), {
                "etype": entity_type, "eid": str(entity_id),
                "rid": str(recipient_id), "by": str(granted_by),
                "lvl": permission_level, "can": bool(allow_comment),
            })).mappings().first()
            id_ = row["id"]
        await self.session.commit()
        return SimpleNamespace(share_code=str(id_))

    async def get_entity_shares(self, entity_type: str, entity_id: UUID,
                                viewer_id: UUID) -> List[dict]:
        """Get all shares for an entity."""
        rows = (await self.session.execute(text("""
            SELECT id, entity_type, entity_id, recipient_id, permission_level,
                   allow_comment, granted_at, expires_at
              FROM sharing.shares
             WHERE entity_type = :etype AND entity_id = :eid
               AND revoked_at IS NULL
             ORDER BY granted_at DESC
        """), {"etype": entity_type, "eid": str(entity_id)})).mappings().all()
        return [{
            "id": str(r["id"]),
            "share_code": str(r["id"]),
            "entity_type": entity_type,
            "entity_id": str(entity_id),
            "recipient_id": str(r["recipient_id"]),
            "recipient": {"id": str(r["recipient_id"])},
            "permission_level": r["permission_level"],
            "granted_at": _iso(r["granted_at"]),
            "expires_at": _iso(r["expires_at"]) if r["expires_at"] else None,
            "allow_comment": r["allow_comment"],
        } for r in rows]

    async def check_permission(self, entity_type: str, entity_id: UUID,
                               user_id: UUID, required_level: str,
                               viewer_id: UUID) -> SimpleNamespace:
        """Check if a user has required permission on an entity."""
        if required_level not in VALID_LEVELS:
            raise APIError(error_code="INVALID_PERMISSION_LEVEL",
                           message="سطح دسترسی نامعتبر.", status_code=400)
        row = (await self.session.execute(text("""
            SELECT permission_level FROM sharing.effective_permissions
             WHERE entity_type = :etype AND entity_id = :eid
               AND recipient_id = :uid
        """), {"etype": entity_type, "eid": str(entity_id),
               "uid": str(user_id)})).mappings().first()
        if row:
            return SimpleNamespace(user_id=user_id, has_permission=True,
                                   permission_level=row["permission_level"],
                                   source="direct")
        return SimpleNamespace(user_id=user_id, has_permission=False,
                               permission_level=required_level, source="denied")

    async def revoke_share(self, share_code: str, revoked_by: UUID) -> dict:
        """Revoke a share by its id (used as the share code)."""
        row = (await self.session.execute(text("""
            UPDATE sharing.shares
               SET revoked_at = now(), revoked_reason = 'revoked'
             WHERE id = :sid AND revoked_at IS NULL
            RETURNING id
        """), {"sid": share_code})).mappings().first()
        if not row:
            raise APIError(error_code="SHARE_NOT_FOUND",
                           message="اشتراک یافت نشد.", status_code=404)
        await self.session.commit()
        return {"status": "revoked", "share_code": share_code}
```

================================================================================
## FILE: backend/app/modules/ssoldap/__init__.py
================================================================================

```python
"""SSO/LDAP module public interface (stub — full implementation per Architecture v2.0 Section M12)."""
from app.modules.ssoldap.api.routes import router


def register_event_handlers(event_bus) -> None:
    """Subscribe to cross-module events (no-op stub)."""


__all__ = ["router", "register_event_handlers"]
```

================================================================================
## FILE: backend/app/modules/ssoldap/services/ldap_service.py
================================================================================

```python
"""
app/modules/ssoldap/services/ldap_service.py

این ماژول (M12) قبلاً فقط یک ``api/`` خالی بود — نه db، نه services.
طبق سند:
  - بخش ۲.۵: SSO/LDAP جزو فاز ۱ (پیش‌نیاز همه‌چیز) است.
  - بخش ۱۴ (جدول ریسک): «SSO با Kerberos در محیط واقعی AD کار نکند» →
    ریسک بالا → **«Fallback به LDAP Bind از روز اول»**.

پس اول ``LDAP Bind`` (نام‌کاربری+رمز مستقیم به AD) ساخته می‌شود —
چون بدون Keytab/KDC واقعی هم قابل‌ساخت و تا حدی قابل‌تست است. Kerberos/
SPNEGO کامل (``gssapi``) نیاز به محیط AD واقعی برای تست دارد و باید
جدا (به‌عنوان Spike دوروزه، طبق توصیه‌ی خودِ سند) پیگیری شود —
``app/modules/ssoldap/api/negotiate.py`` در همین پچ فقط یک اسکلت
401 برمی‌گرداند، نه پیاده‌سازی کامل SPNEGO.

⚠️ وابستگی‌ها: `pip list` شما نشان داد ``ldap3`` نصب نیست. برای همین
import آن اینجا **تنبل (lazy)** است — تا وقتی کسی واقعاً وارد کردن
LDAP نزند، بقیه‌ی اپ (که به این ماژول نیازی ندارد) از کار نمی‌افتد.
نصب لازم:

    pip install ldap3

⚠️ تنظیمات لازم (باید به ``app/core/config.py`` اضافه شوند — چون به
محتوای فایل شما دسترسی ندارم، فقط اسم‌هایی که این فایل انتظار دارد
را مستند می‌کنم):

    LDAP_SERVER_URI        # مثل "ldaps://ad.corp.local:636"
    LDAP_BASE_DN           # مثل "DC=corp,DC=local"
    LDAP_BIND_DN           # اکانت سرویس فقط-خواندنی برای search
    LDAP_BIND_PASSWORD     # طبق سند باید AES-256-GCM رمزنگاری‌شده در Vault/DB
                            # باشد؛ اگر از env var/Secret Manager می‌آید همین کافی است
    LDAP_USER_SEARCH_FILTER = "(sAMAccountName={username})"
    LDAP_ATTR_OBJECT_GUID = "objectGUID"
    LDAP_ATTR_NATIONAL_ID  # نام Attribute سفارشی AD شما برای کد ملی — باید با تیم AD هماهنگ شود
    LDAP_ATTR_DISPLAY_NAME = "displayName"
    LDAP_ATTR_MEMBEROF = "memberOf"
    LDAP_GROUP_ROLE_MAP: dict[str, str]  # DN گروه AD → کد نقش داخلی، مثل:
        # {"CN=Managers,OU=Groups,DC=corp,DC=local": "manager"}
    LDAP_AUTO_PROVISION: bool = True
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


class LdapAuthError(Exception):
    """احراز هویت LDAP شکست خورد (رمز غلط، کاربر یافت نشد، سرور در دسترس نیست)."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(f"{code}: {message}")


@dataclass(frozen=True)
class LdapUserInfo:
    """نتیجه‌ی موفق احراز هویت + جست‌وجوی LDAP — چیزی که SsoLoginService مصرف می‌کند."""

    dn: str
    object_guid: str
    sam_account_name: str
    display_name: str
    national_id: str | None
    member_of: list[str] = field(default_factory=list)


def escape_ldap_filter_value(value: str) -> str:
    """طبق سند (بخش امنیت، ردیف A03 Injection): ``escape_filter_chars`` برای LDAP.

    این تابع pure و بدون وابستگی به ldap3 است تا بدون نصب ldap3 هم قابل‌تست
    باشد (ldap3.utils.conv.escape_filter_chars هم دقیقاً همین RFC 4515 را
    پیاده می‌کند — اگر ldap3 نصب بود می‌توانید مستقیم از آن استفاده کنید).
    """
    replacements = {
        "\\": r"\5c",
        "*": r"\2a",
        "(": r"\28",
        ")": r"\29",
        "\x00": r"\00",
    }
    return "".join(replacements.get(ch, ch) for ch in value)


def map_groups_to_roles(member_of: list[str], group_role_map: dict[str, str]) -> list[str]:
    """نگاشت DN گروه‌های AD به کدهای نقش داخلی — طبق سند بخش ۱.۳: «نگاشت memberOf → roles».

    مقایسه‌ی DN بدون حساسیت به بزرگی/کوچکی حروف و فاصله‌های اضافه انجام
    می‌شود، چون AD معمولاً DN را با فرمت‌بندی متفاوت (فاصله بعد از کاما)
    برمی‌گرداند.
    """
    normalized_map = {_normalize_dn(dn): role for dn, role in group_role_map.items()}
    roles = []
    for dn in member_of:
        role = normalized_map.get(_normalize_dn(dn))
        if role and role not in roles:
            roles.append(role)
    return roles


def _normalize_dn(dn: str) -> str:
    return re.sub(r",\s*", ",", dn.strip().lower())


class LdapService:
    """Bind مستقیم کاربر به AD (نه Kerberos) — endpoint: ``POST /auth/sso/ldap-login``."""

    def __init__(self, settings: Any) -> None:
        self.settings = settings

    async def authenticate(self, username: str, password: str) -> LdapUserInfo:
        """کاربر را مستقیماً به AD bind می‌کند و اطلاعاتش را برمی‌گرداند.

        دو مرحله (طبق الگوی رایج AD bind، چون sAMAccountName به‌تنهایی DN
        نیست): (۱) با اکانت سرویس bind و DN کاربر را search می‌کند،
        (۲) با DN واقعی و رمز کاربر دوباره bind می‌کند تا رمز واقعاً
        تأیید شود.
        """
        try:
            import ldap3
            from ldap3 import ALL, Connection, Server
            from ldap3.core.exceptions import LDAPBindError, LDAPException
        except ImportError as exc:  # pragma: no cover
            raise LdapAuthError(
                "LDAP_NOT_CONFIGURED",
                "پکیج ldap3 نصب نیست — `pip install ldap3` را اجرا کنید.",
            ) from exc

        if not username or not password:
            raise LdapAuthError("INVALID_CREDENTIALS", "نام کاربری/رمز خالی است.")

        safe_username = escape_ldap_filter_value(username)
        search_filter = self.settings.LDAP_USER_SEARCH_FILTER.format(username=safe_username)

        server = Server(self.settings.LDAP_SERVER_URI, get_info=ALL, use_ssl=True)

        # مرحله ۱: bind با اکانت سرویس (فقط خواندنی) + search برای پیدا کردن DN کاربر
        try:
            service_conn = Connection(
                server, user=self.settings.LDAP_BIND_DN,
                password=self.settings.LDAP_BIND_PASSWORD, auto_bind=True,
            )
        except LDAPException as exc:
            raise LdapAuthError("LDAP_UNAVAILABLE", "اتصال به AD ممکن نشد.") from exc

        attrs = [
            self.settings.LDAP_ATTR_OBJECT_GUID,
            self.settings.LDAP_ATTR_DISPLAY_NAME,
            self.settings.LDAP_ATTR_MEMBEROF,
        ]
        national_id_attr = getattr(self.settings, "LDAP_ATTR_NATIONAL_ID", None)
        if national_id_attr:
            attrs.append(national_id_attr)

        service_conn.search(
            search_base=self.settings.LDAP_BASE_DN,
            search_filter=search_filter,
            attributes=attrs,
        )
        if not service_conn.entries:
            service_conn.unbind()
            raise LdapAuthError("USER_NOT_FOUND", "کاربر در AD یافت نشد.")

        entry = service_conn.entries[0]
        user_dn = entry.entry_dn
        service_conn.unbind()

        # مرحله ۲: bind واقعی با DN کاربر + رمزی که کاربر فرستاده — این
        # مرحله است که واقعاً رمز را تأیید می‌کند.
        try:
            user_conn = Connection(server, user=user_dn, password=password, auto_bind=True)
            user_conn.unbind()
        except LDAPBindError as exc:
            raise LdapAuthError("INVALID_CREDENTIALS", "نام کاربری یا رمز عبور اشتباه است.") from exc

        member_of = list(entry[self.settings.LDAP_ATTR_MEMBEROF].values) \
            if self.settings.LDAP_ATTR_MEMBEROF in entry else []
        national_id = None
        if national_id_attr and national_id_attr in entry:
            values = entry[national_id_attr].values
            national_id = values[0] if values else None

        return LdapUserInfo(
            dn=user_dn,
            object_guid=str(entry[self.settings.LDAP_ATTR_OBJECT_GUID].value),
            sam_account_name=username,
            display_name=str(entry[self.settings.LDAP_ATTR_DISPLAY_NAME].value),
            national_id=national_id,
            member_of=member_of,
        )
```

================================================================================
## MISSING FILES (not found in source repo)
================================================================================

- [MISSING] `﻿backend/app/modules/groups/api/router.py`
- [MISSING] `backend/app/modules/groups/db/repository.py`
- [MISSING] `backend/app/modules/groups/services/__init__.py`
- [MISSING] `backend/app/modules/groups/services/group_service.py`
- [MISSING] `backend/app/modules/groups/schemas.py`
- [MISSING] `backend/app/modules/groups/events.py`
- [MISSING] `backend/app/modules/goals/api/router.py`
- [MISSING] `backend/app/modules/goals/db/repository.py`
- [MISSING] `backend/app/modules/goals/services/__init__.py`
- [MISSING] `backend/app/modules/goals/services/goal_service.py`
- [MISSING] `backend/app/modules/goals/services/dependency_service.py`
- [MISSING] `backend/app/modules/goals/schemas.py`
- [MISSING] `backend/app/modules/goals/events.py`
- [MISSING] `backend/app/modules/calendar/api/router.py`
- [MISSING] `backend/app/modules/calendar/db/models.py`
- [MISSING] `backend/app/modules/calendar/services/__init__.py`
- [MISSING] `backend/app/modules/calendar/schemas.py`
- [MISSING] `backend/app/modules/calendar/events.py`
- [MISSING] `backend/app/modules/sharing/api/router.py`
- [MISSING] `backend/app/modules/sharing/services/__init__.py`
- [MISSING] `backend/app/modules/sharing/schemas.py`
- [MISSING] `backend/app/modules/sharing/events.py`
- [MISSING] `backend/app/modules/inbox/api/router.py`
- [MISSING] `backend/app/modules/inbox/services/__init__.py`
- [MISSING] `backend/app/modules/inbox/schemas.py`
- [MISSING] `backend/app/modules/inbox/events.py`
- [MISSING] `backend/app/modules/reporting/api/router.py`
- [MISSING] `backend/app/modules/reporting/services/__init__.py`
- [MISSING] `backend/app/modules/reporting/services/report_service.py`
- [MISSING] `backend/app/modules/reporting/services/export_service.py`
- [MISSING] `backend/app/modules/reporting/schemas.py`
- [MISSING] `backend/app/modules/ssoldap/api/router.py`
- [MISSING] `backend/app/modules/ssoldap/services/__init__.py`
- [MISSING] `backend/app/modules/ssoldap/services/kerberos_service.py`
- [MISSING] `backend/app/modules/ssoldap/services/sync_service.py`
- [MISSING] `backend/app/modules/ssoldap/schemas.py`

