# PART 7/12 of GAP PACK

## FILE: bastehC_domain/backend/app/modules/inbox/api/routes.py
## SIZE: 5345 bytes
==========================================================================================

```python
from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, Body, Path, Query
from fastapi.responses import JSONResponse

from app.core.dependencies import get_db_session, get_current_user
from app.core.errors import APIError, NotFoundError
from app.modules.inbox.ports import (
    InboxItemCreate, InboxItemUpdate, InboxItemResponse,
    OutboxItemCreate, ReceiptState, InboxExport
)
from app.modules.inbox.services.inbox_service import InboxService
from app.modules.inbox.db.Models import InboxItems, Receipts, OutboxItems
from app.core.database import async_session_context


router = APIRouter(prefix="/inbox", tags=["Inbox"])


@router.get("/outbox", response_model=dict)
async def list_outbox(
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """List outbox items for a user.

    NOTE: defined BEFORE /{user_id} so "outbox" is not parsed as a UUID.
    """
    async with db_session() as session:
        try:
            service = InboxService(session)
            items = await service.list_outbox(user_id)
            return {
                "status": "success",
                "data": {"items": items}
            }
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.post("/", response_model=dict)
async def create_inbox_item(
    request: InboxItemCreate,
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Create an inbox item."""
    async with db_session() as session:
        try:
            service = InboxService(session)
            result = await service.create_item(
                sender_id=user_id,
                recipient_id=request.recipient_id,
                item_type=request.item_type,
                entity_type=request.entity_type,
                entity_id=str(request.entity_id) if request.entity_id else None,
                title=request.title,
                message=request.message,
                priority=request.priority,
                due_at=request.due_at,
                expires_at=request.expires_at
            )
            return {
                "status": "item_created",
                "item_id": str(result.id),
                "action_state": result.action_state,
                "receipt_state": result.receipt_state
            }
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.get("/{user_id}", response_model=dict)
async def list_inbox(
    user_id: UUID = Path(...),
    state: Optional[str] = Query(None),
    db_session=Depends(get_db_session)
):
    """List inbox items for a user."""
    async with db_session() as session:
        try:
            service = InboxService(session)
            items = await service.list_items(user_id, state)
            return {
                "status": "success",
                "data": {"items": items}
            }
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.post("/{item_id}/act", response_model=dict)
async def act_on_item(
    item_id: UUID = Path(...),
    action: str = Body(...),
    note: Optional[str] = Body(None),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Act on an inbox item (accept, reject, defer)."""
    async with db_session() as session:
        try:
            service = InboxService(session)
            result = await service.act_on_item(item_id, action, note, user_id)
            return {
                "status": "item_acted",
                "item_id": str(item_id),
                "action_state": result.action_state,
                "receipt_state": result.receipt_state,
                "acted_at": result.acted_at.isoformat() if result.acted_at else None,
                "note": result.note
            }
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.post("/{item_id}/read", response_model=dict)
async def mark_read(
    item_id: UUID = Path(...),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Mark inbox item as read."""
    async with db_session() as session:
        try:
            service = InboxService(session)
            result = await service.mark_read(item_id, user_id)
            return {
                "status": "item_marked_read",
                "receipt_state": result.receipt_state
            }
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )
```

==========================================================================================
## FILE: bastehC_domain/backend/app/modules/inbox/db/Models.py
## SIZE: 5136 bytes
==========================================================================================

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

==========================================================================================
## FILE: bastehC_domain/backend/app/modules/inbox/ports.py
## SIZE: 3296 bytes
==========================================================================================

```python
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
```

==========================================================================================
## FILE: bastehC_domain/backend/app/modules/inbox/services/deferred_check.py
## SIZE: 3134 bytes
==========================================================================================

```python
"""
Inbox Deferred State Timeout Check
Architecture Reference: Section 9.1 - State Machine
Handles transition of deferred items back to pending when defer_until <= now.
"""

import asyncio
from typing import Dict
from datetime import datetime
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.modules.inbox.db.Models import InboxItems


async def check_deferred_timeout() -> dict:
    """Check and process deferred items that should return to pending state.
    
    Architecture 9.1: deferred -> pending when defer_until <= now
    
    Returns:
        dict with processing results
    """
    from app.core.database import engine
    
    now = datetime.utcnow()
    
    async with engine.begin() as conn:
        # Find deferred items where defer_until <= now
        result = await conn.execute(
            select(InboxItems).where(
                InboxItems.action_state == "deferred",
                InboxItems.defer_until <= now
            )
        )
        
        deferred_items = result.scalars().all()
        
        processed = 0
        for item in deferred_items:
            # Transition: deferred -> pending
            item.action_state = "pending"
            # Clear defer_until since it's now active again
            item.defer_until = None
            # Reset receipt state to sent (will be updated when recipient acts)
            # Note: receipt state should remain as acted or reset based on business logic
            
            processed += 1
        
        if processed > 0:
            await conn.commit()
        
        return {
            "transitioned_count": processed,
            "from_state": "deferred",
            "to_state": "pending",
            "processed_at": now.isoformat(),
            "success": True
        }


async def check_all_expiries() -> dict:
    """Check all inbox item expiries (combined check for expires and deferred timeouts)."""
    from app.core.database import engine
    
    now = datetime.utcnow()
    results = {}
    
    async with engine.begin() as conn:
        # Check expired items
        result = await conn.execute(
            select(InboxItems).where(
                InboxItems.expires_at < now,
                InboxItems.action_state == "pending"
            )
        )
        expired = result.scalars().all()
        
        for item in expired:
            item.action_state = "expired"
        
        # Check deferred timeouts
        result = await conn.execute(
            select(InboxItems).where(
                InboxItems.action_state == "deferred",
                InboxItems.defer_until <= now
            )
        )
        deferred = result.scalars().all()
        
        for item in deferred:
            item.action_state = "pending"
            item.defer_until = None
    
    await conn.commit()
    
    return {
        "expired_count": len(expired),
        "deferred_transitioned": len(deferred),
        "processed_at": now.isoformat(),
        "success": True
    }
```

==========================================================================================
## FILE: bastehC_domain/backend/app/modules/inbox/services/inbox_service.py
## SIZE: 9297 bytes
==========================================================================================

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

==========================================================================================
## FILE: bastehC_domain/backend/app/modules/reporting/api/dashboard.py
## SIZE: 9604 bytes
==========================================================================================

```python
"""Dashboard read/composite endpoints (raw SQL, schema-qualified).

Rationale: ORM models in app/modules/*/db/Models.py drifted from the
alembic DDL (missing schema + columns), so every module service currently
500s on real queries. Rather than rewriting six model files, the dashboard
reads the architecture-compliant tables directly with qualified names.
Each widget query is independent -- one failing table never breaks the
whole summary.
"""

from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, Body
from fastapi.responses import JSONResponse
from sqlalchemy import text

from app.core.dependencies import get_db_session, get_current_user
from app.core.errors import APIError


dashboard_router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


def _rows(result):
    return [dict(r._mapping) for r in result]


def _iso(row: dict) -> dict:
    for k, v in list(row.items()):
        if hasattr(v, "isoformat"):
            row[k] = v.isoformat()
        elif not isinstance(v, (str, int, float, bool, type(None))):
            row[k] = str(v)
    return row


async def _fetch(session, sql: str, params: dict):
    try:
        result = await session.execute(text(sql), params)
        return [_iso(r) for r in _rows(result)]
    except Exception:
        return None  # widget-level degradation, never 500 the dashboard


@dashboard_router.get("/summary", response_model=dict)
async def dashboard_summary(
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session),
):
    """One call powering the whole dashboard page."""
    async with db_session() as session:
        p = {"uid": str(user_id)}

        goals = await _fetch(session, """
            SELECT id::text AS id, title, description, status,
                   progress_pct, due_date, created_at
              FROM planning.goals
             WHERE owner_id = :uid AND deleted_at IS NULL
             ORDER BY created_at DESC LIMIT 10
        """, p) or []

        goal_counts = await _fetch(session, """
            SELECT status, COUNT(*)::int AS n
              FROM planning.goals
             WHERE owner_id = :uid AND deleted_at IS NULL
             GROUP BY status
        """, p) or []

        tasks = await _fetch(session, """
            SELECT t.id::text AS id, t.title, t.status, t.priority,
                   t.due_date, g.title AS goal_title
              FROM planning.tasks t
              LEFT JOIN planning.goals g ON g.id = t.goal_id
             WHERE (t.owner_id = :uid OR t.assignee_id = :uid)
               AND t.deleted_at IS NULL AND t.status IN ('pending','in_progress')
             ORDER BY t.created_at DESC LIMIT 10
        """, p) or []

        inbox = await _fetch(session, """
            SELECT i.id::text AS id, i.title, i.message, i.item_type,
                   i.priority, i.action_state, i.created_at,
                   u.display_name AS sender_name
              FROM inbox.items i
              LEFT JOIN auth.users u ON u.id = i.sender_id
             WHERE i.recipient_id = :uid AND i.action_state = 'pending'
             ORDER BY i.created_at DESC LIMIT 10
        """, p) or []

        inbox_pending = await _fetch(session, """
            SELECT COUNT(*)::int AS n FROM inbox.items
             WHERE recipient_id = :uid AND action_state = 'pending'
        """, p)
        pending_n = (inbox_pending or [{"n": 0}])[0]["n"]

        groups = await _fetch(session, """
            SELECT g.id::text AS id, g.name, gm.is_manager
              FROM groups.groups g
              JOIN groups.group_members gm ON gm.group_id = g.id
             WHERE gm.user_id = :uid AND g.deleted_at IS NULL AND g.is_active
             ORDER BY g.name LIMIT 20
        """, p) or []

        rooms = await _fetch(session, """
            SELECT r.id::text AS id, r.title, r.linked_type
              FROM chat.rooms r
              JOIN chat.room_members m ON m.room_id = r.id
             WHERE m.user_id = :uid AND m.left_at IS NULL
               AND r.deleted_at IS NULL AND NOT r.is_archived
             ORDER BY r.created_at DESC LIMIT 10
        """, p)
        if rooms is None:  # older DDL without left_at? degrade gracefully
            rooms = []

        stats = {
            "goals_active": sum(r["n"] for r in goal_counts if r["status"] == "active"),
            "goals_completed": sum(r["n"] for r in goal_counts if r["status"] == "completed"),
            "goals_total": sum(r["n"] for r in goal_counts),
            "tasks_open": len(tasks),
            "inbox_pending": pending_n,
            "groups_count": len(groups),
            "rooms_count": len(rooms),
        }

        return {
            "status": "success",
            "data": {
                "stats": stats,
                "recent_goals": goals,
                "open_tasks": tasks,
                "pending_inbox": inbox,
                "my_groups": groups,
                "my_rooms": rooms,
            },
        }


@dashboard_router.get("/goals", response_model=dict)
async def dashboard_goals(
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session),
):
    async with db_session() as session:
        goals = await _fetch(session, """
            SELECT id::text AS id, title, description, status,
                   progress_pct, due_date, created_at
              FROM planning.goals
             WHERE owner_id = :uid AND deleted_at IS NULL
             ORDER BY created_at DESC LIMIT 50
        """, {"uid": str(user_id)}) or []
        return {"status": "success", "data": goals}


@dashboard_router.post("/goals", response_model=dict, status_code=201)
async def dashboard_create_goal(
    payload: dict = Body(...),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session),
):
    title = (payload.get("title") or "").strip()
    if not title:
        return JSONResponse(status_code=400, content={
            "error": "TITLE_REQUIRED",
            "message": "عنوان هدف الزامی است.",
            "success": False,
        })
    async with db_session() as session:
        try:
            result = await session.execute(text("""
                INSERT INTO planning.goals
                    (owner_id, title, description, due_date, status, progress_pct)
                VALUES (:uid, :title, :desc, :due, 'active', 0)
                RETURNING id::text AS id
            """), {
                "uid": str(user_id),
                "title": title[:255],
                "desc": (payload.get("description") or None),
                "due": payload.get("due_date") or None,
            })
            new_id = result.scalar_one()
            await session.commit()
            return {"status": "success", "data": {"id": new_id}}
        except APIError as e:
            return JSONResponse(status_code=e.status_code, content={
                "error": e.error_code, "message": e.message, "success": False})
        except Exception:
            await session.rollback()
            return JSONResponse(status_code=500, content={
                "error": "CREATE_FAILED",
                "message": "ایجاد هدف ناموفق بود.",
                "success": False,
            })


@dashboard_router.post("/inbox/{item_id}/act", response_model=dict)
async def dashboard_inbox_act(
    item_id: UUID,
    payload: dict = Body(...),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session),
):
    action = (payload.get("action") or "").strip().lower()
    if action not in ("accepted", "rejected", "deferred"):
        return JSONResponse(status_code=400, content={
            "error": "INVALID_ACTION",
            "message": "عمل باید accepted/rejected/deferred باشد.",
            "success": False,
        })
    async with db_session() as session:
        try:
            result = await session.execute(text("""
                UPDATE inbox.items
                   SET action_state = CAST(:action AS inbox.item_action),
                       receipt_state = 'acted',
                       acted_at = now(),
                       response_note = :note,
                       defer_until = CASE WHEN :action = 'deferred'
                                          THEN COALESCE(:defer, now() + interval '3 days')
                                          ELSE defer_until END,
                       seen_at = COALESCE(seen_at, now())
                 WHERE id = :iid AND recipient_id = :uid
                   AND action_state = 'pending'
                RETURNING id::text AS id
            """), {
                "action": action,
                "note": payload.get("note"),
                "defer": payload.get("defer_until"),
                "iid": str(item_id),
                "uid": str(user_id),
            })
            row = result.mappings().first()
            if row is None:
                return JSONResponse(status_code=404, content={
                    "error": "NOT_FOUND",
                    "message": "آیتم یافت نشد یا قبلاً تعیین تکلیف شده.",
                    "success": False,
                })
            await session.commit()
            return {"status": "success",
                    "data": {"id": row["id"], "action_state": action}}
        except Exception:
            await session.rollback()
            return JSONResponse(status_code=500, content={
                "error": "ACT_FAILED",
                "message": "ثبت تصمیم ناموفق بود.",
                "success": False,
            })
```

==========================================================================================
## FILE: bastehC_domain/backend/app/modules/reporting/api/routes.py
## SIZE: 5737 bytes
==========================================================================================

```python
"""
Reporting Module API Routes
Architecture Reference: Sections 10.1, 10.2, 10.3
Endpoints: /api/v1/reporting
"""

from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, Body, Path
from fastapi.responses import JSONResponse

from app.core.dependencies import (
    get_db_session, get_current_user, get_reporting_service
)
from app.core.errors import APIError, NotFoundError
from app.core.database import async_session_context
from app.modules.reporting.ports import (
    LayoutBlock, DashboardLayout, UserDashboardSettings,
    UserWidgetSettings, DashboardData, ReportExport, ReportImport
)
from app.modules.reporting.services.reporting_service import ReportingService
from app.modules.reporting.db.Models import DashboardLayouts, UserDashboardSettings, UserWidgetSettings, ReportExports


router = APIRouter(prefix="/reporting", tags=["Reporting"])


@router.post("/layouts", response_model=dict)
async def save_layout(
    layout_data: dict,
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Save dashboard layout."""
    async with db_session() as session:
        try:
            service = ReportingService(session)
            layout_id = await service.save_layout(user_id, layout_data)
            return {"status": "layout_saved", "layout_id": str(layout_id)}
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.get("/layouts/{layout_id}", response_model=dict)
async def get_layout(
    layout_id: UUID = Path(...),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Get a dashboard layout."""
    async with db_session() as session:
        try:
            service = ReportingService(session)
            layout = await service.get_layout(layout_id, user_id)
            return {"status": "success", "data": layout}
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.get("/layouts", response_model=dict)
async def list_layouts(
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """List user's dashboard layouts."""
    async with db_session() as session:
        try:
            service = ReportingService(session)
            layouts = await service.list_layouts(user_id)
            return {"status": "success", "data": {"layouts": layouts}}
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.post("/layouts/import", response_model=dict)
async def import_layout(
    import_data: dict,
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Import dashboard layout from JSON."""
    async with db_session() as session:
        try:
            service = ReportingService(session)
            result = await service.import_layout(user_id, import_data)
            return {"status": "layout_imported", "result": result}
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.post("/widgets/settings", response_model=dict)
async def save_widget_settings(
    settings_data: dict,
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Save widget settings."""
    async with db_session() as session:
        try:
            service = ReportingService(session)
            result = await service.save_widget_settings(user_id, settings_data)
            return {"status": "widgets_saved", "result": result}
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.get("/widgets/settings", response_model=dict)
async def get_widget_settings(
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Get widget settings."""
    async with db_session() as session:
        try:
            service = ReportingService(session)
            settings = await service.get_widget_settings(user_id)
            return {"status": "success", "data": {"widgets": settings}}
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.post("/widgets/settings/reset", response_model=dict)
async def reset_widget_settings(
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Reset widget settings to default."""
    async with db_session() as session:
        try:
            service = ReportingService(session)
            result = await service.reset_widget_settings(user_id)
            return {"status": "widgets_reset", "result": result}
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )
```

==========================================================================================
## FILE: bastehC_domain/backend/app/modules/reporting/db/Models.py
## SIZE: 5588 bytes
==========================================================================================

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


# --- Dashboard Layouts ---

class DashboardLayouts(BaseModel, AuditMixin):
    """Dashboard layout configurations."""
    
    __tablename__ = "dashboard_layouts"
    __table_args__ = (
        UniqueConstraint("user_id", "view_mode", "is_default", name="uq_layout_default"),
        Index("ix_layouts_user", "user_id"),
    )
    
    # Primary key inherited
    user_id = Column(
        String(36),
        ForeignKey("auth.users.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    name = Column(String(64), nullable=False)
    view_mode = Column(
        String(16),
        nullable=False,
        default="daily",
        comment="daily | weekly | monthly"
    )
    is_default = Column(Boolean, nullable=False, default=False)
    schema_version = Column(Integer, nullable=False, default=1)
    
    # Blocks stored as JSON
    blocks = Column(JSON, nullable=False, default="[]")
    
    # Timestamps inherited from AuditMixin
    
    # Relationships
    # user = relationship("Users", foreign_keys=[user_id])
    # settings = relationship("UserDashboardSettings", back_populates="layout")


# --- User Dashboard Settings ---

class UserDashboardSettings(BaseModel, AuditMixin):
    """User-specific dashboard settings."""
    
    __tablename__ = "user_dashboard_settings"
    __table_args__ = (
        UniqueConstraint("layout_id", "block_key", name="uq_layout_block"),
        Index("ix_settings_layout", "layout_id"),
    )
    
    # Primary key components
    id = Column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4())
    )
    layout_id = Column(
        String(36),
        ForeignKey("dashboard_layouts.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    block_key = Column(String(48), nullable=False)
    is_visible = Column(Boolean, nullable=False, default=True)
    position_x = Column(Integer, nullable=False)
    position_y = Column(Integer, nullable=False)
    width = Column(Integer, nullable=False)
    height = Column(Integer, nullable=False)
    is_collapsed = Column(Boolean, nullable=False, default=False)
    config = Column(JSON, nullable=False, default="{}")
    updated_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Unique constraint: one setting per block per layout
    __table_args__ += (
        UniqueConstraint("layout_id", "block_key", name="uq_layout_block"),
    )
    
    # Relationships
    # layout = relationship("DashboardLayouts", back_populates="settings")


# --- User Widget Settings ---

class UserWidgetSettings(BaseModel, AuditMixin):
    """Per-widget settings (clock, etc.)."""
    
    __tablename__ = "user_widget_settings"
    __table_args__ = (
        UniqueConstraint("user_id", "widget_key", "platform", name="uq_widget_user_platform"),
        Index("ix_widgets_user", "user_id"),
    )
    
    # Primary key components
    id = Column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4())
    )
    user_id = Column(
        String(36),
        ForeignKey("auth.users.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    widget_key = Column(String(48), nullable=False)
    platform = Column(
        String(16),
        nullable=False,
        default="all",
        comment="desktop | web | all"
    )
    is_visible = Column(Boolean, nullable=False, default=True)
    position_x = Column(Integer, nullable=False)
    position_y = Column(Integer, nullable=False)
    width = Column(Integer, nullable=False)
    height = Column(Integer, nullable=False)
    z_index = Column(Integer, nullable=False, default=10)
    style = Column(JSON, nullable=False, default="{}")  # {bg, fg, font_family, font_size, opacity}
    config = Column(JSON, nullable=False, default="{}")  # widget-specific
    updated_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Unique constraint
    __table_args__ += (
        UniqueConstraint("user_id", "widget_key", "platform", name="uq_widget_user_platform"),
    )
    
    # Relationships
    # user = relationship("Users", foreign_keys=[user_id])


# --- Export/Import ---

class ReportExports(BaseModel, AuditMixin):
    """Report export records."""
    
    __tablename__ = "report_exports"
    __table_args__ = (
        Index("ix_exports_user", "user_id"),
    )
    
    id = Column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4())
    )
    user_id = Column(
        String(36),
        ForeignKey("auth.users.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    schema_version = Column(Integer, nullable=False)
    layout_id = Column(String(36), nullable=True)
    name = Column(String(64), nullable=True)
    view_mode = Column(String(16), nullable=True)
    blocks = Column(JSON, nullable=False, default="[]")
    exported_at = Column(DateTime(timezone=True), server_default=func.now())


# --- Export all ---
__all__ = [
    "DashboardLayouts", "UserDashboardSettings", "UserWidgetSettings",
    "ReportExports"
]
```

==========================================================================================
## FILE: bastehC_domain/backend/app/modules/reporting/ports.py
## SIZE: 2931 bytes
==========================================================================================

```python
from typing import Protocol, Optional, List, Tuple, Dict, Any
from uuid import UUID
from datetime import datetime
from pydantic import BaseModel, Field


# --- Dashboard Layout ---

class LayoutBlock(BaseModel):
    """Single block in a dashboard layout."""
    block_key: str
    position_x: int = Field(ge=0, le=11)
    position_y: int = Field(ge=0, le=200)
    width: int = Field(ge=1, le=12)
    height: int = Field(ge=1, le=20)
    is_visible: bool = True
    config: dict = Field(default_factory=dict)


class DashboardLayout(BaseModel):
    """Complete dashboard layout."""
    id: UUID
    user_id: UUID
    name: str
    view_mode: str = "daily"  # daily | weekly | monthly
    is_default: bool = False
    schema_version: int = 1
    blocks: List[LayoutBlock]
    created_at: datetime
    updated_at: datetime


# --- User Dashboard Settings ---

class UserDashboardSettings(BaseModel):
    """User-specific dashboard settings."""
    id: UUID
    user_id: UUID
    layout_id: UUID
    block_key: str
    is_visible: bool = True
    position_x: int = Field(ge=0, le=11)
    position_y: int = Field(ge=0, le=200)
    width: int = Field(ge=1, le=12)
    height: int = Field(ge=1, le=20)
    is_collapsed: bool = False
    config: dict = Field(default_factory=dict)
    updated_at: datetime


# --- User Widget Settings ---

class UserWidgetSettings(BaseModel):
    """Per-widget settings (clock, etc.)."""
    id: UUID
    user_id: UUID
    widget_key: str  # clock | quick_add | mini_calendar
    platform: str = "all"  # desktop | web | all
    is_visible: bool = True
    position_x: int = Field(ge=0)
    position_y: int = Field(ge=0)
    width: int = Field(ge=160, le=640)
    height: int = Field(ge=80, le=400)
    z_index: int = Field(default=10)
    style: dict = Field(default_factory=dict)  # {bg, fg, font_family, font_size, opacity}
    config: dict = Field(default_factory=dict)  # widget-specific config


# --- Dashboard Data ---

class DashboardData(BaseModel):
    """Complete dashboard data response."""
    layout: DashboardLayout
    widgets: Dict[str, UserWidgetSettings]
    visible_sections: dict


# --- Report Export/Import ---

class ReportExport(BaseModel):
    """Report export format."""
    schema_version: int
    layout: DashboardLayout
    widgets: List[UserWidgetSettings]


class ReportImport(BaseModel):
    """Report import format."""
    schema_version: int
    name: str
    view_mode: str
    blocks: List[LayoutBlock]


# --- Section Types ---

class SectionType(BaseModel):
    """Dashboard section types."""
    key: str
    label: str
    description: str
    default_blocks: List[str]


# Export all
__all__ = [
    "LayoutBlock", "DashboardLayout", "UserDashboardSettings",
    "UserWidgetSettings", "DashboardData", "ReportExport", "ReportImport",
    "SectionType"
]
```

==========================================================================================
## FILE: bastehC_domain/backend/app/modules/reporting/services/reporting_service.py
## SIZE: 9548 bytes
==========================================================================================

```python
"""Reporting service — raw SQL against the real DDL (schema ``reporting``).

Architecture Reference: Sections 10.1, 10.2, 10.3.
Note: dashboard blocks live in ``reporting.user_dashboard_settings``
(layout JSON blocks == block_key settings), not on the layout row.
The unique layout index is PARTIAL (``WHERE is_default``), so upserts
are manual SELECT -> INSERT/UPDATE.
"""
import json
from typing import Optional, List
from types import SimpleNamespace
from uuid import UUID
from datetime import datetime

from sqlalchemy import text

from app.core.errors import APIError, NotFoundError


def _iso(v):
    return v.isoformat() if isinstance(v, datetime) else v


class ReportingService:
    """Service layer for Reporting module operations (real DDL)."""

    def __init__(self, session):
        self.session = session

    async def save_layout(self, user_id: UUID, layout_data: dict) -> UUID:
        """Save dashboard layout for user (upsert by view_mode)."""
        view_mode = layout_data.get("view_mode", "daily")
        name = layout_data.get("name", "چیدمان جدید")
        schema_version = layout_data.get("schema_version", 1)
        is_default = layout_data.get("is_default", False)

        existing = (await self.session.execute(text("""
            SELECT id FROM reporting.dashboard_layouts
             WHERE user_id = :uid AND view_mode = :vm
             ORDER BY is_default DESC, updated_at DESC LIMIT 1
        """), {"uid": str(user_id), "vm": view_mode})).mappings().first()
        if existing:
            await self.session.execute(text("""
                UPDATE reporting.dashboard_layouts
                   SET name = :name, is_default = :def, schema_version = :sv,
                       updated_at = now()
                 WHERE id = :lid
            """), {"lid": str(existing["id"]), "name": name,
                   "def": bool(is_default), "sv": schema_version})
            layout_id = existing["id"]
        else:
            row = (await self.session.execute(text("""
                INSERT INTO reporting.dashboard_layouts
                    (user_id, name, view_mode, is_default, schema_version)
                VALUES (:uid, :name, :vm, :def, :sv)
                RETURNING id
            """), {"uid": str(user_id), "name": name, "vm": view_mode,
                   "def": bool(is_default), "sv": schema_version})).mappings().first()
            layout_id = row["id"]

        # Store widget/block placement in user_dashboard_settings
        blocks = layout_data.get("blocks", [])
        if layout_data.get("widgets"):
            blocks = layout_data["widgets"]
        for b in blocks:
            bkey = b.get("block_key") or b.get("key")
            if not bkey:
                continue
            await self.session.execute(text("""
                INSERT INTO reporting.user_dashboard_settings
                    (user_id, layout_id, block_key, is_visible,
                     position_x, position_y, width, height, is_collapsed, config)
                VALUES (:uid, :lid, :key, :vis, :x, :y, :w, :h, :col, CAST(:cfg AS jsonb))
                ON CONFLICT (layout_id, block_key)
                DO UPDATE SET is_visible = EXCLUDED.is_visible,
                              position_x = EXCLUDED.position_x,
                              position_y = EXCLUDED.position_y,
                              width = EXCLUDED.width,
                              height = EXCLUDED.height,
                              is_collapsed = EXCLUDED.is_collapsed,
                              config = EXCLUDED.config,
                              updated_at = now()
            """), {
                "uid": str(user_id), "lid": str(layout_id), "key": bkey,
                "vis": bool(b.get("is_visible", True)),
                "x": int(b.get("position_x", b.get("x", 0))),
                "y": int(b.get("position_y", b.get("y", 0))),
                "w": int(b.get("width", b.get("w", 4))),
                "h": int(b.get("height", b.get("h", 4))),
                "col": bool(b.get("is_collapsed", False)),
                "cfg": json.dumps(b.get("config") or {}),
            })
        await self.session.commit()
        return layout_id

    async def get_layout(self, layout_id: UUID, user_id: UUID) -> dict:
        """Get dashboard layout with widget settings."""
        row = (await self.session.execute(text("""
            SELECT id, name, view_mode, is_default, schema_version, created_at, updated_at
              FROM reporting.dashboard_layouts WHERE id = :lid AND user_id = :uid
        """), {"lid": str(layout_id), "uid": str(user_id)})).mappings().first()
        if not row:
            raise NotFoundError("layout")
        blocks = (await self.session.execute(text("""
            SELECT block_key, is_visible, position_x, position_y, width, height,
                   is_collapsed, config
              FROM reporting.user_dashboard_settings
             WHERE layout_id = :lid ORDER BY position_y, position_x
        """), {"lid": str(layout_id)})).mappings().all()
        return {
            "id": str(row["id"]),
            "name": row["name"],
            "view_mode": row["view_mode"],
            "is_default": row["is_default"],
            "schema_version": row["schema_version"],
            "blocks": [dict(b) for b in blocks],
        }

    async def list_layouts(self, user_id: UUID) -> List[dict]:
        """List user's dashboard layouts."""
        rows = (await self.session.execute(text("""
            SELECT id, name, view_mode, is_default
              FROM reporting.dashboard_layouts WHERE user_id = :uid
             ORDER BY created_at DESC
        """), {"uid": str(user_id)})).mappings().all()
        return [{"id": str(r["id"]), "name": r["name"],
                 "view_mode": r["view_mode"], "is_default": r["is_default"]}
                for r in rows]

    async def import_layout(self, user_id: UUID, import_data: dict) -> dict:
        """Import dashboard layout from JSON."""
        schema_version = import_data.get("schema_version", 1)
        if schema_version < 1:
            raise APIError(error_code="INVALID_SCHEMA_VERSION",
                           message="نسخه اسکیمای ناصحیح است.", status_code=400)
        layout_id = await self.save_layout(user_id, {
            "name": import_data.get("name", "چیدمان وارد شده"),
            "view_mode": import_data.get("view_mode", "daily"),
            "is_default": import_data.get("is_default", False),
            "schema_version": schema_version,
            "blocks": import_data.get("blocks", []),
        })
        return {"layout_id": str(layout_id), "schema_version": schema_version}

    async def save_widget_settings(self, user_id: UUID, settings_data: dict) -> dict:
        """Save widget settings for user."""
        widgets = settings_data.get("widgets", [])
        for w in widgets:
            wkey = w.get("widget_key") or w.get("key")
            if not wkey:
                continue
            platform = w.get("platform", "all")
            await self.session.execute(text("""
                INSERT INTO reporting.user_widget_settings
                    (user_id, widget_key, platform, is_visible,
                     position_x, position_y, width, height, z_index, style, config)
                VALUES (:uid, :key, :plat, :vis, :x, :y, :w, :h, :z, CAST(:style AS jsonb), CAST(:cfg AS jsonb))
                ON CONFLICT (user_id, widget_key, platform)
                DO UPDATE SET is_visible = EXCLUDED.is_visible,
                              position_x = EXCLUDED.position_x,
                              position_y = EXCLUDED.position_y,
                              width = EXCLUDED.width,
                              height = EXCLUDED.height,
                              z_index = EXCLUDED.z_index,
                              style = EXCLUDED.style,
                              config = EXCLUDED.config,
                              updated_at = now()
            """), {
                "uid": str(user_id), "key": wkey, "plat": platform,
                "vis": bool(w.get("is_visible", True)),
                "x": int(w.get("position_x", 0)),
                "y": int(w.get("position_y", 0)),
                "w": int(w.get("width", 160)),
                "h": int(w.get("height", 80)),
                "z": int(w.get("z_index", 10)),
                "style": json.dumps(w.get("style") or {}),
                "cfg": json.dumps(w.get("config") or {}),
            })
        return {"status": "widgets_saved", "updated_count": len(widgets)}

    async def get_widget_settings(self, user_id: UUID) -> dict:
        """Get all widget settings for user."""
        rows = (await self.session.execute(text("""
            SELECT widget_key, platform, is_visible, position_x, position_y,
                   width, height, z_index, style, config
              FROM reporting.user_widget_settings WHERE user_id = :uid
             ORDER BY position_y, position_x
        """), {"uid": str(user_id)})).mappings().all()
        return {"widgets": [dict(r) for r in rows]}

    async def reset_widget_settings(self, user_id: UUID) -> dict:
        """Reset widget settings to default."""
        result = await self.session.execute(text(
            "DELETE FROM reporting.user_widget_settings WHERE user_id = :uid"),
            {"uid": str(user_id)})
        count = result.rowcount or 0
        await self.session.commit()
        return {"status": "widgets_reset", "reset_count": count}
```

==========================================================================================
## FILE: bastehC_domain/backend/app/modules/sharing/api/routes.py
## SIZE: 4410 bytes
==========================================================================================

```python
"""
Sharing Module API Routes
Architecture Reference: Sections 4.6, 8.2, 11.1
Endpoints: /api/v1/sharing
"""

from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, Body, Path
from fastapi.responses import JSONResponse

from app.core.dependencies import (
    get_db_session, get_current_user, get_sharing_service
)
from app.core.errors import APIError, NotFoundError
from app.core.database import async_session_context
from app.modules.sharing.ports import (
    ShareCreate, ShareUpdate, ShareResponse, ACLOptions,
    PermissionCheck, ShareExport
)
from app.modules.sharing.services.sharing_service import SharingService


router = APIRouter(prefix="/sharing", tags=["Sharing"])


@router.post("/", response_model=dict)
async def create_share(
    request: ShareCreate,
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Create a share/permission for an entity."""
    async with db_session() as session:
        try:
            service = SharingService(session)
            result = await service.create_share(
                entity_type=request.entity_type,
                entity_id=request.entity_id,
                recipient_id=request.recipient_id,
                permission_level=request.permission_level,
                allow_comment=request.allow_comment,
                granted_by=user_id
            )
            return {"status": "share_created", "share_code": result.share_code}
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.get("/entity/{entity_type}/{entity_id}", response_model=dict)
async def get_entity_shares(
    entity_type: str = Path(...),
    entity_id: UUID = Path(...),
    viewer_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Get all shares for an entity."""
    async with db_session() as session:
        try:
            service = SharingService(session)
            shares = await service.get_entity_shares(entity_type, entity_id, viewer_id)
            return {
                "status": "success",
                "data": {"shares": shares}
            }
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.post("/check", response_model=dict)
async def check_permission(
    entity_type: str = Body(...),
    entity_id: UUID = Body(...),
    user_id: UUID = Body(...),
    required_level: str = Body(...),
    viewer_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Check if a user has required permission on an entity."""
    async with db_session() as session:
        try:
            service = SharingService(session)
            result = await service.check_permission(
                entity_type, entity_id, user_id, required_level, viewer_id
            )
            return {
                "status": "success",
                "data": {
                    "has_permission": result.has_permission,
                    "permission_level": result.permission_level,
                    "source": result.source
                }
            }
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.post("/revoke", response_model=dict)
async def revoke_share(
    share_code: str = Body(..., embed=True),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Revoke a share."""
    async with db_session() as session:
        try:
            service = SharingService(session)
            result = await service.revoke_share(share_code, user_id)
            return {"status": "share_revoked", "result": result}
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )
```

==========================================================================================
## FILE: bastehC_domain/backend/app/modules/sharing/db/Models.py
## SIZE: 2833 bytes
==========================================================================================

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

==========================================================================================
## FILE: bastehC_domain/backend/app/modules/sharing/ports.py
## SIZE: 1996 bytes
==========================================================================================

```python
from typing import Protocol, Optional, List, Tuple, Dict, Any
from uuid import UUID
from datetime import datetime
from pydantic import BaseModel, Field


# --- Share Schemas ---

class ShareCreate(BaseModel):
    """Create share request."""
    entity_type: str  # 'goal' | 'task' | 'group' | 'document'
    entity_id: UUID
    recipient_id: UUID
    permission_level: str  # 'read' | 'write' | 'manage'
    expires_at: Optional[datetime] = None
    allow_comment: bool = False


class ShareUpdate(BaseModel):
    """Update share request."""
    permission_level: Optional[str] = Field(None, pattern="^(read|write|manage)$")
    allow_comment: Optional[bool] = Field(None)


class ShareResponse(BaseModel):
    """Share response."""
    id: UUID
    share_code: str  # Unique code for recipient access
    entity_type: str
    entity_id: UUID
    recipient_id: UUID
    permission_level: str
    granted_at: datetime
    expires_at: Optional[datetime]
    allow_comment: bool
    recipient: dict  # Limited user info


# --- ACL Schemas ---

class ACLOptions(BaseModel):
    """ACL configuration for an entity."""
    entity_type: str
    entity_id: UUID
    owner_id: UUID
    shared_with: List[dict] = Field(default_factory=list)  # [user_id, permission_level]
    inherited_from: Optional[UUID] = None  # Group ID if inherited


# --- Permission Check ---

class PermissionCheck(BaseModel):
    """Permission check result."""
    user_id: UUID
    has_permission: bool
    permission_level: str  # 'read' | 'write' | 'manage'
    source: str  # 'direct' | 'inherited' | 'denied'


# --- Export ---

class ShareExport(BaseModel):
    """Share export format."""
    id: UUID
    entity_type: str
    entity_id: UUID
    recipient_id: UUID
    permission_level: str
    granted_at: datetime


# Export all
__all__ = [
    "ShareCreate", "ShareUpdate", "ShareResponse", "ACLOptions",
    "PermissionCheck", "ShareExport"
]
```

==========================================================================================
## FILE: bastehC_domain/backend/app/modules/sharing/services/sharing_service.py
## SIZE: 5849 bytes
==========================================================================================

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

==========================================================================================
## FILE: bastehC_domain/backend/app/modules/ssoldap/api/deps.py
## SIZE: 1354 bytes
==========================================================================================

```python
"""app/modules/ssoldap/api/deps.py

Composition root for the SSO/LDAP module (this file was the missing
piece that made ``POST /auth/sso/ldap-login`` raise NotImplementedError).

Builds SsoLoginService from the real AuthService / UserRepository /
LdapService, mirroring app/core/dependencies.get_auth_service.
"""

from __future__ import annotations

from fastapi import Depends

from app.core.dependencies import (
    get_session_dep,
    get_user_repository,
    get_auth_service,
)
from app.modules.ssoldap.services.ldap_service import LdapService
from app.modules.ssoldap.services.sso_login_service import SsoLoginService
from app.core.config import settings


def get_ldap_service() -> LdapService:
    """Build LdapService bound to app settings (ldap3 imported lazily)."""
    return LdapService(settings)


def get_sso_login_service(
    session=Depends(get_session_dep),
    user_repo=Depends(get_user_repository),
    ldap_service: LdapService = Depends(get_ldap_service),
    auth_service=Depends(get_auth_service),
) -> SsoLoginService:
    """Compose SsoLoginService for the ldap-login endpoint."""
    return SsoLoginService(
        settings=settings,
        user_repo=user_repo,
        ldap_service=ldap_service,
        auth_service=auth_service,
        role_assignment_service=None,  # wired when LDAP_GROUP_ROLE_MAP is enabled
    )
```

==========================================================================================
