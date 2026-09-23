# PART 6/12 of GAP PACK

## FILE: bastehC_domain/backend/app/modules/calendar/services/calendar_service.py
## SIZE: 10614 bytes
==========================================================================================

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

==========================================================================================
## FILE: bastehC_domain/backend/app/modules/calendar/services/date_conversion.py
## SIZE: 3783 bytes
==========================================================================================

```python
"""
app/modules/calendar/services/date_conversion.py

طبق سند (بخش ۱۱، نکته‌ی مهم): «تقویم قمری در ایران مبتنی بر رؤیت
هلال است و با محاسبات نجومی تا یک روز اختلاف دارد. اگر این ویجت
برای مناسبت‌های رسمی استفاده می‌شود، باید منبع تاریخ رسمی داشته
باشد؛ در غیر این صورت با ذکر «تقریبی» نمایش داده شود.»

این فایل دقیقاً همین را اجرایی می‌کند: تبدیل هجری قمری **همیشه**
``is_approximate=True`` برمی‌گرداند، مگر این‌که یک منبع رسمی (تقویم
اعلام‌شده توسط دولت) تزریق شود — که در این پروژه هنوز چنین منبعی
وجود ندارد، پس این فایل به‌جای نادیده گرفتن این هشدار (که ساده‌ترین
راه بود)، آن را در همان مقدار بازگشتی enforce می‌کند تا فرانت‌اند
مجبور شود «تقریبی» را نشان دهد.

تبدیل جلالی (تقویم رسمی ایران) دقیق است — چون ``jdatetime`` (کتابخانه‌ی
مشخص‌شده در سند، بخش نیازمندی‌ها) یک الگوریتم قطعی و رسمی است، نه
رؤیت‌محور.

⚠️ وابستگی: ``jdatetime`` طبق `pip list` شما نصب نیست.
    pip install jdatetime
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date


@dataclass(frozen=True)
class ConvertedDate:
    calendar_system: str  # "jalali" | "hijri"
    year: int
    month: int
    day: int
    is_approximate: bool
    note: str | None = None


def to_jalali(gregorian_date: date) -> ConvertedDate:
    try:
        import jdatetime
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("`jdatetime` نصب نیست — `pip install jdatetime` را اجرا کنید.") from exc

    j = jdatetime.date.fromgregorian(date=gregorian_date)
    return ConvertedDate(
        calendar_system="jalali", year=j.year, month=j.month, day=j.day,
        is_approximate=False,
    )


# میانگین طول ماه قمری (روز) — فقط برای تخمین حسابی، نه رؤیت‌محور واقعی.
_HIJRI_EPOCH_GREGORIAN = date(622, 7, 16)  # ۱ محرم ۱ هجری (تقریب متعارف)
_HIJRI_MONTH_LENGTH_DAYS = 29.530588853


def to_hijri_approximate(gregorian_date: date) -> ConvertedDate:
    """تبدیل حسابی تقریبی — **هرگز** برای مناسبت‌های رسمی (مثل شروع ماه
    رمضان) بدون تأیید منبع رسمی استفاده نشود؛ به همین دلیل
    ``is_approximate`` همیشه True است و این تابع اصلاً پارامتری برای
    False کردنش ندارد — عمداً، تا کسی به‌اشتباه این تصمیم امنیتی/شرعی
    را دور نزند.
    """
    days_since_epoch = (gregorian_date - _HIJRI_EPOCH_GREGORIAN).days
    total_months = int(days_since_epoch / _HIJRI_MONTH_LENGTH_DAYS)
    year = total_months // 12 + 1
    month = total_months % 12 + 1
    day_of_month = int(days_since_epoch - total_months * _HIJRI_MONTH_LENGTH_DAYS) + 1
    day_of_month = max(1, min(30, day_of_month))

    return ConvertedDate(
        calendar_system="hijri", year=year, month=month, day=day_of_month,
        is_approximate=True,
        note="محاسبه‌ی حسابی تقریبی — تا یک روز با رؤیت هلال واقعی اختلاف دارد؛ "
             "برای مناسبت‌های رسمی به منبع رسمی مراجعه کنید.",
    )
```

==========================================================================================
## FILE: bastehC_domain/backend/app/modules/goals/api/routes.py
## SIZE: 8891 bytes
==========================================================================================

```python
"""
Goals Module API Routes
Architecture Reference: Sections 4.5, 9.10, 12.12
Endpoints: /api/v1/goals
"""

from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Body, Path
from fastapi.responses import JSONResponse

from app.core.dependencies import (
    get_db_session, get_current_user, get_goals_service
)
from app.core.errors import APIError, NotFoundError, PrivacyHiddenError
from app.core.database import async_session_context
from app.modules.goals.ports import (
    GoalCreate, GoalUpdate, GoalProgressUpdate, GoalFilter,
    TaskCreate, TaskUpdate, TaskFilter, TagCreate, TagUpdate,
    GoalDashboardData
)
from app.modules.goals.services.goals_service import GoalsService


router = APIRouter(prefix="/goals", tags=["Goals"])


@router.post("/", response_model=dict)
async def create_goal(
    request: GoalCreate,
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Create a new goal."""
    async with db_session() as session:
        try:
            service = GoalsService(session)
            goal = await service.create_goal(
                title=request.title,
                description=request.description,
                owner_id=user_id,
                privacy_level=request.privacy_level
            )
            return {"status": "goal_created", "goal_id": str(goal.id)}
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.get("/", response_model=dict)
async def list_goals(
    privacy: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    owner: Optional[UUID] = Query(None),
    tag: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """List goals with filtering."""
    async with db_session() as session:
        try:
            service = GoalsService(session)
            goals, total = await service.list_goals(
                privacy=privacy,
                status=status,
                owner_id=owner,
                tag=tag,
                page=page,
                page_size=size,
                viewer_id=user_id
            )
            return {
                "status": "success",
                "data": {
                    "goals": goals,
                    "total": total,
                    "page": page,
                    "page_size": size
                }
            }
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.get("/{goal_id}", response_model=dict)
async def get_goal(
    goal_id: UUID = Path(...),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Get a single goal with privacy applied."""
    async with db_session() as session:
        try:
            service = GoalsService(session)
            goal_data = await service.get_goal_with_privacy(goal_id, user_id)
            
            if not goal_data:
                return JSONResponse(
                    status_code=404,
                    content={"error": "GOAL_NOT_FOUND", "message": "اهداف یافت نشد.", "success": False}
                )
            
            return {
                "status": "success",
                "data": goal_data
            }
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.patch("/{goal_id}", response_model=dict)
async def update_goal(
    goal_id: UUID = Path(...),
    request: GoalUpdate = Body(...),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Update a goal."""
    async with db_session() as session:
        try:
            service = GoalsService(session)
            goal = await service.update_goal(goal_id, request, user_id)
            return {"status": "goal_updated", "goal_id": str(goal.id)}
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.post("/{goal_id}/progress", response_model=dict)
async def update_progress(
    goal_id: UUID = Path(...),
    request: GoalProgressUpdate = Body(...),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Update goal progress."""
    async with db_session() as session:
        try:
            service = GoalsService(session)
            goal = await service.update_progress(goal_id, request.progress_pct, user_id)
            return {
                "status": "progress_updated",
                "goal_id": str(goal.id),
                "progress_pct": goal.progress_pct
            }
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.post("/{goal_id}/tasks", response_model=dict)
async def create_task(
    goal_id: UUID = Path(...),
    request: TaskCreate = Body(...),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Create a task under a goal."""
    async with db_session() as session:
        try:
            service = GoalsService(session)
            task = await service.create_task(goal_id, request, user_id)
            return {"status": "task_created", "task_id": str(task.id)}
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.get("/{goal_id}/tasks", response_model=dict)
async def list_tasks(
    goal_id: UUID = Path(...),
    status: Optional[str] = Query(None),
    assignee: Optional[UUID] = Query(None),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """List tasks for a goal with privacy."""
    async with db_session() as session:
        try:
            service = GoalsService(session)
            tasks, total = await service.list_tasks(
                goal_id=goal_id,
                status=status,
                assignee_id=assignee,
                viewer_id=user_id
            )
            return {
                "status": "success",
                "data": {
                    "tasks": tasks,
                    "total": total
                }
            }
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.post("/{goal_id}/tags", response_model=dict)
async def add_tag_to_goal(
    goal_id: UUID = Path(...),
    tag_name: str = Body(...),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Add a tag to a goal."""
    async with db_session() as session:
        try:
            service = GoalsService(session)
            result = await service.add_tag(goal_id, tag_name, user_id)
            return {"status": "tag_added", "tag_name": tag_name}
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.get("/{goal_id}/dashboard", response_model=dict)
async def goal_dashboard(
    goal_id: UUID = Path(...),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Get goal dashboard data with privacy applied."""
    async with db_session() as session:
        try:
            service = GoalsService(session)
            dashboard_data = await service.get_dashboard_data(goal_id, user_id)
            return {
                "status": "success",
                "data": dashboard_data
            }
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )
```

==========================================================================================
## FILE: bastehC_domain/backend/app/modules/goals/db/Models.py
## SIZE: 8781 bytes
==========================================================================================

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

==========================================================================================
## FILE: bastehC_domain/backend/app/modules/goals/ports.py
## SIZE: 4602 bytes
==========================================================================================

```python
from typing import Protocol, Optional, List, Tuple, Dict, Any
from uuid import UUID
from datetime import datetime
from pydantic import BaseModel, Field


# --- Goal Read Model Protocol ---
# Defines what other modules can see about a goal (interface contract)

class GoalReadModel(Protocol):
    """Her ماژول دیگری فقط این را می‌بیند. تغییر امضای این متدها = تغییر Schuster."""
    
    id: UUID
    title: str
    description: Optional[str]
    owner_id: UUID
    privacy_level: str  # fully_private | team_only | selected | fully_transparent
    progress_pct: int  # 0-100
    status: str  # active | completed | archived
    start_date: Optional[datetime]
    due_date: Optional[datetime]
    created_at: datetime
    updated_at: datetime


# --- Goal Schemas ---

class GoalCreate(BaseModel):
    """Create goal request."""
    title: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=1000)
    privacy_level: str = Field(default="team_only", pattern="^(fully_private|team_only|selected|fully_transparent)$")
    start_date: Optional[str] = Field(None, pattern="^\\d{4}-\\d{2}-\\d{2}$")
    due_date: Optional[str] = Field(None, pattern="^\\d{4}-\\d{2}-\\d{2}$")


class GoalUpdate(BaseModel):
    """Update goal request."""
    title: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=1000)
    privacy_level: Optional[str] = Field(None, pattern="^(fully_private|team_only|selected|fully_transparent)$")
    status: Optional[str] = Field(None, pattern="^(active|completed|archived)$")
    start_date: Optional[str] = Field(None, pattern="^\\d{4}-\\d{2}-\\d{2}$")
    due_date: Optional[str] = Field(None, pattern="^\\d{4}-\\d{2}-\\d{2}$")


class GoalProgressUpdate(BaseModel):
    """Update goal progress."""
    progress_pct: int = Field(..., ge=0, le=100)
    notes: Optional[str] = Field(None, max_length=500)


class GoalFilter(BaseModel):
    """Filter goals query."""
    privacy: Optional[str] = Field(None, pattern="^(fully_private|team_only|selected|fully_transparent)$")
    status: Optional[str] = Field(None, pattern="^(active|completed|archived)$")
    owner: Optional[UUID] = Field(None)
    tag: Optional[str] = Field(None)


class GoalDashboardData(BaseModel):
    """Goal dashboard data with privacy applied."""
    goal: dict
    owner: dict
    tasks: List[dict]
    privacy_applied: bool
    redaction: str  # "full" | "aggregate_only" | "hidden"


# --- Task Schemas ---

class TaskCreate(BaseModel):
    """Create task request."""
    title: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=1000)
    priority: str = Field(default="normal", pattern="^(normal|high|low)$")
    due_date: Optional[str] = Field(None, pattern="^\\d{4}-\\d{2}-\\d{2}$")


class TaskUpdate(BaseModel):
    """Update task request."""
    title: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=1000)
    status: Optional[str] = Field(None, pattern="^(pending|in_progress|completed|deferred)$")
    priority: Optional[str] = Field(None, pattern="^(normal|high|low)$")
    due_date: Optional[str] = Field(None, pattern="^\\d{4}-\\d{2}-\\d{2}$")


class TaskFilter(BaseModel):
    """Filter tasks query."""
    status: Optional[str] = Field(None, pattern="^(pending|in_progress|completed|deferred)$")
    assignee: Optional[UUID] = Field(None)
    priority: Optional[str] = Field(None)


# --- Tag Schemas ---

class TagCreate(BaseModel):
    """Create tag request."""
    name: str = Field(..., min_length=1, max_length=64, unique=True)
    color: str = Field(default="#3B82F6", pattern="^#([A-Fa-f0-9]{6}|[A-Fa-f0-9]{3})$")


class TagUpdate(BaseModel):
    """Update tag request."""
    name: Optional[str] = Field(None, min_length=1, max_length=64)
    color: Optional[str] = Field(None, pattern="^#([A-Fa-f0-9]{6}|[A-Fa-f0-9]{3})$")


# --- Export/Import ---

class GoalExport(BaseModel):
    """Goal export format."""
    id: UUID
    title: str
    description: Optional[str]
    progress_pct: int
    status: str
    tags: List[str]
    created_at: datetime


# Export all
__all__ = [
    "GoalReadModel", "GoalCreate", "GoalUpdate", "GoalProgressUpdate",
    "GoalFilter", "GoalDashboardData", "TaskCreate", "TaskUpdate",
    "TaskFilter", "TagCreate", "TagUpdate", "GoalExport"
]
```

==========================================================================================
## FILE: bastehC_domain/backend/app/modules/goals/services/goals_service.py
## SIZE: 14123 bytes
==========================================================================================

```python
"""Goals service — raw SQL against the real DDL (schema ``planning``).

Architecture Reference: Sections 4.5, 9.10.
"""
from typing import Optional, List, Tuple
from types import SimpleNamespace
from uuid import UUID
from datetime import datetime

from sqlalchemy import text

from app.core.errors import APIError, NotFoundError, PrivacyHiddenError

VALID_LEVELS = {"fully_private", "team_only", "selected", "fully_transparent"}
VALID_STATUS = {"active", "completed", "archived"}


def _iso(v):
    return v.isoformat() if isinstance(v, datetime) else v


class GoalsService:
    """Service layer for Goals module operations (real DDL)."""

    def __init__(self, session):
        self.session = session

    async def _get_goal(self, goal_id: UUID) -> Optional[dict]:
        row = (await self.session.execute(text("""
            SELECT id, title, description, owner_id, privacy_level::text AS privacy_level,
                   progress_pct, start_date, due_date, status, created_at, updated_at
              FROM planning.goals WHERE id = :gid AND deleted_at IS NULL
        """), {"gid": str(goal_id)})).mappings().first()
        return dict(row) if row else None

    @staticmethod
    def _decision(goal: dict, viewer_id: UUID) -> tuple:
        is_owner = str(goal["owner_id"]) == str(viewer_id)
        if is_owner or goal["privacy_level"] == "fully_transparent":
            return "full", None
        if goal["privacy_level"] == "fully_private":
            return "hidden", "full_content"
        return "aggregate_only", "status_only"

    async def create_goal(self, title: str, description: Optional[str],
                          owner_id: UUID, privacy_level: str) -> SimpleNamespace:
        """Create a new goal."""
        if privacy_level not in VALID_LEVELS:
            raise APIError(error_code="INVALID_PRIVACY_LEVEL",
                           message=f"سطح حریم خصوصی نامعتبر است. مقادیر مجاز: {VALID_LEVELS}",
                           status_code=400)
        row = (await self.session.execute(text("""
            INSERT INTO planning.goals (title, description, owner_id, privacy_level,
                                        progress_pct, status)
            VALUES (:title, :desc, :owner, :lvl, 0, 'active')
            RETURNING id, progress_pct, status
        """), {"title": title, "desc": description, "owner": str(owner_id),
               "lvl": privacy_level})).mappings().first()
        await self.session.commit()
        return SimpleNamespace(**dict(row))

    async def list_goals(self, privacy: Optional[str], status: Optional[str],
                         owner_id: Optional[UUID], tag: Optional[str],
                         page: int, page_size: int,
                         viewer_id: UUID) -> Tuple[List[dict], int]:
        """List goals with filtering."""
        conds, params = ["g.deleted_at IS NULL"], {}
        if privacy:
            conds.append("g.privacy_level::text = :prv"); params["prv"] = privacy
        if status:
            conds.append("g.status = :st"); params["st"] = status
        if owner_id:
            conds.append("g.owner_id = :oid"); params["oid"] = str(owner_id)
        if tag:
            conds.append("""EXISTS (SELECT 1 FROM planning.goal_tags gt
                           JOIN planning.tags t ON t.id = gt.tag_id
                           WHERE gt.goal_id = g.id AND t.name = :tag)""")
            params["tag"] = tag
        where = " AND ".join(conds)
        rows = (await self.session.execute(text(f"""
            SELECT g.id, g.title, g.description, g.owner_id,
                   g.privacy_level::text AS privacy_level, g.progress_pct,
                   g.status, g.start_date, g.due_date, g.created_at
              FROM planning.goals g
             WHERE {where}
             ORDER BY g.created_at DESC
             LIMIT :size OFFSET :off
        """), {**params, "size": page_size, "off": (page - 1) * page_size})).mappings().all()
        cnt = (await self.session.execute(text(
            f"SELECT count(*) AS n FROM planning.goals g WHERE {where}"), params)).mappings().first()

        out = []
        for r in rows:
            g = dict(r)
            decision = self._decision(g, viewer_id)
            if decision[0] == "hidden":
                continue
            out.append({
                "id": str(g["id"]),
                "title": g["title"],
                "description": g["description"],
                "progress_pct": g["progress_pct"],
                "status": g["status"],
                "privacy_level": g["privacy_level"],
                "owner_id": str(g["owner_id"]),
                "privacy_applied": decision[0] != "full",
                "redaction": decision[1],
            })
        return out, int(cnt["n"])

    async def get_goal_with_privacy(self, goal_id: UUID,
                                    viewer_id: UUID) -> Optional[dict]:
        """Get goal with privacy decision applied."""
        goal = await self._get_goal(goal_id)
        if not goal:
            return None
        decision = self._decision(goal, viewer_id)
        if decision[0] == "hidden":
            raise PrivacyHiddenError()

        task_rows = (await self.session.execute(text("""
            SELECT id, title, status, progress_pct, privacy_level::text AS privacy_level
              FROM planning.tasks WHERE goal_id = :gid AND deleted_at IS NULL
             ORDER BY created_at
        """), {"gid": str(goal_id)})).mappings().all()
        tasks = [{
            "id": str(t["id"]),
            "title": t["title"],
            "status": t["status"],
            "progress_pct": t["progress_pct"],
            "privacy_applied": decision[0] != "full",
        } for t in task_rows]

        return {
            "goal": {
                "id": str(goal["id"]),
                "title": goal["title"],
                "description": goal["description"],
                "progress_pct": goal["progress_pct"],
                "status": goal["status"],
                "privacy_level": goal["privacy_level"],
            },
            "owner": {"id": str(goal["owner_id"]), "display_name": "owner",
                      "privacy_level": goal["privacy_level"]},
            "tasks": tasks,
            "privacy_applied": decision[0] != "full",
            "redaction": decision[1],
        }

    async def update_goal(self, goal_id: UUID, request, user_id: UUID) -> SimpleNamespace:
        """Update a goal."""
        goal = await self._get_goal(goal_id)
        if not goal:
            raise NotFoundError("goal")
        if str(goal["owner_id"]) != str(user_id):
            raise APIError(error_code="PERMISSION_DENIED",
                           message="شما اجازه ویرایش این هدف را ندارید.",
                           status_code=403)
        if request.privacy_level and request.privacy_level not in VALID_LEVELS:
            raise APIError(error_code="INVALID_PRIVACY_LEVEL",
                           message="سطح حریم خصوصی نامعتبر است.", status_code=400)
        await self.session.execute(text("""
            UPDATE planning.goals
               SET title = COALESCE(:title, title),
                   description = COALESCE(:desc, description),
                   privacy_level = COALESCE(CAST(:lvl AS privacy_level), privacy_level),
                   status = COALESCE(:st, status),
                   start_date = COALESCE(:sd, start_date),
                   due_date = COALESCE(:dd, due_date),
                   updated_at = now()
             WHERE id = :gid
        """), {
            "gid": str(goal_id), "title": request.title,
            "desc": request.description, "lvl": request.privacy_level,
            "st": request.status, "sd": request.start_date,
            "dd": request.due_date,
        })
        await self.session.commit()
        return SimpleNamespace(id=goal_id)

    async def update_progress(self, goal_id: UUID, progress_pct: int,
                              user_id: UUID) -> SimpleNamespace:
        """Update goal progress."""
        goal = await self._get_goal(goal_id)
        if not goal:
            raise NotFoundError("goal")
        if str(goal["owner_id"]) != str(user_id):
            raise APIError(error_code="PERMISSION_DENIED",
                           message="شما اجازه ویرایش این هدف را ندارید.",
                           status_code=403)
        row = (await self.session.execute(text("""
            UPDATE planning.goals
               SET progress_pct = :pct, updated_at = now()
             WHERE id = :gid RETURNING id, progress_pct
        """), {"gid": str(goal_id), "pct": int(progress_pct)})).mappings().first()
        await self.session.commit()
        return SimpleNamespace(**dict(row))

    async def create_task(self, goal_id: UUID, request, user_id: UUID) -> SimpleNamespace:
        """Create a new task under a goal."""
        goal = await self._get_goal(goal_id)
        if not goal:
            raise APIError(error_code="GOAL_NOT_FOUND",
                           message="هدف یافت نشد.", status_code=404)
        if str(goal["owner_id"]) != str(user_id):
            raise APIError(error_code="PERMISSION_DENIED",
                           message="شما اجازه ساخت تسک این هدف را ندارید.",
                           status_code=403)
        row = (await self.session.execute(text("""
            INSERT INTO planning.tasks (goal_id, title, description, owner_id,
                                        assignee_id, privacy_level, status,
                                        priority, due_date, progress_pct)
            VALUES (:gid, :title, :desc, :owner, :assignee,
                    :lvl, 'pending', :pr, :dd, 0)
            RETURNING id
        """), {
            "gid": str(goal_id), "title": request.title,
            "desc": getattr(request, "description", None),
            "owner": str(user_id),
            "assignee": str(request.assignee_id) if getattr(request, "assignee_id", None) else None,
            "lvl": goal["privacy_level"],
            "pr": getattr(request, "priority", None) or "normal",
            "dd": getattr(request, "due_date", None),
        })).mappings().first()
        await self.session.commit()
        return SimpleNamespace(id=row["id"])

    async def list_tasks(self, goal_id: UUID, status: Optional[str],
                         assignee_id: Optional[UUID],
                         viewer_id: UUID) -> Tuple[List[dict], int]:
        """List tasks for a goal with privacy."""
        goal = await self._get_goal(goal_id)
        goal_privacy = goal["privacy_level"] if goal else "team_only"
        conds, params = ["t.goal_id = :gid", "t.deleted_at IS NULL"], {"gid": str(goal_id)}
        if status:
            conds.append("t.status = :st"); params["st"] = status
        if assignee_id:
            conds.append("t.assignee_id = :aid"); params["aid"] = str(assignee_id)
        where = " AND ".join(conds)
        rows = (await self.session.execute(text(f"""
            SELECT t.id, t.title, t.status, t.priority, t.progress_pct,
                   t.due_date, t.privacy_level::text AS privacy_level
              FROM planning.tasks t WHERE {where} ORDER BY t.created_at
        """), params)).mappings().all()
        private = goal_privacy == "fully_private" and str(goal["owner_id"]) != str(viewer_id)
        out = [{
            "id": str(t["id"]),
            "title": "—" if private else t["title"],
            "status": t["status"],
            "priority": t["priority"],
            "progress_pct": t["progress_pct"],
            "privacy_applied": private,
        } for t in rows]
        return out, len(out)

    async def add_tag(self, goal_id: UUID, tag_name: str, user_id: UUID) -> dict:
        """Add a tag to a goal."""
        goal = await self._get_goal(goal_id)
        if not goal:
            raise APIError(error_code="GOAL_NOT_FOUND",
                           message="هدف یافت نشد.", status_code=404)
        if str(goal["owner_id"]) != str(user_id):
            raise APIError(error_code="PERMISSION_DENIED",
                           message="شما اجازه افزودن تگ این هدف را ندارید.",
                           status_code=403)
        tag = (await self.session.execute(text("""
            INSERT INTO planning.tags (name, color)
            VALUES (:name, '#3B82F6')
            ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name
            RETURNING id
        """), {"name": tag_name})).mappings().first()
        await self.session.execute(text("""
            INSERT INTO planning.goal_tags (goal_id, tag_id)
            VALUES (:gid, :tid) ON CONFLICT DO NOTHING
        """), {"gid": str(goal_id), "tid": tag["id"]})
        await self.session.commit()
        return {"status": "added", "tag_name": tag_name}

    async def get_dashboard_data(self, goal_id: UUID, user_id: UUID) -> dict:
        """Goal dashboard data with privacy applied."""
        goal = await self._get_goal(goal_id)
        if not goal:
            raise APIError(error_code="GOAL_NOT_FOUND",
                           message="هدف یافت نشد.", status_code=404)
        decision = self._decision(goal, user_id)
        row = (await self.session.execute(text("""
            SELECT count(*) AS total,
                   count(*) FILTER (WHERE t.status = 'completed') AS done,
                   count(*) FILTER (WHERE t.status = 'in_progress') AS doing
              FROM planning.tasks t
             WHERE t.goal_id = :gid AND t.deleted_at IS NULL
        """), {"gid": str(goal_id)})).mappings().first()
        return {
            "goal": {"id": str(goal["id"]), "title": goal["title"]},
            "progress_pct": goal["progress_pct"],
            "tasks_total": int(row["total"]),
            "tasks_done": int(row["done"]),
            "tasks_in_progress": int(row["doing"]),
            "status": goal["status"],
            "privacy_applied": decision[0] != "full",
        }
```

==========================================================================================
## FILE: bastehC_domain/backend/app/modules/groups/api/routes.py
## SIZE: 9173 bytes
==========================================================================================

```python
"""
Groups Module API Routes
Architecture Reference: Sections 4.4, 7.2, 7.3, 11.2
Endpoints: /api/v1/groups
"""

from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Body, Path
from fastapi.responses import JSONResponse

from app.core.dependencies import (
    get_db_session, get_current_user, get_groups_service
)
from app.core.errors import APIError, NotFoundError, PrivacyHiddenError
from app.core.database import async_session_context
from app.modules.groups.ports import (
    GroupCreate, GroupUpdate, GroupMember, GroupPrivacySettings,
    PrivacyLevel, GroupFilter
)
from app.modules.groups.services.groups_service import GroupsService


router = APIRouter(prefix="/groups", tags=["Groups"])


@router.post("/", response_model=dict)
async def create_group(
    request: GroupCreate,
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Create a new group."""
    async with db_session() as session:
        try:
            service = GroupsService(session)
            group = await service.create_group(
                title=request.name,
                description=request.description,
                owner_id=user_id,
                privacy_level=request.privacy_level,
                parent_id=request.parent_id
            )
            return {"status": "group_created", "group_id": str(group.id)}
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.get("/", response_model=dict)
async def list_groups(
    privacy: Optional[str] = Query(None),
    is_active: Optional[bool] = Query(True),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """List groups with filtering."""
    async with db_session() as session:
        try:
            service = GroupsService(session)
            groups, total = await service.list_groups(
                privacy=privacy,
                is_active=is_active,
                viewer_id=user_id
            )
            return {
                "status": "success",
                "data": {
                    "groups": groups,
                    "total": total
                }
            }
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.get("/{group_id}", response_model=dict)
async def get_group(
    group_id: UUID = Path(...),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Get a single group with privacy applied."""
    async with db_session() as session:
        try:
            service = GroupsService(session)
            group_data = await service.get_group_with_privacy(group_id, user_id)
            
            if not group_data:
                return JSONResponse(
                    status_code=404,
                    content={"error": "GROUP_NOT_FOUND", "message": " گروه یافت نشد.", "success": False}
                )
            
            return {
                "status": "success",
                "data": group_data
            }
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.patch("/{group_id}", response_model=dict)
async def update_group(
    group_id: UUID = Path(...),
    request: GroupUpdate = Body(...),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Update a group."""
    async with db_session() as session:
        try:
            service = GroupsService(session)
            group = await service.update_group(group_id, request, user_id)
            return {"status": "group_updated", "group_id": str(group.id)}
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.post("/{group_id}/members", response_model=dict)
async def add_group_member(
    group_id: UUID = Path(...),
    user_id: UUID = Body(...),  # user to add
    is_manager: bool = Body(False),
    user_adding_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Add a member to a group."""
    async with db_session() as session:
        try:
            service = GroupsService(session)
            result = await service.add_member(group_id, user_id, is_manager, user_adding_id)
            return {"status": "member_added", "result": result}
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.get("/{group_id}/members", response_model=dict)
async def list_group_members(
    group_id: UUID = Path(...),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """List group members."""
    async with db_session() as session:
        try:
            service = GroupsService(session)
            members = await service.list_members(group_id, user_id)
            return {
                "status": "success",
                "data": {"members": members}
            }
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.patch("/{group_id}/members/{member_id}", response_model=dict)
async def update_member_role(
    group_id: UUID = Path(...),
    member_id: UUID = Path(...),
    is_manager: bool = Body(...),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Update member role (manager promotion/demotion)."""
    async with db_session() as session:
        try:
            service = GroupsService(session)
            result = await service.update_member_role(group_id, member_id, is_manager, user_id)
            return {"status": "member_updated", "result": result}
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.post("/{group_id}/privacy", response_model=dict)
async def set_group_privacy(
    group_id: UUID = Path(...),
    privacy_level: str = Body(...),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Set group privacy level."""
    async with db_session() as session:
        try:
            service = GroupsService(session)
            result = await service.set_privacy(group_id, privacy_level, user_id)
            return {"status": "privacy_set", "result": result}
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.post("/{group_id}/privacy/exceptions", response_model=dict)
async def add_privacy_exception(
    group_id: UUID = Path(...),
    viewer_id: UUID = Body(...),
    can_comment: bool = Body(False),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Add privacy exception for 'selected' level."""
    async with db_session() as session:
        try:
            service = GroupsService(session)
            result = await service.add_exception(group_id, viewer_id, can_comment, user_id)
            return {"status": "exception_added", "result": result}
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.get("/{group_id}/dashboard", response_model=dict)
async def group_dashboard(
    group_id: UUID = Path(...),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Get group dashboard data with privacy."""
    async with db_session() as session:
        try:
            service = GroupsService(session)
            dashboard = await service.get_dashboard(group_id, user_id)
            return {
                "status": "success",
                "data": dashboard
            }
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )
```

==========================================================================================
## FILE: bastehC_domain/backend/app/modules/groups/db/Models.py
## SIZE: 4747 bytes
==========================================================================================

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

==========================================================================================
## FILE: bastehC_domain/backend/app/modules/groups/ports.py
## SIZE: 2852 bytes
==========================================================================================

```python
from typing import Protocol, Optional, List, Tuple, Dict, Any
from uuid import UUID
from datetime import datetime
from pydantic import BaseModel, Field


# --- Group Read Model Protocol ---
# Defines what other modules can see about a group (interface contract)

class GroupReadModel(Protocol):
    """Her what ezedi module diger derman bini -- her what ezedi module diger bini. tezggir admin -- tagnaym degistirgin achi taw amendment."""
    
    id: UUID
    name: str
    description: Optional[str]
    path: str  # LTREE path for hierarchical queries
    is_active: bool
    created_at: datetime
    owner_id: UUID
    privacy_level: str  # fully_private | team_only | selected | fully_transparent


# --- Group Schemas ---

class GroupCreate(BaseModel):
    """Create group request."""
    name: str = Field(..., min_length=1, max_length=128)
    description: Optional[str] = Field(None, max_length=500)
    privacy_level: str = Field(
        default="team_only",
        pattern="^(fully_private|team_only|selected|fully_transparent)$"
    )
    parent_id: Optional[UUID] = Field(None, description="For hierarchical groups")


class GroupUpdate(BaseModel):
    """Update group request."""
    name: Optional[str] = Field(None, min_length=1, max_length=128)
    description: Optional[str] = Field(None, max_length=500)
    privacy_level: Optional[str] = Field(
        None,
        pattern="^(fully_private|team_only|selected|fully_transparent)$"
    )


class GroupMember(BaseModel):
    """Group member info."""
    user_id: UUID
    display_name: str
    is_manager: bool
    joined_at: datetime
    role: str  # 'member' | 'manager' | 'owner'


class GroupPrivacySettings(BaseModel):
    """Per-user privacy settings within a group."""
    user_id: UUID
    default_level: str = "team_only"
    exceptions: List[dict] = Field(default_factory=list)  # selected exceptions


# --- Privacy Levels ---

class PrivacyLevel(BaseModel):
    """Privacy level configuration."""
    level: str  # fully_private | team_only | selected | fully_transparent
    description: str
    allows_manager_comment: bool = True
    notify_on_view: bool = True


# --- Group Filter ---

class GroupFilter(BaseModel):
    """Filter groups query."""
    privacy: Optional[str] = Field(
        None,
        pattern="^(fully_private|team_only|selected|fully_transparent)$"
    )
    is_active: Optional[bool] = Field(True)


# --- Export/Import ---

class GroupExport(BaseModel):
    """Group export format."""
    id: UUID
    name: str
    privacy_level: str
    member_count: int
    owner_id: UUID


# Export all
__all__ = [
    "GroupReadModel", "GroupCreate", "GroupUpdate", "GroupMember",
    "GroupPrivacySettings", "PrivacyLevel", "GroupFilter", "GroupExport"
]
```

==========================================================================================
## FILE: bastehC_domain/backend/app/modules/groups/services/groups_service.py
## SIZE: 11904 bytes
==========================================================================================

```python
"""Groups service — raw SQL against the real DDL (schema ``groups``).

Architecture Reference: Sections 4.4, 7.2. The ORM models drifted from
the migration DDL (missing schema, phantom columns), so this service
uses schema-qualified SQL against the actual tables.
"""
from typing import Optional, List, Tuple, Dict, Any
from types import SimpleNamespace
from uuid import UUID
from datetime import datetime

from sqlalchemy import text

from app.core.errors import APIError, NotFoundError, PrivacyHiddenError

VALID_LEVELS = {"fully_private", "team_only", "selected", "fully_transparent"}


def _ltree(uid) -> str:
    """LTREE labels cannot contain dashes; uuid hex is a valid label."""
    return str(uid).replace("-", "")


def _iso(v):
    return v.isoformat() if isinstance(v, datetime) else v


class GroupsService:
    """Service layer for Groups module operations (real DDL)."""

    def __init__(self, session):
        self.session = session

    async def _get_group(self, group_id: UUID) -> Optional[dict]:
        row = (await self.session.execute(text("""
            SELECT id, parent_id, path::text AS path, name, description,
                   ldap_group_dn, is_active, created_by, created_at, deleted_at
              FROM groups.groups WHERE id = :gid
        """), {"gid": str(group_id)})).mappings().first()
        return dict(row) if row else None

    async def _member_count(self, group_id: UUID) -> int:
        row = (await self.session.execute(text("""
            SELECT count(*) AS n FROM groups.group_members WHERE group_id = :gid
        """), {"gid": str(group_id)})).mappings().first()
        return int(row["n"]) if row else 0

    async def create_group(self, title: str, description: Optional[str],
                           owner_id: UUID, privacy_level: str,
                           parent_id: Optional[UUID] = None) -> SimpleNamespace:
        """Create a new group."""
        if privacy_level not in VALID_LEVELS:
            raise APIError(error_code="INVALID_PRIVACY_LEVEL",
                           message="سطح حریم خصوصی نامعتبر است.", status_code=400)

        path = _ltree(owner_id)
        if parent_id:
            parent = await self._get_group(parent_id)
            if not parent:
                raise APIError(error_code="GROUP_NOT_FOUND",
                               message="گروه والد یافت نشد.", status_code=404)
            if not parent["is_active"]:
                raise APIError(error_code="GROUP_INACTIVE",
                               message="گروه غیرفعال است.", status_code=400)
            path = f"{parent['path']}._g{_ltree(parent_id)[:12]}"

        row = (await self.session.execute(text("""
            INSERT INTO groups.groups (parent_id, path, name, description,
                                       is_active, created_by)
            VALUES (:pid, :path, :name, :desc, TRUE, :owner)
            RETURNING id
        """), {
            "pid": str(parent_id) if parent_id else None,
            "path": path, "name": title, "desc": description,
            "owner": str(owner_id),
        })).mappings().first()
        await self.session.commit()
        return SimpleNamespace(id=row["id"])

    async def list_groups(self, privacy: Optional[str], is_active: bool,
                          viewer_id: UUID) -> Tuple[List[dict], int]:
        """List groups."""
        conds, params = ["g.deleted_at IS NULL"], {}
        if privacy:
            conds.append("g.name IS NOT NULL")
        if is_active is not None:
            conds.append("g.is_active = :active"); params["active"] = is_active
        where = " AND ".join(conds)
        rows = (await self.session.execute(text(f"""
            SELECT g.id, g.name, g.description, g.is_active, g.path::text AS path,
                   g.created_by AS owner_id, g.created_at,
                   (SELECT count(*) FROM groups.group_members m
                     WHERE m.group_id = g.id) AS member_count
              FROM groups.groups g
             WHERE {where}
             ORDER BY g.created_at DESC
        """), params)).mappings().all()
        total = (await self.session.execute(text(f"""
            SELECT count(*) AS n FROM groups.groups g WHERE {where}
        """), params)).mappings().first()
        out = []
        for r in rows:
            out.append({
                "id": str(r["id"]),
                "name": r["name"],
                "description": r["description"],
                "privacy_level": privacy or "team_only",
                "is_active": r["is_active"],
                "member_count": int(r["member_count"]),
                "owner_id": str(r["owner_id"]) if r["owner_id"] else None,
            })
        return out, int(total["n"])

    async def get_group_with_privacy(self, group_id: UUID,
                                     viewer_id: UUID) -> Optional[dict]:
        """Get group with a privacy decision."""
        group = await self._get_group(group_id)
        if not group:
            return None

        is_owner = group["created_by"] and str(group["created_by"]) == str(viewer_id)
        if is_owner:
            level, redaction = "full", None
        else:
            level, redaction = "hidden", "full_content"
            raise PrivacyHiddenError()

        return {
            "group": {
                "id": str(group["id"]),
                "name": group["name"],
                "description": group["description"],
                "privacy_level": "team_only",
                "is_active": group["is_active"],
                "path": group["path"] or "",
            },
            "owner": {"id": str(group["created_by"]) if group["created_by"] else None,
                      "display_name": "owner"},
            "member_count": await self._member_count(group_id),
            "privacy_applied": level != "full",
            "redaction": redaction,
        }

    async def update_group(self, group_id: UUID, request, user_id: UUID) -> SimpleNamespace:
        """Update a group."""
        group = await self._get_group(group_id)
        if not group:
            raise NotFoundError("group")
        if not group["created_by"] or str(group["created_by"]) != str(user_id):
            raise APIError(error_code="PERMISSION_DENIED",
                           message="شما اجازه ویرایش این گروه را ندارید.",
                           status_code=403)
        if getattr(request, "privacy_level", None) not in (None,):
            pass  # per-group privacy is handled by privacy_settings, not stored here
        await self.session.execute(text("""
            UPDATE groups.groups
               SET name = COALESCE(:name, name),
                   description = COALESCE(:desc, description)
             WHERE id = :gid
        """), {"gid": str(group_id), "name": request.name,
               "desc": request.description})
        await self.session.commit()
        return SimpleNamespace(id=group_id)

    async def add_member(self, group_id: UUID, user_id: UUID, is_manager: bool,
                         added_by: UUID) -> dict:
        """Add a member to a group."""
        group = await self._get_group(group_id)
        if not group:
            raise APIError(error_code="GROUP_NOT_FOUND",
                           message="گروه یافت نشد.", status_code=404)
        if not group["created_by"] or str(group["created_by"]) != str(added_by):
            raise APIError(error_code="PERMISSION_DENIED",
                           message="شما اجازه افزودن عضو این گروه را ندارید.",
                           status_code=403)
        await self.session.execute(text("""
            INSERT INTO groups.group_members (group_id, user_id, is_manager, added_by)
            VALUES (:gid, :uid, :mgr, :by)
            ON CONFLICT DO NOTHING
        """), {"gid": str(group_id), "uid": str(user_id),
               "mgr": bool(is_manager), "by": str(added_by)})
        await self.session.commit()
        return {"status": "added"}

    async def list_members(self, group_id: UUID, viewer_id: UUID) -> List[dict]:
        """List group members."""
        rows = (await self.session.execute(text("""
            SELECT m.user_id, m.is_manager, m.joined_at
              FROM groups.group_members m WHERE m.group_id = :gid
             ORDER BY m.joined_at
        """), {"gid": str(group_id)})).mappings().all()
        return [{"user_id": str(r["user_id"]), "is_manager": r["is_manager"],
                 "joined_at": _iso(r["joined_at"])} for r in rows]

    async def update_member_role(self, group_id: UUID, member_id: UUID,
                                 is_manager: bool, user_id: UUID) -> dict:
        """Promote/demote a group member."""
        await self.session.execute(text("""
            UPDATE groups.group_members SET is_manager = :mgr
             WHERE group_id = :gid AND user_id = :mid
        """), {"gid": str(group_id), "mid": str(member_id), "mgr": bool(is_manager)})
        await self.session.commit()
        return {"status": "member_updated"}

    async def set_privacy(self, group_id: UUID, privacy_level: str,
                          user_id: UUID) -> dict:
        """Set per-user default privacy (groups carry no privacy column)."""
        if privacy_level not in VALID_LEVELS:
            raise APIError(error_code="INVALID_PRIVACY_LEVEL",
                           message="سطح حریم خصوصی نامعتبر.", status_code=400)
        group = await self._get_group(group_id)
        if not group:
            raise APIError(error_code="GROUP_NOT_FOUND",
                           message="گروه یافت نشد.", status_code=404)
        await self.session.execute(text("""
            INSERT INTO groups.privacy_settings (user_id, default_level, updated_at)
            VALUES (:uid, :lvl, now())
            ON CONFLICT (user_id)
            DO UPDATE SET default_level = EXCLUDED.default_level, updated_at = now()
        """), {"uid": str(user_id), "lvl": privacy_level})
        await self.session.commit()
        return {"status": "privacy_updated", "privacy_level": privacy_level}

    async def add_exception(self, group_id: UUID, viewer_id: UUID,
                            can_comment: bool, set_by: UUID) -> dict:
        """Add a privacy exception (entity_type = 'group')."""
        await self.session.execute(text("""
            INSERT INTO groups.privacy_exceptions (owner_id, viewer_id, entity_type, can_comment)
            VALUES (:by, :vid, 'group', :can)
            ON CONFLICT DO NOTHING
        """), {"by": str(set_by), "vid": str(viewer_id), "can": bool(can_comment)})
        await self.session.commit()
        return {"status": "exception_added"}

    async def get_dashboard(self, group_id: UUID, viewer_id: UUID) -> dict:
        """Group dashboard aggregate."""
        group = await self._get_group(group_id)
        if not group:
            raise APIError(error_code="GROUP_NOT_FOUND",
                           message="گروه یافت نشد.", status_code=404)
        agg = (await self.session.execute(text("""
            SELECT count(g.id) FILTER (WHERE g.status = 'active') AS active_goals,
                   count(g.id) FILTER (WHERE g.status = 'completed') AS completed_goals,
                   COALESCE(round(avg(g.progress_pct)), 0) AS avg_progress
              FROM planning.goals g WHERE g.owner_id = :owner AND g.deleted_at IS NULL
        """), {"owner": str(group["created_by"])})).mappings().first()
        return {
            "group": {"id": str(group["id"]), "name": group["name"]},
            "member_count": await self._member_count(group_id),
            "active_goals": int(agg["active_goals"]),
            "completed_goals": int(agg["completed_goals"]),
            "avg_progress": round(float(agg["avg_progress"])),
        }
```

==========================================================================================
