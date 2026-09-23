# BUNDLE: basteh4
# Source: GAP\basteh4
================================================================================

================================================================================
## FILE: backend/app/modules/chat/__init__.py
================================================================================

```python
"""Chat module public interface."""
from app.modules.chat.api.routes import router

__all__ = ["router"]
```

================================================================================
## FILE: backend/app/modules/chat/db/models.py
================================================================================

```python
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
```

================================================================================
## FILE: backend/app/modules/chat/services/chat_service.py
================================================================================

```python
"""Chat service — raw SQL against the real DDL (schema ``chat``).

Architecture Reference: Sections 8.1, 8.2, 8.3.
"""
from typing import Optional, List
from types import SimpleNamespace
from uuid import UUID
from datetime import datetime

from sqlalchemy import text

from app.core.errors import APIError, NotFoundError


def _iso(v):
    return v.isoformat() if isinstance(v, datetime) else v


class ChatService:
    """Service layer for Chat module operations (real DDL)."""

    def __init__(self, session):
        self.session = session

    async def _member_of(self, room_id: UUID, user_id: UUID) -> bool:
        row = (await self.session.execute(text("""
            SELECT 1 FROM chat.room_members
             WHERE room_id = :rid AND user_id = :uid AND left_at IS NULL
        """), {"rid": str(room_id), "uid": str(user_id)})).first()
        return row is not None

    async def create_room(self, title: str, linked_type: Optional[str],
                          linked_id: Optional[UUID], owner_id: UUID) -> SimpleNamespace:
        """Create a new chat room."""
        row = (await self.session.execute(text("""
            INSERT INTO chat.rooms (title, linked_type, linked_id, owner_id,
                                    is_archived, retention_days)
            VALUES (:title, :ltype, :lid, :owner, FALSE, 30)
            RETURNING id, title, owner_id, is_archived
        """), {"title": title, "ltype": linked_type,
               "lid": str(linked_id) if linked_id else None,
               "owner": str(owner_id)})).mappings().first()
        # Add room creator as an owner member
        await self.session.execute(text("""
            INSERT INTO chat.room_members (room_id, user_id, role)
            VALUES (:rid, :uid, 'owner')
            ON CONFLICT DO NOTHING
        """), {"rid": row["id"], "uid": str(owner_id)})
        await self.session.commit()
        return SimpleNamespace(id=row["id"], title=row["title"],
                               owner_id=row["owner_id"], is_archived=row["is_archived"])

    async def list_rooms(self, user_id: UUID) -> List[dict]:
        """List rooms user is member of."""
        rows = (await self.session.execute(text("""
            SELECT r.id, r.title, r.is_archived, r.owner_id, r.linked_type, r.linked_id,
                   (SELECT count(*) FROM chat.room_members m
                     WHERE m.room_id = r.id AND m.left_at IS NULL) AS member_count
              FROM chat.rooms r
              JOIN chat.room_members m ON m.room_id = r.id
             WHERE m.user_id = :uid AND m.left_at IS NULL
               AND r.is_archived = FALSE
             ORDER BY r.created_at DESC
        """), {"uid": str(user_id)})).mappings().all()
        return [{
            "id": str(r["id"]),
            "title": r["title"],
            "is_archived": r["is_archived"],
            "member_count": int(r["member_count"]),
            "owner_id": str(r["owner_id"]),
            "linked_type": r["linked_type"],
            "linked_id": str(r["linked_id"]) if r["linked_id"] else None,
        } for r in rows]

    async def get_room(self, room_id: UUID, user_id: UUID) -> Optional[dict]:
        """Get room with membership check."""
        row = (await self.session.execute(text("""
            SELECT id, title, owner_id, is_archived, linked_type, linked_id,
                   retention_days, created_at
              FROM chat.rooms WHERE id = :rid
        """), {"rid": str(room_id)})).mappings().first()
        if not row:
            return None
        if not await self._member_of(room_id, user_id):
            return None
        cnt = (await self.session.execute(text("""
            SELECT count(*) AS n FROM chat.room_members
             WHERE room_id = :rid AND left_at IS NULL
        """), {"rid": str(room_id)})).mappings().first()
        return {
            "id": str(row["id"]),
            "title": row["title"],
            "description": None,
            "is_archived": row["is_archived"],
            "member_count": int(cnt["n"]),
            "owner_id": str(row["owner_id"]),
            "linked_type": row["linked_type"],
            "linked_id": str(row["linked_id"]) if row["linked_id"] else None,
        }

    async def add_member(self, room_id: UUID, user_id: UUID, role: str,
                         added_by: UUID) -> dict:
        """Add member to room."""
        room = (await self.session.execute(text(
            "SELECT 1 FROM chat.rooms WHERE id = :rid"),
            {"rid": str(room_id)})).first()
        if not room:
            raise APIError(error_code="ROOM_NOT_FOUND",
                           message="اتاق یافت نشد.", status_code=404)
        await self.session.execute(text("""
            INSERT INTO chat.room_members (room_id, user_id, role, joined_at)
            VALUES (:rid, :uid, :role, now())
            ON CONFLICT (room_id, user_id)
            DO UPDATE SET left_at = NULL, role = EXCLUDED.role
        """), {"rid": str(room_id), "uid": str(user_id), "role": role})
        await self.session.commit()
        return {"status": "added", "room_id": str(room_id), "user_id": str(user_id)}

    async def send_message(self, room_id: UUID, body: str,
                           sender_id: UUID) -> SimpleNamespace:
        """Send a chat message."""
        room = (await self.session.execute(text("""
            SELECT is_archived, owner_id FROM chat.rooms WHERE id = :rid
        """), {"rid": str(room_id)})).mappings().first()
        if not room:
            raise APIError(error_code="ROOM_NOT_FOUND",
                           message="اتاق یافت نشد.", status_code=404)
        if room["is_archived"] and str(room["owner_id"]) != str(sender_id):
            raise APIError(error_code="ROOM_ARCHIVED",
                           message="اتاق آرشیو شده است.", status_code=403)
        if not await self._member_of(room_id, sender_id):
            raise APIError(error_code="NOT_MEMBER",
                           message="شما عضو این اتاق نیستید.", status_code=403)
        if len(body) > 4000:
            raise APIError(error_code="MESSAGE_TOO_LONG",
                           message="متن پیام بیش از حد مجاز است.", status_code=400)
        row = (await self.session.execute(text("""
            INSERT INTO chat.messages (room_id, sender_id, body, message_type, is_edited)
            VALUES (:rid, :uid, :body, 'text', FALSE)
            RETURNING id, room_id, sender_id, body, created_at, message_type, is_edited
        """), {"rid": str(room_id), "uid": str(sender_id), "body": body})).mappings().first()
        await self.session.commit()
        return SimpleNamespace(**dict(row))

    async def get_messages(self, room_id: UUID, viewer_id: UUID) -> List[dict]:
        """Get messages for a room."""
        if not await self._member_of(room_id, viewer_id):
            return []
        rows = (await self.session.execute(text("""
            SELECT id, room_id, sender_id, body, message_type, is_edited,
                   is_edited AS edited, created_at
              FROM chat.messages
             WHERE room_id = :rid AND deleted_at IS NULL
             ORDER BY created_at ASC
             LIMIT 200
        """), {"rid": str(room_id)})).mappings().all()
        return [{
            "id": str(m["id"]),
            "room_id": str(m["room_id"]),
            "sender_id": str(m["sender_id"]),
            "body": m["body"],
            "sender_name": "user",
            "created_at": _iso(m["created_at"]),
            "message_type": m["message_type"],
            "is_edited": m["is_edited"],
        } for m in rows]

    async def archive_room(self, room_id: UUID, archived_by: UUID) -> dict:
        """Archive a chat room."""
        room = (await self.session.execute(text("""
            SELECT owner_id FROM chat.rooms WHERE id = :rid
        """), {"rid": str(room_id)})).mappings().first()
        if not room:
            raise APIError(error_code="ROOM_NOT_FOUND",
                           message="اتاق یافت نشد.", status_code=404)
        if str(room["owner_id"]) != str(archived_by):
            raise APIError(error_code="PERMISSION_DENIED",
                           message="شما اجازه آرشیو این اتاق را ندارید.", status_code=403)
        await self.session.execute(text("""
            UPDATE chat.rooms SET is_archived = TRUE, archived_at = now()
             WHERE id = :rid
        """), {"rid": str(room_id)})
        await self.session.commit()
        return {"status": "archived"}
```

================================================================================
## FILE: backend/app/modules/files/__init__.py
================================================================================

```python
"""File storage module public interface (real DDL)."""
from app.modules.files.api.routes import router

__all__ = ["router"]
```

================================================================================
## FILE: backend/app/modules/files/db/models.py
================================================================================

```python
"""
app/modules/files/db/models.py

مدل ``files.uploads`` — عیناً طبق DDL سند معماری v2.0 (بخش مربوط به
schema files، همان بخشی که جدول ``chat.messages`` هم در آن است).
این ماژول قبلاً فقط یک ``api/`` خالی بود؛ هیچ db/services نداشت.
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import CHAR, BigInteger, Boolean, DateTime, String
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func

try:
    from app.core.db.base import Base
except ImportError:  # pragma: no cover
    from sqlalchemy.orm import DeclarativeBase

    class Base(DeclarativeBase):  # type: ignore[no-redef]
        pass


MAX_UPLOAD_SIZE_BYTES = 52_428_800  # ۵۰ مگابایت — طبق CHECK constraint سند


class Upload(Base):
    __tablename__ = "uploads"
    __table_args__ = {"schema": "files"}

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True)
    uploader_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    context_type: Mapped[str] = mapped_column(String(32), nullable=False)  # chat|task_attachment|avatar
    context_id: Mapped[UUID | None] = mapped_column(PG_UUID(as_uuid=True), nullable=True)
    original_name: Mapped[str] = mapped_column(String(255), nullable=False)
    object_key: Mapped[str] = mapped_column(String(512), nullable=False, unique=True)
    mime_declared: Mapped[str | None] = mapped_column(String(128), nullable=True)
    mime_detected: Mapped[str | None] = mapped_column(String(128), nullable=True)
    size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    sha256: Mapped[str] = mapped_column(CHAR(64), nullable=False)
    scan_status: Mapped[str] = mapped_column(String(16), nullable=False, server_default="pending")
    scan_engine: Mapped[str | None] = mapped_column(String(32), nullable=True)
    scanned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    is_available: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
```

================================================================================
## FILE: backend/app/modules/files/services/file_service.py
================================================================================

```python
"""
app/modules/files/services/file_service.py

سه قدم اصلی طبق دیاگرام توالی سند:
  ۱) presign_upload   — کلاینت مستقیم به S3/MinIO آپلود می‌کند (نه از طریق API ما)
  ۲) finalize_upload  — بعد از آپلود موفق کلاینت، این را صدا می‌زند؛ رکورد DB
                          ساخته و اسکن AV (فعلاً هم‌زمان) اجرا می‌شود
  ۳) get_download_url — فقط اگر ``is_available=True`` باشد URL می‌دهد
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID, uuid4

from app.core.errors import APIError
from app.modules.files.db.models import MAX_UPLOAD_SIZE_BYTES, Upload
from app.modules.files.services.av_scan_service import AvScanService
from app.modules.files.services.storage import ObjectStorageClient
from app.modules.files.services.validators import (
    ALLOWED_EXTENSIONS,
    FileValidationError,
    validate_extension,
    validate_size,
)


class FileService:
    def __init__(
        self, session: Any, storage: ObjectStorageClient,
        av_scan_service: AvScanService, upload_repo: Any,
    ) -> None:
        self.session = session
        self.storage = storage
        self.av_scan_service = av_scan_service
        self.upload_repo = upload_repo

    async def presign_upload(
        self, *, uploader_id: UUID, context_type: str, context_id: UUID | None,
        filename: str, size_bytes: int,
    ) -> dict:
        try:
            ext = validate_extension(filename)
            validate_size(size_bytes)
        except FileValidationError as exc:
            raise APIError(error_code=exc.code, message=exc.message, status_code=400) from exc

        object_key = self._build_object_key(context_type, ext)
        content_type = ALLOWED_EXTENSIONS[ext]
        put_url = self.storage.presigned_put_url(object_key, content_type)

        return {
            "upload_url": put_url,
            "object_key": object_key,
            "expires_in": 300,
            "max_size_bytes": MAX_UPLOAD_SIZE_BYTES,
        }

    async def finalize_upload(
        self, *, uploader_id: UUID, context_type: str, context_id: UUID | None,
        object_key: str, original_name: str, size_bytes: int,
        mime_declared: str | None, sha256: str,
    ) -> dict:
        validate_size(size_bytes)  # دوباره چک می‌شود — کلاینت می‌توانست دروغ بگوید

        upload = Upload(
            id=uuid4(),
            uploader_id=uploader_id,
            context_type=context_type,
            context_id=context_id,
            original_name=original_name,
            object_key=object_key,
            mime_declared=mime_declared,
            size_bytes=size_bytes,
            sha256=sha256,
            scan_status="pending",
            is_available=False,
        )
        await self.upload_repo.add(upload)
        await self.upload_repo.commit()

        # TODO: وقتی Celery نصب شد، این خط به یک task غیرهمزمان منتقل شود
        # تا کاربر منتظر نتیجه‌ی اسکن نماند (سند دقیقاً همین را می‌خواهد).
        await self.av_scan_service.scan(upload)
        await self.upload_repo.commit()

        return {
            "file_id": str(upload.id),
            "scan_status": upload.scan_status,
            "is_available": upload.is_available,
        }

    async def get_download_url(self, file_id: UUID, requester_id: UUID) -> str:
        upload = await self.upload_repo.get(file_id)
        if upload is None:
            raise APIError(error_code="FILE_NOT_FOUND", message="فایل یافت نشد.", status_code=404)
        if not upload.is_available:
            raise APIError(
                error_code="FILE_NOT_AVAILABLE",
                message="فایل هنوز در دسترس نیست (در انتظار اسکن یا آلوده تشخیص داده شده).",
                status_code=403,
            )
        # TODO: اینجا دقیقاً جایی است که باید مجوز دسترسی به context (پیام
        # چت/تسک) را هم چک کنید — از طریق PolicyEngine ماژول sharing؛ من به
        # آن کد دسترسی ندارم، پس این‌جا نگذاشتم تا چیزی را اشتباه فرض نکنم.
        return self.storage.presigned_get_url(upload.object_key, upload.original_name)

    def _build_object_key(self, context_type: str, ext: str) -> str:
        now = datetime.now(timezone.utc)
        return f"{context_type}/{now.year:04d}/{now.month:02d}/{uuid4()}{ext}"
```

================================================================================
## FILE: backend/app/modules/notification/__init__.py
================================================================================

```python
"""Notification module public interface (real DDL).

Subscribes to auth login / role-change events and writes a
notification row for the affected user (inbox channel).
"""

from app.modules.notification.api.routes import router
from app.modules.notification.events import register_event_handlers

__all__ = ["router", "register_event_handlers"]
```

================================================================================
## FILE: backend/app/modules/notification/events.py
================================================================================

```python
"""Notification module event handlers (real DDL, M10).

Subscribes to selected domain events and persists an inbox notification
inside the same transaction (transactional=True), exactly like the
audit module.  The bus invokes ``handler(event, session)`` with the
publisher's session, so no separate DB wiring is needed.

Idempotency: handled out-of-the-box by the bus for transactional
consumers (publishers do not re-fire failed events synchronously).
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

logger = logging.getLogger("notification.events")

# Event type strings (kept literal, per module-boundary rule).
AUTH_LOGIN_SUCCEEDED = "auth.login.succeeded"
AUTH_LOGIN_FAILED = "auth.login.failed"
AUTH_PASSWORD_CHANGED = "auth.password.changed"
AUTH_DEVICE_TRUSTED = "auth.device.trusted"
RBAC_ROLE_ASSIGNED = "rbac.role.assigned"

_TITLES = {
    AUTH_LOGIN_SUCCEEDED: "ورود موفق",
    AUTH_LOGIN_FAILED: "ورود ناموفق",
    AUTH_PASSWORD_CHANGED: "تغییر رمز عبور",
    AUTH_DEVICE_TRUSTED: "دستگاه مورد اعتماد",
    RBAC_ROLE_ASSIGNED: "نقش جدید",
}

_ALL = tuple(_TITLES.keys())


def register_event_handlers(bus) -> None:
    """Subscribe to domain events that produce inbox notifications.

    Transactional (synchronous, same-transaction) consumers are the
    right fit here: the notification row should roll back with the
    domain transaction, and the publisher's session is provided by
    the bus on every ``publish()`` call.
    """
    for evt in _ALL:
        bus.subscribe(evt, _handle, transactional=True)


async def _handle(event: Any, session: Any) -> None:
    from app.modules.notification.services.notification_service import NotificationService

    event_type = getattr(event, "event_type", "")
    actor_id = getattr(event, "actor_id", None)
    payload = getattr(event, "payload", None) or {}

    if not actor_id:
        actor_id = payload.get("user_id") or payload.get("identifier")
        if not actor_id:
            return

    title = _TITLES.get(event_type, event_type)
    kind = event_type.rsplit(".", 1)[-1]
    created = None
    try:
        svc = NotificationService(session)
        created = await svc.create({
            "user_id": actor_id,
            "type": kind,
            "title": title,
            "message": payload.get("reason"),
            "data": payload,
            "priority": "normal",
        })
    except Exception:
        logger.exception("failed to persist notification event_type=%s", event_type)
        raise

    _publish_live(actor_id, created, event_type, title, payload)


def _publish_live(actor_id: Any, created: Any, event_type: str, title: str,
                  payload: dict) -> None:
    """Push a live event to any open ``/ws/notifications`` socket."""
    import json

    try:
        from app.core.redis import get_redis_broker

        broker = get_redis_broker()
        msg = {
            "type": "notification",
            "event_type": event_type,
            "id": str(getattr(created, "id", "")),
            "title": title,
            "message": payload.get("reason"),
            "created_at": getattr(created, "created_at", None),
        }
        asyncio.get_running_loop().create_task(
            broker.publish(f"notifications:{actor_id}", json.dumps(msg, ensure_ascii=False, default=str))
        )
    except Exception:
        logger.debug("live notification publish skipped", exc_info=True)
```

================================================================================
## FILE: backend/app/modules/notification/services/notification_service.py
================================================================================

```python
"""Notification service — real DDL (M10).

Raw SQL against schema ``notification``: notifications, preferences, log.
"""

from __future__ import annotations

import json
from datetime import datetime
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
        elif isinstance(v, (dict, list)):
            d[k] = json.dumps(v, ensure_ascii=False)
    return d


class NotificationStateMachine:
    """Manages notifications, delivery log and user preferences."""

    def __init__(self, session):
        self.session = session

    # --- Create / list ---

    async def create(self, spec: dict) -> SimpleNamespace:
        """Persist a notification with default priority."""
        row = (await self.session.execute(text("""
            INSERT INTO notification.notifications (
                user_id, type, title, message, data,
                is_read, action_url, action_text,
                related_entity_type, related_entity_id,
                priority, expires_at
            )
            VALUES (:uid, :type, :title, :msg, :data,
                    FALSE, :aurl, :atext,
                    :rtype, :rid,
                    :prio, :exp)
            RETURNING id, created_at, is_read
        """), {
            "uid": str(spec["user_id"]),
            "type": spec["type"],
            "title": spec["title"],
            "msg": spec.get("message"),
            "data": json.dumps(spec.get("data")) if spec.get("data") else None,
            "aurl": spec.get("action_url"),
            "atext": spec.get("action_text"),
            "rtype": spec.get("related_entity_type"),
            "rid": str(spec["related_entity_id"]) if spec.get("related_entity_id") else None,
            "prio": spec.get("priority", "normal"),
            "exp": spec.get("expires_at"),
        })).mappings().first()
        await self.session.commit()
        return SimpleNamespace(id=row["id"], created_at=_iso(row["created_at"]),
                               is_read=row["is_read"])

    async def list_for_user(self, user_id: UUID, limit: int = 50,
                            unread_only: bool = False) -> list[dict]:
        """List recent notifications, newest first."""
        conds, params = ["user_id = :uid"], {"uid": str(user_id)}
        if unread_only:
            conds.append("is_read = FALSE")
        rows = (await self.session.execute(text(f"""
            SELECT id, type, title, message, data, is_read,
                   action_url, action_text, priority, created_at, read_at
              FROM notification.notifications
             WHERE {" AND ".join(conds)}
             ORDER BY created_at DESC
             LIMIT {int(limit)}
        """), params)).mappings().all()
        return [_row_serialize(r) for r in rows]

    async def unread_count(self, user_id: UUID) -> int:
        row = (await self.session.execute(text("""
            SELECT count(*) AS n FROM notification.notifications
             WHERE user_id = :uid AND is_read = FALSE
        """), {"uid": str(user_id)})).mappings().first()
        return row["n"] or 0

    async def mark_read(self, user_id: UUID, notification_id: UUID) -> SimpleNamespace:
        row = (await self.session.execute(text("""
            UPDATE notification.notifications
               SET is_read = TRUE, read_at = now()
             WHERE id = :nid AND user_id = :uid
          RETURNING id, is_read, read_at
        """), {"nid": str(notification_id), "uid": str(user_id)})).mappings().first()
        await self.session.commit()
        if not row:
            raise NotFoundError(resource="notification")
        return SimpleNamespace(id=row["id"], is_read=row["is_read"],
                               read_at=_iso(row["read_at"]))

    async def mark_all_read(self, user_id: UUID) -> int:
        result = (await self.session.execute(text("""
            UPDATE notification.notifications
               SET is_read = TRUE, read_at = now()
             WHERE user_id = :uid AND is_read = FALSE
        """), {"uid": str(user_id)}))
        await self.session.commit()
        return result.rowcount

    # --- Preferences ---

    async def get_preferences(self, user_id: UUID) -> dict:
        row = (await self.session.execute(text("""
            SELECT user_id, email_enabled, push_enabled, inbox_enabled,
                   types, quiet_hours_start, quiet_hours_end
              FROM notification.preferences WHERE user_id = :uid
        """), {"uid": str(user_id)})).mappings().first()
        if not row:
            await self._ensure_preferences(user_id)
            row = (await self.session.execute(text("""
                SELECT user_id, email_enabled, push_enabled, inbox_enabled,
                       types, quiet_hours_start, quiet_hours_end
                  FROM notification.preferences WHERE user_id = :uid
            """), {"uid": str(user_id)})).mappings().first()
        return _row_serialize(row)

    async def _ensure_preferences(self, user_id: UUID) -> None:
        await self.session.execute(text("""
            INSERT INTO notification.preferences (user_id, email_enabled,
                push_enabled, inbox_enabled, types)
            VALUES (:uid, TRUE, TRUE, TRUE,
                    '{"all": true}'::jsonb)
            ON CONFLICT (user_id) DO NOTHING
        """), {"uid": str(user_id)})
        await self.session.commit()

    async def update_preferences(self, user_id: UUID, patch: dict) -> dict:
        from app.modules.notification.ports import PreferencesUpdate
        valid = PreferencesUpdate(**patch)
        upserts = []
        params: dict = {"uid": str(user_id)}
        fields = [("email_enabled", "email_enabled"), ("push_enabled", "push_enabled"),
                  ("inbox_enabled", "inbox_enabled"), ("quiet_hours_start", "qhs"),
                  ("quiet_hours_end", "qhe")]
        for col, key in fields:
            val = getattr(valid, col)
            if val is not None:
                upserts.append(f"{col} = :{key}")
                params[key] = val
        if valid.types is not None:
            upserts.append("types = :types")
            params["types"] = json.dumps(valid.types, ensure_ascii=False)
        await self._ensure_preferences(user_id)
        if upserts:
            upserts.append("updated_at = now()")
            await self.session.execute(text(f"""
                UPDATE notification.preferences
                   SET {" , ".join(upserts)}
                 WHERE user_id = :uid
            """), params)
            await self.session.commit()
        return await self.get_preferences(user_id)

    # --- Delivery log ---

    async def log_delivery(self, user_id: UUID, notification_id: UUID,
                           action: str, ip: Optional[str] = None,
                           ua: Optional[str] = None) -> None:
        await self.session.execute(text("""
            INSERT INTO notification.log (user_id, action, notification_id,
                                          ip_address, user_agent)
            VALUES (:uid, :act, :nid, :ip, :ua)
        """), {"uid": str(user_id), "act": action, "nid": str(notification_id),
               "ip": ip, "ua": ua})
        await self.session.commit()


NotificationService = NotificationStateMachine
```

================================================================================
## FILE: backend/app/ws/__init__.py
================================================================================

```python
"""WebSocket gateway (architecture ADR-05, sections 8.1, 12.8).

Exposes ``/ws/chat`` and ``/ws/notifications`` plus the connection
manager wired to the configurable Redis primary key.
"""
```

================================================================================
## MISSING FILES (not found in source repo)
================================================================================

- [MISSING] `﻿backend/app/ws/connection_manager.py`
- [MISSING] `backend/app/ws/auth_handshake.py`
- [MISSING] `backend/app/ws/rate_limiter.py`
- [MISSING] `backend/app/ws/router.py`
- [MISSING] `backend/app/modules/chat/api/router.py`
- [MISSING] `backend/app/modules/chat/db/repository.py`
- [MISSING] `backend/app/modules/chat/services/__init__.py`
- [MISSING] `backend/app/modules/chat/services/message_service.py`
- [MISSING] `backend/app/modules/chat/schemas.py`
- [MISSING] `backend/app/modules/chat/events.py`
- [MISSING] `backend/app/modules/notification/api/router.py`
- [MISSING] `backend/app/modules/notification/db/models.py`
- [MISSING] `backend/app/modules/notification/services/__init__.py`
- [MISSING] `backend/app/modules/notification/services/email_service.py`
- [MISSING] `backend/app/modules/notification/schemas.py`
- [MISSING] `backend/app/modules/files/api/router.py`
- [MISSING] `backend/app/modules/files/services/__init__.py`
- [MISSING] `backend/app/modules/files/services/minio_service.py`
- [MISSING] `backend/app/modules/files/services/av_scanner.py`
- [MISSING] `backend/app/modules/files/schemas.py`
- [MISSING] `backend/app/modules/files/events.py`

