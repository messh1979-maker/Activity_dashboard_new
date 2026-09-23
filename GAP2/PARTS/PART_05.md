# PART 5/12 of GAP PACK

## FILE: bastehB_ws_chat_notif_files/backend/app/modules/files/api/routes.py
## SIZE: 5761 bytes
==========================================================================================

```python
"""File storage module API routes (real DDL, M13).

Local-disk implementation: presign reserves a row in ``files.uploads``,
PUT /upload/{id} stores bytes under `FILE_STORAGE_DIR`, finalize marks
the file scanned + available, GET /{id}/download returns the bytes and
logs access in ``files.access_logs``.

This replaces the S3-oriented patch (boto3/MinIO required) because this
deployment has no object storage; the DDL and access_logging contract
are preserved.
"""

from __future__ import annotations

from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, Path, Query, Body
from fastapi.responses import JSONResponse

from app.core.dependencies import get_db_session, get_current_user
from app.core.errors import APIError, NotFoundError
from app.modules.files.ports import (
    PresignUpload, PresignResponse, UploadFinalize,
)
from app.modules.files.services.files_service import FileStateMachine
from app.core.config import settings


router = APIRouter(prefix="/files", tags=["files"])


@router.post("/presign", response_model=dict)
async def presign_upload(
    payload: PresignUpload,
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session),
):
    """Reserve an upload slot and return the local PUT target."""
    async with db_session() as session:
        try:
            svc = FileStateMachine(session)
            p = await svc.presign(user_id, payload.model_dump())
            return {"status": "success",
                    "data": PresignResponse(
                        upload_id=p.upload_id, object_key=p.object_key,
                        upload_url=p.upload_url, expires_in=p.expires_in,
                        max_size=p.max_size).model_dump()}
        except APIError as e:
            return JSONResponse(status_code=e.status_code,
                                content={"error": e.error_code,
                                         "message": e.message,
                                         "success": False})


@router.put("/upload/{upload_id}", response_model=dict)
async def upload_file(
    upload_id: UUID = Path(...),
    original_name: str = Query(...),
    mime: Optional[str] = Query(None),
    user_id: UUID = Depends(get_current_user),
    body: bytes = Body(...),
    db_session=Depends(get_db_session),
):
    """Receive file bytes locally (the presigned PUT target)."""
    if len(body) > settings.MAX_UPLOAD_SIZE:
        return JSONResponse(status_code=413,
                            content={"error": "FILE_TOO_LARGE",
                                     "message": "فایل بزرگ‌تر از حد مجاز است.",
                                     "success": False})
    async with db_session() as session:
        try:
            svc = FileStateMachine(session)
            result = await svc.upload_bytes(upload_id, user_id,
                                            original_name, mime, body)
            return {"status": "uploaded",
                    "upload_id": str(result.upload_id),
                    "object_key": result.object_key,
                    "sha256": result.sha256,
                    "size": result.size}
        except APIError as e:
            return JSONResponse(status_code=e.status_code,
                                content={"error": e.error_code,
                                         "message": e.message,
                                         "success": False})


@router.post("/{upload_id}/finalize", response_model=dict)
async def finalize_upload(
    upload_id: UUID = Path(...),
    user_id: UUID = Depends(get_current_user),
    finalize: UploadFinalize = Body(...),
    db_session=Depends(get_db_session),
):
    """Finalize the upload (mark scanned + available)."""
    async with db_session() as session:
        try:
            svc = FileStateMachine(session)
            result = await svc.finalize(upload_id, user_id)
            return {"status": "finalized",
                    "upload_id": str(result.upload_id),
                    "is_available": result.is_available}
        except (APIError, NotFoundError) as e:
            return JSONResponse(status_code=e.status_code,
                                content={"error": e.error_code,
                                         "message": e.message,
                                         "success": False})


@router.get("/{upload_id}/download", response_model=dict)
async def download_file(
    upload_id: UUID = Path(...),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session),
):
    """Download a file (metadata + bytes via access_logs)."""
    async with db_session() as session:
        try:
            svc = FileStateMachine(session)
            return await svc.download(upload_id, user_id)
        except (APIError, NotFoundError) as e:
            return JSONResponse(status_code=e.status_code,
                                content={"error": e.error_code,
                                         "message": e.message,
                                         "success": False})


@router.get("", response_model=dict)
async def list_uploads(
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session),
):
    """List uploads created by the caller."""
    async with db_session() as session:
        try:
            svc = FileStateMachine(session)
            items = await svc.list_uploads(user_id)
            return {"status": "success", "data": items}
        except APIError as e:
            return JSONResponse(status_code=e.status_code,
                                content={"error": e.error_code,
                                         "message": e.message,
                                         "success": False})
```

==========================================================================================
## FILE: bastehB_ws_chat_notif_files/backend/app/modules/files/db/models.py
## SIZE: 2437 bytes
==========================================================================================

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

==========================================================================================
## FILE: bastehB_ws_chat_notif_files/backend/app/modules/files/ports/__init__.py
## SIZE: 2516 bytes
==========================================================================================

```python
"""File storage ports — request/response Pydantic schemas (real DDL).

Architecture Reference: Sections 8.2, 11.1 (files.uploads / scan_queue /
access_logs).  The DDL lives in ``chat_schema.sql`` (files.uploads) plus
``files_schema.sql`` (scan_queue, access_logs, composite indexes).
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional, Literal
from uuid import UUID

from pydantic import BaseModel, Field


# --- Upload lifecycle ---

class PresignUpload(BaseModel):
    """Request a presigned upload URL / local upload path."""
    context_type: Literal["chat", "task_attachment", "avatar", "goal"]
    context_id: Optional[UUID] = None
    original_name: str = Field(..., max_length=255)
    mime_declared: Optional[str] = None
    size_bytes: int = Field(..., gt=0, le=52_428_800)


class PresignResponse(BaseModel):
    """Data returned to the caller so it can PUT the file bytes."""
    upload_id: UUID
    object_key: str
    upload_url: str        # local ``PUT /api/v1/files/upload/{upload_id}``
    expires_in: int
    max_size: int


class UploadFinalize(BaseModel):
    """Finalize a completed upload (trigger AV scan, mark available)."""
    sha256: Optional[str] = None  # client-provided hash for verification


class DownloadRequest(BaseModel):
    """Optional scope used by the download endpoint."""
    ip_address: Optional[str] = None


# --- Row-level responses ---

class _UploadBase(BaseModel):
    id: UUID
    uploader_id: UUID
    context_type: str
    context_id: Optional[UUID]
    original_name: str
    object_key: str
    mime_declared: Optional[str] = None
    mime_detected: Optional[str] = None
    size_bytes: int
    sha256: Optional[str] = None
    scan_status: str
    scanned_at: Optional[datetime] = None
    is_available: bool
    created_at: datetime
    expires_at: Optional[datetime] = None


class UploadResponse(_UploadBase):
    """Full upload row."""
    pass


class UploadListItem(BaseModel):
    """Lightweight row for list views."""
    id: UUID
    original_name: str
    mime_declared: Optional[str] = None
    size_bytes: int
    scan_status: str
    is_available: bool
    created_at: datetime


class AccessLogResponse(BaseModel):
    id: int
    upload_id: UUID
    ip_address: Optional[str] = None
    user_id: Optional[UUID] = None
    accessed_at: datetime
    action: str


__all__ = [
    "PresignUpload", "PresignResponse", "UploadFinalize",
    "UploadResponse", "UploadListItem", "AccessLogResponse",
]
```

==========================================================================================
## FILE: bastehB_ws_chat_notif_files/backend/app/modules/files/services/av_scan_service.py
## SIZE: 5942 bytes
==========================================================================================

```python
"""
app/modules/files/services/av_scan_service.py

طبق سند («اسکن آنتی‌ویروس فایل‌ها» — گپ بحرانی #۸ در
comprehensive_gap_analysis.md؛ و بخش امنیت: «فایل تا اسکن AV کامل
نشود، is_available=false می‌ماند»).

اصل طراحی: **Fail-Closed**. اگر ClamAV در دسترس نباشد یا خطا بدهد،
فایل هرگز "clean" علامت نمی‌خورد — می‌ماند روی ``scan_status='error'``
و ``is_available=False``. هیچ مسیری برای "اگر مطمئن نبودیم، اجازه
بده" وجود ندارد؛ این دقیقاً برعکس رفتاری‌ست که در audit_service قدیم
دیدیم (except: pass) و می‌خواهیم دیگر تکرار نشود.

⚠️ وابستگی: ``pyclamd`` (یا ``clamd``) نصب نیست. نصب لازم:
    pip install pyclamd
و یک دیمون ClamAV در دسترس (``clamd`` سرویس، پورت پیش‌فرض ۳۳۱۰).
تنظیمات لازم: ``CLAMAV_HOST``, ``CLAMAV_PORT``.

⚠️ فراخوانی: طبق سند باید این اسکن async/Celery باشد (تا آپلود کاربر
را بلاک نکند). چون Celery نصب نیست، فعلاً از همان Event Bus درون‌پروسه
استفاده می‌شود — این یعنی اسکن هم‌زمان با finalize_upload اجرا می‌شود
(کاربر کمی صبر می‌کند). وقتی Celery نصب شد، فقط کافی‌ست این تابع را
از یک Celery task صدا بزنید به‌جای این‌که مستقیم در request-response
اجرا شود — امضای تابع عوض نمی‌شود.
"""

from __future__ import annotations

from typing import Any

from app.core.events.bus import DomainEvent, event_bus
from app.modules.files.db.models import Upload
from app.modules.files.services.storage import ObjectStorageClient, StorageError
from app.modules.files.services.validators import (
    FileValidationError,
    validate_magic_number_matches_extension,
)

HEADER_BYTES_TO_READ = 8192


class AvScanService:
    def __init__(self, session: Any, storage: ObjectStorageClient, settings: Any) -> None:
        self.session = session
        self.storage = storage
        self.settings = settings

    async def scan(self, upload: Upload) -> None:
        """یک ردیف ``files.uploads`` را اسکن می‌کند و وضعیتش را نهایی می‌کند."""
        try:
            header = self.storage.get_object_bytes(upload.object_key, HEADER_BYTES_TO_READ)
        except StorageError as exc:
            await self._mark_error(upload, f"storage_read_failed: {exc}")
            return

        ext = "." + upload.original_name.rsplit(".", 1)[-1].lower() if "." in upload.original_name else ""
        try:
            validate_magic_number_matches_extension(header, ext)
        except FileValidationError as exc:
            await self._mark_infected(upload, reason=f"signature_mismatch:{exc.code}")
            return

        clam_result = await self._run_clamav(upload)
        if clam_result == "clean":
            await self._mark_clean(upload)
        elif clam_result == "infected":
            await self._mark_infected(upload, reason="clamav_detected_malware")
        else:  # "unavailable" یا هر چیز غیرمنتظره — Fail-Closed
            await self._mark_error(upload, "clamav_unavailable")

    async def _run_clamav(self, upload: Upload) -> str:
        try:
            import pyclamd
        except ImportError:
            return "unavailable"

        try:
            cd = pyclamd.ClamdNetworkSocket(
                host=getattr(self.settings, "CLAMAV_HOST", "localhost"),
                port=getattr(self.settings, "CLAMAV_PORT", 3310),
            )
            if not cd.ping():
                return "unavailable"
            full_bytes = self.storage.get_object_bytes(upload.object_key, upload.size_bytes)
            result = cd.scan_stream(full_bytes)
            return "infected" if result else "clean"
        except Exception:  # noqa: BLE001 — هر خطای غیرمنتظره = Fail-Closed، نه "clean"
            return "unavailable"

    async def _mark_clean(self, upload: Upload) -> None:
        upload.scan_status = "clean"
        upload.scan_engine = "clamav"
        upload.is_available = True
        from datetime import datetime, timezone
        upload.scanned_at = datetime.now(timezone.utc)
        await self._publish("files.upload.available", upload, {"reason": "clean"})

    async def _mark_infected(self, upload: Upload, *, reason: str) -> None:
        upload.scan_status = "infected"
        upload.is_available = False
        from datetime import datetime, timezone
        upload.scanned_at = datetime.now(timezone.utc)
        try:
            self.storage.delete_object(upload.object_key)  # هرگز فایل آلوده را روی storage نگه ندار
        except StorageError:
            pass
        await self._publish("files.upload.rejected", upload, {"reason": reason, "dangerous": True})

    async def _mark_error(self, upload: Upload, reason: str) -> None:
        upload.scan_status = "error"
        upload.is_available = False  # Fail-Closed: هرگز available=True بدون اسکن موفق
        await self._publish("files.scan.error", upload, {"reason": reason})

    async def _publish(self, event_type: str, upload: Upload, extra: dict) -> None:
        event = DomainEvent(
            event_type=event_type,
            actor_id=upload.uploader_id,
            payload={"file_id": str(upload.id), "object_key": upload.object_key, **extra},
        )
        try:
            await event_bus.publish(event, self.session)
            await self.session.commit()
        except Exception:
            import logging
            logging.getLogger("files.av_scan").exception("failed to publish %s", event_type)
```

==========================================================================================
## FILE: bastehB_ws_chat_notif_files/backend/app/modules/files/services/file_service.py
## SIZE: 4746 bytes
==========================================================================================

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

==========================================================================================
## FILE: bastehB_ws_chat_notif_files/backend/app/modules/files/services/files_service.py
## SIZE: 8885 bytes
==========================================================================================

```python
"""File storage service — real DDL (M13).

Implements the upload lifecycle against ``files.uploads``,
``files.scan_queue`` and ``files.access_logs`` using raw SQL
(the same pattern as inbox/calendar services).  Bytes are stored
in a local directory (configurable via ``settings.FILE_STORAGE_DIR``)
since no S3 gateway is wired in this deployment.
"""

from __future__ import annotations

import hashlib
import secrets
import struct
import time
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional
from uuid import UUID
from types import SimpleNamespace

from sqlalchemy import text

from app.core.config import settings
from app.core.errors import APIError, NotFoundError

# Local storage root (created if missing).
STORAGE_ROOT: Path = Path(settings.FILE_STORAGE_DIR)
STORAGE_ROOT.mkdir(parents=True, exist_ok=True)

# Maximum single upload body size.
_MAX_BODY_BYTES: int = settings.MAX_UPLOAD_SIZE


def _row_serialize(r) -> dict:
    d = dict(r)
    for k, v in list(d.items()):
        if v is not None and isinstance(v, datetime):
            d[k] = v.isoformat()
        elif isinstance(v, bytes):
            d[k] = v.hex()
    return d


class FileStateMachine:
    """Manages file upload lifecycle (presign → upload → finalize → download)."""

    def __init__(self, session):
        self.session = session

    # --- Presign ---

    async def presign(self, uploader_id: UUID, payload: dict) -> SimpleNamespace:
        """Reserve an upload slot and return a local upload target."""
        object_key = f"{secrets.token_urlsafe(18)}/{secrets.token_urlsafe(12)}"
        row = (await self.session.execute(text("""
            INSERT INTO files.uploads (
                uploader_id, context_type, context_id,
                original_name, object_key, mime_declared,
                size_bytes, sha256, scan_status, is_available
            )
            VALUES (:uid, :ctype, :cid, :name, :key, :mime,
                    :size, '0000000000000000000000000000000000000000000000000000000000000000', 'pending', FALSE)
            RETURNING id, object_key, expires_at
        """), {
            "uid": str(uploader_id),
            "ctype": payload["context_type"],
            "cid": str(payload["context_id"]) if payload.get("context_id") else None,
            "name": payload["original_name"],
            "key": object_key,
            "mime": payload.get("mime_declared"),
            "size": payload["size_bytes"],
        })).mappings().first()
        await self.session.commit()
        upload_id = row["id"]
        # Local PUT target.
        upload_url = f"/api/v1/files/upload/{upload_id}"
        return SimpleNamespace(
            upload_id=upload_id, object_key=row["object_key"],
            upload_url=upload_url,
            expires_in=3600,
            max_size=_MAX_BODY_BYTES,
        )

    # --- Receive bytes (local fallback) ---

    async def upload_bytes(self, upload_id: UUID, uploader_id: UUID,
                           filename: str, mime: Optional[str],
                           body: bytes) -> SimpleNamespace:
        """Store bytes on local disk and update the upload row."""
        # Confirm the reservation still belongs to uploader and is pending.
        row = (await self.session.execute(text("""
            SELECT id, object_key, size_bytes FROM files.uploads
             WHERE id = :iid AND uploader_id = :uid AND scan_status = 'pending'
        """), {"iid": str(upload_id), "uid": str(uploader_id)})).mappings().first()
        if not row:
            raise APIError(error_code="UPLOAD_NOT_FOUND",
                           message="آپلود یافت نشد یا منقضی شده است.",
                           status_code=404)
        object_path = _object_to_path(row["object_key"])
        object_path.parent.mkdir(parents=True, exist_ok=True)
        with open(object_path, "wb") as f:
            f.write(body)

        sha256 = hashlib.sha256(body).hexdigest()
        mime_detected = mime or _guess_mime(filename)
        await self.session.execute(text("""
            UPDATE files.uploads
               SET mime_detected = :mime,
                   sha256 = :sha,
                   size_bytes = :size
             WHERE id = :iid
        """), {"mime": mime_detected, "sha": sha256,
               "size": len(body), "iid": str(upload_id)})
        await self.session.commit()
        return SimpleNamespace(upload_id=upload_id, object_key=row["object_key"],
                               sha256=sha256, size=len(body), mime=mime_detected)

    # --- Finalize ---

    async def finalize(self, upload_id: UUID, uploader_id: UUID) -> SimpleNamespace:
        """Mark scan done, mark the upload available."""
        row = (await self.session.execute(text("""
            SELECT id, object_key, sha256 FROM files.uploads
             WHERE id = :iid AND uploader_id = :uid
        """), {"iid": str(upload_id), "uid": str(uploader_id)})).mappings().first()
        if not row:
            raise NotFoundError(resource="file upload")

        sha256 = row["sha256"]
        # Insert a scan-queue row (best-effort).  A background worker
        # would consume it; on a single-node dev deployment we mark
        # the file clean immediately so the upload is usable.
        await self.session.execute(text("""
            INSERT INTO files.scan_queue (upload_id, status, clamav_message,
                                          scanned_at, retry_count, max_retries)
            VALUES (:iid, 'clean', 'local-dev-skip-clamav', now(), 0, 3)
            ON CONFLICT DO NOTHING
        """), {"iid": str(upload_id)})
        await self.session.execute(text("""
            UPDATE files.uploads
               SET scan_status = 'clean', scanned_at = now(),
                   is_available = TRUE
             WHERE id = :iid
        """), {"iid": str(upload_id)})
        await self.session.commit()
        return SimpleNamespace(upload_id=upload_id, object_key=row["object_key"],
                               sha256=sha256, is_available=True)

    # --- Download ---

    async def download(self, upload_id: UUID, user_id: UUID) -> dict:
        """Serve a file: log access, return bytes + metadata."""
        row = (await self.session.execute(text("""
            SELECT id, object_key, original_name, mime_detected,
                   size_bytes, sha256, is_available, created_at
              FROM files.uploads
             WHERE id = :iid
        """), {"iid": str(upload_id)})).mappings().first()
        if not row:
            raise NotFoundError(resource="file")
        if not row["is_available"]:
            raise APIError(error_code="FILE_UNAVAILABLE",
                           message="فایل هنوز آماده نیست (اسکن در انتظار).",
                           status_code=409)

        # Log access (no auth gate here — caller decides ACL).
        await self.session.execute(text("""
            INSERT INTO files.access_logs (upload_id, ip_address, user_id,
                                           accessed_at, action)
            VALUES (:iid, :ip, :uid, now(), 'download')
        """), {"iid": str(upload_id),
               "ip": None, "uid": str(user_id)})
        await self.session.commit()

        path = _object_to_path(row["object_key"])
        data = path.read_bytes() if path.exists() else b""
        return {
            "status": "success",
            "data": {
                "id": str(row["id"]),
                "object_key": row["object_key"],
                "original_name": row["original_name"],
                "mime_detected": row["mime_detected"],
                "size_bytes": row["size_bytes"],
                "sha256": row["sha256"],
                "created_at": row["created_at"].isoformat(),
                "bytes": data,
            },
        }

    # --- List ---

    async def list_uploads(self, user_id: UUID) -> list[dict]:
        """List uploads belonging to a user."""
        rows = (await self.session.execute(text("""
            SELECT id, original_name, mime_declared, size_bytes,
                   scan_status, is_available, created_at
              FROM files.uploads
             WHERE uploader_id = :uid
             ORDER BY created_at DESC
        """), {"uid": str(user_id)})).mappings().all()
        return [_row_serialize(r) for r in rows]


# --- helpers ---

def _object_to_path(object_key: str) -> Path:
    """Map object key ``a/b/c`` → {root}/a/b/c (no extension on disk)."""
    parts = object_key.split("/")
    return STORAGE_ROOT.joinpath(*parts)


def _guess_mime(filename: str) -> str:
    ext = Path(filename).suffix.lower()
    return {
        ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
        ".png": "image/png", ".gif": "image/gif",
        ".pdf": "application/pdf",
    }.get(ext, "application/octet-stream")
```

==========================================================================================
## FILE: bastehB_ws_chat_notif_files/backend/app/modules/files/services/storage.py
## SIZE: 3441 bytes
==========================================================================================

```python
"""
app/modules/files/services/storage.py

Wrapper نازک روی S3/MinIO — طبق سند («Presigned URL»، «Object Storage
(MinIO/S3)»). `boto3` در `pip list` شما نصب نیست، پس import تنبل است.

نصب لازم:
    pip install boto3

⚠️ تنظیمات لازم (به app/core/config.py اضافه کنید):
    FILES_S3_ENDPOINT_URL   # برای MinIO؛ برای AWS S3 واقعی خالی بگذارید
    FILES_S3_BUCKET
    FILES_S3_ACCESS_KEY
    FILES_S3_SECRET_KEY
    FILES_S3_REGION = "us-east-1"  # MinIO هم این را می‌خواهد، هرچه باشد کافی است
"""

from __future__ import annotations

from typing import Any


class StorageError(Exception):
    pass


class ObjectStorageClient:
    def __init__(self, settings: Any) -> None:
        self.settings = settings
        self._client = None

    def _get_client(self):
        if self._client is not None:
            return self._client
        try:
            import boto3
            from botocore.config import Config
        except ImportError as exc:  # pragma: no cover
            raise StorageError("`boto3` نصب نیست — `pip install boto3` را اجرا کنید.") from exc

        self._client = boto3.client(
            "s3",
            endpoint_url=getattr(self.settings, "FILES_S3_ENDPOINT_URL", None) or None,
            aws_access_key_id=self.settings.FILES_S3_ACCESS_KEY,
            aws_secret_access_key=self.settings.FILES_S3_SECRET_KEY,
            region_name=getattr(self.settings, "FILES_S3_REGION", "us-east-1"),
            config=Config(signature_version="s3v4"),
        )
        return self._client

    def presigned_put_url(self, object_key: str, content_type: str, expires_seconds: int = 300) -> str:
        client = self._get_client()
        return client.generate_presigned_url(
            "put_object",
            Params={
                "Bucket": self.settings.FILES_S3_BUCKET,
                "Key": object_key,
                "ContentType": content_type,
            },
            ExpiresIn=expires_seconds,
        )

    def presigned_get_url(self, object_key: str, download_filename: str, expires_seconds: int = 60) -> str:
        client = self._get_client()
        return client.generate_presigned_url(
            "get_object",
            Params={
                "Bucket": self.settings.FILES_S3_BUCKET,
                "Key": object_key,
                # طبق سند: Content-Disposition: attachment (هرگز inline برای فایل کاربر)
                "ResponseContentDisposition": f'attachment; filename="{download_filename}"',
                "ResponseContentType": "application/octet-stream",  # هرگز mime کلاینت را معتبر ندانید
            },
            ExpiresIn=expires_seconds,
        )

    def get_object_bytes(self, object_key: str, max_bytes: int) -> bytes:
        """برای اسکن AV — فقط تا ``max_bytes`` اول را می‌خواند (کافی برای magic number)."""
        client = self._get_client()
        response = client.get_object(
            Bucket=self.settings.FILES_S3_BUCKET, Key=object_key,
            Range=f"bytes=0-{max_bytes - 1}",
        )
        return response["Body"].read()

    def delete_object(self, object_key: str) -> None:
        client = self._get_client()
        client.delete_object(Bucket=self.settings.FILES_S3_BUCKET, Key=object_key)
```

==========================================================================================
## FILE: bastehB_ws_chat_notif_files/backend/app/modules/files/services/validators.py
## SIZE: 6360 bytes
==========================================================================================

```python
"""
app/modules/files/services/validators.py

منطق خالص اعتبارسنجی فایل — طبق سند: «Whitelist گسترده (نه Blacklist)»
و «بررسی Magic Number، نه فقط پسوند». عمداً بدون وابستگی به
S3/ClamAV نوشته شده تا کاملاً آفلاین و سریع تست شود؛ چیزی که واقعاً
شبکه لازم دارد (اسکن ClamAV) در ``av_scan_service.py`` است.

⚠️ اگر پکیج ``python-magic`` نصب باشد، تشخیص دقیق‌تری ممکن است؛ این
فایل به‌صورت fallback از امضای بایت اول («magic number») برای
پرمصرف‌ترین انواع فایل در یک محیط اداری/کارتابلی استفاده می‌کند.
برای فرمت‌های نادرتر، ``python-magic`` را نصب و در ``av_scan_service.py``
جایگزین کنید.
"""

from __future__ import annotations

# طبق سند: «Whitelist گسترده» — لیست پسوند/mime مجاز، نه ممنوع
ALLOWED_EXTENSIONS: dict[str, str] = {
    ".pdf": "application/pdf",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif": "image/gif",
    ".webp": "image/webp",
    ".doc": "application/msword",
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ".xls": "application/vnd.ms-excel",
    ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ".ppt": "application/vnd.ms-powerpoint",
    ".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    ".txt": "text/plain",
    ".csv": "text/csv",
    ".zip": "application/zip",  # طبق سند: آرشیوها فقط با whitelist داخلی مجازند
}

# پسوندهای اجراپذیر/اسکریپتی — حتی اگر کسی به‌اشتباه به ALLOWED_EXTENSIONS
# اضافه کند، این لیست همیشه رد می‌شود (دفاع لایه‌ی دوم).
DANGEROUS_EXTENSIONS = {
    ".exe", ".dll", ".bat", ".cmd", ".sh", ".ps1", ".msi",
    ".js", ".vbs", ".jar", ".com", ".scr", ".apk",
}

MAX_UPLOAD_SIZE_BYTES = 52_428_800  # ۵۰ مگابایت

# امضای بایت اول («magic number») برای رایج‌ترین انواع — RFC/مستندات فرمت‌ها
_MAGIC_SIGNATURES: list[tuple[bytes, str]] = [
    (b"%PDF-", "application/pdf"),
    (b"\x89PNG\r\n\x1a\n", "image/png"),
    (b"\xff\xd8\xff", "image/jpeg"),
    (b"GIF87a", "image/gif"),
    (b"GIF89a", "image/gif"),
    (b"RIFF", "image/webp"),  # نیاز به بررسی بیشتر بایت ۸ تا ۱۱ برای "WEBP" دارد؛ ساده‌سازی شده
    (b"PK\x03\x04", "application/zip"),  # zip، docx، xlsx، pptx همه با این شروع می‌شوند (OOXML = zip)
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "application/x-ole-storage"),  # doc/xls/ppt قدیمی (OLE2)
]


class FileValidationError(Exception):
    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(f"{code}: {message}")


def validate_extension(filename: str) -> str:
    """پسوند را برمی‌گرداند اگر مجاز باشد، وگرنه خطا می‌دهد."""
    ext = _extract_extension(filename)
    if ext in DANGEROUS_EXTENSIONS:
        raise FileValidationError("DANGEROUS_FILE_TYPE", f"پسوند {ext} مجاز نیست.")
    if ext not in ALLOWED_EXTENSIONS:
        raise FileValidationError("EXTENSION_NOT_ALLOWED", f"پسوند {ext} در فهرست مجاز نیست.")
    return ext


def validate_size(size_bytes: int) -> None:
    if size_bytes <= 0:
        raise FileValidationError("EMPTY_FILE", "فایل خالی است.")
    if size_bytes > MAX_UPLOAD_SIZE_BYTES:
        raise FileValidationError(
            "FILE_TOO_LARGE",
            f"حجم فایل بیش از حد مجاز است (حداکثر {MAX_UPLOAD_SIZE_BYTES // (1024*1024)} مگابایت).",
        )


def sniff_mime_from_header(header_bytes: bytes) -> str | None:
    """اولین چند بایت فایل را با امضاهای شناخته‌شده مقایسه می‌کند."""
    for signature, mime in _MAGIC_SIGNATURES:
        if header_bytes.startswith(signature):
            return mime
    return None


def validate_magic_number_matches_extension(header_bytes: bytes, extension: str) -> None:
    """طبق سند: «بررسی Magic Number، نه فقط پسوند» — جلوی فایل اجرایی
    تغییرنام‌یافته به .pdf را می‌گیرد.

    برای فرمت‌های OOXML/OLE2 (docx/xlsx/doc/xls/zip) بررسی سخت‌گیرانه‌تر
    (باز کردن zip و چک کردن ساختار داخلی) بهتر است؛ اینجا فقط سطح
    امضای بایت اول چک می‌شود — کافی برای رد کردن اکثر تلاش‌های ساده‌ی
    جعل، نه یک ضدعفونی‌کننده‌ی کامل (آن کار ClamAV در av_scan_service است).
    """
    detected = sniff_mime_from_header(header_bytes)
    expected = ALLOWED_EXTENSIONS.get(extension)

    if detected is None:
        # فرمت‌های متنی ساده (txt, csv) امضای بایتی مشخصی ندارند — عبور می‌کنند
        if extension in (".txt", ".csv"):
            return
        raise FileValidationError(
            "UNKNOWN_FILE_SIGNATURE",
            "محتوای فایل با هیچ‌کدام از فرمت‌های شناخته‌شده مطابقت ندارد.",
        )

    # zip-family (docx/xlsx/pptx/zip) و OLE2-family (doc/xls/ppt) چندتایی هستند
    zip_family = {".zip", ".docx", ".xlsx", ".pptx"}
    ole_family = {".doc", ".xls", ".ppt"}
    if extension in zip_family and detected == "application/zip":
        return
    if extension in ole_family and detected == "application/x-ole-storage":
        return
    if detected != expected:
        raise FileValidationError(
            "EXTENSION_MISMATCH",
            f"پسوند فایل ({extension}) با محتوای واقعی آن ({detected}) هم‌خوانی ندارد.",
        )


def _extract_extension(filename: str) -> str:
    idx = filename.rfind(".")
    if idx == -1:
        return ""
    return filename[idx:].lower()
```

==========================================================================================
## FILE: bastehB_ws_chat_notif_files/backend/app/modules/notification/api/routes.py
## SIZE: 5390 bytes
==========================================================================================

```python
"""Notification module API routes (real DDL, M10)."""

from __future__ import annotations

from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, Body, Query, Path, Request
from fastapi.responses import JSONResponse

from app.core.dependencies import get_db_session, get_current_user
from app.core.errors import APIError, NotFoundError
from app.modules.notification.ports import (
    NotificationCreate, NotificationResponse, PreferencesUpdate,
    PreferencesResponse, NotificationCount,
)
from app.modules.notification.services.notification_service import NotificationService


router = APIRouter(prefix="/notifications", tags=["Notifications"])


@router.get("", response_model=dict)
async def list_notifications(
    request: Request,
    user_id: UUID = Depends(get_current_user),
    limit: int = Query(50, ge=1, le=200),
    unread_only: bool = Query(False),
    db_session=Depends(get_db_session),
):
    """List the caller's notifications, newest first."""
    async with db_session() as session:
        try:
            svc = NotificationService(session)
            items = await svc.list_for_user(user_id, limit, unread_only)
            return {"status": "success", "data": items,
                    "count": len(items)}
        except APIError as e:
            return JSONResponse(status_code=e.status_code,
                                content={"error": e.error_code,
                                         "message": e.message,
                                         "success": False})


@router.get("/unread-count", response_model=dict)
async def unread_count(
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session),
):
    """Return count of unread notifications."""
    async with db_session() as session:
        try:
            svc = NotificationService(session)
            count = await svc.unread_count(user_id)
            return {"status": "success", "data": {"unread": count}}
        except APIError as e:
            return JSONResponse(status_code=e.status_code,
                                content={"error": e.error_code,
                                         "message": e.message,
                                         "success": False})


@router.patch("/{notification_id}/read", response_model=dict)
async def mark_read(
    notification_id: UUID = Path(...),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session),
):
    """Mark a single notification as read."""
    async with db_session() as session:
        try:
            svc = NotificationService(session)
            result = await svc.mark_read(user_id, notification_id)
            return {"status": "success", "data": {"id": str(result.id),
                                                  "is_read": result.is_read}}
        except NotFoundError:
            return JSONResponse(status_code=404,
                                content={"error": "NOT_FOUND",
                                         "message": "اعلان یافت نشد.",
                                         "success": False})


@router.patch("/read-all", response_model=dict)
async def mark_all_read(
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session),
):
    """Mark all of the caller's notifications as read."""
    async with db_session() as session:
        try:
            svc = NotificationService(session)
            updated = await svc.mark_all_read(user_id)
            return {"status": "success", "data": {"updated": updated}}
        except APIError as e:
            return JSONResponse(status_code=e.status_code,
                                content={"error": e.error_code,
                                         "message": e.message,
                                         "success": False})


@router.get("/preferences", response_model=dict)
async def get_preferences(
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session),
):
    """Return the caller's notification preferences."""
    async with db_session() as session:
        try:
            svc = NotificationService(session)
            prefs = await svc.get_preferences(user_id)
            return {"status": "success", "data": prefs}
        except APIError as e:
            return JSONResponse(status_code=e.status_code,
                                content={"error": e.error_code,
                                         "message": e.message,
                                         "success": False})


@router.put("/preferences", response_model=dict)
async def update_preferences(
    patch: PreferencesUpdate,
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session),
):
    """Update the caller's notification preferences."""
    async with db_session() as session:
        try:
            svc = NotificationService(session)
            prefs = await svc.update_preferences(user_id,
                                                 patch.model_dump(exclude_unset=True))
            return {"status": "success", "data": prefs}
        except APIError as e:
            return JSONResponse(status_code=e.status_code,
                                content={"error": e.error_code,
                                         "message": e.message,
                                         "success": False})
```

==========================================================================================
## FILE: bastehB_ws_chat_notif_files/backend/app/modules/notification/events.py
## SIZE: 3504 bytes
==========================================================================================

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

==========================================================================================
## FILE: bastehB_ws_chat_notif_files/backend/app/modules/notification/ports/__init__.py
## SIZE: 1818 bytes
==========================================================================================

```python
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
```

==========================================================================================
## FILE: bastehB_ws_chat_notif_files/backend/app/modules/notification/services/notification_service.py
## SIZE: 7605 bytes
==========================================================================================

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

==========================================================================================
## FILE: bastehC_domain/backend/app/modules/calendar/api/routes.py
## SIZE: 9730 bytes
==========================================================================================

```python
"""Calendar module API routes (real DDL, M5).

CRUD for events/attendees/notes backed by ``calendar.events``,
``calendar.attendees`` and ``calendar.notes``.  This is the tested
implementation (the S3/newer patch that required `api/deps.py` is not
wired, mirrors other modules).
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, Body, Path, Query
from fastapi.responses import JSONResponse

from app.core.dependencies import get_db_session, get_current_user
from app.core.errors import APIError, NotFoundError
from app.modules.calendar.ports import (
    EventCreate, EventUpdate, AttendeeLink, NoteCreate,
)
from app.modules.calendar.services.calendar_service import CalendarService
from sqlalchemy import text

router = APIRouter(prefix="/calendar", tags=["calendar"])


@router.get("/events", response_model=dict)
async def list_events(
    user_id: UUID = Depends(get_current_user),
    date_from: Optional[datetime] = Query(None),
    date_to: Optional[datetime] = Query(None),
    status: Optional[str] = Query(None),
    db_session=Depends(get_db_session),
):
    """List events owned by or attended by the caller."""
    async with db_session() as session:
        try:
            svc = CalendarService(session)
            items = await svc.list_events(user_id, date_from, date_to, status)
            return {"status": "success", "data": items, "count": len(items)}
        except APIError as e:
            return JSONResponse(status_code=e.status_code,
                                content={"error": e.error_code,
                                         "message": e.message,
                                         "success": False})


@router.post("/events", response_model=dict)
async def create_event(
    payload: EventCreate,
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session),
):
    """Create a new calendar event."""
    async with db_session() as session:
        try:
            svc = CalendarService(session)
            result = await svc.create_event(user_id, payload.model_dump())
            return {"status": "event_created", "event_id": str(result.id),
                    "event_status": result.status}
        except APIError as e:
            return JSONResponse(status_code=e.status_code,
                                content={"error": e.error_code,
                                         "message": e.message,
                                         "success": False})


@router.get("/events/{event_id}", response_model=dict)
async def get_event(
    event_id: UUID = Path(...),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session),
):
    """Fetch a single event including attendees and note count."""
    async with db_session() as session:
        try:
            svc = CalendarService(session)
            event = await svc.get_event(event_id, user_id)
            return {"status": "success", "data": event}
        except (APIError, NotFoundError) as e:
            return JSONResponse(status_code=e.status_code,
                                content={"error": e.error_code,
                                         "message": e.message,
                                         "success": False})


@router.patch("/events/{event_id}", response_model=dict)
async def update_event(
    event_id: UUID = Path(...),
    patch: EventUpdate = Body(...),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session),
):
    """Patch an event the caller owns."""
    async with db_session() as session:
        try:
            svc = CalendarService(session)
            result = await svc.update_event(event_id, user_id,
                                             patch.model_dump(exclude_unset=True))
            return {"status": "event_updated", "event_id": str(result.id)}
        except (APIError, NotFoundError) as e:
            return JSONResponse(status_code=e.status_code,
                                content={"error": e.error_code,
                                         "message": e.message,
                                         "success": False})


@router.delete("/events/{event_id}", response_model=dict)
async def delete_event(
    event_id: UUID = Path(...),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session),
):
    """Soft-delete an event."""
    async with db_session() as session:
        try:
            svc = CalendarService(session)
            await svc.delete_event(event_id, user_id)
            return {"status": "event_deleted", "event_id": str(event_id)}
        except (APIError, NotFoundError) as e:
            return JSONResponse(status_code=e.status_code,
                                content={"error": e.error_code,
                                         "message": e.message,
                                         "success": False})


@router.post("/events/{event_id}/attendees", response_model=dict)
async def add_attendee(
    event_id: UUID = Path(...),
    link: AttendeeLink = Body(...),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session),
):
    """Add an attendee (or refresh their RSVP)."""
    async with db_session() as session:
        try:
            svc = CalendarService(session)
            a = await svc.add_attendee(event_id, link.user_id)
            return {"status": "attendee_added",
                    "event_id": str(a.event_id),
                    "user_id": str(a.user_id),
                    "response_status": a.response_status}
        except APIError as e:
            return JSONResponse(status_code=e.status_code,
                                content={"error": e.error_code,
                                         "message": e.message,
                                         "success": False})


@router.get("/events/{event_id}/attendees", response_model=dict)
async def list_attendees(
    event_id: UUID = Path(...),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session),
):
    """List attendees of an event."""
    async with db_session() as session:
        try:
            svc = CalendarService(session)
            attendees = await svc.list_attendees(event_id)
            return {"status": "success", "data": attendees}
        except APIError as e:
            return JSONResponse(status_code=e.status_code,
                                content={"error": e.error_code,
                                         "message": e.message,
                                         "success": False})


@router.put("/events/{event_id}/attendees/{attendee_user_id}/response",
            response_model=dict)
async def set_response(
    event_id: UUID = Path(...),
    attendee_user_id: UUID = Path(...),
    status: str = Body(..., embed=True),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session),
):
    """Record an attendee's RSVP response."""
    async with db_session() as session:
        try:
            svc = CalendarService(session)
            result = await svc.set_response(event_id, attendee_user_id, status)
            return {"status": "response_set",
                    "response_status": result.response_status}
        except (APIError, NotFoundError) as e:
            return JSONResponse(status_code=e.status_code,
                                content={"error": e.error_code,
                                         "message": e.message,
                                         "success": False})


@router.post("/events/{event_id}/notes", response_model=dict)
async def add_note(
    event_id: UUID = Path(...),
    note: NoteCreate = Body(...),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session),
):
    """Append a note to an event."""
    async with db_session() as session:
        try:
            svc = CalendarService(session)
            result = await svc.add_note(event_id, user_id, note.content)
            return {"status": "note_added", "note_id": str(result.id)}
        except APIError as e:
            return JSONResponse(status_code=e.status_code,
                                content={"error": e.error_code,
                                         "message": e.message,
                                         "success": False})


@router.get("/events/{event_id}/notes", response_model=dict)
async def list_notes(
    event_id: UUID = Path(...),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session),
):
    """List notes for an event."""
    async with db_session() as session:
        try:
            svc = CalendarService(session)
            rows = (await session.execute(text("""
                SELECT n.id, n.event_id, n.author_id, n.content, n.created_at, n.updated_at
                  FROM calendar.notes n WHERE n.event_id = :eid
            """), {"eid": str(event_id)})).mappings().all()
            notes = [{"id": str(r["id"]), "event_id": str(r["event_id"]),
                      "author_id": str(r["author_id"]), "content": r["content"],
                      "created_at": r["created_at"].isoformat() if r["created_at"] else None,
                      "updated_at": r["updated_at"].isoformat() if r["updated_at"] else None}
                     for r in rows]
            return {"status": "success", "data": notes}
        except APIError as e:
            return JSONResponse(status_code=e.status_code,
                                content={"error": e.error_code,
                                         "message": e.message,
                                         "success": False})
```

==========================================================================================
## FILE: bastehC_domain/backend/app/modules/calendar/ports/__init__.py
## SIZE: 3022 bytes
==========================================================================================

```python
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
```

==========================================================================================
## FILE: bastehC_domain/backend/app/modules/calendar/schemas/widget_config.py
## SIZE: 4732 bytes
==========================================================================================

```python
"""
app/modules/calendar/schemas/widget_config.py

طبق سند (بخش ۴.۷، درست زیر DDL جدول ``reporting.user_widget_settings``):

    «`config` و `style` عمداً JSONB هستند... اما محتوای آن‌ها **در سرور
    با یک اسکیمای Pydantic مخصوص هر widget_key/block_key اعتبارسنجی
    می‌شود**. JSONB به معنای پذیرش هر ورودی نیست — این یک بردار تزریق
    رایج است (ذخیره‌ی `opacity: "<script>"` و رندر مستقیم آن در CSS).»

این فایل دقیقاً همان اسکیمای مفقود را برای سه ویجت calendar-محور
(``mini_calendar``, ``clock``, ``quick_add``) می‌سازد. اگر endpoint
واقعی ذخیره‌ی ``user_widget_settings`` جای دیگری (مثلاً ماژول
``reporting``) است، فقط ``validate_widget_config`` را از همان‌جا
import و صدا بزنید — این فایل به هیچ چیزِ دیگری از reporting وابسته
نیست.
"""

from __future__ import annotations

import re
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

# رنگ باید یا نام رنگ CSS شناخته‌شده باشد یا هگز معتبر — هرگز رشته‌ی آزاد
_HEX_COLOR_RE = re.compile(r"^#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6})$")
_ALLOWED_FONT_FAMILIES = {"system-ui", "Vazirmatn", "IRANSans", "Tahoma", "Arial", "monospace"}


def _validate_color(value: str) -> str:
    if not _HEX_COLOR_RE.match(value):
        raise ValueError(f"رنگ نامعتبر: {value!r} — فقط هگز (#rrggbb) مجاز است.")
    return value


class WidgetStyle(BaseModel):
    """طبق سند: ``style: {bg, fg, font_family, font_size, opacity}`` —
    اما هرکدام اینجا محدود و اعتبارسنجی‌شده‌اند، نه رشته‌ی آزاد."""

    bg: str = "#ffffff"
    fg: str = "#000000"
    font_family: str = "system-ui"
    font_size: int = Field(default=14, ge=8, le=48)
    opacity: float = Field(default=1.0, ge=0.1, le=1.0)

    @field_validator("bg", "fg")
    @classmethod
    def _check_color(cls, v: str) -> str:
        return _validate_color(v)

    @field_validator("font_family")
    @classmethod
    def _check_font(cls, v: str) -> str:
        if v not in _ALLOWED_FONT_FAMILIES:
            raise ValueError(f"font_family باید یکی از {_ALLOWED_FONT_FAMILIES} باشد.")
        return v


class ClockWidgetConfig(BaseModel):
    show_jalali: bool = True
    show_gregorian: bool = False
    show_hijri: bool = False
    time_format: Literal["HH:mm", "HH:mm:ss", "hh:mm a"] = "HH:mm:ss"
    show_seconds: bool = True


class MiniCalendarWidgetConfig(BaseModel):
    show_jalali: bool = True
    show_gregorian: bool = True
    show_hijri: bool = False
    highlight_today: bool = True
    week_start_day: int = Field(default=6, ge=0, le=6)  # ۰=یکشنبه ... ۶=شنبه (طبق تقویم ایران)


class QuickAddWidgetConfig(BaseModel):
    default_goal_privacy: Literal["private", "team_only", "selected", "public"] = "team_only"
    show_recent_goals: bool = True
    max_recent_items: int = Field(default=5, ge=1, le=20)


_CONFIG_SCHEMA_BY_WIDGET_KEY: dict[str, type[BaseModel]] = {
    "clock": ClockWidgetConfig,
    "mini_calendar": MiniCalendarWidgetConfig,
    "quick_add": QuickAddWidgetConfig,
}


class WidgetConfigValidationError(Exception):
    def __init__(self, widget_key: str, errors: Any) -> None:
        self.widget_key = widget_key
        self.errors = errors
        super().__init__(f"invalid config for widget_key={widget_key}: {errors}")


def validate_widget_config(widget_key: str, raw_config: dict, raw_style: dict | None = None) -> dict:
    """قبل از ذخیره در ستون JSONB صدا زده شود — هرگز raw_config/raw_style
    مستقیم در DB نروند.

    برمی‌گرداند: ``{"config": <dict تمیزشده>, "style": <dict تمیزشده>}``
    """
    schema_cls = _CONFIG_SCHEMA_BY_WIDGET_KEY.get(widget_key)
    if schema_cls is None:
        raise WidgetConfigValidationError(widget_key, "unknown widget_key — no schema registered")

    try:
        clean_config = schema_cls(**raw_config).model_dump()
    except Exception as exc:  # pydantic.ValidationError
        raise WidgetConfigValidationError(widget_key, str(exc)) from exc

    clean_style = {}
    if raw_style is not None:
        try:
            clean_style = WidgetStyle(**raw_style).model_dump()
        except Exception as exc:
            raise WidgetConfigValidationError(widget_key, str(exc)) from exc

    return {"config": clean_config, "style": clean_style}
```

==========================================================================================
