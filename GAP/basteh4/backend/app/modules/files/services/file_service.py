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
