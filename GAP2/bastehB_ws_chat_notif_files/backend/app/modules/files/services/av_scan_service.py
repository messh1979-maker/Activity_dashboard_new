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
