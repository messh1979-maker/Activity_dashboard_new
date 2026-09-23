"""
app/modules/audit/services/audit_service.py

پیاده‌سازی واقعی «ثبت Audit Log با زنجیره‌ی هش»، طبق بخش ۱۲.۳ سند.

⚠️ تفاوت آگاهانه با نمونه‌کد سند: نمونه‌ی سند همه‌ی اطلاعات هویتی
(ip، mac، device_fingerprint و...) را از ``request_ctx.get()``
می‌خواند. آن ContextVar/middleware (``app/core/middleware/``) هنوز
در این پروژه ساخته نشده (طبق بررسی پوشه‌ها). پس اینجا این مقادیر را
به‌عنوان پارامتر ورودی اختیاری می‌گیرد (پیش‌فرض None) — همین امروز
کار می‌کند، و وقتی context/middleware واقعی ساخته شد، فراخوان
(events.py) فقط باید این آرگومان‌ها را از آن‌جا پر کند؛ امضای
AuditService عوض نمی‌شود.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from app.modules.audit.db.models import AuditLog, LoginAuditLog
from app.modules.audit.db.repositories import AuditRepository

# فیلدهایی که هرگز نباید خام در JSONB جزئیات audit ذخیره شوند —
# حتی اگر caller اشتباهاً آن‌ها را در payload بگذارد.
_SENSITIVE_KEYS = {
    "password", "password_hash", "current_password", "new_password",
    "national_id", "refresh_token", "access_token", "hmac_key",
    "secret", "otp", "mfa_token",
}


def mask_sensitive(value: dict[str, Any] | None) -> dict[str, Any] | None:
    """یک لایه‌ی دفاعی ساده — کلیدهای حساس را قبل از نوشتن در Audit پاک می‌کند."""
    if value is None:
        return None
    return {
        k: ("***REDACTED***" if k.lower() in _SENSITIVE_KEYS else v)
        for k, v in value.items()
    }


class AuditService:
    def __init__(self, session: Any) -> None:
        self.session = session
        self.repo = AuditRepository(session)

    async def log(
        self,
        *,
        action: str,
        result: str = "success",
        user_id: UUID | None = None,
        entity_type: str | None = None,
        entity_id: UUID | None = None,
        old_value: dict[str, Any] | None = None,
        new_value: dict[str, Any] | None = None,
        details: dict[str, Any] | None = None,
        ip_address: str | None = None,
        mac_address: str | None = None,
        mac_verified: bool = False,
        device_fingerprint: str | None = None,
        device_id: UUID | None = None,
        user_agent: str | None = None,
        session_id: UUID | None = None,
        request_id: UUID | None = None,
        correlation_id: UUID | None = None,
    ) -> AuditLog:
        """یک ردیف در ``audit.audit_logs`` می‌نویسد و آن را به زنجیره‌ی هش وصل می‌کند."""
        prev_hash = await self.repo.last_audit_log_hash()

        row = AuditLog(
            user_id=user_id, action=action, result=result,
            entity_type=entity_type, entity_id=entity_id,
            timestamp=datetime.now(timezone.utc),
            ip_address=ip_address, mac_address=mac_address, mac_verified=mac_verified,
            device_fingerprint=device_fingerprint, device_id=device_id,
            user_agent=user_agent, session_id=session_id,
            old_value=mask_sensitive(old_value), new_value=mask_sensitive(new_value),
            details=mask_sensitive(details),
            request_id=request_id, correlation_id=correlation_id,
            prev_hash=prev_hash,
        )
        row.row_hash = self._chain_hash_audit(prev_hash, row)
        self.session.add(row)  # همان تراکنش عملیات اصلی — طبق سند
        return row

    async def log_login(
        self,
        *,
        success: bool,
        auth_method: str,
        user_id: UUID | None = None,
        username: str | None = None,
        national_id_hash: str | None = None,
        mfa_used: str | None = None,
        failure_reason: str | None = None,
        ip_address: str | None = None,
        mac_address: str | None = None,
        mac_verified: bool = False,
        device_fingerprint: str | None = None,
        device_is_trusted: bool | None = None,
        user_agent: str | None = None,
        session_id: UUID | None = None,
        risk_score: int | None = None,
    ) -> LoginAuditLog:
        """یک ردیف در ``audit.login_audit_logs`` می‌نویسد (جدول اختصاصی لاگین، سند بخش ۴.۸)."""
        prev_hash = await self.repo.last_login_audit_hash()

        row = LoginAuditLog(
            user_id=user_id, username=username, national_id_hash=national_id_hash,
            auth_method=auth_method, mfa_used=mfa_used,
            timestamp=datetime.now(timezone.utc),
            ip_address=ip_address, mac_address=mac_address, mac_verified=mac_verified,
            device_fingerprint=device_fingerprint, device_is_trusted=device_is_trusted,
            user_agent=user_agent, success=success, failure_reason=failure_reason,
            session_id=session_id, risk_score=risk_score,
            prev_hash=prev_hash,
        )
        row.row_hash = self._chain_hash_login(prev_hash, row)
        self.session.add(row)
        return row

    # ── زنجیره‌ی هش — دقیقاً طبق فرمول بخش ۴.۸:
    #    row_hash = SHA256(prev_hash ‖ id ‖ user_id ‖ action ‖ timestamp ‖ ip ‖ mac ‖ result ‖ details)
    #    نکته: چون `id` قبل از INSERT واقعی (autoincrement) هنوز مقدار ندارد،
    #    از تلفیق (prev_hash + سایر فیلدهای معین‌شده در همین لحظه) استفاده
    #    می‌شود — دقیقاً مثل نمونه‌کد سند در ۱۲.۳ که هم `id` را در فرمول
    #    متنی نمی‌آورد (چون در لحظه‌ی ساخت شیء هنوز تعیین نشده).

    @staticmethod
    def _chain_hash_audit(prev_hash: str | None, row: AuditLog) -> str:
        material = "|".join([
            prev_hash or "GENESIS",
            str(row.user_id), row.action,
            row.timestamp.isoformat(),
            str(row.ip_address) if row.ip_address else "",
            row.mac_address or "",
            row.result,
            json.dumps(row.details, sort_keys=True, ensure_ascii=False) if row.details else "null",
        ])
        return hashlib.sha256(material.encode()).hexdigest()

    @staticmethod
    def _chain_hash_login(prev_hash: str | None, row: LoginAuditLog) -> str:
        material = "|".join([
            prev_hash or "GENESIS",
            str(row.user_id), row.username or "",
            row.timestamp.isoformat(),
            str(row.ip_address) if row.ip_address else "",
            row.mac_address or "",
            "success" if row.success else "failure",
            row.failure_reason or "",
        ])
        return hashlib.sha256(material.encode()).hexdigest()
