"""
app/modules/audit/db/repositories.py

``last_row_hash`` باید زیر یک قفل مشورتی (advisory lock) خوانده شود تا
اگر دو نوشته‌ی audit هم‌زمان اتفاق بیفتد، هر دو یک ``prev_hash`` یکسان
نخوانند (که زنجیره را می‌شکند). طبق سند (بخش ۱۲.۳): «قفل مشورتی برای
ترتیب صحیح».

از ``pg_advisory_xact_lock`` استفاده شده (نه ``pg_advisory_lock``)
چون قفل تراکنشی است — خودکار در پایان تراکنش (commit/rollback) آزاد
می‌شود؛ نیازی به unlock دستی نیست و در صورت کرش سرویس، قفل باقی
نمی‌ماند.
"""

from __future__ import annotations

from typing import Type

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.modules.audit.db.models import AuditLog, LoginAuditLog

# عدد دلخواه ولی ثابت برای هر زنجیره — دو زنجیره‌ی audit_logs و
# login_audit_logs مستقل از هم قفل می‌شوند (کلید متفاوت برای هرکدام)
# تا نوشتن هم‌زمان روی یکی، دیگری را بلاک نکند.
_LOCK_KEY_AUDIT_LOGS = "audit_hash_chain:audit_logs"
_LOCK_KEY_LOGIN_LOGS = "audit_hash_chain:login_audit_logs"


class AuditRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def last_audit_log_hash(self) -> str | None:
        await self.session.execute(
            text("SELECT pg_advisory_xact_lock(hashtext(:key))"),
            {"key": _LOCK_KEY_AUDIT_LOGS},
        )
        result = await self.session.execute(
            select(AuditLog.row_hash).order_by(AuditLog.id.desc()).limit(1)
        )
        return result.scalar_one_or_none()

    async def last_login_audit_hash(self) -> str | None:
        await self.session.execute(
            text("SELECT pg_advisory_xact_lock(hashtext(:key))"),
            {"key": _LOCK_KEY_LOGIN_LOGS},
        )
        result = await self.session.execute(
            select(LoginAuditLog.row_hash).order_by(LoginAuditLog.id.desc()).limit(1)
        )
        return result.scalar_one_or_none()
