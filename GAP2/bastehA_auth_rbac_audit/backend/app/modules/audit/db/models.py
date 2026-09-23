"""
app/modules/audit/db/models.py

مدل‌های ORM جدول‌های ماژول Audit — دقیقاً مطابق DDL سند معماری v2.0،
بخش ۴.۸. این فایل قبلاً وجود نداشت (پوشه‌ی db/ اصلاً زیر
app/modules/audit/ نبود) — پس اینجا از صفر ساخته شده، بدون ریسک
تداخل با چیزی که از قبل بود.

⚠️ پارتیشن‌بندی (`PARTITION BY RANGE (timestamp)`) در سطح ORM پیاده
نشده — پارتیشن‌بندی یک تصمیم DDL/عملیاتی است که باید در Migration
دستی مدیریت شود (پارتیشن‌های فصلی جدید باید هر فصل ساخته شوند؛
معمولاً با یک Job زمان‌بندی‌شده). برای MVP، جدول ساده (بدون
پارتیشن) کاملاً کار می‌کند؛ پارتیشن‌بندی را می‌توان بعداً، وقتی حجم
داده واقعاً به آن نیاز پیدا کرد، از طریق یک migration جدا اضافه کرد.

⚠️ فرض: ``from app.core.db.base import Base`` — مثل outbox.py، اگر
اسم/مسیر واقعی فرق دارد فقط این import را در هر دو فایل یکسان اصلاح
کنید.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import CHAR, Boolean, DateTime, SmallInteger, String, Text, BigInteger
from sqlalchemy.dialects.postgresql import INET, JSONB, UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func

try:
    from app.core.db.base import Base
except ImportError:  # pragma: no cover — فقط برای import مستقل این فایل
    from sqlalchemy.orm import DeclarativeBase

    class Base(DeclarativeBase):  # type: ignore[no-redef]
        pass


class AuditLog(Base):
    """``audit.audit_logs`` — لاگ عمومی همه‌ی عملیات (سند، بخش ۴.۸)."""

    __tablename__ = "audit_logs"
    __table_args__ = {"schema": "audit"}

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    user_id: Mapped[UUID | None] = mapped_column(PG_UUID(as_uuid=True), nullable=True)
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    entity_type: Mapped[str | None] = mapped_column(String(50), nullable=True)
    entity_id: Mapped[UUID | None] = mapped_column(PG_UUID(as_uuid=True), nullable=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    # هویت شبکه و دستگاه
    ip_address: Mapped[str | None] = mapped_column(INET, nullable=True)
    mac_address: Mapped[str | None] = mapped_column(String(17), nullable=True)
    mac_verified: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    device_fingerprint: Mapped[str | None] = mapped_column(String(255), nullable=True)
    device_id: Mapped[UUID | None] = mapped_column(PG_UUID(as_uuid=True), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(Text, nullable=True)
    session_id: Mapped[UUID | None] = mapped_column(PG_UUID(as_uuid=True), nullable=True)

    result: Mapped[str] = mapped_column(String(20), nullable=False)  # success|failure|denied
    details: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    old_value: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    new_value: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    geo_location: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    request_id: Mapped[UUID | None] = mapped_column(PG_UUID(as_uuid=True), nullable=True)
    correlation_id: Mapped[UUID | None] = mapped_column(PG_UUID(as_uuid=True), nullable=True)

    # یکپارچگی — زنجیره‌ی هش
    prev_hash: Mapped[str | None] = mapped_column(CHAR(64), nullable=True)
    row_hash: Mapped[str] = mapped_column(CHAR(64), nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class LoginAuditLog(Base):
    """``audit.login_audit_logs`` — لاگ اختصاصی تلاش‌های ورود (سند، بخش ۴.۸)."""

    __tablename__ = "login_audit_logs"
    __table_args__ = {"schema": "audit"}

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    user_id: Mapped[UUID | None] = mapped_column(PG_UUID(as_uuid=True), nullable=True)
    username: Mapped[str | None] = mapped_column(String(100), nullable=True)
    national_id_hash: Mapped[str | None] = mapped_column(CHAR(64), nullable=True)
    auth_method: Mapped[str] = mapped_column(String(20), nullable=False)  # local|sso|ldap|kerberos
    mfa_used: Mapped[str | None] = mapped_column(String(16), nullable=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    ip_address: Mapped[str | None] = mapped_column(INET, nullable=True)
    mac_address: Mapped[str | None] = mapped_column(String(17), nullable=True)
    mac_verified: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    device_fingerprint: Mapped[str | None] = mapped_column(String(255), nullable=True)
    device_is_trusted: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    user_agent: Mapped[str | None] = mapped_column(Text, nullable=True)
    success: Mapped[bool] = mapped_column(Boolean, nullable=False)
    failure_reason: Mapped[str | None] = mapped_column(String(255), nullable=True)
    session_id: Mapped[UUID | None] = mapped_column(PG_UUID(as_uuid=True), nullable=True)
    geo_location: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    risk_score: Mapped[int | None] = mapped_column(SmallInteger, nullable=True)  # 0..100

    prev_hash: Mapped[str | None] = mapped_column(CHAR(64), nullable=True)
    row_hash: Mapped[str] = mapped_column(CHAR(64), nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
