# BUNDLE: basteh2
# Source: GAP\basteh2
================================================================================

================================================================================
## FILE: backend/app/modules/audit/__init__.py
================================================================================

```python
"""Audit module public interface (real DDL-backed audit, section M11)."""
from app.modules.audit.api.routes import router
from app.modules.audit.events import register_event_handlers


__all__ = ["router", "register_event_handlers"]
```

================================================================================
## FILE: backend/app/modules/audit/db/models.py
================================================================================

```python
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
```

================================================================================
## FILE: backend/app/modules/audit/events.py
================================================================================

```python
"""
app/modules/audit/events.py  (نسخه‌ی به‌روز — جایگزین نسخه‌ی audit_module_patch.zip)

تنها تغییر نسبت به نسخه‌ی قبلی: "rbac.denied" هم به فهرست رویدادهایی
که audit ثبت می‌کند اضافه شد — چون app/modules/rbac/api/deps.py (در
همین پچ) این رویداد را منتشر می‌کند و باید جایی ثبت شود.
"""

from __future__ import annotations

import logging
from typing import Any

from app.modules.audit.services.audit_service import AuditService

logger = logging.getLogger("audit.events")

_LOGIN_EVENT_TYPES = ("auth.login.succeeded", "auth.login.failed")

_GENERIC_AUDIT_EVENT_TYPES = (
    "auth.user.registered",
    "auth.logout",
    "auth.password.changed",
    "auth.device.registered",
    "auth.device.trusted",
    "auth.user.created_by_admin",
    "auth.user.updated",
    "auth.user.deactivated",
    "auth.user.login_mode.changed",
    "rbac.role.assigned",
    "rbac.role.revoked",
    "rbac.denied",
)

_ALL_SUBSCRIBED_EVENTS = _LOGIN_EVENT_TYPES + _GENERIC_AUDIT_EVENT_TYPES


async def _handle_login_event(event: Any, session: Any) -> None:
    audit = AuditService(session)
    payload = event.payload or {}
    await audit.log_login(
        success=(event.event_type == "auth.login.succeeded"),
        auth_method=payload.get("auth_method", "local"),
        user_id=event.actor_id,
        username=payload.get("identifier"),
        mfa_used=payload.get("mfa_used"),
        failure_reason=payload.get("reason"),
    )


async def _handle_generic_event(event: Any, session: Any) -> None:
    audit = AuditService(session)
    payload = event.payload or {}
    user_id = payload.get("target_user_id", event.actor_id) \
        if event.event_type.startswith(("rbac.", "auth.user.")) else event.actor_id
    result = "denied" if event.event_type == "rbac.denied" else "success"
    await audit.log(
        action=event.event_type,
        user_id=user_id,
        result=result,
        details=payload,
    )


def register_event_handlers(bus) -> None:
    for event_type in _LOGIN_EVENT_TYPES:
        bus.subscribe(event_type, _handle_login_event)
    for event_type in _GENERIC_AUDIT_EVENT_TYPES:
        bus.subscribe(event_type, _handle_generic_event)
    logger.debug("audit module subscribed to %d event types", len(_ALL_SUBSCRIBED_EVENTS))
```

================================================================================
## FILE: backend/app/modules/audit/services/audit_service.py
================================================================================

```python
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
```

================================================================================
## FILE: backend/app/modules/auth/__init__.py
================================================================================

```python
"""Auth module public interface."""
from fastapi import APIRouter

from app.modules.auth.api.routes import router as auth_router
from app.modules.auth.api.admin_routes import router as admin_users_router

router = APIRouter()
router.include_router(auth_router)
router.include_router(admin_users_router)

__all__ = ["router"]
```

================================================================================
## FILE: backend/app/modules/auth/api/deps.py
================================================================================

```python
"""Auth module dependencies (composition root for admin user management).

Wires the real ``get_current_user`` from core so the RBAC ``require_permission``
guard resolves, and builds ``AdminUserService`` with the live session repo.
"""
from __future__ import annotations

from fastapi import Depends

from app.core.dependencies import get_current_user, get_user_repository
from app.modules.auth.admin_ports import AdminCreateUserRequest


async def get_admin_user_service(
    user_repo=Depends(get_user_repository),
):
    """Build AdminUserService with the real repo (auth.users ORM)."""
    from app.modules.auth.services.admin_user_service import AdminUserService

    return AdminUserService(user_repo=user_repo)


__all__ = ["get_current_user", "get_admin_user_service", "AdminCreateUserRequest"]
```

================================================================================
## FILE: backend/app/modules/auth/db/__init__.py
================================================================================

```python
"""Auth persistence layer."""
```

================================================================================
## FILE: backend/app/modules/auth/db/models.py
================================================================================

```python
"""Auth DB models matching ``alembic/versions/auth_schema.sql``.

Column types mirror the SQL schema exactly (PostgreSQL UUID/ENUM/INET/JSONB)
so INSERTs succeed. Columns that the database fills via defaults
(created_at, failed counters, ...) are omitted from the model.
"""
import uuid as uuid_lib
from datetime import datetime

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import ENUM, INET, JSONB, UUID as PGUUID

from app.core.db.base import Base

auth_mode_enum = ENUM(
    "local", "sso", "both",
    name="auth_mode", schema="auth", create_type=False,
)
login_method_enum = ENUM(
    "local", "sso", "ldap", "kerberos", "recovery",
    name="login_method", schema="auth", create_type=False,
)


class Users(Base):
    """Application users (table ``auth.users``)."""

    __tablename__ = "users"
    __table_args__ = {"schema": "auth", "extend_existing": True}

    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid_lib.uuid4)
    username = Column(String(64), nullable=False)
    national_id_enc = Column(LargeBinary, nullable=False)
    national_id_nonce = Column(LargeBinary, nullable=False)
    national_id_hash = Column(String(64), nullable=False)
    national_id_last4 = Column(String(4), nullable=False)
    display_name = Column(String(128), nullable=False)
    auth_mode = Column(auth_mode_enum, nullable=False, default="local")
    sso_enabled = Column(Boolean, nullable=False, default=False)
    ldap_dn = Column(Text, nullable=True)
    ldap_object_guid = Column(PGUUID(as_uuid=True), nullable=True)
    ldap_sam_account = Column(String(256), nullable=True)
    ldap_synced_at = Column(DateTime(timezone=True), nullable=True)
    password_hash = Column(Text, nullable=True)
    password_changed_at = Column(DateTime(timezone=True), nullable=True)
    must_change_password = Column(Boolean, nullable=False, default=False)
    token_version = Column(Integer, nullable=False, default=1)
    mfa_enabled = Column(Boolean, nullable=False, default=False)
    mfa_method = Column(String(16), nullable=True)
    mfa_secret_enc = Column(LargeBinary, nullable=True)
    mfa_secret_nonce = Column(LargeBinary, nullable=True)
    mfa_enrolled_at = Column(DateTime(timezone=True), nullable=True)
    is_active = Column(Boolean, nullable=False, default=True)
    failed_login_count = Column(Integer, nullable=False, default=0)
    locked_until = Column(DateTime(timezone=True), nullable=True)
    last_login_at = Column(DateTime(timezone=True), nullable=True)


class UserDevices(Base):
    """Registered user devices (table ``auth.user_devices``)."""

    __tablename__ = "user_devices"
    __table_args__ = (
        UniqueConstraint("user_id", "device_fingerprint",
                         name="uq_device_user_fingerprint"),
        {"schema": "auth", "extend_existing": True},
    )

    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid_lib.uuid4)
    user_id = Column(
        PGUUID(as_uuid=True),
        ForeignKey("auth.users.id", ondelete="CASCADE"),
        nullable=False,
    )
    device_fingerprint = Column(String(255), nullable=False)
    mac_address = Column(String(17), nullable=True)
    mac_source = Column(String(16), nullable=True)
    platform = Column(String(16), nullable=False)
    device_label = Column(String(128), nullable=True)
    os_info = Column(String(128), nullable=True)
    user_agent = Column(Text, nullable=True)
    hmac_key_enc = Column(LargeBinary, nullable=True)
    is_trusted = Column(Boolean, nullable=False, default=False)
    trusted_at = Column(DateTime(timezone=True), nullable=True)
    trusted_by_mfa = Column(Boolean, nullable=False, default=False)
    first_seen_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    last_seen_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    last_ip = Column(INET, nullable=True)
    is_blocked = Column(Boolean, nullable=False, default=False)
    blocked_reason = Column(String(255), nullable=True)


class Sessions(Base):
    """Login sessions / refresh families (table ``auth.sessions``)."""

    __tablename__ = "sessions"
    __table_args__ = {"schema": "auth", "extend_existing": True}

    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid_lib.uuid4)
    user_id = Column(
        PGUUID(as_uuid=True),
        ForeignKey("auth.users.id", ondelete="CASCADE"),
        nullable=False,
    )
    device_id = Column(
        PGUUID(as_uuid=True),
        ForeignKey("auth.user_devices.id", ondelete="SET NULL"),
        nullable=True,
    )
    refresh_hash = Column(String(64), nullable=False, unique=True)
    family_id = Column(PGUUID(as_uuid=True), nullable=False)
    auth_method = Column(login_method_enum, nullable=False)
    mfa_satisfied = Column(Boolean, nullable=False, default=False)
    ip_address = Column(INET, nullable=True)
    geo_location = Column(JSONB, nullable=True)
    issued_at = Column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    last_active_at = Column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    expires_at = Column(DateTime(timezone=True), nullable=False)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    revoked_reason = Column(String(64), nullable=True)


Index("ix_auth_users_hash", Users.national_id_hash)


class MFARecoveryCodes(Base):
    """MFA recovery codes (table ``auth.mfa_recovery_codes``)."""

    __tablename__ = "mfa_recovery_codes"
    __table_args__ = {"schema": "auth", "extend_existing": True}

    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid_lib.uuid4)
    user_id = Column(
        PGUUID(as_uuid=True),
        ForeignKey("auth.users.id", ondelete="CASCADE"),
        nullable=False,
    )
    code_hash = Column(String(64), nullable=False, unique=True)
    used_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


__all__ = ["Users", "UserDevices", "Sessions", "MFARecoveryCodes"]
```

================================================================================
## FILE: backend/app/modules/auth/events.py
================================================================================

```python
"""
app/modules/auth/events.py

رویدادهایی که ماژول Auth منتشر می‌کند — طبق قرارداد رابط سند
(بخش ۲.۲: هر ماژول رویدادهای خودش را از ``events.py`` صادر می‌کند)
و کاتالوگ رویدادها (بخش ۲.۴).

هیچ ماژول دیگری نباید این فایل را import کند تا از رویداد مطلع شود —
فقط باید با رشته‌ی ``event_type`` (مثل ``AUTH_LOGIN_SUCCEEDED``ی که
همین‌جا صادر شده) در ``event_bus.subscribe(...)`` مشترک شود. صادر کردن
این ثابت‌ها فقط برای جلوگیری از اشتباه تایپی در همین ماژول (auth) است؛
مصرف‌کننده‌ها (مثل audit) باید مقدار رشته را مستقیم بنویسند تا
وابستگی کد به auth ایجاد نشود — دقیقاً همان قاعده‌ای که تست
``test_module_boundaries.py`` اجرا می‌کند.
"""

from __future__ import annotations

# ── کاتالوگ رویدادها (بخش ۲.۴ سند) + رویدادهای اضافه‌ی مورد نیاز کد فعلی
AUTH_USER_REGISTERED = "auth.user.registered"
AUTH_LOGIN_SUCCEEDED = "auth.login.succeeded"
AUTH_LOGIN_FAILED = "auth.login.failed"
AUTH_LOGOUT = "auth.logout"
AUTH_PASSWORD_CHANGED = "auth.password.changed"
AUTH_DEVICE_REGISTERED = "auth.device.registered"
AUTH_DEVICE_TRUSTED = "auth.device.trusted"
```

================================================================================
## FILE: backend/app/modules/auth/ports.py
================================================================================

```python
from typing import Protocol, Optional, List, Tuple, Dict, Any
from uuid import UUID
from datetime import datetime
from pydantic import BaseModel


# --- User Read Model Protocol ---
# Defines what other modules can see about a user (interface contract)

class UserReadModel(Protocol):
    """Her ماژول دیگری فقط این را می‌بیند. تغییر امضای این متدها = تغییر شکننده."""
    
    id: UUID
    username: str
    display_name: str
    national_id_masked: str  # masked: ******1234
    is_active: bool
    roles: List[str]
    permissions: List[str]
    privacy_level: str
    auth_mode: str  # local | sso | both
    mfa_enabled: bool
    last_login_at: Optional[datetime]


# --- Authentication Request/Response Schemas ---

class LoginRequest(BaseModel):
    """Login request schema."""
    identifier: str  # username or national_id
    password: str
    remember_me: bool = False
    captcha_token: Optional[str] = None


class MFAVerifyRequest(BaseModel):
    """MFA verification request."""
    mfa_token: str  # TOTP code or SMS code
    mfa_method: str  # totp | email | sms
    challenge_token: Optional[str] = None  # login-issued challenge (identifies user)


class MFACodeRequest(BaseModel):
    """TOTP code used during enrollment confirmation."""
    code: str


class RegisterRequest(BaseModel):
    """User registration request."""
    national_id: str  # 10-digit with check digit
    username: str
    password: str
    display_name: str
    email: Optional[str] = None
    mobile: Optional[str] = None


class TokenResponse(BaseModel):
    """Authentication token response."""
    access_token: str
    refresh_token: str
    token_type: str = "Bearer"
    expires_in: int
    # Serialized UserReadModel (kept as dict: pydantic cannot build a
    # schema for the Protocol interface above).
    user: dict
    device: Optional[dict] = None  # device info if new


# --- Device Binding Schemas ---

class DeviceRegisterRequest(BaseModel):
    """Device registration request."""
    device_fingerprint: str  # SHA256 fingerprint
    mac_address: str  # MAC address (desktop only)
    mac_source: str  # psutil | uuid_getnode | unavailable
    platform: str  # desktop | web | mobile_web
    device_label: str  # user-assigned label
    os_info: str  # OS description


class DeviceTrustRequest(BaseModel):
    """Device trust confirmation."""
    device_id: UUID
    trusted: bool  # user confirmation
    mfa_satisfied: bool  # MFA was used to trust


# --- Password Management ---

class PasswordChangeRequest(BaseModel):
    """Change password request."""
    current_password: str
    new_password: str


class PasswordForgotRequest(BaseModel):
    """Password forgot/request reset."""
    identifier: str  # username or national_id


class RefreshRequest(BaseModel):
    """Refresh token request schema."""
    refresh_token: str


# --- Audit Log Schemas (lightweight) ---

class AuditLogEntry(BaseModel):
    """Lightweight audit log entry for API responses."""
    id: int
    action: str
    timestamp: datetime
    result: str
    user_id: Optional[UUID]
    ip_address: Optional[str]
    mac_verified: bool


# Export all schemas
__all__ = [
    "UserReadModel", "LoginRequest", "MFAVerifyRequest",
    "RegisterRequest", "TokenResponse", "DeviceRegisterRequest",
    "DeviceTrustRequest", "PasswordChangeRequest", 
    "PasswordForgotRequest", "AuditLogEntry", "RefreshRequest"
]
```

================================================================================
## FILE: backend/app/modules/auth/services/__init__.py
================================================================================

```python
"""Auth services public interface."""
from app.modules.auth.db.mfa import MFAService

__all__ = ["MFAService"]
```

================================================================================
## FILE: backend/app/modules/auth/services/auth_service.py
================================================================================

```python
import hashlib
import secrets
import base64
from typing import Optional, Tuple, Dict, Any
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

from passlib.context import CryptContext
from fastapi import HTTPException, status

from app.core.config import settings
from app.core.errors import APIError, AuthenticationError, MFARequiredError
from app.core.events.bus import event_bus
from app.modules.auth import events as auth_events
from app.modules.auth.ports import (
    LoginRequest, MFAVerifyRequest, RegisterRequest, TokenResponse,
    DeviceRegisterRequest, DeviceTrustRequest, PasswordChangeRequest,
    PasswordForgotRequest, AuditLogEntry
)


# Password hashing context
pwd_context = CryptContext(
    schemes=["argon2"],
    argon2__time_cost=3,
    deprecated="auto",
)


class AuthService:
    """Core authentication service implementing the logic for user login, 
    registration, MFA, and device management."""
    
    def __init__(self, user_repo, device_repo, mfa_service):
        self.user_repo = user_repo
        self.device_repo = device_repo
        self.mfa_service = mfa_service
    
    # --- Registration ---
    
    async def register(self, request: RegisterRequest) -> dict:
        """Register a new user with national ID."""
        
        # Validate national ID format (10 digits with check digit)
        if not self._validate_national_id(request.national_id):
            raise APIError(
                error_code="INVALID_NATIONAL_ID",
                message="فرمت کد ملی صحیح نیست.",
                status_code=status.HTTP_400_BAD_REQUEST
            )
        
        # Check if user already exists
        existing = await self.user_repo.get_by_national_id(request.national_id)
        if existing:
            raise APIError(
                error_code="USER_EXISTS",
                message="کاربری با این کد ملی قبلاً ثبت شده است.",
                status_code=status.HTTP_409_CONFLICT
            )
        
        # Check username availability
        existing_username = await self.user_repo.get_by_username(request.username)
        if existing_username:
            raise APIError(
                error_code="USERNAME_EXISTS",
                message="این نام کاربری قبلاً استفاده شده است.",
                status_code=status.HTTP_409_CONFLICT
            )
        
        # Hash password
        password_hash = pwd_context.hash(request.password)
        
        # Create user (national ID stored encrypted + hashed for lookup)
        from app.modules.auth.db.models import Users
        from app.modules.auth.db.repositories import national_id_hash
        nid_enc, nid_nonce = self._encrypt_national_id(request.national_id)
        user = Users(
            username=request.username,
            national_id_enc=nid_enc,
            national_id_nonce=nid_nonce,
            national_id_hash=national_id_hash(request.national_id),
            national_id_last4=request.national_id[-4:],
            password_hash=password_hash,
            display_name=request.display_name,
            auth_mode="local",
            is_active=True,
        )
        # Transient (non-column) attributes used by the read model below
        user.national_id = request.national_id
        
        await self.user_repo.add(user)
        await self.user_repo.commit()
        
        # Create initial device entry
        await self.device_repo.create_initial_device(user.id)
        
        # Publish domain event — audit (and anything else that subscribes,
        # e.g. notification for a welcome email) reacts without auth ever
        # importing their internal tables (ADR-02 / section 2.3).
        await self._publish_event(
            auth_events.AUTH_USER_REGISTERED,
            actor_id=user.id,
            payload={"username": user.username},
        )
        
        return {"status": "success", "user_id": str(user.id)}
    
    # --- Login ---
    
    async def login(self, request: LoginRequest) -> Tuple[dict, Optional[str]]:
        """Authenticate user and return tokens.
        
        Returns:
            Tuple of (token_response, mfa_required_flag)
        """
        
        # Find user by identifier (username or national ID)
        user = await self.user_repo.get_by_identifier(request.identifier)
        if not user:
            await self._publish_event(
                auth_events.AUTH_LOGIN_FAILED,
                payload={"identifier": request.identifier, "reason": "user_not_found"},
            )
            # Generic error to avoid leaking whether user exists
            raise AuthenticationError(
                message="اطلاعات ورود نادرست است."
            )
        
        # Check if account is active
        if not user.is_active:
            await self._publish_event(
                auth_events.AUTH_LOGIN_FAILED,
                actor_id=user.id,
                payload={"identifier": request.identifier, "reason": "account_inactive"},
            )
            raise AuthenticationError(
                message="حساب کاربری فعال نیست."
            )
        
        # Verify password
        if not pwd_context.verify(request.password, user.password_hash):
            # Increment failed login counter
            user.failed_login_count += 1
            # Lock account if too many failures
            if user.failed_login_count >= 5:
                user.locked_until = datetime.utcnow() + timedelta(minutes=30)
            await self.user_repo.commit()
            await self._publish_event(
                auth_events.AUTH_LOGIN_FAILED,
                actor_id=user.id,
                payload={
                    "identifier": request.identifier,
                    "reason": "wrong_password",
                    "failed_login_count": user.failed_login_count,
                },
            )
            raise AuthenticationError(
                message="اطلاعات ورود نادرست است."
            )
        
        # Reset failed login counter on success
        user.failed_login_count = 0
        user.locked_until = None
        await self.user_repo.commit()
        
        # Check MFA status
        mfa_required = bool(user.mfa_enabled) and not getattr(
            user, "is_trusted_device", False
        )
        
        if mfa_required:
            # Generate MFA token (short-lived)
            mfa_token = self.mfa_service.generate_mfa_token(user.id)
            return {
                "mfa_required": True,
                "mfa_token": mfa_token,
                "mfa_method": user.mfa_method,
                "expires_in": 300  # 5 minutes
            }, True
        
        # No MFA needed — login is fully successful right here.
        # NOTE: if MFA *is* required, the success event is published once
        # verify_mfa() actually confirms the second factor (see below) —
        # publishing it here too would record a "succeeded" login for an
        # attempt that hasn't cleared MFA yet.
        await self._publish_event(
            auth_events.AUTH_LOGIN_SUCCEEDED,
            actor_id=user.id,
            payload={"identifier": request.identifier, "mfa_used": "none"},
        )
        return await self._generate_tokens(user), False
    
    # --- Token Generation ---
    
    async def _generate_tokens(self, user) -> dict:
        """Generate access and refresh tokens for a user."""
        from jose import jwt  # PyJWT

        # Bump FIRST so the freshly issued access token carries the new
        # version; bumping after encoding instantly revokes the new token.
        user.token_version += 1
        await self.user_repo.commit()

        # Access token (HS256 + exp claim; python-jose has no expires_at kwarg)
        access_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = jwt.encode(
            {
                "sub": str(user.id),
                "username": user.username,
                "roles": getattr(user, "roles", []) or [],
                "permissions": getattr(user, "permissions", []) or [],
                "privacy_level": getattr(user, "privacy_level", None) or "team_only",
                "token_version": user.token_version,
                "type": "access",
                "exp": datetime.utcnow() + access_expires,
            },
            settings.SECRET_KEY,
            algorithm=settings.ALGORITHM,
        )
        
        # Refresh token
        refresh_token = secrets.token_urlsafe(32)
        # Store hash of refresh token
        refresh_token_hash = hashlib.sha256(refresh_token.encode()).hexdigest()
        
        # Store in sessions table
        from app.modules.auth.db.models import Sessions
        session = Sessions(
            user_id=user.id,
            refresh_hash=refresh_token_hash,
            family_id=getattr(user, "family_id", None) or uuid4(),
            auth_method=user.auth_mode,
            mfa_satisfied=bool(user.mfa_enabled),
            expires_at=datetime.utcnow() + timedelta(
                days=settings.REFRESH_TOKEN_EXPIRE_DAYS
            ),
        )
        await self.user_repo.add(session)
        await self.user_repo.commit()

        # Get user read model for response
        user_read = self._get_user_read_model(user)
        
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "Bearer",
            "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            "user": user_read,
        }
    
    # --- MFA ---
    
    async def verify_mfa(self, mfa_token: str, mfa_method: str, user_id: UUID) -> bool:
        """Verify MFA token."""
        verified = await self.mfa_service.verify_token(mfa_token, mfa_method, user_id)
        if verified:
            # This is the actual "login succeeded" moment for an MFA-gated
            # login — the plain login() above only got this far because
            # mfa_required was True, so it deliberately did not publish
            # AUTH_LOGIN_SUCCEEDED itself.
            await self._publish_event(
                auth_events.AUTH_LOGIN_SUCCEEDED,
                actor_id=user_id,
                payload={"mfa_used": mfa_method},
            )
        else:
            await self._publish_event(
                auth_events.AUTH_LOGIN_FAILED,
                actor_id=user_id,
                payload={"reason": "mfa_invalid", "mfa_method": mfa_method},
            )
        return verified
    
    async def enroll_mfa(self, user_id: UUID, secret: str) -> dict:
        """Enroll TOTP MFA for a user."""
        return await self.mfa_service.enroll(user_id, secret)
    
    # --- Device Management ---
    
    async def register_device(self, request: DeviceRegisterRequest, user_id: UUID) -> dict:
        """Register a new device for a user."""
        # Generate HMAC key for this device
        hmac_key = secrets.token_bytes(32)
        
        from app.modules.auth.db.models import UserDevices
        device = UserDevices(
            user_id=user_id,
            device_fingerprint=request.device_fingerprint,
            mac_address=request.mac_address,
            mac_source=request.mac_source,
            platform=request.platform,
            device_label=request.device_label,
            os_info=request.os_info,
            hmac_key_enc=self._encrypt_hmac_key(hmac_key),
            is_trusted=False,
        )
        await self.device_repo.add(device)
        await self.user_repo.commit()

        await self._publish_event(
            auth_events.AUTH_DEVICE_REGISTERED,
            actor_id=user_id,
            payload={
                "device_id": str(device.id),
                "platform": request.platform,
                "device_label": request.device_label,
            },
        )
        
        return {
            "device_id": str(device.id),
            "hmac_key": base64.b64encode(hmac_key).decode(),  # Only sent once
            "is_trusted": False,
            "requires_mfa_to_trust": True,
        }
    
    async def trust_device(self, device_id: UUID, mfa_satisfied: bool, user_id: UUID) -> dict:
        """Mark device as trusted (requires MFA)."""
        from app.modules.auth.db.models import UserDevices
        device = await self.device_repo.get(device_id)
        if device.user_id != user_id:
            raise APIError(
                error_code="DEVICE_NOT_FOUND",
                message="دستگاه یافت نشد.",
                status_code=status.HTTP_404_NOT_FOUND
            )
        
        device.is_trusted = True
        device.trusted_at = datetime.utcnow()
        device.trusted_by_mfa = mfa_satisfied
        await self.user_repo.commit()

        await self._publish_event(
            auth_events.AUTH_DEVICE_TRUSTED,
            actor_id=user_id,
            payload={"device_id": str(device_id), "mfa_satisfied": mfa_satisfied},
        )
        
        return {"status": "device_trusted"}
    
    # --- Password Management ---
    
    async def change_password(self, user_id: UUID, request: PasswordChangeRequest) -> dict:
        """Change user password."""
        user = await self.user_repo.get(user_id)
        if not user:
            raise APIError(
                error_code="USER_NOT_FOUND",
                message="کاربر یافت نشد.",
                status_code=status.HTTP_404_NOT_FOUND
            )
        
        # Verify current password
        if not pwd_context.verify(request.current_password, user.password_hash):
            raise APIError(
                error_code="INVALID_PASSWORD",
                message="رمز فعلی صحیح نیست.",
                status_code=status.HTTP_400_BAD_REQUEST
            )
        
        # Hash new password
        new_hash = pwd_context.hash(request.new_password)
        user.password_hash = new_hash
        user.password_changed_at = datetime.utcnow()
        user.must_change_password = False
        await self.user_repo.commit()
        
        # Invalidate all sessions (force re-login)
        user.token_version += 1
        await self.user_repo.commit()
        
        await self._publish_event(
            auth_events.AUTH_PASSWORD_CHANGED,
            actor_id=user_id,
            payload={},
        )
        
        return {"status": "password_changed"}
    
    # --- Password Reset ---
    
    async def forgot_password(self, request: PasswordForgotRequest) -> dict:
        """Start password reset process."""
        user = await self.user_repo.get_by_identifier(request.identifier)
        if not user:
            # Don't reveal if user exists - security through obscurity
            return {"status": "sent"}  # Always say sent for security
        
        # Generate reset token
        reset_token = secrets.token_urlsafe(32)
        reset_token_hash = hashlib.sha256(reset_token.encode()).hexdigest()
        
        # Store in user record
        user.password_reset_token = reset_token_hash
        user.password_reset_expires = datetime.utcnow() + timedelta(hours=24)
        await self.user_repo.commit()
        
        # In real implementation: send email with reset link
        # For now, just return that process started
        return {"status": "reset_initiated", "expires_in_hours": 24}
    
    # --- Profile / Session / Devices ---

    async def get_profile(self, user_id: UUID) -> dict:
        """Current user profile + effective roles/permissions."""
        user = await self.user_repo.get(user_id)
        if not user:
            raise APIError(
                error_code="USER_NOT_FOUND",
                message="کاربر یافت نشد.",
                status_code=status.HTTP_404_NOT_FOUND,
            )
        profile = self._get_user_read_model(user)
        profile["id"] = str(profile["id"])
        return profile

    async def logout(self, user_id: UUID) -> dict:
        """Revoke all sessions for the user (bump token_version)."""
        user = await self.user_repo.get(user_id)
        if not user:
            raise APIError(
                error_code="USER_NOT_FOUND",
                message="کاربر یافت نشد.",
                status_code=status.HTTP_404_NOT_FOUND,
            )
        user.token_version += 1
        await self.user_repo.commit()
        await self._publish_event(auth_events.AUTH_LOGOUT, actor_id=user_id, payload={})
        return {"status": "logged_out"}

    async def list_devices(self, user_id: UUID) -> list:
        """List known devices with masked MAC addresses."""
        from sqlalchemy import select

        from app.modules.auth.db.models import UserDevices

        result = await self.user_repo.session.execute(
            select(UserDevices).where(UserDevices.user_id == user_id)
        )
        devices = result.scalars().all()
        items = []
        for d in devices:
            mac = d.mac_address or ""
            masked = (
                f"{mac[:5]}**:**:**:{mac[-2:]}"
                if len(mac) == 17 else None
            )
            items.append({
                "id": str(d.id),
                "device_label": d.device_label,
                "platform": d.platform,
                "mac_address_masked": masked,
                "is_trusted": d.is_trusted,
                "last_seen_at": d.last_seen_at.isoformat() if d.last_seen_at else None,
                "last_ip": str(d.last_ip) if d.last_ip else None,
            })
        return items

    async def _generate_tokens_by_id(self, user_id: UUID) -> dict:
        """Generate fresh tokens for a user ID (used by /refresh)."""
        user = await self.user_repo.get(user_id)
        if not user or not user.is_active:
            raise APIError(
                error_code="USER_NOT_FOUND",
                message="کاربر یافت نشد.",
                status_code=status.HTTP_404_NOT_FOUND,
            )
        return await self._generate_tokens(user)

    async def refresh_session(self, refresh_token: str, db_session=None) -> dict:
        """Validate an opaque refresh token and rotate the session.

        The refresh token is stored as SHA-256 in ``auth.sessions``. We look
        it up, reject revoked/expired sessions, revoke the old session and
        issue fresh tokens. Returns the new ``{status, tokens, user}``-shaped
        response expected by the frontend auth client.
        """
        from sqlalchemy import select
        from app.modules.auth.db.models import Sessions

        session = self.user_repo.session
        if session is None:
            raise APIError(
                error_code="SESSION_ERROR",
                message="نشست قابل استفاده نیست.",
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        refresh_hash = hashlib.sha256(refresh_token.encode()).hexdigest()

        result = await session.execute(
            select(Sessions).where(Sessions.refresh_hash == refresh_hash)
        )
        s = result.scalar_one_or_none()
        if s is None:
            raise APIError(
                error_code="TOKEN_INVALID",
                message="توکن یافت نشد.",
                status_code=status.HTTP_401_UNAUTHORIZED,
            )
        if s.revoked_at is not None:
            raise APIError(
                error_code="TOKEN_REVOKED",
                message="نشست باطل شده است.",
                status_code=status.HTTP_401_UNAUTHORIZED,
            )
        # NOTE: timestamptz columns come back timezone-aware from asyncpg,
        # so compare against an aware "now" (naive utcnow() would TypeError).
        now_utc = datetime.now(timezone.utc)
        expires_at = s.expires_at
        if expires_at is not None:
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)
            if expires_at < now_utc:
                raise APIError(
                    error_code="TOKEN_EXPIRED",
                    message="نشست منقضی شده است.",
                    status_code=status.HTTP_401_UNAUTHORIZED,
                )

        # Revoke the old session (rotation).
        s.revoked_at = datetime.utcnow()
        s.revoked_reason = "refresh"

        user = await self.user_repo.get(s.user_id)
        if not user or not user.is_active:
            raise APIError(
                error_code="USER_NOT_FOUND",
                message="کاربر یافت نشد.",
                status_code=status.HTTP_404_NOT_FOUND,
            )

        # Carry the session family forward so rotation stays in one family.
        user.family_id = s.family_id
        new_tokens = await self._generate_tokens(user)
        await self.user_repo.commit()
        return {
            "status": "token_refreshed",
            "tokens": {
                "access_token": new_tokens.get("access_token"),
                "refresh_token": new_tokens.get("refresh_token"),
                "token_type": "Bearer",
                "expires_in": new_tokens.get("expires_in"),
            },
            "user": new_tokens.get("user"),
        }

    # --- Helper methods ---
    
    def _validate_national_id(self, national_id: str) -> bool:
        """Validate Iranian national ID format and checksum."""
        # Remove any separators
        national_id = national_id.strip()
        
        # Must be exactly 10 digits
        if not national_id.isdigit() or len(national_id) != 10:
            return False
        
        # Calculate checksum (official Iranian algorithm)
        digits = [int(d) for d in national_id]
        # Iranian national ID checksum: sum of (digit * position) % 11
        # Positions: 10, 9, 8, 7, 6, 5, 4, 3, 2 (from left to right, excluding check digit)
        weights = [10, 9, 8, 7, 6, 5, 4, 3, 2]
        weighted_sum = sum(d * w for d, w in zip(digits[:9], weights))
        remainder = weighted_sum % 11

        # Official check digit rules:
        # If remainder < 2, the 10th digit must equal remainder;
        # otherwise it must equal (11 - remainder).
        expected_check = remainder if remainder < 2 else 11 - remainder

        return digits[9] == expected_check
    
    def _encrypt_national_id(self, national_id: str) -> tuple:
        """Encrypt national ID with AES-GCM; returns (ciphertext, nonce)."""
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        nonce = secrets.token_bytes(12)  # 96-bit nonce for GCM
        kdf_key = hashlib.sha256(settings.SECRET_KEY.encode()).digest()
        aesgcm = AESGCM(kdf_key)
        return aesgcm.encrypt(nonce, national_id.encode(), None), nonce

    def _encrypt_hmac_key(self, key: bytes) -> bytes:
        """Encrypt HMAC key using AES-GCM with a per-key nonce."""
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        nonce = secrets.token_bytes(12)  # 96-bit nonce for GCM
        # In production, use a key from Vault, not hardcoded
        # Here we use a simplified approach
        kdf_key = hashlib.sha256(settings.SECRET_KEY.encode()).digest()
        aesgcm = AESGCM(kdf_key)
        encrypted = aesgcm.encrypt(nonce, key, None)
        return nonce + encrypted  # prepend nonce
    
    def _decrypt_hmac_key(self, encrypted_key: bytes) -> bytes:
        """Decrypt HMAC key."""
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        kdf_key = hashlib.sha256(settings.SECRET_KEY.encode()).digest()
        nonce = encrypted_key[:12]
        ciphertext = encrypted_key[12:]
        aesgcm = AESGCM(kdf_key)
        return aesgcm.decrypt(nonce, ciphertext, None)
    
    def _get_user_read_model(self, user) -> dict:
        """Convert user model to read model for API responses."""
        from datetime import datetime
        
        # Get masked national ID (last 4 digits)
        national_id = getattr(user, "national_id", None)
        if not national_id:
            national_id = f"*****{user.national_id_last4}" if getattr(
                user, "national_id_last4", None) else "******"
        national_id_masked = (
            f"*****{national_id[-4:]}" if national_id else "******"
        )

        return {
            "id": user.id,
            "username": user.username,
            "display_name": user.display_name,
            "national_id_masked": national_id_masked,
            "is_active": user.is_active,
            "roles": getattr(user, "roles", None) or [],
            "permissions": getattr(user, "permissions", None) or [],
            "privacy_level": getattr(user, "privacy_level", None) or "team_only",
            "auth_mode": user.auth_mode or "local",
            "mfa_enabled": user.mfa_enabled or False,
            "last_login_at": user.last_login_at,
        }
    
    async def _publish_event(
        self, event_type: str, *, payload: dict, actor_id: UUID | None = None
    ) -> None:
        """رویداد دامنه را منتشر می‌کند — جایگزین متد قدیمی ``_audit_log``.

        برخلاف نسخه‌ی قبلی، اینجا هیچ importی به ``app.modules.audit``
        وجود ندارد (نقض مرز ماژول که تست ``test_module_boundaries.py``
        آن را گرفت). به‌جایش یک ``DomainEvent`` روی ``event_bus`` منتشر
        می‌شود؛ ماژول Audit (اگر مشترک شده باشد) و هر ماژول دیگری که به
        این رویداد علاقه دارد (مثلاً Notification برای هشدار «ورود از
        دستگاه جدید» طبق کاتالوگ رویدادهای سند) بدون هیچ وابستگی کدی
        به auth، آن را دریافت می‌کنند.

        TODO(security): وقتی ``core/context.py`` (ContextVar) و
        ``core/middleware/`` واقعی پیاده شدند (بخش ۱.۲ و ۳.۱ سند)،
        ``ip_address`` / ``mac_address`` / ``device_fingerprint`` باید
        از آن‌جا در payload اضافه شوند — نه از پارامترهای متد سرویس
        (که هنوز به این service پاس داده نمی‌شوند).
        """
        from app.core.events.bus import DomainEvent

        event = DomainEvent(event_type=event_type, payload=payload, actor_id=actor_id)
        try:
            await event_bus.publish(event, self.user_repo.session)
            await self.user_repo.commit()
        except Exception:
            # مطابق طراحی bus.py: خطای یک handler بالا می‌آید. این‌جا آن را
            # قورت نمی‌دهیم (برخلاف باگ قبلی) اما هم اجازه نمی‌دهیم شکست
            # انتشار رویداد، کل جریان login/register/... را متوقف کند —
            # چون در نبود Outbox dispatcher واقعی هنوز، این یک تصمیم آگاهانه
            # است، نه بی‌توجهی. اگر می‌خواهید شکست انتشار رویداد باعث شکست
            # کل عملیات شود (مثلاً برای الزامات Compliance)، این except را
            # حذف کنید تا خطا بالا برود.
            import logging
            logging.getLogger("auth.events").exception(
                "failed to publish event_type=%s", event_type
            )
```

================================================================================
## FILE: backend/app/modules/rbac/__init__.py
================================================================================

```python
"""RBAC module public interface."""
from app.modules.rbac.api.routes import router

__all__ = ["router"]
```

================================================================================
## FILE: backend/app/modules/rbac/db/models.py
================================================================================

```python
import uuid
from uuid import UUID
from datetime import datetime
from sqlalchemy import func

from sqlalchemy import (
    Column, Integer, String, Boolean, DateTime,
    ForeignKey, Table, UniqueConstraint, Index, Text, JSON
)
from sqlalchemy.orm import relationship

from app.core.db.base import AuditMixin, BaseModel


# --- Permissions Table ---

class Permissions(BaseModel, AuditMixin):
    """System permissions defining what actions are allowed."""
    
    __tablename__ = "permissions"
    __table_args__ = (
        UniqueConstraint("code", name="uq_permission_code"),
        Index("ix_permissions_module_action", "module", "action"),
    )
    
    # Primary key inherited
    code = Column(String(100), nullable=False, unique=True)
    # Format: "module.action" e.g., "goal.create", "group.manage"
    
    module = Column(String(40), nullable=False)
    # Module name e.g., "goal", "group", "user", "rbac"
    
    action = Column(String(40), nullable=False)
    # Action name e.g., "create", "read", "update", "delete", "manage"
    
    title_fa = Column(String(120), nullable=False)
    # Persian title for UI display
    
    is_dangerous = Column(
        Boolean,
        nullable=False,
        default=False,
        comment="Requires secondary confirmation"
    )
    
    # Relationships
    # role_permissions = relationship("RolePermissions", back_populates="permission")
    # user_actions = relationship("UserActions", back_populates="permission")


# --- Roles Table ---

class Roles(BaseModel, AuditMixin):
    """System roles with hierarchical levels."""
    
    __tablename__ = "roles"
    __table_args__ = (
        UniqueConstraint("code", name="uq_role_code"),
        Index("ix_roles_level", "level"),
    )
    
    # Primary key inherited
    code = Column(String(32), nullable=False, unique=True)
    # e.g., "super_admin", "admin", "manager", "user", "viewer"
    
    title_fa = Column(String(64), nullable=False)
    # Persian title for UI display
    
    level = Column(
        Integer,
        nullable=False,
        server_default="1",
        comment="Hierarchy level (1=lowest, 10=highest). Used for privilege escalation prevention."
    )
    
    is_system = Column(
        Boolean,
        nullable=False,
        default=True,
        comment="System role (cannot be deleted, only modified)"
    )
    
    description = Column(Text, nullable=True)
    
    # Relationships
    # role_permissions = relationship("RolePermissions", back_populates="role")
    # user_roles = relationship("UserRoles", back_populates="role")


# --- Role-Permission Junction Table ---

class RolePermissions(BaseModel, AuditMixin):
    """Junction table for role-permission many-to-many relationship."""
    
    __tablename__ = "role_permissions"
    __table_args__ = (
        UniqueConstraint("role_id", "permission_id", name="uq_role_permission"),
    )
    
    # Primary key inherited
    role_id = Column(
        Integer,
        ForeignKey("roles.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    permission_id = Column(
        Integer,
        ForeignKey("permissions.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    
    # Composite primary key (role_id, permission_id)
    
    # Relationships
    # role = relationship("Roles", back_populates="role_permissions")
    # permission = relationship("Permissions", back_populates="role_permissions")


# --- User-Role Junction Table ---

class UserRoles(BaseModel, AuditMixin):
    """Junction table for user-role many-to-many relationship with scoping."""
    
    __tablename__ = "user_roles"
    __table_args__ = (
        UniqueConstraint(
            "user_id", "role_id", "scope_type", "scope_id",
            name="uq_user_role"
        ),
        Index("ix_user_roles_user", "user_id"),
        Index("ix_user_roles_scope", "scope_type", "scope_id"),
    )
    
    # Primary key components
    user_id = Column(
        String(36),  # UUID as string
        ForeignKey("auth.users.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    role_id = Column(
        Integer,
        ForeignKey("roles.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    scope_type = Column(
        String(16),
        nullable=False,
        default="global",
        comment="global | group"
    )
    scope_id = Column(
        String(36),
        nullable=True,
        comment="group_id when scope_type=group, otherwise NULL"
    )
    
    # Additional fields
    granted_by = Column(String(36), nullable=True)  # UUID of who granted
    granted_at = Column(DateTime(timezone=True), server_default=func.now())
    expires_at = Column(DateTime(timezone=True), nullable=True)
    source = Column(
        String(16),
        nullable=False,
        default="manual",
        comment="manual | ldap_group"
    )
    
    # Relationships
    # user = relationship("Users", foreign_keys=[user_id])
    # role = relationship("Roles", back_populates="user_roles")


# --- LDAP Group Sync ---

class LDAPGroupSync(BaseModel, AuditMixin):
    """LDAP group synchronization tracking."""
    
    __tablename__ = "ldap_group_sync"
    __table_args__ = (
        UniqueConstraint("ldap_dn", name="uq_ldap_group_dn"),
    )
    
    # Primary key inherited
    ldap_dn = Column(String(512), nullable=False)
    # Distinguished Name from Active Directory
    
    sync_status = Column(
        String(16),
        nullable=False,
        default="pending",
        comment="pending | success | failed"
    )
    sync_last_run = Column(DateTime(timezone=True), nullable=True)
    synced_group_ids = Column(Text, nullable=True)  # JSON array of group IDs
    error_message = Column(Text, nullable=True)


# Export all
__all__ = [
    "Permissions", "Roles", "RolePermissions", "UserRoles",
    "LDAPGroupSync"
]
```

================================================================================
## FILE: backend/app/modules/rbac/events.py
================================================================================

```python
"""
app/modules/rbac/events.py  (نسخه‌ی به‌روز — جایگزین نسخه‌ی rbac_patch.zip)

علاوه بر ثابت‌های event_type قبلی، حالا rbac به رویداد خودش
(``rbac.role.assigned``) مشترک می‌شود تا کش Permission کاربر را فوراً
باطل کند — دقیقاً طبق بخش ۱۲.۴ سند: «رویداد rbac.role.assigned کش آن
کاربر را فوراً باطل می‌کند». این خودِ ماژول است که به رویداد خودش گوش
می‌دهد (self-subscription) — نقض مرز ماژول نیست، چون هیچ importی از
ماژول دیگر لازم نشد.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger("rbac.events")

RBAC_ROLE_ASSIGNED = "rbac.role.assigned"
RBAC_ROLE_REVOKED = "rbac.role.revoked"
RBAC_ACCESS_DENIED = "rbac.denied"


async def _invalidate_permission_cache(event: Any, session: Any) -> None:
    from app.modules.rbac.services.permission_service import PermissionService

    payload = event.payload or {}
    target_user_id = payload.get("target_user_id")
    if not target_user_id:
        return

    try:
        from app.modules.rbac.api.deps_internal import get_redis_client_sync  # type: ignore
        redis_client = get_redis_client_sync()
    except ImportError:
        redis_client = None
        logger.debug(
            "no redis client wiring found (app.modules.rbac.api.deps_internal) — "
            "cache invalidation skipped; the 60s TTL will still expire it naturally"
        )

    service = PermissionService(session, redis_client)
    await service.invalidate(target_user_id)


def register_event_handlers(bus) -> None:
    """طبق قرارداد main.py: ``m.register_event_handlers(event_bus)``."""
    bus.subscribe(RBAC_ROLE_ASSIGNED, _invalidate_permission_cache)
    bus.subscribe(RBAC_ROLE_REVOKED, _invalidate_permission_cache)
    logger.debug("rbac module subscribed to its own role-change events for cache invalidation")
```

================================================================================
## FILE: backend/app/modules/rbac/ports.py
================================================================================

```python
from typing import Protocol, Optional, List, Tuple
from uuid import UUID
from datetime import datetime
from pydantic import BaseModel, Field


# --- Permission Protocol ---

class PermissionReadModel(Protocol):
    """Read model for permissions visible to other modules."""
    code: str  # e.g., "goal.create", "group.manage"
    module: str
    action: str
    title_fa: str
    is_dangerous: bool


# --- Role Protocol ---

class RoleReadModel(Protocol):
    """Read model for roles visible to other modules."""
    id: int
    code: str  # e.g., "super_admin", "admin", "manager", "user", "viewer"
    title_fa: str
    level: int  # for privilege escalation prevention
    is_system: bool


# --- User Role Assignment ---

class UserRoleAssignment(BaseModel):
    """User role assignment schema."""
    user_id: UUID
    role_id: int
    scope_type: str = "global"  # global | group
    scope_id: Optional[UUID] = None  # group_id for scoped roles
    source: str = "manual"  # manual | ldap_group
    granted_at: datetime = Field(default_factory=datetime.utcnow)
    expires_at: Optional[datetime] = None


# --- Role Schemas ---

class PermissionCreate(BaseModel):
    """Create permission request."""
    code: str = Field(..., min_length=1, max_length=100)
    module: str = Field(..., min_length=1, max_length=40)
    action: str = Field(..., min_length=1, max_length=40)
    title_fa: str = Field(..., min_length=1, max_length=120)
    is_dangerous: bool = False


class PermissionUpdate(BaseModel):
    """Update permission request."""
    title_fa: Optional[str] = Field(None, min_length=1, max_length=120)
    is_dangerous: Optional[bool] = Field(None)


class RoleCreate(BaseModel):
    """Create role request."""
    code: str = Field(..., min_length=1, max_length=32, unique=True)
    title_fa: str = Field(..., min_length=1, max_length=64)
    level: int = Field(default=1, ge=1, le=10)
    is_system: bool = True
    description: Optional[str] = Field(None, max_length=255)


class RoleUpdate(BaseModel):
    """Update role request."""
    title_fa: Optional[str] = Field(None, min_length=1, max_length=64)
    level: Optional[int] = Field(None, ge=1, le=10)
    is_system: Optional[bool] = Field(None)


# --- User Role Assignment Schemas ---

class AssignRoleRequest(BaseModel):
    """Assign role to user."""
    role_id: int
    scope_type: str = "global"
    scope_id: Optional[UUID] = None
    target_user_id: Optional[UUID] = None  # defaults to self when omitted


class RevokeRoleRequest(BaseModel):
    """Revoke role from user."""
    role_id: int
    scope_type: str = "global"
    target_user_id: Optional[UUID] = None  # defaults to self when omitted


# --- RBAC Decision ---

class RBACDecision(BaseModel):
    """RBAC authorization decision."""
    allowed: bool
    reason: Optional[str] = None
    redaction: Optional[str] = None  # for privacy-aware responses


# Export all
__all__ = [
    "PermissionReadModel", "RoleReadModel",
    "UserRoleAssignment", "PermissionCreate", "PermissionUpdate",
    "RoleCreate", "RoleUpdate", "AssignRoleRequest", "RevokeRoleRequest",
    "RBACDecision"
]
```

================================================================================
## FILE: backend/app/modules/rbac/services/permission_service.py
================================================================================

```python
"""
app/modules/rbac/services/permission_service.py

``effective_permissions(user_id)`` طبق بخش ۱۲.۴ سند: «نتیجه در Redis با
TTL ۶۰ ثانیه کش می‌شود». ابطال کش با رویداد ``rbac.role.assigned``
(که ``RoleAssignmentService`` در rbac_patch.zip قبلاً منتشر می‌کند)
در ``app/modules/rbac/events.py`` انجام می‌شود — نه اینجا.

⚠️ فرض: مسیر Redis client شما را نمی‌دانم، پس این کلاس یک شیء
async سازگار با ``redis.asyncio.Redis`` (متدهای get/setex/delete)
می‌گیرد. اگر wrapper اختصاصی دارید (مثل ``app.core.cache.get_redis()``)،
همان را در dependency تزریق کنید — امضای PermissionService عوض
نمی‌شود.
"""

from __future__ import annotations

import json
from typing import Any
from uuid import UUID

CACHE_TTL_SECONDS = 60
_CACHE_KEY_PREFIX = "rbac:perms:"


def cache_key(user_id: UUID) -> str:
    return f"{_CACHE_KEY_PREFIX}{user_id}"


class PermissionService:
    def __init__(self, session: Any, redis_client: Any | None = None) -> None:
        self.session = session
        self.redis = redis_client

    async def effective_permissions(self, user_id: UUID) -> set[str]:
        if self.redis is not None:
            cached = await self._get_cached(user_id)
            if cached is not None:
                return cached

        perms = await self._load_from_db(user_id)

        if self.redis is not None:
            await self._set_cached(user_id, perms)

        return perms

    async def invalidate(self, user_id: UUID) -> None:
        """توسط subscriber رویداد rbac.role.assigned/revoked صدا زده می‌شود."""
        if self.redis is None:
            return
        try:
            await self.redis.delete(cache_key(user_id))
        except Exception:  # noqa: BLE001 — خرابی کش نباید عملیات اصلی را بشکند
            import logging
            logging.getLogger("rbac.permissions").exception(
                "failed to invalidate permission cache for user_id=%s", user_id
            )

    # ── داخلی ──────────────────────────────────────────────
    async def _load_from_db(self, user_id: UUID) -> set[str]:
        from sqlalchemy import text

        # طبق schema بخش ۴.۳: user_roles → role_permissions → permissions
        # نقش‌های منقضی‌شده (expires_at گذشته) حساب نمی‌شوند.
        result = await self.session.execute(
            text(
                """
                SELECT DISTINCT p.code
                FROM rbac.user_roles ur
                JOIN rbac.role_permissions rp ON rp.role_id = ur.role_id
                JOIN rbac.permissions p ON p.id = rp.permission_id
                WHERE ur.user_id = :user_id
                  AND (ur.expires_at IS NULL OR ur.expires_at > now())
                """
            ),
            {"user_id": str(user_id)},
        )
        return {row[0] for row in result.fetchall()}

    async def _get_cached(self, user_id: UUID) -> set[str] | None:
        try:
            raw = await self.redis.get(cache_key(user_id))
        except Exception:  # noqa: BLE001 — کش در دسترس نبود؛ برو سراغ DB
            return None
        if raw is None:
            return None
        try:
            return set(json.loads(raw))
        except (TypeError, ValueError):
            return None

    async def _set_cached(self, user_id: UUID, perms: set[str]) -> None:
        try:
            await self.redis.setex(cache_key(user_id), CACHE_TTL_SECONDS, json.dumps(sorted(perms)))
        except Exception:  # noqa: BLE001 — نوشتن کش شکست خورد؛ درخواست جاری هنوز درست جواب می‌گیرد
            import logging
            logging.getLogger("rbac.permissions").exception(
                "failed to cache permissions for user_id=%s", user_id
            )
```

================================================================================
## MISSING FILES (not found in source repo)
================================================================================

- [MISSING] `﻿backend/app/modules/auth/api/__init__.py`
- [MISSING] `backend/app/modules/auth/api/router.py`
- [MISSING] `backend/app/modules/auth/db/repository.py`
- [MISSING] `backend/app/modules/auth/services/mfa_service.py`
- [MISSING] `backend/app/modules/auth/services/device_service.py`
- [MISSING] `backend/app/modules/auth/schemas.py`
- [MISSING] `backend/app/modules/rbac/api/router.py`
- [MISSING] `backend/app/modules/rbac/db/repository.py`
- [MISSING] `backend/app/modules/rbac/services/__init__.py`
- [MISSING] `backend/app/modules/rbac/services/policy_engine.py`
- [MISSING] `backend/app/modules/rbac/cache.py`
- [MISSING] `backend/app/modules/rbac/schemas.py`
- [MISSING] `backend/app/modules/audit/api/router.py`
- [MISSING] `backend/app/modules/audit/services/__init__.py`
- [MISSING] `backend/app/modules/audit/services/hash_chain.py`
- [MISSING] `backend/app/modules/audit/schemas.py`

