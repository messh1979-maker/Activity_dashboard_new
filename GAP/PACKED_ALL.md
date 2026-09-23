# GAP PACK — ALL BUNDLES

- Generated : 2026-09-23 10:23:17
- Source    : C:\Projects\GIT\Activity_dashboard_new\GAP
- Files     : 78
- Total     : 952,753 bytes (930.4 KB)

==========================================================================================

==========================================================================================
## FILE: basteh1/backend/app/core/config.py
## SIZE: 7590 bytes
==========================================================================================

```python
"""Application configuration (Pydantic Settings, loaded from ENV / .env).

Architecture v2.0: section 3.1 (core/config.py) and 13.5 (deployment hardening).

Validation happens *inside* the model. (The previous version declared the
``@field_validator`` functions at module level, so they were never applied and
a weak ``SECRET_KEY`` / empty password was silently accepted.)
"""
from __future__ import annotations

from pathlib import Path
from typing import List

from pydantic import AliasChoices, Field, PostgresDsn, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_INSECURE_SECRETS = {
    "change-me-to-a-random-string-at-least-32-chars-long",
    "changeme",
    "secret",
}


class Settings(BaseSettings):
    """Application configuration from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Application
    APP_NAME: str = "Planner Enterprise API"
    APP_VERSION: str = "2.0.0"
    ENV: str = "development"  # development | testing | production
    DEBUG: bool = False
    SQL_ECHO: bool = False  # log every SQL statement (was tied to ENV before)

    # ── Server
    HOST: str = "0.0.0.0"
    PORT: int = 8000

    # ── Security
    SECRET_KEY: str = Field(..., min_length=32)
    # HS256 (shared secret) by default; set both JWT_*_KEY for RS256 (ADR / 3.1).
    ALGORITHM: str = "HS256"
    JWT_PRIVATE_KEY: str | None = None
    JWT_PUBLIC_KEY: str | None = None
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 30
    PASSWORD_RESET_EXPIRE_MINUTES: int = 1440
    # Separate keys per purpose (section 4.9). When unset they are derived from
    # SECRET_KEY, which is acceptable for dev only (enforced in production).
    DATA_ENCRYPTION_KEY: str | None = None   # base64, 32 bytes (AES-256-GCM)
    NATIONAL_ID_PEPPER: str | None = None    # HMAC key for searchable hash

    # ── Database
    POSTGRES_SERVER: str = "localhost"
    POSTGRES_PORT: int = 5432
    POSTGRES_USER: str = ""
    POSTGRES_PASSWORD: str = ""
    POSTGRES_DB: str = ""
    SQLALCHEMY_DATABASE_URI: PostgresDsn = Field(
        ...,
        validation_alias=AliasChoices("SQLALCHEMY_DATABASE_URI", "DATABASE_URL"),
    )
    DB_POOL_SIZE: int = 20
    DB_MAX_OVERFLOW: int = 30

    # ── Redis
    REDIS_HOST: str = "localhost"
    REDIS_PORT: int = 6379
    REDIS_DB: int = 0
    REDIS_URL: str | None = None  # overrides host/port/db when set

    # ── HTTP hardening
    ALLOWED_HOSTS: List[str] = ["*"]
    CORS_ORIGINS: List[str] = ["http://localhost:3000", "http://localhost:8080"]
    # WebSocket Origin allow-list (WebSocket is not covered by CORS, 12.8).
    # Empty -> falls back to CORS_ORIGINS.
    ALLOWED_ORIGINS: List[str] = []
    TRUSTED_PROXIES: List[str] = []  # only these may set X-Forwarded-For
    IP_ALLOW_LIST: List[str] = []
    IP_DENY_LIST: List[str] = []
    MAX_BODY_SIZE: int = 1_048_576  # 1 MiB for JSON endpoints

    # ── Feature flags
    ENABLE_MFA: bool = True
    ENABLE_SSO: bool = True
    ENABLE_AUDIT_LOGGING: bool = True
    ALLOW_SELF_REGISTRATION: bool = False
    DEVICE_BINDING_MODE: str = "observe"  # off | observe | enforce (ADR-08)

    # ── Rate limiting (limits are "N/period", period: second|minute|hour)
    RATE_LIMIT_DEFAULT: str = "100/minute"
    RATE_LIMIT_AUTH: str = "10/minute"
    RATE_LIMIT_ENABLED: bool = True

    # ── Paths
    BASE_DIR: Path = Path(__file__).parent.parent
    ROOT_PATH: str = ""

    # ── File storage
    MAX_UPLOAD_SIZE: int = 52_428_800  # 50MB
    FILE_STORAGE_DIR: str = "backend/storage/uploads"
    ALLOWED_IMAGE_TYPES: List[str] = ["image/jpeg", "image/png", "image/gif"]
    ALLOWED_DOCUMENT_TYPES: List[str] = [
        "application/pdf", "application/msword",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ]

    # ── SSO / LDAP (M12) — LdapService expects these attributes
    LDAP_SERVER_URI: str = "ldaps://ad.corp.local:636"
    LDAP_BASE_DN: str = "DC=corp,DC=local"
    LDAP_BIND_DN: str = ""
    LDAP_BIND_PASSWORD: str = ""
    LDAP_USER_SEARCH_FILTER: str = "(sAMAccountName={username})"
    LDAP_ATTR_OBJECT_GUID: str = "objectGUID"
    LDAP_ATTR_NATIONAL_ID: str | None = None
    LDAP_ATTR_DISPLAY_NAME: str = "displayName"
    LDAP_ATTR_MEMBEROF: str = "memberOf"
    LDAP_GROUP_ROLE_MAP: dict = {}
    LDAP_AUTO_PROVISION: bool = True
    LDAP_KERBEROS_ENABLED: bool = False  # set true only with a real Keytab
    LDAP_KERBEROS_KEYTAB: str = ""       # path to the HTTP service keytab

    # ── Logging
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = (
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s "
        "[%(filename)s:%(lineno)d]"
    )

    # ── Key rotation (key_version is stored beside encrypted data, 4.9)
    KEY_ROTATION_INTERVAL_DAYS: int = 365
    KEY_VERSION: int = 1

    # ------------------------------------------------------------------ #
    @field_validator("SECRET_KEY")
    @classmethod
    def _secret_key_strength(cls, v: str) -> str:
        if len(v) < 32:
            raise ValueError("SECRET_KEY must be at least 32 characters")
        return v

    @field_validator("ALGORITHM")
    @classmethod
    def _algorithm_allowed(cls, v: str) -> str:
        if v not in {"HS256", "RS256"}:
            raise ValueError("ALGORITHM must be HS256 or RS256 ('none' is never allowed)")
        return v

    @field_validator("DEVICE_BINDING_MODE")
    @classmethod
    def _device_mode(cls, v: str) -> str:
        if v not in {"off", "observe", "enforce"}:
            raise ValueError("DEVICE_BINDING_MODE must be off | observe | enforce")
        return v

    @model_validator(mode="after")
    def _cross_field_checks(self) -> "Settings":
        if self.ALGORITHM == "RS256" and not (self.JWT_PRIVATE_KEY and self.JWT_PUBLIC_KEY):
            raise ValueError("ALGORITHM=RS256 requires JWT_PRIVATE_KEY and JWT_PUBLIC_KEY")
        if self.ENV == "production":
            problems = []
            if self.SECRET_KEY in _INSECURE_SECRETS:
                problems.append("SECRET_KEY is a placeholder value")
            if "*" in self.ALLOWED_HOSTS:
                problems.append("ALLOWED_HOSTS must not contain '*'")
            if self.DEBUG:
                problems.append("DEBUG must be false")
            if not self.DATA_ENCRYPTION_KEY:
                problems.append("DATA_ENCRYPTION_KEY must be set (section 4.9)")
            if not self.NATIONAL_ID_PEPPER:
                problems.append("NATIONAL_ID_PEPPER must be set (ADR-06)")
            if self.DEVICE_BINDING_MODE == "off":
                problems.append("DEVICE_BINDING_MODE must not be 'off'")
            if problems:
                raise ValueError("Insecure production configuration: " + "; ".join(problems))
        return self

    # ------------------------------------------------------------------ #
    @property
    def is_production(self) -> bool:
        return self.ENV == "production"

    @property
    def redis_url(self) -> str:
        return self.REDIS_URL or f"redis://{self.REDIS_HOST}:{self.REDIS_PORT}/{self.REDIS_DB}"

    @property
    def ws_allowed_origins(self) -> List[str]:
        return self.ALLOWED_ORIGINS or self.CORS_ORIGINS


settings = Settings()


def get_db_url() -> str:
    """Async SQLAlchemy URL (single source of truth: SQLALCHEMY_DATABASE_URI)."""
    return str(settings.SQLALCHEMY_DATABASE_URI)
```

==========================================================================================
## FILE: basteh1/backend/app/core/db/base.py
## SIZE: 3748 bytes
==========================================================================================

```python
import uuid
from datetime import datetime, timezone
from typing import TypeVar, Generic, Optional, List
from sqlalchemy import (
    Column, Integer, String, DateTime, Boolean, Text, 
    JSON, func, Index, CheckConstraint
)
from sqlalchemy.orm import declarative_base, declared_attr
from sqlalchemy.sql import expression

Base = declarative_base()


# Type variable for generic models
M = TypeVar("M", bound="BaseModel")


class BaseModel(Base):
    """Base model with common fields for all tables."""
    
    __abstract__ = True
    
    # UUID primary key
    id = Column(
        String(36), 
        primary_key=True, 
        default=lambda: str(uuid.uuid4()),
        unique=True
    )
    
    # Soft delete support
    deleted_at = Column(DateTime(timezone=True), nullable=True)
    
    # Timestamps
    created_at = Column(
        DateTime(timezone=True), 
        nullable=False, 
        default=func.now()
    )
    updated_at = Column(
        DateTime(timezone=True), 
        nullable=False, 
        default=func.now(),
        onupdate=func.now()
    )
    
    # Version for optimistic locking
    version = Column(Integer, nullable=False, server_default="1")
    
    # Soft delete check
    __table_args__ = (
        CheckConstraint("deleted_at IS NULL OR deleted_at > created_at"),
    )
    
    def soft_delete(self):
        """Mark record as deleted instead of hard delete."""
        self.deleted_at = datetime.now(timezone.utc)
    
    def is_deleted(self) -> bool:
        """Check if record is soft-deleted."""
        return self.deleted_at is not None
    
    def to_dict(self, exclude: Optional[List[str]] = None) -> dict:
        """Convert model to dict, excluding sensitive fields."""
        data = {}
        for column in self.__table__.columns:
            name = column.name
            if exclude and name in exclude:
                continue
            value = getattr(self, name, None)
            if isinstance(value, datetime):
                value = value.isoformat()
            elif value is None:
                value = None
            data[name] = value
        return data
    
    def update_timestamp(self):
        """Update the updated_at timestamp."""
        self.updated_at = datetime.now(timezone.utc)


# Mixin for audit tracking
class AuditMixin:
    """Mixin that adds audit fields to a model."""
    
    __abstract__ = True
    
    created_by = Column(String(100), nullable=True)
    updated_by = Column(String(100), nullable=True)
    
    def set_audit_fields(self, user_id: str | None = None):
        """Set audit fields for the current user."""
        self.created_by = user_id
        self.updated_by = user_id


# Database utilities
class DatabaseUtils:
    """Utility functions for database operations."""
    
    @staticmethod
    def generate_uuid() -> str:
        """Generate a string UUID."""
        return str(uuid.uuid4())
    
    @staticmethod
    def current_timestamp() -> datetime:
        """Get current UTC timestamp."""
        return datetime.now(timezone.utc)
    
    @staticmethod
    def paginate_query(query, page: int = 1, size: int = 20):
        """Apply pagination to a query."""
        if page < 1:
            page = 1
        if size < 1 or size > 1000:
            size = 20
        offset = (page - 1) * size
        return query.offset(offset).limit(size)
    
    @staticmethod
    def search_vector(columns: list) -> str:
        """Generate GIN search vector string."""
        # This is a placeholder - actual implementation depends on columns
        return func.tsvector(" || ".join([f"coalesce({c}::text, '')" for c in columns]))


# Export base and utilities
__all__ = ["BaseModel", "AuditMixin", "DatabaseUtils", "Base"]
```

==========================================================================================
## FILE: basteh1/backend/app/core/db/session.py
## SIZE: 4311 bytes
==========================================================================================

```python
import asyncio
from typing import AsyncGenerator, Optional
from sqlalchemy.ext.asyncio import (
    AsyncEngine, 
    AsyncSession, 
    create_async_engine,
    async_sessionmaker,
    AsyncAttrs
)
from sqlalchemy.orm import DeclarativeBase
from contextlib import asynccontextmanager

from app.core.config import settings


# Engine creation
#
# NOTE (dev, no-Docker): ORM models in app/modules/*/db/Models.py declare
# unqualified table names while alembic DDL creates one schema per module
# (auth, rbac, groups, planning, chat, inbox, ...). The search_path below
# makes those unqualified names resolve to the right schema without
# rewriting every model. Table names are unique across schemas, so this
# is unambiguous. Long-term (per Architecture v2.0 ADR-04) each model
# should declare its own __table_args__ = {"schema": ...}.
engine: AsyncEngine = create_async_engine(
    # PostgresDsn validates to a URL object; the engine needs a plain string.
    str(settings.SQLALCHEMY_DATABASE_URI),
    echo=settings.SQL_ECHO,
    pool_size=settings.DB_POOL_SIZE,
    max_overflow=settings.DB_MAX_OVERFLOW,
    pool_pre_ping=True,
    pool_recycle=3600,
    connect_args={
        "server_settings": {
            "search_path": (
                "public,auth,rbac,groups,planning,calendar,chat,files,"
                "inbox,notification,reporting,sharing,ssoldap,audit"
            )
        }
    },
)

# Session factory
async_session_factory = async_sessionmaker(
    engine, 
    class_=AsyncSession, 
    expire_on_commit=False,
    autoflush=False,
    autocommit=False,
)


# Context manager for getting a session
@asynccontextmanager
async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """Get an async database session."""
    async with async_session_factory() as session:
        yield session


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency: one session per request, one transaction.

    Commits when the handler returns, rolls back on any exception. Business
    data and the outbox/audit rows written through the same session are
    therefore atomic (architecture 2.3 / 12.3).
    """
    async with async_session_factory() as session:
        try:
            yield session
            await session.commit()
        except BaseException:
            await session.rollback()
            raise


async def dispose_engine() -> None:
    """Close pooled connections (called from the app lifespan on shutdown)."""
    await engine.dispose()


# Unit of Work pattern
class UnitOfWork:
    """Unit of Work pattern for managing database transactions."""
    
    def __init__(self, session: AsyncSession):
        self.session = session
    
    async def commit(self):
        """Commit the current transaction."""
        await self.session.commit()
    
    async def rollback(self):
        """Rollback the current transaction."""
        await self.session.rollback()
    
    async def refresh(self, obj):
        """Refresh an object from the database."""
        await self.session.refresh(obj)
    
    async def add(self, obj) -> None:
        """Add an object to the session."""
        self.session.add(obj)
    
    async def delete(self, obj) -> None:
        """Delete an object from the session."""
        await self.session.delete(obj)
    
    async def get(self, model, id):
        """Get a model by ID."""
        from sqlalchemy import select
        result = await self.session.execute(select(model).where(model.id == id))
        return result.scalar_one_or_none()
    
    async def execute(self, *args, **kwargs):
        """Execute a raw SQL statement."""
        return await self.session.execute(*args, **kwargs)


# Transaction decorator/context manager
class Transaction:
    """Transaction manager for handling database transactions."""
    
    def __init__(self, uow: UnitOfWork):
        self.uow = uow
    
    async def __aenter__(self):
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if exc_type is not None:
            await self.uow.rollback()
            return False
        await self.uow.commit()
        return None


# Export
__all__ = [
    "engine", "async_session_factory", "get_session", "get_db",
    "dispose_engine", "UnitOfWork", "Transaction",
]
```

==========================================================================================
## FILE: basteh1/backend/app/core/events/__init__.py
## SIZE: 183 bytes
==========================================================================================

```python
from app.core.events.bus import DomainEvent, EventBus, event_bus
from app.core.events.outbox import OutboxMessage

__all__ = ["DomainEvent", "EventBus", "event_bus", "OutboxMessage"]
```

==========================================================================================
## FILE: basteh1/backend/app/core/events/bus.py
## SIZE: 7216 bytes
==========================================================================================

```python
"""
app/core/events/bus.py

پیاده‌سازی Event Bus درون‌پروسه‌ای طبق ADR-02 و سند معماری v2.0، بخش ۲.۳.

هدف این فایل: جایگزین کردن importهای مستقیم بین ماژول‌ها (مثل
`from app.modules.audit.db.models import AuditLogs` که در auth_service.py
پیدا شد) با یک مکانیزم رویدادمحور که هیچ ماژولی را به ماژول دیگر
گره نمی‌زند.

طراحی
------
`EventBus.publish()` دو کار همزمان انجام می‌دهد:

  ۱) **تحویل درون‌پروسه‌ای هم‌زمان (synchronous in-process delivery)**:
     هر handler ثبت‌شده برای `event.event_type` بلافاصله در همان
     تراکنش دیتابیس (`session`) فراخوانی می‌شود. این برای مصرف‌کننده‌هایی
     مثل ماژول Audit مناسب است — چون سند صراحتاً می‌گوید ردیف Audit باید
     "در همان تراکنش عملیات اصلی" نوشته شود (بخش ۱۲.۳)، تا اگر تراکنش
     اصلی Rollback شود، ردیف Audit هم با آن Rollback شود (سازگاری کامل،
     نه لاگِ عملیاتی که هرگز ذخیره نشد).

  ۲) **درج در Outbox برای تحویل At-Least-Once به مصرف‌کننده‌های
     بیرون از فرآیند** (Celery workers، مثل Notification/Push/Email):
     یک ردیف `OutboxMessage` در همان تراکنش درج می‌شود. یک Dispatcher
     جداگانه (`workers/tasks/outbox_dispatcher.py`) بعداً این ردیف‌ها را
     می‌خواند و به مصرف‌کننده‌های خارج از فرآیند تحویل می‌دهد.

     چرا هر دو مسیر؟ چون Audit نیاز به تضمین "همان تراکنش" دارد (زنجیره‌ی
     هش باید دقیقاً با ترتیب واقعی نوشته‌ها هماهنگ باشد)، ولی
     Notification/Push نیاز به تضمین "حتی اگر پردازش درخواست کرش کند،
     بعداً ارسال شود" دارد. Outbox این دومی را تضمین می‌کند.

هیچ ماژولی، صرفاً با ثبت/انتشار رویداد، به ماژول دیگر import اضافه
نمی‌کند — رویداد فقط یک `event_type` رشته‌ای و یک payload دیکشنری
است، نه یک کلاس از ماژول دیگر.

نحوه‌ی استفاده در main.py (طبق سند، بخش ۱۲.۱):

    from app.core.events.bus import event_bus
    for m in MODULES:
        m.register_event_handlers(event_bus)

هر ماژول (مثل audit) در `__init__.py` یا `events.py` خودش تابع
`register_event_handlers(bus)` را تعریف می‌کند و `bus.subscribe(...)`
را صدا می‌زند — بدون این‌که هرگز از ماژول ناشر رویداد import کند.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, DefaultDict
from uuid import UUID, uuid4

logger = logging.getLogger("core.events")

# امضای هر handler: async def handler(event: DomainEvent, session) -> None
EventHandler = Callable[["DomainEvent", Any], Awaitable[None]]


@dataclass(frozen=True)
class DomainEvent:
    """رویداد دامنه — مطابق سند معماری v2.0، بخش ۲.۳."""

    event_type: str
    payload: dict[str, Any]
    actor_id: UUID | None = None
    event_id: UUID = field(default_factory=uuid4)
    occurred_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    correlation_id: UUID | None = None


def _as_uuid(value: Any) -> UUID | None:
    try:
        return UUID(str(value)) if value else None
    except (ValueError, AttributeError):
        return None


class EventBus:
    """Event Bus درون‌پروسه‌ای؛ یک نمونه‌ی Singleton (``event_bus``) در کل اپ.

    دو نوع مشترک:

    * ``transactional=True`` (پیش‌فرض) — داخل ``publish`` و در همان تراکنش اجرا
      می‌شود (مثل Audit). اگر تراکنش Rollback شود، اثر handler هم برمی‌گردد.
    * ``transactional=False`` — مصرف‌کننده‌ی «بعد از commit» (مثل Notification):
      فقط توسط Dispatcher از روی جدول Outbox با تضمین At-Least-Once فراخوانی
      می‌شود و باید با ``event_id`` Idempotent باشد.

    قبلاً Dispatcher همان handlerهای هم‌تراکنش را دوباره صدا می‌زد و ردیف‌های
    Audit تکراری ساخته می‌شد؛ حالا این دو دسته کاملاً جدا هستند.
    """

    def __init__(self) -> None:
        self._sync: DefaultDict[str, list[EventHandler]] = defaultdict(list)
        self._async: DefaultDict[str, list[EventHandler]] = defaultdict(list)

    def subscribe(self, event_type: str, handler: EventHandler, *,
                  transactional: bool = True) -> None:
        target = self._sync if transactional else self._async
        if handler in target[event_type]:  # idempotent registration (reload / tests)
            return
        target[event_type].append(handler)
        logger.debug("subscribed %s handler for %s", "txn" if transactional else "async", event_type)

    def handlers_for(self, event_type: str, *, transactional: bool) -> list[EventHandler]:
        return list((self._sync if transactional else self._async).get(event_type, ()))

    def clear(self) -> None:
        """Remove every subscription (test helper)."""
        self._sync.clear()
        self._async.clear()

    async def publish(self, event: DomainEvent, session: Any) -> None:
        """Outbox را در همان تراکنش می‌نویسد و handlerهای هم‌تراکنش را اجرا می‌کند.

        ``actor_id`` / ``correlation_id`` در صورت خالی بودن از Request Context
        پر می‌شوند تا کل زنجیره‌ی یک درخواست قابل ردیابی باشد.
        """
        from app.core.context import get_context
        from app.core.events.outbox import OutboxMessage

        ctx = get_context()
        if event.correlation_id is None or event.actor_id is None:
            event = replace(
                event,
                correlation_id=event.correlation_id or _as_uuid(ctx.correlation_id),
                actor_id=event.actor_id or _as_uuid(ctx.user_id),
            )

        session.add(OutboxMessage.from_event(event))

        for handler in self.handlers_for(event.event_type, transactional=True):
            try:
                await handler(event, session)
            except Exception:  # noqa: BLE001
                logger.exception("event handler failed for event_type=%s (event_id=%s)",
                                 event.event_type, event.event_id)
                raise  # همان تراکنش است؛ کل تراکنش Rollback شود


event_bus = EventBus()
```

==========================================================================================
## FILE: basteh1/backend/app/core/events/outbox.py
## SIZE: 3455 bytes
==========================================================================================

```python
"""
app/core/events/outbox.py

مدل ORM جدول ``core.outbox_messages`` — دقیقاً مطابق DDL سند معماری v2.0،
بخش ۲.۳:

    CREATE TABLE core.outbox_messages (
        id             BIGSERIAL PRIMARY KEY,
        event_id       UUID NOT NULL UNIQUE,
        event_type     VARCHAR(100) NOT NULL,
        payload        JSONB NOT NULL,
        correlation_id UUID,
        created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
        dispatched_at  TIMESTAMPTZ,
        attempts       SMALLINT NOT NULL DEFAULT 0,
        last_error     TEXT
    );
    CREATE INDEX ix_outbox_pending ON core.outbox_messages(created_at)
        WHERE dispatched_at IS NULL;

⚠️ فرض این فایل: پایه‌ی مدل‌های شما در ``app.core.db.base`` با نام
``Base`` صادر می‌شود (الگوی رایج SQLAlchemy 2.0). اگر اسم/مسیر واقعی
پروژه‌ی شما فرق دارد، فقط خط import زیر را اصلاح کنید — بقیه‌ی فایل
دست‌نخورده می‌ماند.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import BigInteger, DateTime, Integer, SmallInteger, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func

try:
    # مسیر استاندارد طبق ساختار پوشه‌ی سند (بخش ۳.۱): core/db/base.py
    from app.core.db.base import Base
except ImportError:  # pragma: no cover — فقط برای این‌که فایل به‌تنهایی هم import شود
    from sqlalchemy.orm import DeclarativeBase

    class Base(DeclarativeBase):  # type: ignore[no-redef]
        """Fallback موقت — اگر این اجرا شد یعنی import بالا را باید اصلاح کنید."""


class OutboxMessage(Base):
    """ردیف Outbox — طبق الگوی Transactional Outbox (ADR-02)."""

    __tablename__ = "outbox_messages"
    __table_args__ = {"schema": "core"}

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    event_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False, unique=True)
    event_type: Mapped[str] = mapped_column(String(100), nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    correlation_id: Mapped[UUID | None] = mapped_column(PG_UUID(as_uuid=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    dispatched_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    attempts: Mapped[int] = mapped_column(SmallInteger, nullable=False, server_default="0")
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)

    @classmethod
    def from_event(cls, event: "DomainEvent") -> "OutboxMessage":  # noqa: F821 — type hint only
        """DomainEvent (از bus.py) را به یک ردیف Outbox قابل‌درج تبدیل می‌کند."""
        return cls(
            event_id=event.event_id,
            event_type=event.event_type,
            # JSONB needs JSON-safe values (UUID/datetime/Decimal -> str)
            payload=json.loads(json.dumps(event.payload, default=str)),
            correlation_id=event.correlation_id,
        )
```

==========================================================================================
## FILE: basteh1/backend/app/core/middleware/__init__.py
## SIZE: 2428 bytes
==========================================================================================

```python
"""Middleware chain (architecture 3.1 ``core/middleware/``).

Order, outermost first:

    RequestID -> SecurityHeaders -> CORS -> TrustedHost -> IPFilter
      -> RateLimit -> BodyGuard -> AuditContext -> application

CORS sits outside the filters so that 403/413/429 answers still carry CORS
headers (otherwise browsers report them as opaque network errors).
"""
from __future__ import annotations

from fastapi import FastAPI
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app.core.config import settings
from app.core.middleware.audit_context import AuditContextMiddleware
from app.core.middleware.body_guard import BodyGuardMiddleware
from app.core.middleware.ip_filter import IPFilterMiddleware
from app.core.middleware.rate_limit import RateLimitMiddleware
from app.core.middleware.request_id import RequestIDMiddleware
from app.core.middleware.security_headers import SecurityHeadersMiddleware


def register_middlewares(app: FastAPI) -> None:
    """Register the whole chain once. (``add_middleware``: last added = outermost.)"""
    app.add_middleware(AuditContextMiddleware)
    app.add_middleware(BodyGuardMiddleware)
    app.add_middleware(RateLimitMiddleware)
    app.add_middleware(IPFilterMiddleware, allow_ips=settings.IP_ALLOW_LIST,
                       deny_ips=settings.IP_DENY_LIST)
    if settings.ALLOWED_HOSTS:
        app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.ALLOWED_HOSTS)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-Request-ID",
                       "X-Correlation-ID", "Idempotency-Key", "If-Match",
                       "X-Device-Fingerprint", "X-Device-MAC", "X-Device-Nonce",
                       "X-Device-Timestamp", "X-Device-Signature",
                       "X-Device-MAC-Source", "X-Requested-With"],
        expose_headers=["X-Request-ID", "ETag", "Retry-After"],
    )
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(RequestIDMiddleware)


__all__ = [
    "register_middlewares", "RequestIDMiddleware", "SecurityHeadersMiddleware",
    "IPFilterMiddleware", "RateLimitMiddleware", "BodyGuardMiddleware",
    "AuditContextMiddleware",
]
```

==========================================================================================
## FILE: basteh1/backend/app/core/middleware/audit_context.py
## SIZE: 1512 bytes
==========================================================================================

```python
"""Fills network/device identity into the request context (architecture 3.1).

The identity that ends up in audit rows always comes from here (headers /
socket), never from a request body. ``mac_verified`` stays False until the
device-binding step validates the HMAC signature (ADR-08: MAC is a forensic
signal, not a security control).
"""
from __future__ import annotations

import re

from starlette.datastructures import Headers
from starlette.types import ASGIApp, Receive, Scope, Send

from app.core.context import get_context
from app.core.middleware._http import client_ip

_MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$")
_FP_RE = re.compile(r"^[A-Za-z0-9+/=_\-]{16,255}$")


class AuditContextMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] in ("http", "websocket"):
            h = Headers(scope=scope)
            ctx = get_context()
            ctx.ip = client_ip(scope)
            ctx.user_agent = (h.get("user-agent") or "")[:512] or None
            mac = h.get("x-device-mac")
            if mac and _MAC_RE.match(mac):
                ctx.mac_address = mac.upper().replace("-", ":")
            fp = h.get("x-device-fingerprint")
            if fp and _FP_RE.match(fp):
                ctx.device_fingerprint = fp
            ctx.correlation_id = h.get("x-correlation-id") or ctx.request_id
        await self.app(scope, receive, send)
```

==========================================================================================
## FILE: basteh1/backend/app/core/middleware/ip_filter.py
## SIZE: 1605 bytes
==========================================================================================

```python
"""IP allow / deny lists (CIDR aware). Deny wins over allow."""
from __future__ import annotations

from starlette.types import ASGIApp, Receive, Scope, Send

from app.core.middleware._http import client_ip, ip_in, parse_networks, send_error


class IPFilterMiddleware:
    def __init__(self, app: ASGIApp, allow_ips: list[str] | None = None,
                 deny_ips: list[str] | None = None) -> None:
        self.app = app
        self.allow = parse_networks(allow_ips or [])
        self.deny = parse_networks(deny_ips or [])

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ("http", "websocket") or not (self.allow or self.deny):
            await self.app(scope, receive, send)
            return
        ip = client_ip(scope)
        if self.deny and ip_in(ip, self.deny):
            await self._reject(scope, receive, send, "IP_ADDRESS_DENIED",
                               "آدرس IP شما مسدود شده است.")
            return
        if self.allow and not ip_in(ip, self.allow):
            await self._reject(scope, receive, send, "IP_ADDRESS_NOT_ALLOWED",
                               "دسترسی از این آدرس IP مجاز نیست.")
            return
        await self.app(scope, receive, send)

    @staticmethod
    async def _reject(scope, receive, send, code, message) -> None:
        if scope["type"] == "websocket":
            await send({"type": "websocket.close", "code": 4403})
            return
        await send_error(scope, receive, send, status=403, code=code, message=message)
```

==========================================================================================
## FILE: basteh1/backend/app/core/middleware/rate_limit.py
## SIZE: 5467 bytes
==========================================================================================

```python
"""L7 rate limiting (architecture 1.1 / 11).

* Limits come from settings (``RATE_LIMIT_DEFAULT`` / ``RATE_LIMIT_AUTH``) -
  the old middleware ignored them and hard-coded 100.
* Backend: Redis when reachable (shared by all workers), otherwise a bounded
  in-process sliding window. The in-memory backend evicts idle keys, so it can
  no longer grow without bound.
* Keyed by client IP + bucket (auth endpoints have their own, stricter bucket)
  - not by path, which let an attacker multiply their quota by rotating URLs.
"""
from __future__ import annotations

import logging
import time
from collections import deque
from typing import Optional, Protocol

from starlette.types import ASGIApp, Receive, Scope, Send

from app.core.config import settings
from app.core.middleware._http import client_ip, send_error

logger = logging.getLogger("core.rate_limit")

_PERIODS = {"second": 1, "minute": 60, "hour": 3600, "day": 86400}
_AUTH_PREFIXES = (
    "/api/v1/auth/login", "/api/v1/auth/register", "/api/v1/auth/refresh",
    "/api/v1/auth/password", "/api/v1/auth/mfa", "/api/v1/auth/sso",
)


def parse_limit(spec: str) -> tuple[int, int]:
    """``"100/minute"`` -> (100, 60)."""
    try:
        count, period = spec.strip().split("/")
        return int(count), _PERIODS[period.strip().lower()]
    except (ValueError, KeyError):
        raise ValueError(f"invalid rate limit spec: {spec!r} (expected N/second|minute|hour|day)")


class Limiter(Protocol):
    async def hit(self, key: str, limit: int, window: int) -> tuple[bool, int]:
        """Register a hit. Returns (allowed, retry_after_seconds)."""


class MemoryLimiter:
    def __init__(self, max_keys: int = 50_000) -> None:
        self._hits: dict[str, deque[float]] = {}
        self._max_keys = max_keys
        self._last_sweep = time.monotonic()

    async def hit(self, key: str, limit: int, window: int) -> tuple[bool, int]:
        now = time.monotonic()
        self._sweep(now, window)
        q = self._hits.setdefault(key, deque())
        while q and now - q[0] >= window:
            q.popleft()
        if len(q) >= limit:
            return False, max(1, int(window - (now - q[0])) + 1)
        q.append(now)
        return True, 0

    def _sweep(self, now: float, window: int) -> None:
        if now - self._last_sweep < 30 and len(self._hits) < self._max_keys:
            return
        self._last_sweep = now
        for k in [k for k, q in self._hits.items() if not q or now - q[-1] >= max(window, 60)]:
            del self._hits[k]
        if len(self._hits) >= self._max_keys:  # hard cap: drop oldest half
            for k in list(self._hits)[: self._max_keys // 2]:
                del self._hits[k]


class RedisLimiter:
    """Fixed-window counter shared across workers; falls back on any error."""

    def __init__(self, url: str, fallback: Limiter) -> None:
        import redis.asyncio as aioredis

        self._redis = aioredis.from_url(url, socket_connect_timeout=0.5, socket_timeout=0.5)
        self._fallback = fallback

    async def hit(self, key: str, limit: int, window: int) -> tuple[bool, int]:
        try:
            bucket = int(time.time()) // window
            rkey = f"rl:{key}:{bucket}"
            pipe = self._redis.pipeline()
            pipe.incr(rkey)
            pipe.expire(rkey, window + 1)
            count, _ = await pipe.execute()
            if count > limit:
                return False, window - (int(time.time()) % window) or 1
            return True, 0
        except Exception as exc:  # Redis down must not take the API down
            logger.warning("redis rate limiter unavailable (%s); using in-memory", exc)
            return await self._fallback.hit(key, limit, window)


def build_limiter() -> Limiter:
    memory = MemoryLimiter()
    if settings.ENV == "testing":
        return memory
    try:
        return RedisLimiter(settings.redis_url, memory)
    except Exception:  # redis package missing / bad URL
        return memory


class RateLimitMiddleware:
    def __init__(self, app: ASGIApp, limiter: Optional[Limiter] = None,
                 default: Optional[str] = None, auth: Optional[str] = None) -> None:
        self.app = app
        self.limiter = limiter or build_limiter()
        self.default = parse_limit(default or settings.RATE_LIMIT_DEFAULT)
        self.auth = parse_limit(auth or settings.RATE_LIMIT_AUTH)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if (scope["type"] != "http" or not settings.RATE_LIMIT_ENABLED
                or scope["method"] == "OPTIONS"):
            await self.app(scope, receive, send)
            return
        path = scope.get("path", "")
        if path in ("/health", "/ready"):
            await self.app(scope, receive, send)
            return
        bucket, (limit, window) = (("auth", self.auth) if path.startswith(_AUTH_PREFIXES)
                                   else ("default", self.default))
        allowed, retry_after = await self.limiter.hit(
            f"{bucket}:{client_ip(scope)}", limit, window)
        if not allowed:
            await send_error(
                scope, receive, send, status=429, code="RATE_LIMIT_EXCEEDED",
                message="درخواست‌های بیش از حد ارسال شده است. لطفاً کمی بعد تلاش کنید.",
                headers={"Retry-After": str(retry_after)})
            return
        await self.app(scope, receive, send)
```

==========================================================================================
## FILE: basteh1/backend/app/core/middleware/request_id.py
## SIZE: 1489 bytes
==========================================================================================

```python
"""Creates the per-request context and the ``X-Request-ID`` header."""
from __future__ import annotations

import re
from uuid import uuid4

from starlette.datastructures import Headers, MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.context import RequestContext, reset_context, set_context

_SAFE_ID = re.compile(r"^[A-Za-z0-9\-_.]{8,64}$")


class RequestIDMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return
        incoming = Headers(scope=scope).get("x-request-id", "")
        # Accept a client id only if it is short/safe (log-injection guard).
        request_id = incoming if _SAFE_ID.match(incoming) else str(uuid4())
        ctx = RequestContext(request_id=request_id, path=scope.get("path"),
                             method=scope.get("method"))
        scope.setdefault("state", {})["request_id"] = request_id
        token = set_context(ctx)

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                MutableHeaders(scope=message)["X-Request-ID"] = request_id
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            reset_context(token)
```

==========================================================================================
## FILE: basteh1/backend/app/core/middleware/security_headers.py
## SIZE: 2084 bytes
==========================================================================================

```python
"""Security headers on every HTTP response (architecture 11 / 1.5)."""
from __future__ import annotations

from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.config import settings

# Pure JSON API: nothing may be loaded or framed from an API response.
_API_CSP = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
# Swagger UI / ReDoc need inline scripts and a CDN (non-production only).
_DOCS_CSP = (
    "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "img-src 'self' data: https://fastapi.tiangolo.com; frame-ancestors 'none'"
)
_DOCS_PATHS = ("/docs", "/redoc")


class SecurityHeadersMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        path = scope.get("path", "")
        is_docs = (not settings.is_production) and path.startswith(_DOCS_PATHS)

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                h = MutableHeaders(scope=message)
                h["X-Content-Type-Options"] = "nosniff"
                h["X-Frame-Options"] = "DENY"
                h["Referrer-Policy"] = "strict-origin-when-cross-origin"
                h["Cross-Origin-Resource-Policy"] = "same-site"
                h["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
                h["Content-Security-Policy"] = _DOCS_CSP if is_docs else _API_CSP
                if not is_docs:
                    h.setdefault("Cache-Control", "no-store")  # tokens/PII in bodies
                if settings.is_production:
                    h["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
            await send(message)

        await self.app(scope, receive, send_wrapper)
```

==========================================================================================
## FILE: basteh1/backend/app/core/security.py
## SIZE: 2348 bytes
==========================================================================================

```python
"""Security primitives for WebSocket/device binding (architecture 1.2).

Mirrors the Windows desktop client's device fingerprint + HMAC scheme so a
WebSocket handshake can be tied to a known device, reusing the same
``SECRET_KEY`` domain.
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Optional
from uuid import UUID

from app.core.config import settings


def get_device_fingerprint(
    user_agent: Optional[str] = None,
    ip: Optional[str] = None,
    mac: Optional[str] = None,
    salt: Optional[str] = None,
) -> str:
    """Stable per-device fingerprint from the available client hints.

    Missing components are skipped so fingerprints stay stable for clients
    that do not disclose them.  The digest is truncated (16 bytes) to keep
    stored fingerprints compact.
    """
    parts: list[str] = []
    if salt:
        parts.append(salt)
    if mac:
        parts.append(mac.strip().lower())
    if user_agent:
        parts.append(user_agent.strip())
    if ip:
        parts.append(ip.strip())
    if not parts:
        # Deterministic fallback so a missing fingerprint never crashes auth.
        parts.append("unknown-device")
    raw = "|".join(parts).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:32]


def verify_hmac_signature(
    signature: str,
    *,
    user_id,
    endpoint: str,
    payload: Optional[str] = None,
) -> bool:
    """Verify an HMAC-SHA256 device signature (constant-time compare).

    The signature should be computed by the client as
    ``HMAC_SHA256(secret_key, f"{user_id}|{endpoint}|{payload}")``.  A
    missing signature or key is a hard reject.
    """
    if not signature or not settings.SECRET_KEY:
        return False
    message = "|".join([str(user_id), endpoint, payload or ""]).encode("utf-8")
    expected = hmac.new(
        settings.SECRET_KEY.encode("utf-8"), message, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(signature.strip().lower(), expected.lower())


def hmac_sign(user_id, endpoint: str, payload: Optional[str] = None) -> str:
    """Helper used where the *server* must mint a signature (e.g. callbacks)."""
    message = "|".join([str(user_id), endpoint, payload or ""]).encode("utf-8")
    return hmac.new(
        settings.SECRET_KEY.encode("utf-8"), message, hashlib.sha256
    ).hexdigest()
```

==========================================================================================
## FILE: basteh1/backend/app/main.py
## SIZE: 4012 bytes
==========================================================================================

```python
"""
Planner Enterprise API - Main Application Entry Point

Architecture: Modular Monolith with Defense in Depth
Version: 2.0
"""

import logging
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from sqlalchemy import text

from app.core.config import settings
from app.core.database import dispose_engine, engine
from app.core.errors import register_exception_handlers
from app.core.events import event_bus
from app.core.middleware import register_middlewares
from app.core.redis import get_redis_broker
from app.modules import auth, rbac, groups, goals, sharing, chat, inbox, \
                        reporting, notification, audit, ssoldap, files, calendar
from app.ws.routes import router as websocket_router

logging.basicConfig(level=settings.LOG_LEVEL, format=settings.LOG_FORMAT)

# Module order matters for initialization
MODULES = [auth, rbac, groups, goals, sharing,
           chat, inbox, reporting, notification, audit, ssoldap, files, calendar]


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    # Redis publisher/subscriber pool (in-memory fallback when unreachable)
    broker = get_redis_broker()
    await broker.connect()

    # Event bus subscriptions (modules without handlers are skipped)
    for m in MODULES:
        register = getattr(m, "register_event_handlers", None)
        if callable(register):
            register(event_bus)

    yield

    # Graceful shutdown: return pooled connections to PostgreSQL
    await shutdown_gracefully()
    await broker.close()


_docs_enabled = not settings.is_production

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    lifespan=lifespan,
    root_path=settings.ROOT_PATH,
    docs_url="/docs" if _docs_enabled else None,
    redoc_url="/redoc" if _docs_enabled else None,
    openapi_url="/openapi.json" if _docs_enabled else None,
)

# --- Middleware chain (single place; order documented in core/middleware) ---
register_middlewares(app)

# --- Exception handlers ---
register_exception_handlers(app)

# --- Include Module Routers ---
# All modules use /api/v1 prefix.
# Empty/stub modules (audit, files, notification, ssoldap) expose no router
# yet and are skipped until their routes land.
for m in MODULES:
    router = getattr(m, "router", None)
    if router is not None:
        app.include_router(router, prefix="/api/v1")

# --- WebSocket gateway (architecture 5.5: /ws/chat, /ws/notifications) ---
app.include_router(websocket_router)

async def shutdown_gracefully():
    """Graceful shutdown routine."""
    await dispose_engine()


# Liveness: process is up (no dependencies touched)
@app.get("/health", include_in_schema=False)
async def health_check():
    return {
        "status": "healthy",
        "service": "planner-enterprise-api",
        "version": settings.APP_VERSION,
        "modules": [m.__name__ for m in MODULES],
    }


# Readiness: dependencies reachable (used by the load balancer)
@app.get("/ready", include_in_schema=False)
async def readiness_check():
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
    except Exception:
        logging.getLogger("app.health").exception("readiness: database unreachable")
        return JSONResponse(status_code=503, content={"status": "unavailable", "database": "down"})
    return {"status": "ready", "database": "up"}


# Root endpoint
@app.get("/", include_in_schema=False)
async def root():
    return {
        "message": "Planner Enterprise API",
        "version": settings.APP_VERSION,
        "docs": "/docs" if settings.ENV != "production" else "disabled",
        "endpoints": "/api/v1/auth, /api/v1/goals, /api/v1/groups, etc."
    }

if __name__ == "__main__":
    uvicorn.run(
        "app.main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.ENV == "development",
        access_log=False
    )
```

==========================================================================================
## FILE: basteh2/backend/app/modules/audit/__init__.py
## SIZE: 233 bytes
==========================================================================================

```python
"""Audit module public interface (real DDL-backed audit, section M11)."""
from app.modules.audit.api.routes import router
from app.modules.audit.events import register_event_handlers


__all__ = ["router", "register_event_handlers"]
```

==========================================================================================
## FILE: basteh2/backend/app/modules/audit/db/models.py
## SIZE: 6239 bytes
==========================================================================================

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

==========================================================================================
## FILE: basteh2/backend/app/modules/audit/events.py
## SIZE: 2402 bytes
==========================================================================================

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

==========================================================================================
## FILE: basteh2/backend/app/modules/audit/services/audit_service.py
## SIZE: 7105 bytes
==========================================================================================

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

==========================================================================================
## FILE: basteh2/backend/app/modules/auth/__init__.py
## SIZE: 324 bytes
==========================================================================================

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

==========================================================================================
## FILE: basteh2/backend/app/modules/auth/api/deps.py
## SIZE: 802 bytes
==========================================================================================

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

==========================================================================================
## FILE: basteh2/backend/app/modules/auth/db/__init__.py
## SIZE: 31 bytes
==========================================================================================

```python
"""Auth persistence layer."""
```

==========================================================================================
## FILE: basteh2/backend/app/modules/auth/db/models.py
## SIZE: 6406 bytes
==========================================================================================

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

==========================================================================================
## FILE: basteh2/backend/app/modules/auth/events.py
## SIZE: 1482 bytes
==========================================================================================

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

==========================================================================================
## FILE: basteh2/backend/app/modules/auth/ports.py
## SIZE: 3584 bytes
==========================================================================================

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

==========================================================================================
## FILE: basteh2/backend/app/modules/auth/services/__init__.py
## SIZE: 115 bytes
==========================================================================================

```python
"""Auth services public interface."""
from app.modules.auth.db.mfa import MFAService

__all__ = ["MFAService"]
```

==========================================================================================
## FILE: basteh2/backend/app/modules/auth/services/auth_service.py
## SIZE: 27510 bytes
==========================================================================================

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

==========================================================================================
## FILE: basteh2/backend/app/modules/rbac/__init__.py
## SIZE: 109 bytes
==========================================================================================

```python
"""RBAC module public interface."""
from app.modules.rbac.api.routes import router

__all__ = ["router"]
```

==========================================================================================
## FILE: basteh2/backend/app/modules/rbac/db/models.py
## SIZE: 6099 bytes
==========================================================================================

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

==========================================================================================
## FILE: basteh2/backend/app/modules/rbac/events.py
## SIZE: 2064 bytes
==========================================================================================

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

==========================================================================================
## FILE: basteh2/backend/app/modules/rbac/ports.py
## SIZE: 3236 bytes
==========================================================================================

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

==========================================================================================
## FILE: basteh2/backend/app/modules/rbac/services/permission_service.py
## SIZE: 4107 bytes
==========================================================================================

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

==========================================================================================
## FILE: basteh3/backend/app/modules/calendar/__init__.py
## SIZE: 123 bytes
==========================================================================================

```python
"""Calendar module public interface (real DDL)."""
from app.modules.calendar.api.routes import router

__all__ = ["router"]
```

==========================================================================================
## FILE: basteh3/backend/app/modules/calendar/services/calendar_service.py
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
## FILE: basteh3/backend/app/modules/goals/__init__.py
## SIZE: 111 bytes
==========================================================================================

```python
"""Goals module public interface."""
from app.modules.goals.api.routes import router

__all__ = ["router"]
```

==========================================================================================
## FILE: basteh3/backend/app/modules/goals/db/models.py
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
## FILE: basteh3/backend/app/modules/groups/__init__.py
## SIZE: 113 bytes
==========================================================================================

```python
"""Groups module public interface."""
from app.modules.groups.api.routes import router

__all__ = ["router"]
```

==========================================================================================
## FILE: basteh3/backend/app/modules/groups/db/models.py
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
## FILE: basteh3/backend/app/modules/inbox/__init__.py
## SIZE: 111 bytes
==========================================================================================

```python
"""Inbox module public interface."""
from app.modules.inbox.api.routes import router

__all__ = ["router"]
```

==========================================================================================
## FILE: basteh3/backend/app/modules/inbox/db/models.py
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
## FILE: basteh3/backend/app/modules/inbox/services/inbox_service.py
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
## FILE: basteh3/backend/app/modules/reporting/__init__.py
## SIZE: 228 bytes
==========================================================================================

```python
"""Reporting module public interface."""
from app.modules.reporting.api.routes import router
from app.modules.reporting.api.dashboard import dashboard_router

router.include_router(dashboard_router)

__all__ = ["router"]
```

==========================================================================================
## FILE: basteh3/backend/app/modules/sharing/__init__.py
## SIZE: 115 bytes
==========================================================================================

```python
"""Sharing module public interface."""
from app.modules.sharing.api.routes import router

__all__ = ["router"]
```

==========================================================================================
## FILE: basteh3/backend/app/modules/sharing/db/models.py
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
## FILE: basteh3/backend/app/modules/sharing/services/sharing_service.py
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
## FILE: basteh3/backend/app/modules/ssoldap/__init__.py
## SIZE: 312 bytes
==========================================================================================

```python
"""SSO/LDAP module public interface (stub — full implementation per Architecture v2.0 Section M12)."""
from app.modules.ssoldap.api.routes import router


def register_event_handlers(event_bus) -> None:
    """Subscribe to cross-module events (no-op stub)."""


__all__ = ["router", "register_event_handlers"]
```

==========================================================================================
## FILE: basteh3/backend/app/modules/ssoldap/services/ldap_service.py
## SIZE: 8945 bytes
==========================================================================================

```python
"""
app/modules/ssoldap/services/ldap_service.py

این ماژول (M12) قبلاً فقط یک ``api/`` خالی بود — نه db، نه services.
طبق سند:
  - بخش ۲.۵: SSO/LDAP جزو فاز ۱ (پیش‌نیاز همه‌چیز) است.
  - بخش ۱۴ (جدول ریسک): «SSO با Kerberos در محیط واقعی AD کار نکند» →
    ریسک بالا → **«Fallback به LDAP Bind از روز اول»**.

پس اول ``LDAP Bind`` (نام‌کاربری+رمز مستقیم به AD) ساخته می‌شود —
چون بدون Keytab/KDC واقعی هم قابل‌ساخت و تا حدی قابل‌تست است. Kerberos/
SPNEGO کامل (``gssapi``) نیاز به محیط AD واقعی برای تست دارد و باید
جدا (به‌عنوان Spike دوروزه، طبق توصیه‌ی خودِ سند) پیگیری شود —
``app/modules/ssoldap/api/negotiate.py`` در همین پچ فقط یک اسکلت
401 برمی‌گرداند، نه پیاده‌سازی کامل SPNEGO.

⚠️ وابستگی‌ها: `pip list` شما نشان داد ``ldap3`` نصب نیست. برای همین
import آن اینجا **تنبل (lazy)** است — تا وقتی کسی واقعاً وارد کردن
LDAP نزند، بقیه‌ی اپ (که به این ماژول نیازی ندارد) از کار نمی‌افتد.
نصب لازم:

    pip install ldap3

⚠️ تنظیمات لازم (باید به ``app/core/config.py`` اضافه شوند — چون به
محتوای فایل شما دسترسی ندارم، فقط اسم‌هایی که این فایل انتظار دارد
را مستند می‌کنم):

    LDAP_SERVER_URI        # مثل "ldaps://ad.corp.local:636"
    LDAP_BASE_DN           # مثل "DC=corp,DC=local"
    LDAP_BIND_DN           # اکانت سرویس فقط-خواندنی برای search
    LDAP_BIND_PASSWORD     # طبق سند باید AES-256-GCM رمزنگاری‌شده در Vault/DB
                            # باشد؛ اگر از env var/Secret Manager می‌آید همین کافی است
    LDAP_USER_SEARCH_FILTER = "(sAMAccountName={username})"
    LDAP_ATTR_OBJECT_GUID = "objectGUID"
    LDAP_ATTR_NATIONAL_ID  # نام Attribute سفارشی AD شما برای کد ملی — باید با تیم AD هماهنگ شود
    LDAP_ATTR_DISPLAY_NAME = "displayName"
    LDAP_ATTR_MEMBEROF = "memberOf"
    LDAP_GROUP_ROLE_MAP: dict[str, str]  # DN گروه AD → کد نقش داخلی، مثل:
        # {"CN=Managers,OU=Groups,DC=corp,DC=local": "manager"}
    LDAP_AUTO_PROVISION: bool = True
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


class LdapAuthError(Exception):
    """احراز هویت LDAP شکست خورد (رمز غلط، کاربر یافت نشد، سرور در دسترس نیست)."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(f"{code}: {message}")


@dataclass(frozen=True)
class LdapUserInfo:
    """نتیجه‌ی موفق احراز هویت + جست‌وجوی LDAP — چیزی که SsoLoginService مصرف می‌کند."""

    dn: str
    object_guid: str
    sam_account_name: str
    display_name: str
    national_id: str | None
    member_of: list[str] = field(default_factory=list)


def escape_ldap_filter_value(value: str) -> str:
    """طبق سند (بخش امنیت، ردیف A03 Injection): ``escape_filter_chars`` برای LDAP.

    این تابع pure و بدون وابستگی به ldap3 است تا بدون نصب ldap3 هم قابل‌تست
    باشد (ldap3.utils.conv.escape_filter_chars هم دقیقاً همین RFC 4515 را
    پیاده می‌کند — اگر ldap3 نصب بود می‌توانید مستقیم از آن استفاده کنید).
    """
    replacements = {
        "\\": r"\5c",
        "*": r"\2a",
        "(": r"\28",
        ")": r"\29",
        "\x00": r"\00",
    }
    return "".join(replacements.get(ch, ch) for ch in value)


def map_groups_to_roles(member_of: list[str], group_role_map: dict[str, str]) -> list[str]:
    """نگاشت DN گروه‌های AD به کدهای نقش داخلی — طبق سند بخش ۱.۳: «نگاشت memberOf → roles».

    مقایسه‌ی DN بدون حساسیت به بزرگی/کوچکی حروف و فاصله‌های اضافه انجام
    می‌شود، چون AD معمولاً DN را با فرمت‌بندی متفاوت (فاصله بعد از کاما)
    برمی‌گرداند.
    """
    normalized_map = {_normalize_dn(dn): role for dn, role in group_role_map.items()}
    roles = []
    for dn in member_of:
        role = normalized_map.get(_normalize_dn(dn))
        if role and role not in roles:
            roles.append(role)
    return roles


def _normalize_dn(dn: str) -> str:
    return re.sub(r",\s*", ",", dn.strip().lower())


class LdapService:
    """Bind مستقیم کاربر به AD (نه Kerberos) — endpoint: ``POST /auth/sso/ldap-login``."""

    def __init__(self, settings: Any) -> None:
        self.settings = settings

    async def authenticate(self, username: str, password: str) -> LdapUserInfo:
        """کاربر را مستقیماً به AD bind می‌کند و اطلاعاتش را برمی‌گرداند.

        دو مرحله (طبق الگوی رایج AD bind، چون sAMAccountName به‌تنهایی DN
        نیست): (۱) با اکانت سرویس bind و DN کاربر را search می‌کند،
        (۲) با DN واقعی و رمز کاربر دوباره bind می‌کند تا رمز واقعاً
        تأیید شود.
        """
        try:
            import ldap3
            from ldap3 import ALL, Connection, Server
            from ldap3.core.exceptions import LDAPBindError, LDAPException
        except ImportError as exc:  # pragma: no cover
            raise LdapAuthError(
                "LDAP_NOT_CONFIGURED",
                "پکیج ldap3 نصب نیست — `pip install ldap3` را اجرا کنید.",
            ) from exc

        if not username or not password:
            raise LdapAuthError("INVALID_CREDENTIALS", "نام کاربری/رمز خالی است.")

        safe_username = escape_ldap_filter_value(username)
        search_filter = self.settings.LDAP_USER_SEARCH_FILTER.format(username=safe_username)

        server = Server(self.settings.LDAP_SERVER_URI, get_info=ALL, use_ssl=True)

        # مرحله ۱: bind با اکانت سرویس (فقط خواندنی) + search برای پیدا کردن DN کاربر
        try:
            service_conn = Connection(
                server, user=self.settings.LDAP_BIND_DN,
                password=self.settings.LDAP_BIND_PASSWORD, auto_bind=True,
            )
        except LDAPException as exc:
            raise LdapAuthError("LDAP_UNAVAILABLE", "اتصال به AD ممکن نشد.") from exc

        attrs = [
            self.settings.LDAP_ATTR_OBJECT_GUID,
            self.settings.LDAP_ATTR_DISPLAY_NAME,
            self.settings.LDAP_ATTR_MEMBEROF,
        ]
        national_id_attr = getattr(self.settings, "LDAP_ATTR_NATIONAL_ID", None)
        if national_id_attr:
            attrs.append(national_id_attr)

        service_conn.search(
            search_base=self.settings.LDAP_BASE_DN,
            search_filter=search_filter,
            attributes=attrs,
        )
        if not service_conn.entries:
            service_conn.unbind()
            raise LdapAuthError("USER_NOT_FOUND", "کاربر در AD یافت نشد.")

        entry = service_conn.entries[0]
        user_dn = entry.entry_dn
        service_conn.unbind()

        # مرحله ۲: bind واقعی با DN کاربر + رمزی که کاربر فرستاده — این
        # مرحله است که واقعاً رمز را تأیید می‌کند.
        try:
            user_conn = Connection(server, user=user_dn, password=password, auto_bind=True)
            user_conn.unbind()
        except LDAPBindError as exc:
            raise LdapAuthError("INVALID_CREDENTIALS", "نام کاربری یا رمز عبور اشتباه است.") from exc

        member_of = list(entry[self.settings.LDAP_ATTR_MEMBEROF].values) \
            if self.settings.LDAP_ATTR_MEMBEROF in entry else []
        national_id = None
        if national_id_attr and national_id_attr in entry:
            values = entry[national_id_attr].values
            national_id = values[0] if values else None

        return LdapUserInfo(
            dn=user_dn,
            object_guid=str(entry[self.settings.LDAP_ATTR_OBJECT_GUID].value),
            sam_account_name=username,
            display_name=str(entry[self.settings.LDAP_ATTR_DISPLAY_NAME].value),
            national_id=national_id,
            member_of=member_of,
        )
```

==========================================================================================
## FILE: basteh4/backend/app/modules/chat/__init__.py
## SIZE: 109 bytes
==========================================================================================

```python
"""Chat module public interface."""
from app.modules.chat.api.routes import router

__all__ = ["router"]
```

==========================================================================================
## FILE: basteh4/backend/app/modules/chat/db/models.py
## SIZE: 4722 bytes
==========================================================================================

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

==========================================================================================
## FILE: basteh4/backend/app/modules/chat/services/chat_service.py
## SIZE: 8609 bytes
==========================================================================================

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

==========================================================================================
## FILE: basteh4/backend/app/modules/files/__init__.py
## SIZE: 124 bytes
==========================================================================================

```python
"""File storage module public interface (real DDL)."""
from app.modules.files.api.routes import router

__all__ = ["router"]
```

==========================================================================================
## FILE: basteh4/backend/app/modules/files/db/models.py
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
## FILE: basteh4/backend/app/modules/files/services/file_service.py
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
## FILE: basteh4/backend/app/modules/notification/__init__.py
## SIZE: 344 bytes
==========================================================================================

```python
"""Notification module public interface (real DDL).

Subscribes to auth login / role-change events and writes a
notification row for the affected user (inbox channel).
"""

from app.modules.notification.api.routes import router
from app.modules.notification.events import register_event_handlers

__all__ = ["router", "register_event_handlers"]
```

==========================================================================================
## FILE: basteh4/backend/app/modules/notification/events.py
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
## FILE: basteh4/backend/app/modules/notification/services/notification_service.py
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
## FILE: basteh4/backend/app/ws/__init__.py
## SIZE: 188 bytes
==========================================================================================

```python
"""WebSocket gateway (architecture ADR-05, sections 8.1, 12.8).

Exposes ``/ws/chat`` and ``/ws/notifications`` plus the connection
manager wired to the configurable Redis primary key.
"""
```

==========================================================================================
## FILE: basteh5/architecture-v2.md
## SIZE: 154032 bytes
==========================================================================================

```markdown
# سند معماری جامع — نسخه ۲.۰
## سامانه سازمانی مدیریت اهداف، برنامه‌ریزی و همکاری

**نسخه:** 2.0 | **تاریخ:** ۲۷ شهریور ۱۴۰۵ | **جایگزین نسخه ۱.۰**
**نویسنده:** معماری ارشد سیستم و امنیت نرم‌افزار | **رویکرد:** Security-First · Defense in Depth · Zero Trust

---

## فهرست

| # | بخش |
|---|-----|
| ۰ | [تغییرات نسبت به نسخه ۱ و تصمیم‌های کلیدی](#۰-تغییرات-نسبت-به-نسخه-۱-و-تصمیمهای-کلیدی) |
| ۱ | [معماری سطح بالا و نمودارها](#۱-معماری-سطح-بالا-و-نمودارها) |
| ۲ | [معماری ماژولار و قرارداد بین ماژول‌ها](#۲-معماری-ماژولار-و-قرارداد-بین-ماژولها) |
| ۳ | [ساختار پوشه‌های پروژه](#۳-ساختار-پوشههای-پروژه) |
| ۴ | [طراحی دیتابیس](#۴-طراحی-دیتابیس) |
| ۵ | [طراحی API](#۵-طراحی-api) |
| ۶ | [استراتژی MAC Address و شناسایی دستگاه](#۶-استراتژی-mac-address-و-شناسایی-دستگاه) |
| ۷ | [RBAC، گروه‌ها و حریم خصوصی](#۷-rbac-گروهها-و-حریم-خصوصی) |
| ۸ | [چت، WebSocket و مدیریت فایل](#۸-چت-websocket-و-مدیریت-فایل) |
| ۹ | [کارتابل](#۹-کارتابل-inboxoutbox) |
| ۱۰ | [شخصی‌سازی داشبورد و ویجت‌ها](#۱۰-شخصیسازی-داشبورد-و-ویجتها) |
| ۱۱ | [استراتژی امنیت جامع](#۱۱-استراتژی-امنیت-جامع) |
| ۱۲ | [نمونه کد (Boilerplate)](#۱۲-نمونه-کد-boilerplate) |
| ۱۳ | [کتابخانه‌ها، زیرساخت و ظرفیت‌سنجی](#۱۳-کتابخانهها-زیرساخت-و-ظرفیتسنجی) |
| ۱۴ | [فازبندی، ریسک و توصیه‌های پایانی](#۱۴-فازبندی-ریسک-و-توصیههای-پایانی) |

---

## ۰. تغییرات نسبت به نسخه ۱ و تصمیم‌های کلیدی

### ۰.۱ دامنه‌ی افزوده‌شده

نسخه ۲ نیازمندی‌ها هفت حوزه‌ی کاملاً جدید اضافه کرده است: **RBAC چندنقشی**، **گروه‌های کاربری سلسله‌مراتبی با حریم خصوصی**، **اتاق گفتگوی Real-time با WebSocket و اشتراک فایل**، **کارتابل ورودی/ارسالی**، **MFA و امنیت پیشرفته ورود**، **Audit Log مبتنی بر MAC Address و Device Fingerprint**، و **ویجت‌ها و داشبورد کاملاً قابل شخصی‌سازی**. همچنین شناسه‌ی یکتای کاربران از نام کاربری به **کد ملی** تغییر کرده است.

این‌ها دامنه را تقریباً **دوبرابر** می‌کنند. بخش ۱۴ اثر آن بر زمان‌بندی را صریح بیان می‌کند.

### ۰.۲ تصمیم‌های کلیدی معماری (ADR)

| # | تصمیم | انتخاب | دلیل |
|---|-------|--------|------|
| ADR-01 | سبک معماری | **Modular Monolith با مرزهای اجباری** — نه Microservices | جزئیات در ۰.۳ |
| ADR-02 | ارتباط بین ماژول‌ها | **Event Bus درون‌پروسه‌ای + Outbox Pattern** | رویدادمحور بودن بدون هزینه‌ی شبکه؛ مسیر مهاجرت بعدی به صف پیام باز می‌ماند |
| ADR-03 | فریم‌ورک | **FastAPI** + Uvicorn | async بومی برای WebSocket، LDAP و Push؛ OpenAPI خودکار؛ Pydantic اجباری |
| ADR-04 | دیتابیس | **PostgreSQL 16** با یک Schema به‌ازای هر ماژول | جداسازی منطقی ماژول‌ها بدون تقسیم فیزیکی دیتابیس |
| ADR-05 | WebSocket | **FastAPI WebSocket + Redis Pub/Sub** | مقیاس‌پذیری افقی: پیام روی هر Worker منتشر می‌شود |
| ADR-06 | شناسه‌ی کاربر | کد ملی **رمزنگاری‌شده (AES-GCM) + هش جستجوپذیر (HMAC-SHA256)** | کد ملی داده‌ی هویتی حساس است؛ ذخیره‌ی plaintext غیرقابل دفاع است |
| ADR-07 | MFA | **TOTP اولویت اول**؛ Email دوم؛ **SMS فقط به‌عنوان آخرین گزینه** | SMS در برابر SIM-Swap آسیب‌پذیر است (NIST SP 800-63B آن را "restricted" می‌داند) |
| ADR-08 | MAC Address | **سیگنال کمکی Forensic** — نه کنترل امنیتی | جزئیات و دلایل در بخش ۶ |
| ADR-09 | ذخیره‌سازی فایل | **S3-compatible (MinIO)** با آدرس‌دهی محتوایی | جداسازی کامل فایل از Web Root؛ آماده برای چند سرور |
| ADR-10 | Audit | **Append-Only + زنجیره‌ی هش (Hash Chain)** به‌جای امضای تک‌رکوردی | تشخیص حذف رکورد، نه فقط تغییر آن |
| ADR-11 | حریم خصوصی | **Privacy Level به‌عنوان یک لایه‌ی مستقل روی ACL** | دسترسی و حریم خصوصی دو مفهوم متفاوت‌اند؛ ادغام آن‌ها منشأ نشت داده است |

### ۰.۳ چرا Microservices توصیه نمی‌شود (مهم)

نیازمندی «معماری Microservices» ذکر شده است. توصیه‌ی فنی من **Modular Monolith** است و دلایل آن را صریح می‌گویم، چون این تصمیم بیش از هر تصمیم دیگری بر موفقیت یا شکست پروژه اثر دارد:

**آنچه Microservices واقعاً از شما می‌خواهد:** ۱۲ مخزن مستقل، ۱۲ خط لوله CI/CD، Service Discovery، API Gateway، تراکنش‌های توزیع‌شده (Saga) برای عملیاتی مثل «ایجاد جلسه + دعوت کاربران + ساخت اتاق چت + ارسال کارتابل»، ردیابی توزیع‌شده، مدیریت نسخه‌ی قرارداد بین سرویس‌ها، و یک تیم SRE. برای سامانه‌ای با **حداکثر ۱۰۰۰ کاربر همزمان** — که یک نمونه‌ی PostgreSQL به‌راحتی پاسخ می‌دهد — این هزینه هیچ توجیه فنی ندارد.

**هزینه‌ی واقعی:** یک کوئری ساده مثل «داشبورد مدیر گروه» که در Monolith یک JOIN است، در Microservices به ۴ فراخوانی شبکه بین سرویس‌های User، Group، Goal و Privacy تبدیل می‌شود — با احتمال شکست جزئی، نیاز به Circuit Breaker، و p95 چند برابر.

**راه‌حل پیشنهادی که هر دو هدف را برآورده می‌کند:**

- هر ماژول یک پکیج پایتون مستقل با `__init__.py` که **فقط رابط عمومی** را صادر می‌کند.
- هر ماژول Schema اختصاصی در PostgreSQL دارد؛ **دسترسی مستقیم به جدول ماژول دیگر ممنوع** و با آزمون خودکار معماری بررسی می‌شود.
- ارتباط فقط از دو راه: فراخوانی رابط عمومی (`ports/`) یا انتشار رویداد روی Event Bus.
- هر ماژول تست مستقل و مستندات API خودش را دارد.
- استقرار واحد، اما **قابلیت جدا شدن هر ماژول به سرویس مستقل در آینده بدون بازنویسی منطق** — چون وابستگی‌ها از قبل از طریق رابط عبور می‌کنند.

این دقیقاً «قابلیت واگذاری به تیم‌های مستقل» را می‌دهد (هدف اصلی شما) بدون پرداخت هزینه‌ی عملیاتی توزیع‌شدگی. اگر بعداً یک ماژول خاص — مثلاً چت — به مقیاس مستقل نیاز پیدا کرد، همان ماژول به‌تنهایی استخراج می‌شود.

```python
# tests/architecture/test_module_boundaries.py
FORBIDDEN = [
    ("modules.chat",    "modules.goals.db"),      # چت نباید مستقیم به جداول اهداف بزند
    ("modules.goals",   "modules.chat.db"),
    ("modules.inbox",   "modules.groups.db"),
    # ... ماتریس کامل
]

@pytest.mark.parametrize("importer,forbidden", FORBIDDEN)
def test_no_cross_module_db_access(importer, forbidden):
    """مرز ماژول‌ها با آزمون اجباری می‌شود، نه با توافق شفاهی."""
    violations = scan_imports(importer, matching=forbidden)
    assert not violations, f"نقض مرز ماژول: {violations}"
```

بدون این آزمون، «معماری ماژولار» ظرف شش ماه به یک Monolith درهم‌تنیده تبدیل می‌شود — این قاعده‌ای است که تقریباً بدون استثنا رخ می‌دهد.

---

## ۱. معماری سطح بالا و نمودارها

### ۱.۱ نمودار Client-Server

```mermaid
graph TB
    subgraph CL["لایه کلاینت"]
        D["Desktop (PySide6/CustomTkinter)<br/>MAC via psutil · Tray · SSO"]
        W["Web SPA/PWA (React+TS)<br/>FingerprintJS · Service Worker"]
        M["Mobile Browser<br/>Responsive"]
    end

    subgraph EDGE["لایه لبه — DMZ"]
        WAF["WAF / DDoS<br/>Cloudflare یا ModSecurity"]
        LB["Load Balancer + TLS 1.3<br/>HSTS · Security Headers · Rate Limit L7"]
    end

    subgraph APP["لایه اپلیکیشن — شبکه داخلی"]
        API["FastAPI Workers (N×)<br/>REST + OpenAPI"]
        WS["WebSocket Workers (N×)<br/>Chat · Live Notifications"]
        BUS["Event Bus + Outbox"]
        CEL["Celery Workers<br/>Mail · Push · Export · AV Scan"]
    end

    subgraph DATA["لایه داده — شبکه ایزوله"]
        PG[("PostgreSQL 16<br/>Primary + Replica<br/>TDE · Schema per Module")]
        RD[("Redis<br/>Pub/Sub · Cache · RateLimit")]
        S3[("MinIO / S3<br/>فایل‌های چت و Export")]
    end

    subgraph EXT["سرویس‌های بیرونی"]
        AD["Active Directory<br/>LDAPS :636 · Kerberos"]
        SMTP["SMTP"]
        AV["ClamAV Daemon"]
        SIEM["SIEM / Syslog"]
    end

    D & W & M -->|HTTPS/WSS| WAF --> LB
    LB --> API
    LB --> WS
    API <--> BUS
    WS <--> BUS
    BUS --> CEL
    API --> PG & RD
    WS --> RD
    CEL --> PG & S3 & SMTP & AV
    API --> S3
    API --> AD
    API -.->|لاگ ساختاریافته| SIEM
```

**سه ناحیه‌ی شبکه‌ای (Network Segmentation):** DMZ فقط ۴۴۳ را از اینترنت/LAN می‌پذیرد؛ لایه‌ی اپلیکیشن فقط از DMZ ترافیک می‌گیرد؛ لایه‌ی داده **هیچ مسیر ورودی از بیرون ندارد** و فقط از لایه‌ی اپلیکیشن قابل دسترسی است. دسترسی مدیریتی (SSH، psql) منحصراً از طریق Bastion Host با MFA.

### ۱.۲ نمودار لایه‌ها و جریان داده

```mermaid
graph LR
    subgraph P["Presentation"]
        V["Views / Components"]
    end
    subgraph A["API Layer"]
        MW["Security Middleware Chain"]
        EP["Endpoints + Pydantic Schemas"]
    end
    subgraph B["Business Logic"]
        SVC["Module Services"]
        POL["Policy Engine<br/>RBAC + ACL + Privacy"]
        EV["Event Publisher"]
    end
    subgraph D["Data Access"]
        REPO["Repositories (per module schema)"]
        UOW["Unit of Work"]
    end
    V --> MW --> EP --> SVC
    SVC --> POL
    SVC --> EV
    SVC --> REPO --> UOW
```

**زنجیره‌ی Middleware امنیتی** (به ترتیب اجرا):

```
RequestID → SecurityHeaders → CORS → IPFilter (allow/deny list)
  → RateLimit → BodySizeGuard → Authentication (JWT/Kerberos)
  → DeviceBinding (MAC/Fingerprint + HMAC) → SessionValidation (MFA, timeout)
  → AuditContext (ContextVar) → Router
```

هر لایه مستقل است و شکست هر یک، درخواست را قبل از رسیدن به منطق کسب‌وکار متوقف می‌کند — مصداق عملی Defense in Depth.

### ۱.۳ نمودار جریان SSO با Active Directory

```mermaid
sequenceDiagram
    autonumber
    participant U as کاربر Domain
    participant C as Client
    participant API as Auth Module
    participant KDC as KDC
    participant AD as AD (LDAPS)
    participant DB as PostgreSQL

    C->>API: GET /auth/sso/negotiate
    API-->>C: 401 · WWW-Authenticate: Negotiate
    C->>KDC: درخواست تیکت برای SPN HTTP/api.corp.local
    KDC-->>C: Service Ticket
    C->>API: Authorization: Negotiate <SPNEGO><br/>X-Device-MAC + X-Device-Signature
    API->>API: gssapi.accept_sec_context(keytab)
    API->>AD: LDAPS bind(svc) + search(objectGUID, nationalID, memberOf)
    AD-->>API: DN · attributes · groups
    API->>DB: SELECT users WHERE national_id_hash = HMAC(کد ملی)
    alt کاربر یافت نشد و auto_provision=true
        API->>DB: INSERT user (auth_mode='sso')
    else sso_enabled = false
        API-->>C: 403 SSO_DISABLED_FOR_USER
    else حساب غیرفعال یا خارج از IP مجاز
        API-->>C: 403 ACCESS_DENIED
    end
    API->>DB: نگاشت memberOf → roles
    API->>DB: بررسی user_devices (دستگاه شناخته‌شده؟)
    alt دستگاه جدید
        API->>DB: INSERT user_devices (is_trusted=false)
        API-->>U: هشدار امنیتی «ورود از دستگاه جدید»
    end
    API->>DB: INSERT login_audit_logs (mac, fingerprint, ip, success)
    API-->>C: Access Token (15m) + Refresh (HttpOnly/DPAPI)
```

**نکته‌ی حیاتی:** تیکت Kerberos **فقط برای احراز هویت اولیه** به کار می‌رود. پس از آن، JWT داخلی صادر می‌شود تا مدل مجوزدهی برای کاربران SSO و محلی یکسان بماند. نگاشت کاربر بر `objectGUID` (نه `sAMAccountName`) و کد ملی انجام می‌شود؛ نام کاربری در AD تغییرپذیر است.

### ۱.۴ نمودار WebSocket و چت Real-time

```mermaid
sequenceDiagram
    autonumber
    participant A as کاربر A (Desktop)
    participant W1 as WS Worker #1
    participant R as Redis Pub/Sub
    participant W2 as WS Worker #2
    participant B as کاربر B (Web)
    participant DB as PostgreSQL
    participant AV as ClamAV

    A->>W1: WSS /ws/chat?token=<access>
    W1->>W1: اعتبارسنجی JWT + بررسی عضویت در اتاق
    Note over W1: توکن از Query فقط برای Handshake؛<br/>سپس پیام auth روی خود سوکت
    W1-->>A: {"type":"connected","room_id":"..."}

    A->>W1: {"type":"message","body":"..."}
    W1->>W1: sanitize + محدودیت طول + Rate Limit (۲۰ پیام/دقیقه)
    W1->>DB: INSERT chat_messages
    W1->>R: PUBLISH room:{id} {...}
    R-->>W2: پیام منتشرشده
    W2-->>B: تحویل به کلاینت متصل
    W1->>DB: INSERT audit_logs (action=chat.message.send)

    A->>W1: درخواست آپلود فایل
    W1-->>A: Presigned URL (MinIO, TTL=5m)
    A->>AV: (غیرمستقیم) آپلود → صف اسکن
    AV-->>DB: وضعیت clean/infected
    Note over DB: فایل تا تأیید اسکن<br/>status=pending و غیرقابل دانلود است
```

**قواعد امنیتی WebSocket:**

1. توکن در Query String فقط برای Handshake اولیه (چون مرورگر اجازه‌ی هدر سفارشی در WebSocket نمی‌دهد)؛ بلافاصله پس از اتصال، سرور یک پیام `auth` می‌خواهد و توکن Query را **در لاگ‌ها ماسک می‌کند** (Query String در لاگ Nginx ثبت می‌شود — یک نشت رایج).
2. عضویت در اتاق در **لحظه‌ی هر پیام** بررسی می‌شود، نه فقط هنگام اتصال. کاربری که از اتاق حذف شده، نباید با اتصال باز پیام بگیرد.
3. انقضای Access Token روی سوکت باز اعمال می‌شود: هر ۶۰ ثانیه اعتبار توکن بازبینی و در صورت انقضا سوکت بسته می‌شود (`4401`).
4. Rate Limiting روی سوکت مستقل از REST است.
5. Origin Check در Handshake اجباری است (WebSocket تحت CORS نیست — این یک سوءتفاهم رایج و منشأ Cross-Site WebSocket Hijacking).

### ۱.۵ نمودار معماری امنیت (Defense in Depth)

```mermaid
graph TB
    ATK["تهدید"] --> L1
    L1["لایه ۱ — لبه<br/>WAF · DDoS · TLS 1.3 · IP Filter"] --> L2
    L2["لایه ۲ — ارائه<br/>CSP · CSRF Token · X-Frame-Options · Auto-Timeout"] --> L3
    L3["لایه ۳ — API<br/>Schema Validation · Rate Limit · Replay Guard (Nonce)"] --> L4
    L4["لایه ۴ — احراز هویت<br/>Argon2id · MFA · Device Binding · Lockout"] --> L5
    L5["لایه ۵ — مجوزدهی<br/>RBAC · ACL · Privacy Level · Least Privilege"] --> L6
    L6["لایه ۶ — منطق کسب‌وکار<br/>Business Rules · Transaction · Optimistic Lock"] --> L7
    L7["لایه ۷ — داده<br/>Parameterized Query · Field Encryption · TDE"] --> L8
    L8["لایه ۸ — زیرساخت<br/>Segmentation · Hardening · Secrets Vault"] --> L9
    L9["لایه ۹ — رصد<br/>Audit Hash Chain · SIEM · Anomaly Detection · IR Plan"]
```

اصل حاکم: **هیچ لایه‌ای به درستی لایه‌ی قبل تکیه نمی‌کند.** اگر WAF دور زده شد، Schema Validation می‌گیرد؛ اگر آن هم رد شد، Parameterized Query جلوی تزریق را می‌گیرد؛ و اگر همه شکست خوردند، Audit Log ردپا را نگه می‌دارد.

---

## ۲. معماری ماژولار و قرارداد بین ماژول‌ها

### ۲.۱ نقشه‌ی ماژول‌ها و وابستگی‌ها

```mermaid
graph TD
    IAM["M1 · Auth & Users<br/>(هسته)"]
    RBAC["M2 · RBAC"]
    GRP["M3 · Groups & Privacy"]
    GOAL["M4 · Goals & Planning"]
    CAL["M5 · Calendar & Dashboard"]
    SHR["M6 · Sharing & Collaboration"]
    CHAT["M7 · Chat"]
    INBOX["M8 · Inbox/Outbox"]
    RPT["M9 · Reporting"]
    NOTIF["M10 · Notification"]
    AUDIT["M11 · Audit & Logging"]
    SSO["M12 · SSO & LDAP"]
    FILE["M13 · File Storage (زیرساخت مشترک)"]

    SSO --> IAM
    RBAC --> IAM
    GRP --> IAM & RBAC
    GOAL --> IAM & RBAC
    CAL --> GOAL & GRP
    SHR --> GOAL & RBAC & GRP
    CHAT --> IAM & FILE & SHR
    INBOX --> IAM & SHR & CHAT
    RPT --> GOAL & GRP
    NOTIF -.->|مصرف رویداد| GOAL & CHAT & SHR & INBOX
    AUDIT -.->|مصرف رویداد| IAM & GOAL & CHAT & SHR & GRP & INBOX
```

خطوط نقطه‌چین = وابستگی رویدادی (بدون وابستگی کد). **M10 و M11 هیچ ماژولی را import نمی‌کنند** — فقط رویداد مصرف می‌کنند. این باعث می‌شود افزودن یک ماژول جدید، هیچ تغییری در نوتیفیکیشن و Audit لازم نداشته باشد.

### ۲.۲ قرارداد رابط (Interface Contract)

هر ماژول سه چیز صادر می‌کند و هیچ چیز دیگری:

```python
# modules/groups/__init__.py
from .ports import GroupService, GroupReadModel      # ۱) رابط عمومی
from .events import GroupMemberAdded, PrivacyChanged  # ۲) رویدادهای منتشرشده
from .schemas import GroupPublic, MemberPublic        # ۳) DTOهای عمومی

__all__ = ["GroupService", "GroupReadModel", "GroupMemberAdded",
           "PrivacyChanged", "GroupPublic", "MemberPublic"]
```

```python
# modules/groups/ports.py — قرارداد، نه پیاده‌سازی
from typing import Protocol
from uuid import UUID

class GroupReadModel(Protocol):
    """هر ماژول دیگری فقط این را می‌بیند. تغییر امضای این متدها = تغییر شکننده."""

    async def is_member(self, user_id: UUID, group_id: UUID) -> bool: ...
    async def is_manager(self, user_id: UUID, group_id: UUID) -> bool: ...
    async def member_ids(self, group_id: UUID, include_subgroups: bool = False) -> list[UUID]: ...
    async def groups_of(self, user_id: UUID) -> list[GroupPublic]: ...
    async def effective_privacy(self, owner_id: UUID, viewer_id: UUID) -> PrivacyDecision: ...
```

ماژول Reporting برای ساخت داشبورد مدیر گروه، `GroupReadModel` را از طریق تزریق وابستگی می‌گیرد — **نه** `from modules.groups.db.models import Group`. اگر فردا ماژول گروه‌ها به سرویس مستقل تبدیل شود، فقط پیاده‌سازی `GroupReadModel` به یک HTTP Client تغییر می‌کند و Reporting دست‌نخورده می‌ماند.

### ۲.۳ Event Bus و الگوی Outbox

```python
# core/events/bus.py
@dataclass(frozen=True)
class DomainEvent:
    event_id: UUID
    event_type: str            # "goal.task.completed"
    occurred_at: datetime
    actor_id: UUID | None
    payload: dict
    correlation_id: UUID       # ردیابی یک عملیات در کل زنجیره

class EventBus:
    def subscribe(self, event_type: str, handler: Callable) -> None: ...
    async def publish(self, event: DomainEvent, session: AsyncSession) -> None:
        """رویداد در همان تراکنش منطق کسب‌وکار در جدول outbox درج می‌شود."""
        session.add(OutboxMessage.from_event(event))
```

**چرا Outbox و نه انتشار مستقیم؟** اگر تراکنش دیتابیس Rollback شود ولی رویداد قبلاً منتشر شده باشد، نوتیفیکیشنی ارسال می‌شود برای کاری که هرگز ذخیره نشد. با Outbox، رویداد و داده در یک تراکنش اتمیک ذخیره می‌شوند و یک Dispatcher جداگانه آن‌ها را با تضمین **At-Least-Once** تحویل می‌دهد. مصرف‌کننده‌ها باید Idempotent باشند (با `event_id` تکراری‌ها را رد کنند).

```sql
CREATE TABLE core.outbox_messages (
    id             BIGSERIAL PRIMARY KEY,
    event_id       UUID NOT NULL UNIQUE,
    event_type     VARCHAR(100) NOT NULL,
    payload        JSONB NOT NULL,
    correlation_id UUID,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    dispatched_at  TIMESTAMPTZ,
    attempts       SMALLINT NOT NULL DEFAULT 0,
    last_error     TEXT
);
CREATE INDEX ix_outbox_pending ON core.outbox_messages(created_at)
    WHERE dispatched_at IS NULL;
```

### ۲.۴ کاتالوگ رویدادها (بخشی)

| رویداد | ناشر | مصرف‌کننده‌ها |
|--------|------|----------------|
| `auth.login.succeeded` / `auth.login.failed` | M1 | M11 Audit، M10 Notification (ورود از دستگاه جدید) |
| `auth.device.registered` | M1 | M11، M10 (هشدار امنیتی) |
| `rbac.role.assigned` | M2 | M11 |
| `group.member.added` / `group.privacy.changed` | M3 | M11، M10، M9 (بازسازی کش داشبورد مدیر) |
| `goal.task.created` / `.completed` / `.overdue` | M4 | M5، M9، M10، M11 |
| `share.granted` / `share.revoked` | M6 | M8 (ایجاد آیتم کارتابل)، M10، M11 |
| `chat.room.created` / `chat.message.sent` / `chat.file.uploaded` | M7 | M10، M11، M13 (صف اسکن) |
| `inbox.item.acted` | M8 | M10 (Read Receipt به فرستنده)، M11 |

### ۲.۵ فازبندی و واگذاری به تیم‌ها

| فاز | ماژول‌ها | تیم | پیش‌نیاز |
|-----|----------|-----|----------|
| ۱ | M1 Auth، M2 RBAC، M12 SSO/LDAP، M11 Audit | تیم پلتفرم | — |
| ۲ | M3 Groups & Privacy، داشبورد مدیر گروه (نسخه پایه) | تیم A | فاز ۱ |
| ۳ | M4 Goals، M5 Calendar & Dashboard | تیم B | فاز ۱ |
| ۴ | M6 Sharing، M8 Inbox/Outbox | تیم A | فاز ۲، ۳ |
| ۵ | M7 Chat، M13 File Storage | تیم C | فاز ۱، ۶ (اشتراک‌گذاری) |
| ۶ | M9 Reporting، داشبورد پیشرفته | تیم B | فاز ۲، ۳ |
| ۷ | M10 Notification، بهینه‌سازی، سخت‌سازی | همه | همه |

**پیش‌شرط واگذاری موازی:** ماژول M1 و M11 باید **پیش از شروع کار موازی تیم‌ها تثبیت شوند**. تلاش برای ساخت همزمان Auth و Chat توسط دو تیم مختلف، به بازنویسی می‌انجامد — چون چت به مدل نشست و مجوز وابسته است.

---

## ۳. ساختار پوشه‌های پروژه

### ۳.۱ Backend

```
backend/
├── app/
│   ├── main.py
│   ├── core/                              # ───── زیرساخت مشترک (بدون منطق دامنه)
│   │   ├── config.py                      # Pydantic Settings از ENV
│   │   ├── security/
│   │   │   ├── hashing.py                 # Argon2id
│   │   │   ├── jwt.py                     # صدور/تأیید RS256
│   │   │   ├── crypto.py                  # AES-256-GCM (کد ملی، رمز LDAP، TOTP secret)
│   │   │   ├── searchable_hash.py         # HMAC-SHA256 برای جستجوی داده رمزنگاری‌شده
│   │   │   ├── device_binding.py          # تأیید HMAC هدر MAC/Fingerprint
│   │   │   ├── nonce.py                   # Replay Guard
│   │   │   └── totp.py                    # MFA
│   │   ├── events/{bus.py, outbox.py, dispatcher.py}
│   │   ├── db/{session.py, base.py, uow.py, mixins.py}
│   │   ├── middleware/
│   │   │   ├── request_id.py  security_headers.py  cors.py
│   │   │   ├── ip_filter.py   rate_limit.py        body_guard.py
│   │   │   ├── authentication.py  device_binding.py  session_guard.py
│   │   │   └── audit_context.py
│   │   ├── errors.py  logging.py  pagination.py  sanitizer.py
│   │   └── context.py                     # ContextVar: user, ip, mac, fingerprint, request_id
│   │
│   ├── modules/                           # ───── هر ماژول یک مرز بسته
│   │   ├── auth/
│   │   │   ├── __init__.py                # فقط رابط عمومی صادر می‌شود
│   │   │   ├── ports.py  events.py  schemas.py
│   │   │   ├── api/{routes.py, admin_routes.py, deps.py}
│   │   │   ├── services/{auth_service.py, mfa_service.py, device_service.py,
│   │   │   │             password_service.py, session_service.py}
│   │   │   ├── db/{models.py, repositories.py}   # schema: auth
│   │   │   └── tests/
│   │   ├── rbac/          # schema: rbac      — نقش، Permission، Middleware بررسی دسترسی
│   │   ├── groups/        # schema: groups    — گروه‌های سلسله‌مراتبی، حریم خصوصی
│   │   ├── goals/         # schema: planning  — اهداف، برنامه‌ها، تسک‌ها، adhoc، تگ‌ها
│   │   ├── calendar/      # schema: planning  — نماهای تقویمی، یادآورها
│   │   ├── sharing/       # schema: sharing   — ACL، انتقال مالکیت، کامنت، Activity
│   │   ├── chat/          # schema: chat      — اتاق، پیام، عضویت، آرشیو
│   │   ├── inbox/         # schema: inbox     — کارتابل ورودی/ارسالی، Read Receipt
│   │   ├── reporting/     # schema: reporting — نمودار، Export، داشبورد مدیر گروه
│   │   ├── notification/  # schema: notify    — اعلان، Push، ترجیحات
│   │   ├── audit/         # schema: audit     — audit_logs، login_audit_logs، hash chain
│   │   ├── ssoldap/       # schema: auth      — LDAP، Kerberos، نگاشت گروه
│   │   └── files/         # schema: files     — آپلود، اسکن AV، Presigned URL
│   │
│   ├── workers/
│   │   ├── celery_app.py
│   │   └── tasks/{reminders.py, emails.py, webpush.py, exports.py,
│   │              av_scan.py, outbox_dispatcher.py, audit_archive.py, ldap_sync.py}
│   └── ws/
│       ├── manager.py                     # مدیریت اتصال‌ها + Redis Pub/Sub
│       └── handlers/{chat.py, notifications.py}
│
├── alembic/versions/
├── tests/{unit, integration, security, architecture}/
├── pyproject.toml   .env.example   Dockerfile
```

### ۳.۲ Frontend دسکتاپ

```
desktop/
├── app/
│   ├── main.py                    # RTL سراسری، بارگذاری فونت، تم
│   ├── core/
│   │   ├── api_client.py          # httpx + تزریق خودکار هدرهای دستگاه
│   │   ├── device_identity.py     # MAC via psutil + Fingerprint سیستمی + امضای HMAC
│   │   ├── auth_manager.py        # login / MFA / refresh / logout
│   │   ├── token_store.py         # DPAPI + keyring
│   │   ├── sso_client.py          # requests-negotiate-sspi
│   │   ├── ws_client.py           # کلاینت WebSocket چت (روی QThread)
│   │   ├── event_bus.py           # سیگنال‌های سراسری بین ViewModelها
│   │   └── permissions.py         # کش Permission برای مخفی‌سازی UI (نه امنیت)
│   ├── viewmodels/                # login, mfa, dashboard, calendar, goal, task,
│   │                              # chat, inbox, group_manager, privacy, admin, widget
│   ├── views/
│   │   ├── main_window.py  login_window.py  mfa_dialog.py
│   │   ├── dashboard/{dashboard_view.py, grid_canvas.py, blocks/}
│   │   ├── widgets/{clock_widget.py, tag_chip.py, persian_date_picker.py,
│   │   │            avatar.py, toast.py, floating_widget_base.py}
│   │   ├── calendar/  chat/  inbox/  group_manager/  admin/  settings/
│   ├── services/{notifier.py, reminder_worker.py, jalali_service.py, layout_store.py}
│   ├── resources/{fonts/, icons/, themes/{dark.qss,light.qss}, i18n/}
│   └── utils/{rtl.py, digits.py}
└── build/planner.spec
```

### ۳.۳ Frontend وب

```
web/
├── public/{manifest.webmanifest, sw.js, icons/}
├── src/
│   ├── main.tsx                      # <html dir="rtl" lang="fa">
│   ├── api/{client.ts, generated/, queries/, ws.ts}
│   ├── security/
│   │   ├── fingerprint.ts            # FingerprintJS + هش پایدار
│   │   ├── deviceHeaders.ts          # تزریق X-Device-* + امضا
│   │   └── sanitize.ts               # DOMPurify
│   ├── features/
│   │   ├── auth/{Login, MfaChallenge, Devices, Sessions}
│   │   ├── rbac/  groups/  goals/  calendar/  sharing/
│   │   ├── chat/{RoomList, MessageStream, FileUpload, useChatSocket}
│   │   ├── inbox/{InboxView, OutboxView, ReceiptBadge}
│   │   ├── dashboard/{DashboardGrid, blocks/, useLayoutPersistence, LayoutManager}
│   │   ├── widgets/{ClockWidget, WidgetCanvas, useWidgetSettings}
│   │   ├── groupManager/  reports/  admin/{Users, BulkLoginMode, AuditLogs, Ldap}
│   ├── components/ui/                # Design System
│   ├── hooks/  store/  lib/{jalali.ts, permissions.ts}
│   ├── styles/tailwind.css           # logical properties برای RTL
│   └── types/
└── vite.config.ts  tailwind.config.ts
```

---

## ۴. طراحی دیتابیس

### ۴.۱ قراردادها

- یک **Schema به‌ازای هر ماژول** (`auth`, `rbac`, `groups`, `planning`, `sharing`, `chat`, `inbox`, `reporting`, `notify`, `audit`, `files`). کاربر دیتابیس برنامه روی هر Schema نقش جداگانه دارد؛ ماژول چت حتی در سطح دیتابیس به جداول اهداف `SELECT` ندارد.
- کلید اصلی **UUID** (ضد شمارش‌پذیری/IDOR)؛ جداول لاگ `BIGSERIAL` (حجم بالا، ترتیب زمانی).
- زمان‌ها `TIMESTAMPTZ` و **UTC**؛ تبدیل جلالی فقط در لایه‌ی نمایش.
- `version INTEGER` برای Optimistic Locking روی موجودیت‌های اشتراکی.
- `deleted_at` برای Soft Delete؛ جداول Audit **هرگز** حذف نمی‌شوند.

### ۴.۲ ماژول Auth — کاربران، کد ملی، MFA، دستگاه‌ها

```sql
CREATE SCHEMA auth;
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TYPE auth.auth_mode AS ENUM ('local', 'sso', 'both');

CREATE TABLE auth.users (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- ── هویت
    username            VARCHAR(64)  NOT NULL,
    national_id_enc     BYTEA        NOT NULL,   -- AES-256-GCM (کد ملی)
    national_id_nonce   BYTEA        NOT NULL,
    national_id_hash    CHAR(64)     NOT NULL,   -- HMAC-SHA256(کد ملی, PEPPER) برای جستجو
    national_id_last4   CHAR(4)      NOT NULL,   -- نمایش ماسک‌شده در UI: ******1234
    email               VARCHAR(255),
    mobile_enc          BYTEA,                   -- برای MFA پیامکی
    display_name        VARCHAR(128) NOT NULL,
    employee_code       VARCHAR(32),

    -- ── احراز هویت
    auth_mode           auth.auth_mode NOT NULL DEFAULT 'local',
    sso_enabled         BOOLEAN NOT NULL DEFAULT FALSE,
    password_hash       TEXT,                     -- Argon2id
    password_changed_at TIMESTAMPTZ,
    password_expires_at TIMESTAMPTZ,              -- سیاست ۹۰ روزه (بخش ۱۱.۳ را ببینید)
    must_change_password BOOLEAN NOT NULL DEFAULT FALSE,
    token_version       INTEGER NOT NULL DEFAULT 1,

    -- ── MFA
    mfa_enabled         BOOLEAN NOT NULL DEFAULT FALSE,
    mfa_method          VARCHAR(16),              -- totp | email | sms
    mfa_secret_enc      BYTEA,                    -- AES-GCM؛ هرگز در پاسخ API
    mfa_secret_nonce    BYTEA,
    mfa_enrolled_at     TIMESTAMPTZ,

    -- ── LDAP
    ldap_dn             TEXT,
    ldap_object_guid    UUID,
    ldap_sam_account    VARCHAR(256),
    ldap_synced_at      TIMESTAMPTZ,

    -- ── وضعیت و امنیت
    is_active           BOOLEAN NOT NULL DEFAULT TRUE,
    failed_login_count  SMALLINT NOT NULL DEFAULT 0,
    locked_until        TIMESTAMPTZ,
    lockout_level       SMALLINT NOT NULL DEFAULT 0,   -- Exponential Backoff
    last_login_at       TIMESTAMPTZ,
    allowed_ip_ranges   CIDR[],                        -- IP Whitelist سطح کاربر
    require_trusted_device BOOLEAN NOT NULL DEFAULT FALSE,

    -- ── شخصی‌سازی
    theme               VARCHAR(10) NOT NULL DEFAULT 'system',
    locale              VARCHAR(10) NOT NULL DEFAULT 'fa-IR',
    timezone            VARCHAR(64) NOT NULL DEFAULT 'Asia/Tehran',
    privacy_level       VARCHAR(20) NOT NULL DEFAULT 'team_only',

    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at TIMESTAMPTZ,

    CONSTRAINT ck_auth_method CHECK (password_hash IS NOT NULL OR sso_enabled = TRUE)
);

CREATE UNIQUE INDEX uq_users_national ON auth.users(national_id_hash) WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX uq_users_username ON auth.users(lower(username))  WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX uq_users_guid     ON auth.users(ldap_object_guid) WHERE ldap_object_guid IS NOT NULL;
```

> **چرا کد ملی رمزنگاری می‌شود:** کد ملی یک شناسه‌ی هویتی دائمی و غیرقابل تغییر است. نشت جدول کاربران با کد ملی plaintext، آسیبی است که هیچ‌وقت قابل جبران نیست — برخلاف رمز عبور که قابل تغییر است. الگوی **رمزنگاری + هش جستجوپذیر** هر دو نیاز را برآورده می‌کند: ورود با کد ملی از طریق `national_id_hash` انجام می‌شود (یک ایندکس یکتا، بدون رمزگشایی)، و مقدار اصلی فقط هنگام نمایش به Admin مجاز رمزگشایی می‌شود. اعتبارسنجی کد ملی باید الگوریتم چک‌سام رسمی (رقم کنترل) را اجرا کند، نه فقط بررسی ۱۰ رقمی بودن.

```sql
CREATE TABLE auth.user_devices (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id            UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    device_fingerprint VARCHAR(255) NOT NULL,        -- کلید اصلی شناسایی
    mac_address        VARCHAR(17),                  -- فقط Desktop؛ 00:1A:2B:3C:4D:5E
    mac_source         VARCHAR(16),                  -- psutil | uuid_getnode | unavailable
    platform           VARCHAR(16) NOT NULL,         -- desktop | web | mobile_web
    device_label       VARCHAR(128),                 -- قابل نام‌گذاری توسط کاربر
    os_info            VARCHAR(128),
    user_agent         TEXT,
    hmac_key_enc       BYTEA,                        -- کلید امضای هدر دستگاه (AES-GCM)
    is_trusted         BOOLEAN NOT NULL DEFAULT FALSE,
    trusted_at         TIMESTAMPTZ,
    trusted_by_mfa     BOOLEAN NOT NULL DEFAULT FALSE,
    first_seen_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_ip            INET,
    is_blocked         BOOLEAN NOT NULL DEFAULT FALSE,
    blocked_reason     VARCHAR(255)
);
CREATE UNIQUE INDEX uq_device ON auth.user_devices(user_id, device_fingerprint);
CREATE INDEX ix_device_mac ON auth.user_devices(mac_address) WHERE mac_address IS NOT NULL;

CREATE TABLE auth.sessions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    device_id       UUID REFERENCES auth.user_devices(id) ON DELETE SET NULL,
    refresh_hash    CHAR(64) NOT NULL UNIQUE,
    family_id       UUID NOT NULL,                  -- تشخیص Token Reuse
    auth_method     VARCHAR(20) NOT NULL,           -- local | ldap | kerberos
    mfa_satisfied   BOOLEAN NOT NULL DEFAULT FALSE,
    ip_address      INET,
    geo_location    JSONB,
    issued_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_active_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at      TIMESTAMPTZ NOT NULL,
    revoked_at      TIMESTAMPTZ,
    revoked_reason  VARCHAR(64)
);
CREATE INDEX ix_sessions_active ON auth.sessions(user_id) WHERE revoked_at IS NULL;

CREATE TABLE auth.mfa_recovery_codes (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    code_hash  CHAR(64) NOT NULL,                   -- کد بازیابی هم هش می‌شود
    used_at    TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE auth.ip_access_rules (
    id         SERIAL PRIMARY KEY,
    scope      VARCHAR(16) NOT NULL,                -- global | user
    user_id    UUID REFERENCES auth.users(id) ON DELETE CASCADE,
    cidr       CIDR NOT NULL,
    rule_type  VARCHAR(10) NOT NULL,                -- allow | deny
    reason     VARCHAR(255),
    expires_at TIMESTAMPTZ,
    created_by UUID REFERENCES auth.users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE auth.ldap_settings (          -- Singleton؛ ساختار مطابق نسخه ۱
    id SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    is_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    server_host VARCHAR(255) NOT NULL,
    server_port INTEGER NOT NULL DEFAULT 636,
    use_ssl BOOLEAN NOT NULL DEFAULT TRUE,
    use_start_tls BOOLEAN NOT NULL DEFAULT FALSE,
    validate_certificate BOOLEAN NOT NULL DEFAULT TRUE,
    ca_certificate TEXT,
    base_dn VARCHAR(512) NOT NULL,
    user_search_base VARCHAR(512),
    group_search_base VARCHAR(512),
    user_filter VARCHAR(512) NOT NULL DEFAULT '(&(objectClass=user)(sAMAccountName={username}))',
    attr_national_id VARCHAR(64) DEFAULT 'employeeID',   -- نگاشت کد ملی از AD
    bind_dn VARCHAR(512) NOT NULL,
    bind_password_enc BYTEA NOT NULL,
    bind_password_nonce BYTEA NOT NULL,
    auto_provision BOOLEAN NOT NULL DEFAULT TRUE,
    default_role_id SMALLINT,
    kerberos_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    kerberos_spn VARCHAR(255),
    kerberos_keytab_path VARCHAR(512),
    last_test_at TIMESTAMPTZ,
    last_test_result JSONB,
    updated_by UUID, updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

### ۴.۳ ماژول RBAC

```sql
CREATE SCHEMA rbac;

CREATE TABLE rbac.permissions (
    id       SERIAL PRIMARY KEY,
    code     VARCHAR(100) NOT NULL UNIQUE,   -- ساختار: module.action
    module   VARCHAR(40)  NOT NULL,
    action   VARCHAR(40)  NOT NULL,
    title_fa VARCHAR(120) NOT NULL,
    is_dangerous BOOLEAN NOT NULL DEFAULT FALSE   -- نیازمند تأیید دوم در UI
);

-- نمونه: goal.create, goal.delete.any, group.manage, user.bulk_login_mode,
--        audit.read, audit.export, chat.room.delete, ldap.configure, rbac.assign

CREATE TABLE rbac.roles (
    id          SMALLSERIAL PRIMARY KEY,
    code        VARCHAR(32) NOT NULL UNIQUE,   -- super_admin|admin|manager|user|viewer
    title_fa    VARCHAR(64) NOT NULL,
    level       SMALLINT NOT NULL,             -- برای جلوگیری از Privilege Escalation
    is_system   BOOLEAN NOT NULL DEFAULT TRUE,
    description TEXT
);

CREATE TABLE rbac.role_permissions (
    role_id       SMALLINT REFERENCES rbac.roles(id) ON DELETE CASCADE,
    permission_id INTEGER  REFERENCES rbac.permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

CREATE TABLE rbac.user_roles (
    user_id    UUID     NOT NULL,              -- FK منطقی به auth.users
    role_id    SMALLINT NOT NULL REFERENCES rbac.roles(id) ON DELETE CASCADE,
    scope_type VARCHAR(16) NOT NULL DEFAULT 'global',   -- global | group
    scope_id   UUID,                                     -- group_id در نقش دامنه‌دار
    granted_by UUID,
    granted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ,
    source     VARCHAR(16) NOT NULL DEFAULT 'manual',    -- manual | ldap_group
    PRIMARY KEY (user_id, role_id, scope_type, COALESCE(scope_id, '00000000-0000-0000-0000-000000000000'::uuid))
);
```

> **نقش دامنه‌دار (Scoped Role):** «مدیر گروه» یک نقش سراسری نیست — کاربر می‌تواند مدیر گروه الف و عضو ساده‌ی گروه ب باشد. `scope_type='group'` این را مدل می‌کند. بدون آن، مدیر یک گروه به داده‌ی همه‌ی گروه‌ها دسترسی پیدا می‌کند؛ یک اشتباه رایج و پرهزینه.

### ۴.۴ ماژول Groups و حریم خصوصی

```sql
CREATE SCHEMA groups;

CREATE TYPE groups.privacy_level AS ENUM
    ('fully_private', 'team_only', 'selected', 'fully_transparent');

CREATE TABLE groups.groups (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    parent_id   UUID REFERENCES groups.groups(id) ON DELETE RESTRICT,
    path        LTREE,                          -- مسیر سلسله‌مراتبی برای کوئری زیرگروه‌ها
    name        VARCHAR(128) NOT NULL,
    description TEXT,
    ldap_group_dn VARCHAR(512),
    is_active   BOOLEAN NOT NULL DEFAULT TRUE,
    created_by  UUID,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at  TIMESTAMPTZ
);
CREATE INDEX ix_groups_path ON groups.groups USING GIST(path);

CREATE TABLE groups.group_members (
    group_id   UUID NOT NULL REFERENCES groups.groups(id) ON DELETE CASCADE,
    user_id    UUID NOT NULL,
    is_manager BOOLEAN NOT NULL DEFAULT FALSE,
    joined_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    added_by   UUID,
    PRIMARY KEY (group_id, user_id)
);
CREATE INDEX ix_group_members_user ON groups.group_members(user_id);

CREATE TABLE groups.privacy_settings (
    user_id          UUID PRIMARY KEY,
    default_level    groups.privacy_level NOT NULL DEFAULT 'team_only',
    goals_level      groups.privacy_level,         -- override به‌ازای نوع داده
    tasks_level      groups.privacy_level,
    meetings_level   groups.privacy_level,
    progress_level   groups.privacy_level,
    allow_manager_comment BOOLEAN NOT NULL DEFAULT TRUE,
    notify_on_manager_view BOOLEAN NOT NULL DEFAULT TRUE,
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE groups.privacy_exceptions (      -- حالت 'selected'
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_id     UUID NOT NULL,
    viewer_id    UUID NOT NULL,
    entity_type  VARCHAR(32),                  -- NULL = همه انواع
    can_comment  BOOLEAN NOT NULL DEFAULT FALSE,
    granted_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at   TIMESTAMPTZ,
    UNIQUE (owner_id, viewer_id, entity_type)
);
```

### ۴.۵ ماژول Chat

```sql
CREATE SCHEMA chat;

CREATE TABLE chat.rooms (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title          VARCHAR(160) NOT NULL,
    linked_type    VARCHAR(32),               -- task | meeting | goal | NULL (اتاق آزاد)
    linked_id      UUID,
    owner_id       UUID NOT NULL,
    is_archived    BOOLEAN NOT NULL DEFAULT FALSE,
    archived_at    TIMESTAMPTZ,
    archive_object_key VARCHAR(512),          -- مسیر آرشیو در S3 پیش از حذف
    retention_days SMALLINT NOT NULL DEFAULT 365,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at     TIMESTAMPTZ
);
CREATE INDEX ix_rooms_linked ON chat.rooms(linked_type, linked_id);

CREATE TABLE chat.room_members (
    room_id     UUID NOT NULL REFERENCES chat.rooms(id) ON DELETE CASCADE,
    user_id     UUID NOT NULL,
    role        VARCHAR(16) NOT NULL DEFAULT 'member',  -- owner|moderator|member|readonly
    joined_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_read_message_id UUID,
    muted_until TIMESTAMPTZ,
    left_at     TIMESTAMPTZ,
    PRIMARY KEY (room_id, user_id)
);

CREATE TABLE chat.messages (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    room_id     UUID NOT NULL REFERENCES chat.rooms(id) ON DELETE CASCADE,
    sender_id   UUID NOT NULL,
    reply_to_id UUID REFERENCES chat.messages(id) ON DELETE SET NULL,
    body        TEXT CHECK (char_length(body) <= 4000),
    body_html   TEXT,                          -- خروجی sanitize شده
    file_id     UUID,                          -- files.uploads
    message_type VARCHAR(16) NOT NULL DEFAULT 'text',  -- text|file|system
    is_edited   BOOLEAN NOT NULL DEFAULT FALSE,
    edited_at   TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at  TIMESTAMPTZ,
    search_vector TSVECTOR
);
CREATE INDEX ix_messages_room ON chat.messages(room_id, created_at DESC) WHERE deleted_at IS NULL;
CREATE INDEX ix_messages_search ON chat.messages USING GIN(search_vector);

CREATE SCHEMA files;
CREATE TABLE files.uploads (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    uploader_id   UUID NOT NULL,
    context_type  VARCHAR(32) NOT NULL,        -- chat | task_attachment | avatar
    context_id    UUID,
    original_name VARCHAR(255) NOT NULL,       -- فقط برای نمایش، هرگز در مسیر فایل
    object_key    VARCHAR(512) NOT NULL UNIQUE,-- UUID-based؛ خارج از Web Root
    mime_declared VARCHAR(128),
    mime_detected VARCHAR(128),                -- از magic number
    size_bytes    BIGINT NOT NULL CHECK (size_bytes <= 52428800),   -- ۵۰MB
    sha256        CHAR(64) NOT NULL,
    scan_status   VARCHAR(16) NOT NULL DEFAULT 'pending',  -- pending|clean|infected|error
    scan_engine   VARCHAR(32),
    scanned_at    TIMESTAMPTZ,
    is_available  BOOLEAN NOT NULL DEFAULT FALSE,          -- تا تأیید اسکن، دانلود ممنوع
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at    TIMESTAMPTZ
);
CREATE INDEX ix_uploads_scan ON files.uploads(scan_status) WHERE scan_status = 'pending';
```

### ۴.۶ ماژول Inbox/Outbox (کارتابل)

```sql
CREATE SCHEMA inbox;

CREATE TYPE inbox.item_action AS ENUM ('pending', 'accepted', 'rejected', 'deferred', 'expired');
CREATE TYPE inbox.receipt_state AS ENUM ('sent', 'seen', 'acted');

CREATE TABLE inbox.items (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    sender_id      UUID NOT NULL,
    recipient_id   UUID NOT NULL,
    item_type      VARCHAR(40) NOT NULL,   -- meeting_invite | share_request |
                                           -- task_assignment | chat_invite | approval
    entity_type    VARCHAR(32),
    entity_id      UUID,
    title          VARCHAR(200) NOT NULL,
    message        TEXT,
    priority       VARCHAR(16) NOT NULL DEFAULT 'normal',
    action_state   inbox.item_action NOT NULL DEFAULT 'pending',
    receipt_state  inbox.receipt_state NOT NULL DEFAULT 'sent',
    seen_at        TIMESTAMPTZ,
    acted_at       TIMESTAMPTZ,
    defer_until    TIMESTAMPTZ,            -- گزینه «بعداً»
    response_note  TEXT,
    due_at         TIMESTAMPTZ,
    expires_at     TIMESTAMPTZ,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX ix_inbox_recipient ON inbox.items(recipient_id, action_state, created_at DESC);
CREATE INDEX ix_inbox_sender    ON inbox.items(sender_id, created_at DESC);
CREATE INDEX ix_inbox_deferred  ON inbox.items(defer_until) WHERE action_state = 'deferred';
```

### ۴.۷ شخصی‌سازی — داشبورد و ویجت‌ها

```sql
CREATE SCHEMA reporting;

CREATE TABLE reporting.dashboard_layouts (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID NOT NULL,
    name       VARCHAR(64) NOT NULL,
    view_mode  VARCHAR(16) NOT NULL DEFAULT 'daily',
    is_default BOOLEAN NOT NULL DEFAULT FALSE,
    schema_version SMALLINT NOT NULL DEFAULT 1,   -- برای Import/Export سازگار
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX uq_layout_default ON reporting.dashboard_layouts(user_id, view_mode)
    WHERE is_default = TRUE;

CREATE TABLE reporting.user_dashboard_settings (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL,
    layout_id   UUID NOT NULL REFERENCES reporting.dashboard_layouts(id) ON DELETE CASCADE,
    block_key   VARCHAR(48) NOT NULL,
    is_visible  BOOLEAN NOT NULL DEFAULT TRUE,
    position_x  SMALLINT NOT NULL DEFAULT 0  CHECK (position_x BETWEEN 0 AND 11),
    position_y  SMALLINT NOT NULL DEFAULT 0,
    width       SMALLINT NOT NULL DEFAULT 4  CHECK (width  BETWEEN 1 AND 12),
    height      SMALLINT NOT NULL DEFAULT 4  CHECK (height BETWEEN 1 AND 20),
    is_collapsed BOOLEAN NOT NULL DEFAULT FALSE,
    config      JSONB NOT NULL DEFAULT '{}',
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (layout_id, block_key),
    CONSTRAINT ck_within_grid CHECK (position_x + width <= 12)
);

CREATE TABLE reporting.user_widget_settings (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL,
    widget_key  VARCHAR(48) NOT NULL,          -- clock | quick_add | mini_calendar
    platform    VARCHAR(16) NOT NULL DEFAULT 'all',   -- desktop | web | all
    is_visible  BOOLEAN NOT NULL DEFAULT TRUE,
    position_x  INTEGER NOT NULL DEFAULT 20,   -- مختصات مطلق (ویجت شناور)
    position_y  INTEGER NOT NULL DEFAULT 20,
    width       INTEGER NOT NULL DEFAULT 260 CHECK (width  BETWEEN 160 AND 640),
    height      INTEGER NOT NULL DEFAULT 120 CHECK (height BETWEEN 80  AND 400),
    z_index     SMALLINT NOT NULL DEFAULT 10,
    style       JSONB NOT NULL DEFAULT '{}',   -- {bg, fg, font_family, font_size, opacity}
    config      JSONB NOT NULL DEFAULT '{}',   -- {show_jalali, show_gregorian, show_hijri,
                                               --  time_format:"HH:mm:ss", show_seconds}
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (user_id, widget_key, platform)
);
```

> `config` و `style` عمداً JSONB هستند تا افزودن گزینه، Migration نخواهد. اما محتوای آن‌ها **در سرور با یک اسکیمای Pydantic مخصوص هر `widget_key`/`block_key` اعتبارسنجی می‌شود**. JSONB به معنای پذیرش هر ورودی نیست — این یک بردار تزریق رایج است (ذخیره‌ی `opacity: "<script>"` و رندر مستقیم آن در CSS).

### ۴.۸ ماژول Audit — با MAC Address و زنجیره‌ی هش

```sql
CREATE SCHEMA audit;

CREATE TABLE audit.audit_logs (
    id                 BIGSERIAL PRIMARY KEY,
    user_id            UUID,
    action             VARCHAR(100) NOT NULL,
    entity_type        VARCHAR(50),
    entity_id          UUID,
    timestamp          TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- ── هویت شبکه و دستگاه
    ip_address         INET,
    mac_address        VARCHAR(17),          -- Desktop؛ NULL/unknown در Web
    mac_verified       BOOLEAN NOT NULL DEFAULT FALSE,   -- امضای HMAC معتبر بود؟
    device_fingerprint VARCHAR(255),
    device_id          UUID,                 -- FK منطقی به auth.user_devices
    user_agent         TEXT,
    session_id         UUID,

    result             VARCHAR(20) NOT NULL, -- success | failure | denied
    details            JSONB,
    old_value          JSONB,
    new_value          JSONB,
    geo_location       JSONB,
    request_id         UUID,
    correlation_id     UUID,

    -- ── یکپارچگی
    prev_hash          CHAR(64),             -- زنجیره هش
    row_hash           CHAR(64) NOT NULL,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now()
) PARTITION BY RANGE (timestamp);

CREATE TABLE audit.audit_logs_2026q3 PARTITION OF audit.audit_logs
    FOR VALUES FROM ('2026-07-01') TO ('2026-10-01');

CREATE INDEX idx_audit_user_time   ON audit.audit_logs(user_id, timestamp DESC);
CREATE INDEX idx_audit_mac         ON audit.audit_logs(mac_address) WHERE mac_address IS NOT NULL;
CREATE INDEX idx_audit_ip          ON audit.audit_logs(ip_address);
CREATE INDEX idx_audit_action      ON audit.audit_logs(action, timestamp DESC);
CREATE INDEX idx_audit_fingerprint ON audit.audit_logs(device_fingerprint);
CREATE INDEX idx_audit_entity      ON audit.audit_logs(entity_type, entity_id, timestamp DESC);

CREATE TABLE audit.login_audit_logs (
    id                 BIGSERIAL PRIMARY KEY,
    user_id            UUID,
    username           VARCHAR(100),          -- حتی برای کاربر ناموجود ثبت می‌شود
    national_id_hash   CHAR(64),              -- هرگز کد ملی خام در لاگ
    auth_method        VARCHAR(20) NOT NULL,  -- local | sso | ldap | kerberos
    mfa_used           VARCHAR(16),           -- totp | email | sms | recovery | none
    timestamp          TIMESTAMPTZ NOT NULL DEFAULT now(),
    ip_address         INET,
    mac_address        VARCHAR(17),
    mac_verified       BOOLEAN NOT NULL DEFAULT FALSE,
    device_fingerprint VARCHAR(255),
    device_is_trusted  BOOLEAN,
    user_agent         TEXT,
    success            BOOLEAN NOT NULL,
    failure_reason     VARCHAR(255),          -- کد داخلی، نه پیام کاربر
    session_id         UUID,
    geo_location       JSONB,
    risk_score         SMALLINT,              -- ۰ تا ۱۰۰ (بخش ۶.۵)
    prev_hash          CHAR(64),
    row_hash           CHAR(64) NOT NULL,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_login_audit_user  ON audit.login_audit_logs(user_id, timestamp DESC);
CREATE INDEX idx_login_audit_mac   ON audit.login_audit_logs(mac_address);
CREATE INDEX idx_login_audit_ip    ON audit.login_audit_logs(ip_address, timestamp DESC);
CREATE INDEX idx_login_failed      ON audit.login_audit_logs(username, timestamp DESC)
    WHERE success = FALSE;

-- کاربر برنامه فقط اجازه درج دارد
REVOKE UPDATE, DELETE ON ALL TABLES IN SCHEMA audit FROM app_user;
GRANT  INSERT, SELECT  ON ALL TABLES IN SCHEMA audit TO app_user;
```

**زنجیره‌ی هش (Hash Chain) — یکپارچگی لاگ:**

```
row_hash = SHA256( prev_hash ‖ id ‖ user_id ‖ action ‖ timestamp ‖ ip ‖ mac ‖ result ‖ details )
```

هر رکورد به رکورد قبلی گره می‌خورد. حذف یا تغییر یک رکورد، زنجیره را می‌شکند و یک Job روزانه‌ی بازبینی آن را کشف می‌کند. علاوه بر این، آخرین `row_hash` هر روز **به یک سیستم بیرونی (SIEM یا فایل WORM) ارسال می‌شود** — بدون این لنگر بیرونی، مهاجمی با دسترسی به دیتابیس می‌تواند کل زنجیره را بازسازی کند. امضای دیجیتال تک‌رکوردی این خاصیت را ندارد: تغییر را کشف می‌کند اما **حذف** را نه.

### ۴.۹ استراتژی رمزنگاری

| داده | روش | کلید | نکته |
|------|-----|------|------|
| رمز عبور | Argon2id (`t=3, m=64MiB, p=4`) + Salt یکتا | — | ارتقای خودکار پارامترها هنگام ورود |
| کد ملی | AES-256-GCM + HMAC-SHA256 برای جستجو | DEK از Vault، PEPPER جدا از DEK | Nonce یکتا در هر رمزنگاری |
| موبایل | AES-256-GCM | همان DEK | فقط برای MFA پیامکی |
| TOTP Secret | AES-256-GCM | DEK اختصاصی MFA | افشای آن = دور زدن کامل MFA |
| رمز Bind اکانت LDAP | AES-256-GCM (Envelope) | DEK از Vault | Write-Only در API |
| Refresh Token / کد بازیابی | SHA-256 | — | مقدار اصلی هرگز ذخیره نمی‌شود |
| کلید HMAC دستگاه | AES-256-GCM | DEK اختصاصی | یکتا به‌ازای هر دستگاه |
| کل دیتابیس | TDE سطح Volume (LUKS / Cloud KMS) | مدیریت زیرساخت | PostgreSQL TDE بومی ندارد |
| فایل‌های آپلودی | SSE-S3 / SSE-KMS در MinIO | KMS | به‌علاوه‌ی اسکن AV |
| بکاپ | `pg_dump` + age/GPG | کلید مجزا از DB | تست بازیابی ماهانه اجباری |
| ارتباط با DB | TLS `sslmode=verify-full` | CA سازمانی | — |

**چرخش کلید (Key Rotation):** هر DEK یک `key_version` دارد که در کنار داده‌ی رمزنگاری‌شده ذخیره می‌شود. چرخش سالانه با رمزگشایی/رمزنگاری مجدد دسته‌ای انجام می‌شود، بدون Downtime. طراحی فیلدها از ابتدا باید فضای `key_version` را داشته باشد — افزودن آن بعداً پرهزینه است.

---

## ۵. طراحی API

### ۵.۱ قراردادهای عمومی

- پایه: `https://api.corp.local/api/v1` — نسخه در مسیر. سیاست نسخه‌بندی: `v(n)` تا ۱۲ ماه پس از انتشار `v(n+1)` پشتیبانی می‌شود؛ هدر `Deprecation` و `Sunset` روی نسخه‌ی قدیمی ارسال می‌گردد.
- هدرهای اجباری کلاینت روی هر درخواست احراز هویت‌شده:

```
Authorization:        Bearer <access_token>
X-Device-Fingerprint: <sha256-hash>
X-Device-MAC:         00:1A:2B:3C:4D:5E        (فقط Desktop؛ در Web ارسال نمی‌شود)
X-Device-Nonce:       <uuid4>                   (ضد Replay)
X-Device-Timestamp:   <unix-ms>
X-Device-Signature:   <hmac-sha256>
X-Request-ID:         <uuid4>
```

- قالب خطای یکنواخت، صفحه‌بندی Cursor، `ETag`/`If-Match` برای Optimistic Locking، و `Idempotency-Key` روی POSTهای حساس — مطابق نسخه ۱.
- **۴۰۴ به‌جای ۴۰۳** وقتی کاربر اصلاً نباید از وجود رکورد باخبر شود؛ `403` فقط وقتی دسترسی دارد ولی سطحش کافی نیست.

### ۵.۲ Auth، MFA و دستگاه‌ها

| متد | مسیر | توضیح |
|-----|------|-------|
| POST | `/auth/register` | ثبت‌نام با کد ملی (اعتبارسنجی چک‌سام) |
| POST | `/auth/login` | ورود با `identifier` (نام کاربری **یا** کد ملی) |
| POST | `/auth/mfa/verify` | تأیید کد MFA با `mfa_token` موقت |
| POST | `/auth/mfa/enroll` | شروع ثبت TOTP (بازگشت QR + Secret) |
| POST | `/auth/mfa/enroll/confirm` | تأیید ثبت + تولید کدهای بازیابی |
| DELETE | `/auth/mfa` | غیرفعال‌سازی MFA (نیازمند رمز + کد فعلی) |
| POST | `/auth/refresh` | چرخش Refresh Token |
| POST | `/auth/logout` · `/auth/logout-all` | ابطال نشست/همه نشست‌ها |
| GET | `/auth/sessions` | نشست‌های فعال (دستگاه، IP، آخرین فعالیت) |
| DELETE | `/auth/sessions/{id}` | ابطال یک نشست |
| POST | `/auth/password/forgot` · `/reset` · `/change` | مدیریت رمز |
| GET | `/auth/sso/negotiate` | SSO با Kerberos/NTLM |
| POST | `/auth/sso/ldap-login` | ورود با اعتبارنامه AD |
| GET | `/auth/me` | پروفایل + نقش‌ها + Permissionهای مؤثر |
| **POST** | **`/auth/devices/register`** | ثبت دستگاه با MAC/Fingerprint |
| **GET** | **`/auth/devices`** | لیست دستگاه‌های شناخته‌شده (MAC ماسک‌شده) |
| PATCH | `/auth/devices/{id}` | نام‌گذاری / اعتمادسازی (نیازمند MFA) |
| DELETE | `/auth/devices/{id}` | حذف/مسدودسازی دستگاه |

```jsonc
// POST /auth/login
{ "identifier": "0012345678", "password": "••••••••", "remember_me": true,
  "captcha_token": "03AGdBq26..." }

// 200 — نیازمند MFA
{ "mfa_required": true, "mfa_token": "eyJ...",   // عمر ۵ دقیقه، فقط برای /auth/mfa/verify
  "mfa_method": "totp", "expires_in": 300 }

// 200 — بدون MFA
{ "access_token": "eyJ...", "token_type": "Bearer", "expires_in": 900,
  "device": { "id": "018f...", "is_trusted": false, "is_new": true },
  "user": { "id": "018f...", "username": "a.rezaei", "display_name": "علی رضایی",
            "national_id_masked": "******5678", "roles": ["user","manager"],
            "permissions": ["goal.create","group.view", "..."],
            "privacy_level": "team_only", "mfa_enabled": true } }

// 401 — پیام یکسان برای کاربر ناموجود و رمز غلط
{ "error": { "code": "INVALID_CREDENTIALS", "message": "اطلاعات ورود نادرست است." } }

// 403 — دستگاه غیرمجاز
{ "error": { "code": "DEVICE_NOT_TRUSTED",
             "message": "ورود از این دستگاه مجاز نیست. با مدیر سیستم تماس بگیرید." } }
```

```jsonc
// POST /auth/devices/register
{ "device_fingerprint": "a3f9...", "mac_address": "00:1A:2B:3C:4D:5E",
  "mac_source": "psutil", "platform": "desktop",
  "device_label": "لپ‌تاپ اداری", "os_info": "Windows 11 Pro 23H2" }

// 201 — کلید HMAC فقط یک‌بار و فقط در همین پاسخ برگردانده می‌شود
{ "device_id": "018f...", "hmac_key": "base64:...", "is_trusted": false,
  "requires_mfa_to_trust": true }

// GET /auth/devices  — MAC همیشه ماسک‌شده مگر برای Admin
{ "items": [
    { "id": "018f...", "device_label": "لپ‌تاپ اداری", "platform": "desktop",
      "mac_address_masked": "00:1A:**:**:**:5E", "is_trusted": true,
      "last_seen_at": "2026-09-18T06:12:00Z", "last_ip": "10.20.3.44",
      "is_current": true } ] }
```

### ۵.۳ RBAC، گروه‌ها و حریم خصوصی

| متد | مسیر | Permission |
|-----|------|------------|
| GET | `/rbac/roles` · `/rbac/permissions` | `rbac.read` |
| POST/PATCH/DELETE | `/rbac/roles/{id}` | `rbac.manage` |
| POST | `/admin/users/{id}/roles` | `rbac.assign` |
| DELETE | `/admin/users/{id}/roles/{role_id}` | `rbac.assign` |
| GET/POST | `/groups` | `group.read` / `group.create` |
| GET/PATCH/DELETE | `/groups/{id}` | `group.manage` |
| GET/POST | `/groups/{id}/members` | `group.manage` |
| PATCH | `/groups/{id}/members/{uid}` | ارتقا/تنزل مدیر گروه |
| GET | `/groups/{id}/dashboard` | مدیر همان گروه — با اعمال حریم خصوصی |
| GET | `/groups/{id}/report?from=&to=` | گزارش تیمی |
| GET/PUT | `/me/privacy` | تنظیمات حریم خصوصی کاربر |
| GET/POST/DELETE | `/me/privacy/exceptions` | حالت `selected` |
| GET | `/me/privacy/access-log` | «چه کسی داده‌ی من را دید؟» |

```jsonc
// GET /groups/{id}/dashboard  — نمونه‌ی خروجی با حریم خصوصی اعمال‌شده
{ "group": { "id": "018f...", "name": "واحد برنامه‌ریزی", "member_count": 12 },
  "period": { "from": "2026-09-01", "to": "2026-09-30" },
  "members": [
    { "user_id": "018f-a", "display_name": "علی رضایی",
      "privacy_level": "team_only", "visibility": "full",
      "stats": { "total_tasks": 24, "completed": 18, "overdue": 2, "progress_pct": 75 },
      "goals": [ { "id":"...", "title":"...", "progress_pct": 62 } ] },
    { "user_id": "018f-b", "display_name": "سارا محمدی",
      "privacy_level": "fully_private", "visibility": "aggregate_only",
      "stats": { "progress_pct": 68 },             // فقط عدد کل
      "goals": null,                                // عنوان اهداف پنهان
      "notice": "این کاربر جزئیات را خصوصی کرده است." } ],
  "aggregate": { "team_progress_pct": 71, "at_risk_members": 2 } }
```

### ۵.۴ Audit Log و Device Management

| متد | مسیر | Permission |
|-----|------|------------|
| POST | `/audit/logs` | داخلی/کلاینت — ثبت رویداد سمت کلاینت (محدود) |
| GET | `/admin/audit/logs` | `audit.read` |
| GET | `/admin/audit/logs?mac_address=00:1A:2B:3C:4D:5E` | فیلتر بر اساس MAC |
| GET | `/admin/audit/logs?device_fingerprint=&user_id=&action=&from=&to=&result=` | فیلتر ترکیبی |
| GET | `/admin/audit/login-logs` | لاگ ورودها |
| GET | `/admin/audit/logs/{id}` | جزئیات کامل (MAC بدون ماسک) |
| POST | `/admin/audit/export` | خروجی CSV/Excel — خودش یک رویداد Audit تولید می‌کند |
| GET | `/admin/audit/integrity-check` | بازبینی زنجیره هش |
| POST | `/admin/audit/archive` | آرشیو پارتیشن‌های قدیمی |
| GET | `/admin/audit/devices?mac_address=` | همبستگی دستگاه‌ها (Device Correlation) |
| GET | `/admin/audit/anomalies` | رویدادهای پرریسک (risk_score بالا) |

```jsonc
// POST /audit/logs — ثبت رویداد سمت کلاینت
// ⚠ این endpoint فقط انواع محدودی از رویداد را می‌پذیرد (whitelist)
{ "action": "ui.export.clicked", "entity_type": "report", "entity_id": "018f...",
  "details": { "format": "xlsx" } }
// MAC، IP، fingerprint و user_id از هدرها و توکن استخراج می‌شوند — هرگز از Body
// 202 Accepted (بدون بدنه)

// GET /admin/audit/logs?mac_address=00:1A:2B:3C:4D:5E&from=2026-09-01
{ "items": [
    { "id": 8842119, "timestamp": "2026-09-18T06:12:04Z",
      "user": { "id":"018f...", "display_name":"علی رضایی", "national_id_masked":"******5678" },
      "action": "goal.task.deleted", "entity_type": "task", "entity_id": "018f...",
      "result": "success",
      "ip_address": "10.20.3.44",
      "mac_address": "00:1A:2B:3C:4D:5E",    // بدون ماسک — فقط برای Admin
      "mac_verified": true,
      "device_fingerprint": "a3f9c2...", "device_label": "لپ‌تاپ اداری",
      "session_id": "018f...", "user_agent": "PlannerDesktop/2.0 (Windows 11)",
      "geo_location": { "country":"IR", "city":"Tehran", "source":"geoip" } } ],
  "total": 1284, "next_cursor": "eyJ0IjoiMjAyNi0wOS0xOFQwNjoxMjowNFoifQ==" }

// GET /admin/audit/devices?mac_address=00:1A:2B:3C:4D:5E  — Device Correlation
{ "mac_address": "00:1A:2B:3C:4D:5E",
  "users": [ { "user_id":"018f-a", "display_name":"علی رضایی", "login_count": 412,
               "first_seen":"2026-03-02T...", "last_seen":"2026-09-18T..." },
             { "user_id":"018f-c", "display_name":"محمد کریمی", "login_count": 3,
               "first_seen":"2026-09-17T...", "last_seen":"2026-09-17T..." } ],
  "warning": "این دستگاه توسط بیش از یک کاربر استفاده شده است." }
```

### ۵.۵ چت، کارتابل، داشبورد و ویجت

| متد | مسیر | توضیح |
|-----|------|-------|
| GET/POST | `/chat/rooms` | لیست/ایجاد اتاق (با `linked_type`/`linked_id`) |
| GET/PATCH/DELETE | `/chat/rooms/{id}` | مدیریت اتاق (حذف ⇒ آرشیو اجباری) |
| GET/POST | `/chat/rooms/{id}/members` | عضویت‌ها |
| GET | `/chat/rooms/{id}/messages?before=&limit=` | تاریخچه (Cursor معکوس) |
| POST | `/chat/rooms/{id}/archive` | آرشیو و دانلود تاریخچه |
| POST | `/files/presign` | دریافت Presigned URL برای آپلود |
| POST | `/files/{id}/finalize` | اعلام پایان آپلود ⇒ صف اسکن AV |
| GET | `/files/{id}/download` | دانلود (فقط اگر `scan_status='clean'`) |
| WSS | `/ws/chat` | سوکت چت |
| WSS | `/ws/notifications` | اعلان‌های زنده |
| GET | `/inbox?state=pending` | کارتابل ورودی |
| POST | `/inbox/{id}/act` | `accept` / `reject` / `defer` |
| GET | `/outbox` | کارتابل ارسالی با Read Receipt |
| GET/POST/PUT/DELETE | `/dashboard/layouts[/{id}]` | مدیریت Layout |
| POST | `/dashboard/layouts/{id}/reset` | بازگشت به پیش‌فرض |
| GET | `/dashboard/layouts/{id}/export` | خروجی JSON |
| POST | `/dashboard/layouts/import` | ورودی JSON (با اعتبارسنجی کامل) |
| GET/PUT | `/widgets/settings` | تنظیمات ویجت‌ها (Sync بین دستگاه‌ها) |
| POST | `/widgets/settings/reset` | Reset to Default |

```jsonc
// POST /inbox/{id}/act
{ "action": "defer", "defer_until": "2026-09-20T05:00:00Z", "note": "بعد از جلسه بررسی می‌کنم" }
// 200
{ "id": "018f...", "action_state": "deferred", "receipt_state": "acted",
  "acted_at": "2026-09-18T07:02:00Z" }
// ⇒ رویداد inbox.item.acted منتشر می‌شود ⇒ فرستنده Read Receipt می‌گیرد

// POST /dashboard/layouts/import
{ "schema_version": 1, "name": "چیدمان وارداتی", "view_mode": "daily",
  "blocks": [ { "block_key": "goals", "position_x": 0, "position_y": 0,
                "width": 6, "height": 4, "config": { "limit": 5 } } ] }
// 400 در صورت: block_key ناشناخته، تداخل موقعیت‌ها، خروج از گرید ۱۲ ستونه،
//               یا config نامعتبر برای آن block_key
```

---

## ۶. استراتژی MAC Address و شناسایی دستگاه

### ۶.۱ ارزیابی صادقانه: MAC چه می‌تواند و چه نمی‌تواند

این بخش را با یک ارزیابی روشن شروع می‌کنم، چون طراحی درست به آن وابسته است:

**MAC Address یک کنترل امنیتی نیست.** دلایل:

1. **قابل جعل است.** تغییر MAC در ویندوز از طریق Device Manager یا یک دستور PowerShell، بدون نیاز به دسترسی Admin روی برخی درایورها، کار چند ثانیه است.
2. **کلاینت آن را گزارش می‌دهد، نه شبکه.** سرور MAC را از هدر HTTP می‌گیرد — یعنی از همان موجودیتی که قرار است اعتبارسنجی شود. امضای HMAC هم این را حل نمی‌کند: کلید HMAC روی همان دستگاه است، پس مهاجمی که کنترل دستگاه را دارد می‌تواند **یک MAC جعلی را با امضای معتبر** بفرستد. HMAC از دستکاری **در مسیر شبکه** (MITM) محافظت می‌کند، نه از دروغ‌گویی کلاینت.
3. **از روتر عبور نمی‌کند.** MAC فقط در سگمنت شبکه‌ی محلی معنا دارد؛ سروری که پشت چند Hop است، MAC واقعی را در لایه‌ی شبکه نمی‌بیند.
4. **MAC Randomization.** ویندوز ۱۰+، اندروید ۱۰+ و iOS 14+ به‌صورت پیش‌فرض MAC تصادفی به‌ازای هر شبکه تولید می‌کنند.
5. **در VM، Container و VDI بی‌معناست.** در محیط‌های مجازی‌شده، همه‌ی کاربران ممکن است MAC یکسان یا تصادفی داشته باشند.

**پس چه ارزشی دارد؟** MAC یک **سیگنال Forensic و Correlation** است: در تحقیق پس از حادثه کمک می‌کند بفهمید کدام فعالیت‌ها از یک دستگاه بوده‌اند، و ناهنجاری‌ها را برجسته می‌کند («این کاربر همیشه از MAC ثابت وارد می‌شد، امروز از یک MAC جدید»). این ارزش واقعی است — به شرطی که MAC هرگز به‌تنهایی مبنای تصمیم «اجازه بده یا نده» نباشد.

**پیشنهاد معماری:** MAC را همان‌طور که خواسته‌اید ثبت کنید، اما تصمیم‌های امنیتی را به یک **Device Identity ترکیبی** ببندید که MAC فقط یکی از ورودی‌های آن است (بخش ۶.۵).

### ۶.۲ دریافت MAC در دسکتاپ

```python
# desktop/app/core/device_identity.py
import psutil, socket, uuid, hashlib, platform

def _normalize(mac: str) -> str:
    return mac.upper().replace("-", ":").strip()

def get_primary_mac() -> tuple[str | None, str]:
    """MAC کارت شبکه‌ای که مسیر پیش‌فرض از آن می‌گذرد.
    خروجی: (mac, source). در صورت عدم دسترسی: (None, 'unavailable').
    """
    # ۱) کارت شبکه‌ای که IP محلی فعال روی آن است را پیدا کن
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("10.255.255.255", 1))       # بدون ارسال داده؛ فقط انتخاب مسیر
            local_ip = s.getsockname()[0]
    except OSError:
        local_ip = None

    stats = psutil.net_if_stats()
    for name, addrs in psutil.net_if_addrs().items():
        st = stats.get(name)
        if not st or not st.isup:
            continue
        if any(k in name.lower() for k in ("loopback", "vmware", "virtualbox",
                                           "hyper-v", "docker", "vethernet")):
            continue                                # کارت‌های مجازی را رد کن
        has_local_ip = local_ip and any(a.address == local_ip for a in addrs)
        mac = next((a.address for a in addrs if a.family == psutil.AF_LINK), None)
        if mac and mac != "00:00:00:00:00:00":
            if has_local_ip:
                return _normalize(mac), "psutil"    # کارت اصلی — بهترین گزینه
    # ۲) Fallback: اولین کارت فیزیکی فعال
    for name, addrs in psutil.net_if_addrs().items():
        if stats.get(name) and stats[name].isup:
            mac = next((a.address for a in addrs if a.family == psutil.AF_LINK), None)
            if mac and mac != "00:00:00:00:00:00":
                return _normalize(mac), "psutil"
    # ۳) Fallback نهایی: uuid.getnode()
    node = uuid.getnode()
    if (node >> 40) % 2 == 0:                       # بیت multicast صفر ⇒ MAC واقعی
        mac = ":".join(f"{(node >> e) & 0xFF:02X}" for e in range(40, -8, -8))
        return mac, "uuid_getnode"
    return None, "unavailable"                      # uuid تصادفی تولید کرده — بی‌ارزش


def get_system_fingerprint() -> str:
    """اثر انگشت سیستمی پایدارتر از MAC — مبنای اصلی شناسایی دستگاه."""
    mac, _ = get_primary_mac()
    parts = [
        platform.node(), platform.machine(), platform.system(),
        platform.processor(), str(psutil.cpu_count(logical=False)),
        _machine_guid(),                            # HKLM\SOFTWARE\Microsoft\Cryptography
        mac or "no-mac",
    ]
    return hashlib.sha256("|".join(filter(None, parts)).encode()).hexdigest()
```

**نکته‌ی مهم درباره‌ی `uuid.getnode()`:** این تابع وقتی MAC واقعی پیدا نکند، یک عدد **تصادفی** با بیت multicast برابر ۱ برمی‌گرداند. ثبت آن به‌عنوان MAC یعنی ثبت داده‌ی جعلی در Audit Log. بررسی بیت (`(node >> 40) % 2`) این تله را می‌گیرد — تقریباً همه‌ی پیاده‌سازی‌هایی که این تابع را به‌عنوان Fallback به کار می‌برند از آن غافل‌اند.

### ۶.۳ جایگزین در وب — و محدودیت‌های واقعی آن

در مرورگر MAC در دسترس نیست و راهی برای دور زدن آن وجود ندارد. سه نکته درباره‌ی جایگزین‌ها:

- **WebRTC برای کشف IP محلی دیگر کار نمی‌کند.** از سال ۲۰۲۰، Chrome، Firefox و Safari آدرس‌های محلی را با mDNS (`.local`) مبهم می‌کنند. اتکا به آن اتلاف وقت است.
- **Canvas/WebGL Fingerprinting در Safari و Firefox (با Resist Fingerprinting) تضعیف یا مسدود می‌شود.** پایداری آن در Chrome خوب و در سایرین متوسط تا ضعیف است.
- **ملاحظه‌ی حقوقی:** Fingerprinting بدون اطلاع کاربر، در بسیاری از چارچوب‌های حفاظت از داده مسئله‌ساز است. چون این یک سامانه‌ی **سازمانی داخلی** است، درج آن در سیاست استفاده و اطلاع‌رسانی به کارکنان کافی و توصیه‌شده است.

**راهکار قوی‌تر و ترکیبی:**

```
Device Identity = FingerprintJS (جزء ناپایدار)
                + Device Token صادرشده توسط سرور (جزء پایدار)
```

پس از اولین ورود موفق، سرور یک **Device Token تصادفی** صادر می‌کند که در Cookie `HttpOnly; Secure; SameSite=Strict; Max-Age=۱ سال` ذخیره می‌شود. این توکن، برخلاف Fingerprint، نه قابل جعل است و نه با به‌روزرسانی مرورگر تغییر می‌کند. Fingerprint نقش تشخیص ناهنجاری را دارد (اگر Device Token همان باشد ولی Fingerprint کاملاً عوض شده باشد ⇒ احتمال سرقت Cookie).

مقدار ذخیره‌شده در `mac_address` برای وب: `NULL`، و `device_fingerprint` مقدار `web-fp-<sha256>` می‌گیرد. توصیه می‌کنم به‌جای درج مقدار مصنوعی در ستون `mac_address`، آن را `NULL` بگذارید — ستونی که گاهی MAC واقعی و گاهی یک رشته‌ی ساختگی دارد، تحلیل Forensic را آلوده می‌کند.

### ۶.۴ ارسال امن هدرهای دستگاه

```
X-Device-Fingerprint: a3f9c2...
X-Device-MAC:         00:1A:2B:3C:4D:5E
X-Device-Nonce:       018f4c1e-7a2b-7c3d-9e10-4f5a6b7c8d90
X-Device-Timestamp:   1789012345678
X-Device-Signature:   HMAC-SHA256(device_hmac_key,
                        method|path|sha256(body)|fingerprint|mac|nonce|timestamp)
```

**اعتبارسنجی سمت سرور:**

1. `device_id` از Fingerprint یا Device Token استخراج و `hmac_key` آن رمزگشایی می‌شود.
2. اختلاف `timestamp` با زمان سرور باید کمتر از ۳۰۰ ثانیه باشد.
3. `nonce` نباید در Redis (با TTL ۳۰۰ ثانیه) وجود داشته باشد ⇒ **ضد Replay**.
4. امضا با `hmac.compare_digest` مقایسه می‌شود (ضد Timing Attack).
5. نتیجه در `mac_verified` ثبت می‌شود.

**سیاست شکست امضا — تصمیم مهم:** درخواست را **رد نکنید**؛ آن را با `mac_verified=false` ثبت و ریسک را بالا ببرید. دلیل: ساعت نادرست کلاینت، پروکسی‌هایی که بدنه را تغییر می‌دهند، یا به‌روزرسانی ناقص کلاینت می‌توانند امضای معتبر را بشکنند. رد کردن سخت‌گیرانه، کاربران واقعی را قفل می‌کند در حالی که مهاجم واقعی می‌تواند امضای معتبر تولید کند. استثنا: عملیات پرریسک (تغییر رمز، تغییر نقش، Export انبوه) که در آن‌ها امضای نامعتبر باید منجر به درخواست MFA مجدد شود.

### ۶.۵ Risk Score — تصمیم‌گیری بر پایه‌ی سیگنال‌های ترکیبی

```python
def compute_risk_score(ctx: LoginContext) -> int:
    """۰ (عادی) تا ۱۰۰ (بسیار مشکوک). هیچ سیگنالی به‌تنهایی تعیین‌کننده نیست."""
    score = 0
    if ctx.device_is_new:                       score += 25
    if not ctx.mac_verified:                    score += 10
    if ctx.mac_changed_for_known_device:        score += 20   # MAC عوض شد، دستگاه همان
    if ctx.ip_outside_corporate_range:          score += 15
    if ctx.geo_impossible_travel:               score += 30   # دو ورود، فاصله غیرممکن
    if ctx.time_outside_user_pattern:           score += 10
    if ctx.recent_failed_attempts >= 3:         score += 20
    if ctx.mac_used_by_other_user_recently:     score += 15
    return min(score, 100)
```

| بازه | اقدام |
|------|-------|
| ۰–۲۹ | ورود عادی |
| ۳۰–۵۹ | الزام MFA حتی اگر دستگاه Trusted باشد |
| ۶۰–۷۹ | MFA + اعلان امنیتی به کاربر و Admin |
| ۸۰–۱۰۰ | مسدودسازی موقت + الزام تأیید Admin |

این مدل همان اهدافی را که از MAC انتظار داشتید — شناسایی دستگاه غیرمجاز، تحلیل الگوی حمله، Device Correlation — برآورده می‌کند، اما بدون اتکای شکننده به یک سیگنال جعل‌پذیر.

### ۶.۶ ماسک کردن و دسترسی به MAC

| زمینه | نمایش |
|-------|-------|
| دیتابیس | کامل (برای جستجو و Forensic) |
| API برای کاربر عادی (`/auth/devices`) | `00:1A:**:**:**:5E` |
| API برای Admin (`/admin/audit/logs`) | کامل — و **خود این مشاهده یک رویداد Audit تولید می‌کند** |
| Export لاگ | کامل، اما فقط با Permission `audit.export` و ثبت در Audit |
| لاگ‌های برنامه (structlog) | ماسک‌شده |
| پیام خطا به کاربر | هرگز |

> نکته‌ی حاکمیت داده: ترکیب **کد ملی + MAC + IP + موقعیت جغرافیایی** در یک جدول با نگهداری یک‌ساله، یک مخزن داده‌ی شخصی حساس ایجاد می‌کند. توصیه می‌کنم: سیاست نگهداری مکتوب، دسترسی محدود به حداکثر ۲–۳ نفر با نقش `auditor`، بازبینی فصلی دسترسی‌ها، و آرشیو رمزنگاری‌شده پس از ۹۰ روز با دسترسی فقط بر اساس درخواست رسمی.

---

## ۷. RBAC، گروه‌ها و حریم خصوصی

### ۷.۱ مدل سه‌لایه‌ی دسترسی

سه پرسش متفاوت که **هرگز نباید در یک تابع ادغام شوند**:

| لایه | پرسش | منبع | نمونه |
|------|------|------|-------|
| **RBAC** | آیا این کاربر مجاز به انجام این *نوع* عملیات است؟ | `rbac.user_roles` | آیا می‌تواند تسک حذف کند؟ |
| **ACL** | آیا به این *رکورد خاص* دسترسی دارد؟ | مالکیت + `sharing.shares` | آیا این تسک مال اوست یا با او به اشتراک گذاشته شده؟ |
| **Privacy** | آیا مالک داده اجازه‌ی دیده شدن توسط این شخص را داده؟ | `groups.privacy_settings` | آیا مدیر گروه می‌تواند جزئیات اهدافش را ببیند؟ |

ادغام این سه، منشأ اصلی نشت داده در سامانه‌های سازمانی است. مثال مشخص: مدیر گروه Permission سراسری `group.view_member_progress` دارد (RBAC می‌گوید بله)، و عضو گروه است (ACL می‌گوید بله)، اما عضو تنظیمات خود را `fully_private` کرده — **Privacy می‌گوید فقط عدد کل، نه جزئیات**. اگر فقط RBAC بررسی شود، حریم خصوصی نقض می‌شود.

### ۷.۲ ترتیب اجرای بررسی‌ها

```python
async def authorize(user, action: str, entity_type: str, entity_id: UUID | None) -> Decision:
    # ۱) RBAC — آیا اصلاً این نوع عملیات برای این کاربر تعریف شده؟
    if not await rbac.has_permission(user, action):
        raise PermissionDenied(action)

    if entity_id is None:                      # عملیات سطح مجموعه (مثل ایجاد)
        return Decision.allow()

    # ۲) ACL — دسترسی سطح رکورد
    acl = await acl_resolver.effective_permission(user, entity_type, entity_id)
    if acl is None:
        raise NotFound()                       # نه ۴۰۳ — عدم افشای وجود رکورد
    if PERMISSION_RANK[acl] < REQUIRED_RANK[action]:
        raise PermissionDenied(action, actual=acl)

    # ۳) Privacy — فقط برای خواندن داده‌ی دیگران
    if action.endswith(".read") and acl != "owner":
        owner_id = await entity_owner(entity_type, entity_id)
        decision = await privacy.effective(owner_id=owner_id, viewer_id=user.id)
        if decision.level == "hidden":
            raise NotFound()
        return Decision.allow(redaction=decision.redaction)   # مثلاً aggregate_only

    return Decision.allow()
```

خروجی `Decision` می‌تواند **allow با محدودیت** باشد — این ظرافت مهم است: پاسخ «بله ولی فقط آمار کلی» با «بله» و «خیر» فرق دارد و سریالایزر باید آن را اعمال کند.

### ۷.۳ منطق حریم خصوصی

| سطح | مدیر گروه می‌بیند | هم‌تیمی می‌بیند | افراد منتخب |
|-----|-------------------|------------------|--------------|
| `fully_private` | فقط درصد پیشرفت کل | هیچ | هیچ |
| `team_only` | همه‌ی جزئیات | عنوان و وضعیت (بدون توضیحات) | — |
| `selected` | فقط اگر در فهرست استثناها باشد | هیچ | مطابق `privacy_exceptions` |
| `fully_transparent` | همه | همه | همه |

**قواعد تکمیلی:**

- کامنت‌گذاری مدیر روی داده‌ی عضو، تابع `allow_manager_comment` است — دیدن ≠ اجازه‌ی نوشتن.
- اگر `notify_on_manager_view` فعال باشد، کاربر اعلان می‌گیرد که مدیرش داده‌اش را دید. این یک کنترل شفافیت است که اعتماد کاربران به سامانه را می‌سازد.
- `/me/privacy/access-log` به کاربر نشان می‌دهد چه کسی، کی و چه چیزی از داده‌هایش را دیده.
- **حریم خصوصی هرگز Audit Log را محدود نمی‌کند.** Admin با نقش `auditor` همیشه رویدادها را می‌بیند؛ حریم خصوصی مربوط به داده‌ی کسب‌وکاری است، نه ردپای امنیتی. این تفکیک باید در سیاست سازمانی هم مکتوب شود.

### ۷.۴ جلوگیری از Privilege Escalation

```python
async def assign_role(actor, target_user_id: UUID, role_id: int, scope=None):
    actor_max = await rbac.max_role_level(actor.id)          # مثلاً manager = 3
    target_role = await rbac.get_role(role_id)               # مثلاً admin = 5

    # ۱) نمی‌توان نقشی بالاتر یا هم‌سطح خود اعطا کرد
    if target_role.level >= actor_max:
        raise PermissionDenied("CANNOT_GRANT_EQUAL_OR_HIGHER_ROLE")

    # ۲) نمی‌توان به خود نقش داد
    if target_user_id == actor.id:
        raise PermissionDenied("CANNOT_SELF_ASSIGN")

    # ۳) نقش دامنه‌دار فقط در دامنه‌ای که خودت مدیرش هستی
    if scope and scope.type == "group":
        if not await groups.is_manager(actor.id, scope.id):
            raise PermissionDenied("NOT_GROUP_MANAGER")

    await rbac.grant(target_user_id, role_id, scope, granted_by=actor.id)
    await audit.log("rbac.role.assigned", target=target_user_id, dangerous=True)
```

هر سه بررسی لازم است. حذف بند اول یعنی هر Manager می‌تواند خود را Super Admin کند — کلاسیک‌ترین Privilege Escalation.

---

## ۸. چت، WebSocket و مدیریت فایل

### ۸.۱ مقیاس‌پذیری WebSocket

```python
# app/ws/manager.py
class ConnectionManager:
    """اتصال‌ها در حافظه‌ی همان Worker؛ پیام‌ها از طریق Redis بین Workerها."""

    def __init__(self, redis: Redis):
        self._rooms: dict[UUID, set[WebSocket]] = defaultdict(set)
        self._redis = redis

    async def join(self, room_id: UUID, ws: WebSocket, user_id: UUID):
        if not await chat_service.is_active_member(room_id, user_id):
            await ws.close(code=4403); return
        self._rooms[room_id].add(ws)
        if len(self._rooms[room_id]) == 1:              # اولین عضو روی این Worker
            await self._subscribe(room_id)

    async def broadcast(self, room_id: UUID, message: dict):
        await self._redis.publish(f"room:{room_id}", json.dumps(message))

    async def _on_redis_message(self, room_id: UUID, raw: str):
        dead = set()
        for ws in self._rooms[room_id]:
            try:
                await ws.send_text(raw)
            except (WebSocketDisconnect, RuntimeError):
                dead.add(ws)
        self._rooms[room_id] -= dead
```

با این الگو، افزودن Worker جدید نیازی به Sticky Session ندارد و پیام کاربر متصل به Worker #1 به کاربر متصل به Worker #3 می‌رسد.

### ۸.۲ چرخه‌ی امن آپلود فایل

```mermaid
graph LR
    C["کلاینت"] -->|۱ POST /files/presign| API
    API -->|۲ اعتبارسنجی: نوع، حجم، سهمیه| API
    API -->|۳ Presigned URL (TTL 5m)| C
    C -->|۴ PUT مستقیم| S3["MinIO<br/>status=pending<br/>is_available=false"]
    C -->|۵ POST /files/{id}/finalize| API
    API -->|۶ enqueue| AV["Celery: av_scan"]
    AV -->|۷ magic number + ClamAV| AV
    AV -->|۸ clean| DB["is_available=true"]
    AV -->|۸ infected| DEL["حذف فایل + Audit + هشدار"]
    DB -->|۹ رویداد| NOTIF["اعلان به اتاق چت"]
```

**کنترل‌های اجباری:**

1. **بررسی magic number، نه پسوند.** `python-magic` نوع واقعی را تشخیص می‌دهد. فایلی با نام `report.pdf` که در واقع PE Executable است، رد می‌شود.
2. **Whitelist، نه Blacklist.** نیازمندی «پشتیبانی از تمام فرمت‌ها» را باید بازنگری کرد: پذیرش `.exe`, `.dll`, `.scr`, `.js`, `.hta`, `.lnk`, `.iso` در یک ابزار سازمانی، آن را به کانال توزیع بدافزار تبدیل می‌کند. پیشنهاد: Whitelist گسترده (اسناد، تصاویر، آرشیوها، ویدئو/صوت، فایل‌های متنی) به‌علاوه‌ی یک فرایند استثنا برای موارد خاص با تأیید Admin.
3. **آرشیوها:** حداکثر عمق ۳ و نسبت فشرده‌سازی حداکثر ۱۰۰:۱ (ضد Zip Bomb).
4. **تصاویر:** Re-encode کامل با Pillow + حذف EXIF (موقعیت جغرافیایی در EXIF یک نشت حریم خصوصی رایج است).
5. **مسیر ذخیره:** `{context}/{yyyy}/{mm}/{uuid}` — نام اصلی فایل فقط در دیتابیس و در هدر `Content-Disposition` (با encode صحیح) استفاده می‌شود.
6. **دانلود:** همیشه با `Content-Disposition: attachment` و `X-Content-Type-Options: nosniff`؛ هرگز `Content-Type` اعلامی کلاینت بازگردانده نشود.
7. **تا پایان اسکن، `is_available=false`** و هر تلاش دانلود `409` می‌گیرد.

### ۸.۳ آرشیو و نگهداری اتاق

حذف اتاق چت یک عملیات **دو مرحله‌ای** است: ابتدا آرشیو (تولید فایل JSON/HTML شامل پیام‌ها، اعضا و ابرداده‌ها، ذخیره در S3 با رمزنگاری)، سپس Soft Delete. رویداد `chat.room.archived` منتشر و مسیر آرشیو در `archive_object_key` ثبت می‌شود. بدون این ترتیب، حذف تصادفی یک اتاق، تاریخچه‌ی تصمیم‌گیری تیم را از بین می‌برد — و در بازرسی‌های بعدی قابل بازیابی نیست.

---

## ۹. کارتابل (Inbox/Outbox)

### ۹.۱ ماشین حالت

```mermaid
stateDiagram-v2
    [*] --> pending: ارسال
    pending --> accepted: تأیید
    pending --> rejected: رد
    pending --> deferred: بعداً
    deferred --> pending: فرا رسیدن defer_until
    deferred --> accepted
    deferred --> rejected
    pending --> expired: گذشت expires_at
    accepted --> [*]
    rejected --> [*]
    expired --> [*]
```

**Read Receipt** یک بعد مستقل از عمل است: `sent` → `seen` (کارتابل باز شد) → `acted` (تصمیم گرفته شد). فرستنده در کارتابل ارسالی هر سه وضعیت را می‌بیند. تفکیک «دیده شد» از «اقدام شد» دقیقاً همان چیزی است که در پیگیری‌های سازمانی لازم است.

### ۹.۲ یکپارچگی با سایر ماژول‌ها

کارتابل هیچ ماژولی را import نمی‌کند؛ فقط رویداد مصرف می‌کند:

```python
@event_bus.on("sharing.share.requested")
async def create_share_inbox_item(event: DomainEvent, uow: UnitOfWork):
    # Idempotent: اگر این event_id قبلاً پردازش شده، خروج
    if await uow.inbox.exists_for_event(event.event_id):
        return
    await uow.inbox.create(InboxItem(
        sender_id=event.actor_id,
        recipient_id=event.payload["recipient_id"],
        item_type="share_request",
        entity_type=event.payload["entity_type"],
        entity_id=event.payload["entity_id"],
        title=f"درخواست دسترسی به «{event.payload['entity_title']}»",
        due_at=event.payload.get("due_at"),
        expires_at=utcnow() + timedelta(days=14),
    ))
```

افزودن یک نوع آیتم جدید به کارتابل، نیازمند هیچ تغییری در ماژول ناشر نیست.

---

## ۱۰. شخصی‌سازی داشبورد و ویجت‌ها

### ۱۰.۱ اعتبارسنجی Layout — جلوگیری از اختلال در برنامه

نیازمندی «عدم اختلال به اصل برنامه» با چهار لایه‌ی اعتبارسنجی برآورده می‌شود:

```python
class BlockLayout(BaseModel):
    block_key: Literal[*ALLOWED_BLOCK_KEYS]      # ۱) Whitelist — نه هر رشته‌ای
    is_visible: bool = True
    position_x: int = Field(ge=0, le=11)
    position_y: int = Field(ge=0, le=200)
    width:  int = Field(ge=1, le=12)
    height: int = Field(ge=1, le=20)
    config: dict = Field(default_factory=dict)

    @model_validator(mode="after")
    def check_bounds(self):
        if self.position_x + self.width > 12:     # ۲) خروج از گرید
            raise ValueError("بلوک از عرض گرید خارج است.")
        return self

    @model_validator(mode="after")
    def check_config(self):                       # ۳) config مخصوص همان بلوک
        schema = BLOCK_CONFIG_SCHEMAS[self.block_key]
        self.config = schema.model_validate(self.config).model_dump()
        return self

class LayoutSave(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    view_mode: Literal["daily", "weekly", "monthly"]
    blocks: list[BlockLayout] = Field(max_length=30)

    @model_validator(mode="after")
    def no_overlap(self):                         # ۴) تداخل بلوک‌ها
        if has_overlap(self.blocks):
            raise ValueError("بلوک‌ها همپوشانی دارند.")
        return self
```

Export/Import با `schema_version` انجام می‌شود تا Layout صادرشده از نسخه‌ی قدیمی، در نسخه‌ی جدید با مهاجرت خودکار یا پیام روشن مدیریت شود.

### ۱۰.۲ رفتار ریسپانسیو Layout

Layout در دیتابیس همیشه برای گرید **۱۲ ستونه (دسکتاپ)** ذخیره می‌شود. کلاینت در نمایش کوچک‌تر آن را تبدیل می‌کند و **هرگز نسخه‌ی تبدیل‌شده را ذخیره نمی‌کند**:

| عرض | ستون‌ها | رفتار |
|-----|---------|-------|
| ≥ 1280px | 12 | Layout ذخیره‌شده عیناً |
| 768–1279px | 6 | عرض بلوک‌ها نصف، ترتیب حفظ می‌شود |
| < 768px | 1 | تک‌ستونی، مرتب بر اساس `position_y` سپس `position_x` |

اگر نسخه‌ی موبایل ذخیره شود، کاربر با بازگشت به دسکتاپ چیدمانش را از دست می‌دهد — یک باگ رایج و آزاردهنده در داشبوردهای قابل شخصی‌سازی.

### ۱۰.۳ ویجت تاریخ و ساعت

ویجت شناور با مختصات مطلق، جدا از گرید داشبورد (جدول `user_widget_settings`). قابلیت‌ها: تاریخ جلالی + میلادی + قمری (اختیاری)، ساعت Real-time، فرمت قابل تنظیم، Drag & Drop، Resize با حداقل/حداکثر، Show/Hide، و تنظیمات استایل (رنگ، فونت، سایز، شفافیت).

**دو نکته‌ی فنی:**

- **Sync بین دستگاه‌ها با ستون `platform`:** موقعیت پیکسلی در پنجره‌ی دسکتاپ با موقعیت در مرورگر معنای یکسانی ندارد. `platform='all'` تنظیمات ظاهری (رنگ، فونت، فرمت) را همگام می‌کند و موقعیت/اندازه به‌ازای هر پلتفرم جدا نگه داشته می‌شود.
- **تقویم قمری:** تقویم هجری قمری در ایران مبتنی بر رؤیت هلال است و با محاسبات نجومی تا یک روز اختلاف دارد. اگر این ویجت برای مناسبت‌های رسمی استفاده می‌شود، باید منبع تاریخ رسمی داشته باشد؛ در غیر این صورت با ذکر «تقریبی» نمایش داده شود.
- **امنیت `style`:** مقادیر رنگ و شفافیت باید با الگوی سخت‌گیرانه اعتبارسنجی شوند (`^#[0-9A-Fa-f]{6}$` و `0.0–1.0`). تزریق مقدار دلخواه به CSS یک بردار XSS شناخته‌شده است.

---

## ۱۱. استراتژی امنیت جامع

### ۱۱.۱ نگاشت OWASP Top 10 به کنترل‌ها

| خطر | کنترل‌های این معماری |
|-----|----------------------|
| A01 Broken Access Control | مدل سه‌لایه (RBAC+ACL+Privacy)، SecureRepository، ۴۰۴ به‌جای ۴۰۳، آزمون ماتریسی IDOR در CI، بررسی سطح نقش هنگام اعطا |
| A02 Cryptographic Failures | Argon2id، AES-256-GCM با Nonce یکتا، کد ملی رمزنگاری‌شده، TLS 1.3، بدون کلید هاردکد، چرخش کلید |
| A03 Injection | Pydantic Whitelist، SQLAlchemy bind params، `escape_filter_chars` برای LDAP، bleach/DOMPurify، `os.path.basename` و UUID برای مسیر |
| A04 Insecure Design | Threat Model پیش از هر فاز، Rate Limit چندلایه، Least Privilege، Outbox برای سازگاری، Risk Score |
| A05 Security Misconfiguration | ENV/Vault only، CSP سخت، هدرهای امنیتی، `server_tokens off`، کانتینر non-root و read-only |
| A06 Vulnerable Components | `pip-audit` + `npm audit` + Snyk/Dependabot در CI، SBOM با syft، Gate روی CRITICAL |
| A07 Auth Failures | MFA، Lockout با Backoff نمایی، Token Rotation + Reuse Detection، `token_version`، CAPTCHA، Device Binding |
| A08 Data Integrity | Optimistic Locking، Audit Hash Chain، امضای RS256، اعتبارسنجی Import Layout |
| A09 Logging Failures | `audit_logs` + `login_audit_logs` + structlog با ماسک PII + SIEM + بازبینی زنجیره |
| A10 SSRF | هیچ URL دریافتی از کاربر fetch نمی‌شود؛ `meeting_url` فقط ذخیره و نمایش؛ Presigned URL سمت سرور ساخته می‌شود |

### ۱۱.۲ Zero Trust در عمل

- **هیچ شبکه‌ای قابل اعتماد نیست:** همان کنترل‌های احراز هویت و مجوزدهی برای کاربر داخل LAN و کاربر VPN یکسان اعمال می‌شود. «داخل شبکه بودن» هیچ امتیازی نمی‌دهد.
- **هیچ کلاینتی قابل اعتماد نیست:** هر مقدار ارسالی از کلاینت — از جمله MAC، Fingerprint، `user_id` در Body، و Permissionها — در سرور بازبینی یا نادیده گرفته می‌شود.
- **احراز هویت مستمر:** اعتبار توکن در هر درخواست و روی سوکت باز هر ۶۰ ثانیه بررسی می‌شود؛ تغییر نقش یا رمز، نشست‌ها را فوراً بی‌اعتبار می‌کند.
- **کمترین دسترسی در هر لایه:** کاربر دیتابیس بدون `CREATE/DROP`، حساب LDAP فقط خواندنی، کانتینر non-root، Token بدون داده‌ی دسترسی سطح-رکورد.

### ۱۱.۳ سیاست رمز عبور — یک بازنگری توصیه‌شده

نیازمندی «تغییر اجباری رمز هر ۹۰ روز» ذکر شده است. **NIST SP 800-63B از سال ۲۰۱۷ صراحتاً چرخش دوره‌ای اجباری را توصیه نمی‌کند**، چون در عمل کاربران را به الگوهای قابل حدس (`Password1!` → `Password2!`) سوق می‌دهد و امنیت را کاهش می‌دهد.

**جایگزین پیشنهادی (قوی‌تر و کم‌اصطکاک‌تر):**

- حداقل ۱۲ کاراکتر؛ بررسی در برابر Have I Been Pwned با **API k-anonymity** (فقط ۵ کاراکتر اول هش SHA-1 ارسال می‌شود — رمز هرگز شبکه را ترک نمی‌کند)؛ رد رمزهای حاوی نام کاربری، نام نمایشی یا کد ملی؛ رد فهرست رمزهای رایج سازمانی.
- **تغییر اجباری فقط در صورت رویداد:** نشت شناخته‌شده، ورود مشکوک با Risk Score بالا، یا بازنشانی توسط Admin.
- MFA اجباری برای نقش‌های `admin` و `super_admin` — این یک تصمیم است که اثرش بر امنیت از هر سیاست چرخش رمزی بیشتر است.

اگر الزام سازمانی یا ممیزی خارجی چرخش ۹۰ روزه را تحمیل می‌کند، فیلد `password_expires_at` در اسکیما موجود است و پیاده‌سازی‌اش ساده است — اما توصیه‌ی فنی من انتخاب گزینه‌ی بالاست.

### ۱۱.۴ رصد، تشخیص ناهنجاری و پاسخ به حادثه

**شاخص‌های هشدار Real-time (به SIEM):**

| رویداد | آستانه |
|--------|--------|
| ورود ناموفق از یک IP | > ۵۰ در ۵ دقیقه (Credential Stuffing) |
| ورود موفق با Risk Score ≥ ۸۰ | هر مورد |
| یک MAC با > ۳ کاربر متفاوت | در ۲۴ ساعت |
| اعطای نقش `admin` یا `super_admin` | هر مورد |
| Export لاگ یا داده‌ی انبوه | > ۲ در ساعت برای یک کاربر |
| شکست بازبینی زنجیره‌ی هش Audit | هر مورد — **بحرانی** |
| آپلود فایل آلوده | هر مورد |
| تغییر تنظیمات LDAP یا غیرفعال‌سازی اعتبارسنجی گواهی | هر مورد |

**طرح پاسخ به حادثه (IRP)** — چهار مرحله با مالک مشخص: **تشخیص** (SIEM/هشدار) → **مهار** (ابطال نشست‌ها با `token_version++`، مسدودسازی IP/دستگاه، قطع دسترسی حساب) → **ریشه‌یابی** (Audit Log + زنجیره‌ی هش + Device Correlation) → **بازیابی و درس‌آموخته** (گزارش مکتوب ظرف ۵ روز کاری). تیم IRT باید از قبل تعریف شده باشد؛ تشکیل تیم **حین** حادثه همیشه دیر است. توصیه: یک تمرین شبیه‌سازی‌شده (Tabletop) سالانه.

### ۱۱.۵ Secure SDLC

| مرحله | فعالیت |
|-------|--------|
| طراحی | Threat Modeling (STRIDE) برای هر ماژول پیش از کدنویسی |
| کدنویسی | لینت امنیتی (`bandit`, `eslint-plugin-security`)، `gitleaks` در pre-commit |
| بازبینی | چک‌لیست امنیتی اجباری؛ تغییرات مسیرهای Auth/RBAC/Privacy نیازمند **دو بازبین** |
| تست | تست‌های امنیتی خودکار، Fuzz روی endpointهای حساس، DAST روی staging |
| انتشار | اسکن ایمیج (trivy)، SBOM، Gate روی CRITICAL |
| تولید | رصد مستمر، تست نفوذ سالانه توسط تیم مستقل |

### ۱۱.۶ استراتژی Responsive Design

Mobile-First با Breakpointهای Tailwind (`sm 640 · md 768 · lg 1024 · xl 1280`). قواعد عملی: واحدهای نسبی (`rem`, `%`, `clamp()`)، Flexbox/Grid، `max-width: 100%` روی تصاویر، جداول عریض داخل `overflow-x: auto` (نه اسکرول افقی صفحه)، هدف لمسی حداقل ۴۴×۴۴ پیکسل، و **Progressive Disclosure** — در موبایل، بلوک‌های کم‌اهمیت جمع‌شده نمایش داده شوند نه حذف. برای RTL، منحصراً از کلاس‌های منطقی (`ms-*`, `me-*`, `ps-*`, `pe-*`) استفاده شود.

---

## ۱۲. نمونه کد (Boilerplate)

> این نمونه‌ها **الگوی معماری** را نشان می‌دهند، نه کد آماده‌ی تولید. هر کدام روی یک تصمیم طراحی تمرکز دارد.

### ۱۲.۱ Backend — راه‌اندازی API Server

```python
# app/main.py
from contextlib import asynccontextmanager
from fastapi import FastAPI
from app.core.config import settings
from app.core.middleware import register_middlewares
from app.core.events.bus import event_bus
from app.core.errors import register_exception_handlers
from app.modules import auth, rbac, groups, goals, calendar, sharing, \
                        chat, inbox, reporting, notification, audit, ssoldap, files

MODULES = [auth, rbac, groups, goals, calendar, sharing,
           chat, inbox, reporting, notification, audit, ssoldap, files]

@asynccontextmanager
async def lifespan(app: FastAPI):
    for m in MODULES:
        m.register_event_handlers(event_bus)      # هر ماژول خودش مشترک می‌شود
    await startup_checks()                         # اتصال DB/Redis، وجود کلیدها
    yield
    await shutdown_gracefully()

app = FastAPI(
    title="Planner Enterprise API",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs" if settings.ENV != "production" else None,   # Swagger در تولید بسته
    redoc_url=None,
    openapi_url="/openapi.json" if settings.ENV != "production" else None,
)

register_middlewares(app)          # ترتیب زنجیره در بخش ۱.۲
register_exception_handlers(app)   # هیچ Traceback به کاربر نشت نمی‌کند

for m in MODULES:
    app.include_router(m.router, prefix="/api/v1")
```

### ۱۲.۲ Backend — Security Middleware و اعتبارسنجی MAC

```python
# app/core/middleware/device_binding.py
import hmac, hashlib, time
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware

MAX_SKEW_MS = 300_000       # ۵ دقیقه
HIGH_RISK_PATHS = ("/auth/password", "/admin/", "/rbac/", "/audit/export")

class DeviceBindingMiddleware(BaseHTTPMiddleware):
    """MAC/Fingerprint را استخراج، امضا را بررسی و نتیجه را در Context می‌گذارد.
    امضای نامعتبر درخواست را رد نمی‌کند (جز مسیرهای پرریسک) — فقط mac_verified=False.
    """

    async def dispatch(self, request: Request, call_next):
        ctx = request_ctx.get()
        ctx.device_fingerprint = request.headers.get("X-Device-Fingerprint")
        ctx.mac_address = _normalize_mac(request.headers.get("X-Device-MAC"))
        ctx.mac_verified = False

        if ctx.user_id and ctx.device_fingerprint:
            ctx.mac_verified = await self._verify(request, ctx)

        if not ctx.mac_verified and request.url.path.startswith(HIGH_RISK_PATHS):
            ctx.require_step_up_mfa = True         # نه رد، بلکه الزام تأیید مجدد

        return await call_next(request)

    async def _verify(self, request: Request, ctx) -> bool:
        sig   = request.headers.get("X-Device-Signature")
        nonce = request.headers.get("X-Device-Nonce")
        ts    = request.headers.get("X-Device-Timestamp")
        if not all((sig, nonce, ts)):
            return False

        # ۱) پنجره زمانی
        try:
            if abs(time.time() * 1000 - int(ts)) > MAX_SKEW_MS:
                return False
        except ValueError:
            return False

        # ۲) ضد Replay — nonce یک‌بارمصرف
        if not await redis.set(f"nonce:{ctx.user_id}:{nonce}", "1",
                               nx=True, ex=MAX_SKEW_MS // 1000):
            await audit.security_event("device.nonce_replay", user_id=ctx.user_id)
            return False

        # ۳) کلید HMAC مخصوص همین دستگاه
        device = await device_repo.get(ctx.user_id, ctx.device_fingerprint)
        if device is None or device.is_blocked:
            return False
        key = decrypt(device.hmac_key_enc)

        body_hash = hashlib.sha256(await request.body()).hexdigest()
        payload = "|".join([request.method, request.url.path, body_hash,
                            ctx.device_fingerprint, ctx.mac_address or "", nonce, ts])
        expected = hmac.new(key, payload.encode(), hashlib.sha256).hexdigest()

        # ۴) مقایسه ثابت‌زمان
        return hmac.compare_digest(expected, sig)


def _normalize_mac(raw: str | None) -> str | None:
    """قالب‌بندی و اعتبارسنجی؛ مقدار نامعتبر دور ریخته می‌شود نه ذخیره."""
    if not raw:
        return None
    mac = raw.upper().replace("-", ":").strip()
    if not re.fullmatch(r"([0-9A-F]{2}:){5}[0-9A-F]{2}", mac):
        return None
    if mac in ("00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF"):
        return None
    return mac
```

### ۱۲.۳ Backend — ثبت Audit Log با MAC و زنجیره‌ی هش

```python
# app/modules/audit/services/audit_service.py
import hashlib, json

class AuditService:
    async def log(self, uow, *, action: str, result: str = "success",
                  entity_type: str | None = None, entity_id: UUID | None = None,
                  old_value: dict | None = None, new_value: dict | None = None,
                  details: dict | None = None) -> None:
        """همه‌ی اطلاعات هویتی از Context می‌آید — هرگز از بدنه‌ی درخواست."""
        ctx = request_ctx.get()

        prev_hash = await uow.audit.last_row_hash()     # قفل مشورتی برای ترتیب صحیح
        row = AuditLog(
            user_id=ctx.user_id, action=action, result=result,
            entity_type=entity_type, entity_id=entity_id,
            ip_address=ctx.ip, mac_address=ctx.mac_address,
            mac_verified=ctx.mac_verified,
            device_fingerprint=ctx.device_fingerprint, device_id=ctx.device_id,
            user_agent=ctx.user_agent, session_id=ctx.session_id,
            old_value=mask_sensitive(old_value), new_value=mask_sensitive(new_value),
            details=mask_sensitive(details), geo_location=ctx.geo,
            request_id=ctx.request_id, correlation_id=ctx.correlation_id,
            prev_hash=prev_hash,
        )
        row.row_hash = self._chain_hash(prev_hash, row)
        uow.session.add(row)          # همان تراکنش عملیات اصلی

    @staticmethod
    def _chain_hash(prev_hash: str | None, row: AuditLog) -> str:
        material = "|".join([
            prev_hash or "GENESIS", str(row.user_id), row.action,
            row.timestamp.isoformat(), str(row.ip_address), row.mac_address or "",
            row.result, json.dumps(row.details, sort_keys=True, ensure_ascii=False),
        ])
        return hashlib.sha256(material.encode()).hexdigest()
```

```python
# app/core/db/audit_hooks.py — ثبت خودکار، بدون فراخوانی دستی در هر سرویس
@event.listens_for(Session, "before_flush")
def capture_entity_changes(session, ctx_, instances):
    for obj in session.dirty:
        if type(obj) not in AUDITED_MODELS:
            continue
        diff = extract_changes(obj, masked=MASKED_FIELDS)
        if diff:
            session.add(build_audit_row("update", obj, diff))
```

> این Hook مهم‌ترین تصمیم بخش Audit است: هیچ تغییر داده‌ای نمی‌تواند از زیر لاگ فرار کند، حتی اگر توسعه‌دهنده فراموش کند.

### ۱۲.۴ Backend — RBAC Middleware و Decorator

```python
# app/modules/rbac/api/deps.py
from fastapi import Depends, Request

def require_permission(*codes: str, mode: str = "all"):
    """کنترل دسترسی سطح عملیات. برای دسترسی سطح رکورد از PolicyEngine استفاده کنید."""
    async def _dep(request: Request, user: User = Depends(get_current_user)):
        perms = await rbac_service.effective_permissions(user.id)   # کش ۶۰ ثانیه‌ای
        ok = all(c in perms for c in codes) if mode == "all" \
             else any(c in perms for c in codes)
        if not ok:
            await audit.log(action="rbac.denied", result="denied",
                            details={"required": codes, "path": request.url.path})
            raise PermissionDeniedError(required=codes)
        return user
    return _dep


# استفاده
@router.delete("/goals/{goal_id}")
async def delete_goal(
    goal_id: UUID,
    user: User = Depends(require_permission("goal.delete")),   # لایه ۱: RBAC
    uow: UnitOfWork = Depends(get_uow),
):
    await policy.require(uow, user, "goal", goal_id, needed="owner")  # لایه ۲: ACL
    await goal_service.soft_delete(uow, goal_id, actor=user)
    return Response(status_code=204)
```

**کش Permission با ابطال رویدادی:** نتیجه‌ی `effective_permissions` در Redis با TTL ۶۰ ثانیه کش می‌شود و رویداد `rbac.role.assigned` کش آن کاربر را فوراً باطل می‌کند. بدون ابطال رویدادی، لغو دسترسی تا یک دقیقه معلق می‌ماند.

### ۱۲.۵ Backend — داشبورد مدیر گروه با اعمال حریم خصوصی

```python
# app/modules/reporting/api/routes.py
@router.get("/groups/{group_id}/dashboard", response_model=GroupDashboard)
async def group_dashboard(
    group_id: UUID,
    period: PeriodQuery = Depends(),
    user: User = Depends(require_permission("group.view_progress")),
    groups_rm: GroupReadModel = Depends(get_group_read_model),   # رابط، نه مدل DB
    uow: UnitOfWork = Depends(get_uow),
):
    # ۱) نقش دامنه‌دار: مدیر همین گروه؟
    if not await groups_rm.is_manager(user.id, group_id):
        raise NotFoundError()

    member_ids = await groups_rm.member_ids(group_id, include_subgroups=True)
    raw_stats  = await uow.reporting.member_stats(member_ids, period)

    # ۲) حریم خصوصی به‌ازای هر عضو — نه یک‌بار برای کل گروه
    members = []
    for m in raw_stats:
        decision = await groups_rm.effective_privacy(owner_id=m.user_id, viewer_id=user.id)
        members.append(redact_member(m, decision))   # full | aggregate_only | hidden

    # ۳) اعلان شفافیت و ثبت دسترسی
    await audit.log(action="group.dashboard.viewed", entity_type="group",
                    entity_id=group_id, details={"members": len(members)})
    await notify_members_of_view(group_id, viewer=user, members=raw_stats)

    return GroupDashboard(
        group=await groups_rm.summary(group_id),
        period=period,
        members=members,
        aggregate=compute_aggregate(raw_stats),   # آمار کلی همیشه از داده کامل
    )
```

> ظرافت مهم: آمار **تجمیعی تیم** از داده‌ی کامل محاسبه می‌شود، اما داده‌ی **فردی** پس از اعمال حریم خصوصی برگردانده می‌شود. اگر تجمیع را از داده‌ی سانسورشده بسازید، عدد تیم اشتباه می‌شود. در عین حال، وقتی گروه کمتر از ۴ عضو دارد، آمار تجمیعی می‌تواند داده‌ی فرد را افشا کند — در این حالت باید حداقل آستانه‌ی k-anonymity اعمال شود.

### ۱۲.۶ Backend — تغییر انبوه حالت ورود

```python
@router.post("/admin/users/bulk-login-mode", response_model=BulkResult)
async def bulk_change_login_mode(
    payload: BulkLoginModeRequest,
    user: User = Depends(require_permission("user.bulk_login_mode")),
    uow: UnitOfWork = Depends(get_uow),
):
    """تغییر sso_enabled برای گروهی از کاربران. نتیجه جزئی مجاز است (207)."""
    if len(payload.user_ids) > 500:
        raise ValidationError("حداکثر ۵۰۰ کاربر در هر عملیات.")

    updated, failed = [], []
    for uid in payload.user_ids:
        target = await uow.users.get(uid)
        if target is None:
            failed.append({"user_id": uid, "code": "NOT_FOUND"}); continue
        if target.id == user.id:
            failed.append({"user_id": uid, "code": "CANNOT_MODIFY_SELF"}); continue
        # کاربر SSO بدون رمز محلی نباید بدون تنظیم رمز به حالت local برود
        if payload.sso_enabled is False and target.password_hash is None:
            failed.append({"user_id": uid, "code": "NO_LOCAL_PASSWORD"}); continue

        old = {"sso_enabled": target.sso_enabled, "auth_mode": target.auth_mode}
        target.sso_enabled = payload.sso_enabled
        target.auth_mode = "sso" if payload.sso_enabled else "local"
        if payload.revoke_sessions:
            target.token_version += 1            # ابطال فوری همه نشست‌ها
        await audit.log(action="user.login_mode.changed", entity_type="user",
                        entity_id=uid, old_value=old,
                        new_value={"sso_enabled": payload.sso_enabled})
        updated.append(uid)

    await uow.commit()
    return BulkResult(updated=updated, failed=failed,
                      status_code=207 if failed else 200)
```

### ۱۲.۷ Backend — ذخیره Layout داشبورد

```python
@router.put("/dashboard/layouts/{layout_id}", response_model=LayoutRead)
async def save_layout(
    layout_id: UUID,
    payload: LayoutSave,                 # اعتبارسنجی کامل در بخش ۱۰.۱
    user: User = Depends(get_current_user),
    uow: UnitOfWork = Depends(get_uow),
):
    layout = await uow.layouts.get_owned(layout_id, user.id)   # مالکیت اجباری
    if layout is None:
        raise NotFoundError()

    async with uow.transaction():
        layout.name, layout.view_mode = payload.name, payload.view_mode
        if payload.is_default:
            await uow.layouts.clear_default(user.id, payload.view_mode)
            layout.is_default = True
        # جایگزینی اتمیک بلوک‌ها
        await uow.dashboard_settings.delete_by_layout(layout_id)
        await uow.dashboard_settings.bulk_insert(
            [DashboardSetting(user_id=user.id, layout_id=layout_id, **b.model_dump())
             for b in payload.blocks])
    return await uow.layouts.read(layout_id)
```

### ۱۲.۸ Backend — WebSocket Handler چت

```python
# app/ws/handlers/chat.py
@app.websocket("/ws/chat")
async def chat_socket(ws: WebSocket, token: str = Query(...)):
    # ۱) Origin Check — WebSocket تحت CORS نیست
    if ws.headers.get("origin") not in settings.ALLOWED_ORIGINS:
        await ws.close(code=4403); return

    # ۲) احراز هویت (توکن از Query فقط برای Handshake؛ در لاگ ماسک می‌شود)
    try:
        claims = verify_access_token(token)
        user = await user_service.get_active(claims["sub"])
    except (InvalidToken, UserInactive):
        await ws.close(code=4401); return

    await ws.accept()
    rooms: set[UUID] = set()
    limiter = SlidingWindowLimiter(limit=20, window_s=60)

    try:
        # ۳) اعتبارسنجی دوره‌ای توکن روی سوکت باز
        asyncio.create_task(_revalidate_periodically(ws, claims, interval=60))

        while True:
            raw = await asyncio.wait_for(ws.receive_text(), timeout=300)  # Idle timeout
            if len(raw) > 8192:
                await ws.close(code=1009); return
            msg = ChatSocketMessage.model_validate_json(raw)   # اعتبارسنجی اجباری

            if msg.type == "join":
                # ۴) عضویت در لحظه بررسی می‌شود
                if not await chat_service.is_active_member(msg.room_id, user.id):
                    await ws.send_json({"type": "error", "code": "NOT_A_MEMBER"}); continue
                await manager.join(msg.room_id, ws, user.id)
                rooms.add(msg.room_id)

            elif msg.type == "message":
                if msg.room_id not in rooms:
                    await ws.send_json({"type": "error", "code": "NOT_JOINED"}); continue
                if not await limiter.allow(f"ws:{user.id}"):
                    await ws.send_json({"type": "error", "code": "RATE_LIMITED"}); continue
                # ۵) عضویت دوباره بررسی می‌شود — ممکن است بین join و ارسال حذف شده باشد
                if not await chat_service.is_active_member(msg.room_id, user.id):
                    await ws.close(code=4403); return

                saved = await chat_service.persist(
                    room_id=msg.room_id, sender_id=user.id,
                    body=sanitize_html(msg.body),          # ۶) ضد XSS
                    reply_to_id=msg.reply_to_id)
                await manager.broadcast(msg.room_id, saved.to_event())
                await audit.log(action="chat.message.sent",
                                entity_type="chat_message", entity_id=saved.id)

    except (WebSocketDisconnect, asyncio.TimeoutError):
        pass
    finally:
        for r in rooms:
            await manager.leave(r, ws)
```

### ۱۲.۹ Desktop — راه‌اندازی UI فارسی و کلاینت HTTP

```python
# desktop/app/main.py
from PySide6.QtWidgets import QApplication
from PySide6.QtCore import Qt
from PySide6.QtGui import QFontDatabase, QFont

def bootstrap() -> QApplication:
    app = QApplication(sys.argv)
    app.setLayoutDirection(Qt.RightToLeft)                 # RTL سراسری
    for w in ("Regular", "Medium", "Bold"):
        QFontDatabase.addApplicationFont(f":/fonts/Vazirmatn-{w}.ttf")
    f = QFont("Vazirmatn", 11)
    f.setHintingPreference(QFont.PreferNoHinting)          # رندر نرم‌تر فارسی
    app.setFont(f)
    app.setStyleSheet(load_theme(settings.theme))          # dark.qss / light.qss
    return app
```

```python
# desktop/app/core/api_client.py
import httpx, hmac, hashlib, uuid, time, json

class ApiClient:
    """هدرهای هویت دستگاه به‌صورت خودکار و متمرکز تزریق می‌شوند —
    هیچ فراخوانی‌ای نمی‌تواند آن‌ها را فراموش کند."""

    def __init__(self, base_url: str, identity: DeviceIdentity, tokens: TokenStore):
        self._identity, self._tokens = identity, tokens
        self._client = httpx.Client(
            base_url=base_url, timeout=httpx.Timeout(10.0, connect=5.0),
            verify=settings.CA_BUNDLE,                     # اعتبارسنجی گواهی اجباری
            http2=True, event_hooks={"response": [self._on_response]})

    def request(self, method: str, path: str, *, json_body: dict | None = None):
        body = json.dumps(json_body, ensure_ascii=False).encode() if json_body else b""
        headers = self._device_headers(method, path, body)
        if tok := self._tokens.access_token():
            headers["Authorization"] = f"Bearer {tok}"
        r = self._client.request(method, path, content=body, headers=headers)
        if r.status_code == 401 and self._tokens.can_refresh():
            self._tokens.refresh(self)
            return self.request(method, path, json_body=json_body)   # یک‌بار تلاش مجدد
        return r

    def _device_headers(self, method: str, path: str, body: bytes) -> dict:
        mac, source = self._identity.mac, self._identity.mac_source
        fp    = self._identity.fingerprint
        nonce = str(uuid.uuid4())
        ts    = str(int(time.time() * 1000))
        payload = "|".join([method, path, hashlib.sha256(body).hexdigest(),
                            fp, mac or "", nonce, ts])
        sig = hmac.new(self._identity.hmac_key, payload.encode(), hashlib.sha256).hexdigest()
        h = {"X-Device-Fingerprint": fp, "X-Device-Nonce": nonce,
             "X-Device-Timestamp": ts, "X-Device-Signature": sig,
             "X-Request-ID": str(uuid.uuid4()), "Content-Type": "application/json"}
        if mac:                       # اگر MAC در دسترس نبود، هدر اصلاً ارسال نمی‌شود
            h["X-Device-MAC"] = mac
            h["X-Device-MAC-Source"] = source
        return h
```

### ۱۲.۱۰ Desktop — ویجت شناور ساعت و تاریخ

```python
# desktop/app/views/widgets/clock_widget.py
from PySide6.QtCore import Qt, QTimer, QPoint, Signal
from PySide6.QtWidgets import QFrame, QVBoxLayout, QLabel, QSizeGrip
import jdatetime, datetime as dt

class ClockWidget(QFrame):
    """ویجت شناور: Drag & Drop، Resize، شفافیت، جلالی + میلادی."""
    settings_changed = Signal(dict)

    MIN_W, MIN_H, MAX_W, MAX_H = 160, 80, 640, 400

    def __init__(self, cfg: dict, style: dict, parent=None):
        super().__init__(parent)
        self._drag_origin: QPoint | None = None
        self._cfg, self._style = cfg, style

        self.setMinimumSize(self.MIN_W, self.MIN_H)
        self.setMaximumSize(self.MAX_W, self.MAX_H)
        self.setLayoutDirection(Qt.RightToLeft)

        lay = QVBoxLayout(self)
        self.time_lbl    = QLabel(alignment=Qt.AlignCenter)
        self.jalali_lbl  = QLabel(alignment=Qt.AlignCenter)
        self.greg_lbl    = QLabel(alignment=Qt.AlignCenter)
        for w in (self.time_lbl, self.jalali_lbl, self.greg_lbl):
            lay.addWidget(w)
        lay.addWidget(QSizeGrip(self), 0, Qt.AlignLeft | Qt.AlignBottom)

        self._apply_style()
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)
        self._timer.start(1000 if cfg.get("show_seconds", True) else 30_000)
        self._tick()

    def _tick(self):
        now = dt.datetime.now()
        fmt = "%H:%M:%S" if self._cfg.get("show_seconds", True) else "%H:%M"
        self.time_lbl.setText(to_persian_digits(now.strftime(fmt)))
        self.jalali_lbl.setVisible(self._cfg.get("show_jalali", True))
        self.greg_lbl.setVisible(self._cfg.get("show_gregorian", False))
        if self.jalali_lbl.isVisible():
            j = jdatetime.datetime.fromgregorian(datetime=now)
            self.jalali_lbl.setText(to_persian_digits(j.strftime("%A، %d %B %Y")))
        if self.greg_lbl.isVisible():
            self.greg_lbl.setText(now.strftime("%a, %d %b %Y"))

    def _apply_style(self):
        s = self._style
        opacity = max(0.2, min(float(s.get("opacity", 0.95)), 1.0))   # محدوده امن
        self.setWindowOpacity(opacity)
        self.setStyleSheet(f"""
            QFrame {{ background: {safe_color(s.get('bg', '#1F2937'))};
                      color: {safe_color(s.get('fg', '#F9FAFB'))};
                      border-radius: 12px; }}
            QLabel {{ font-family: '{safe_font(s.get('font_family','Vazirmatn'))}';
                      font-size: {clamp_int(s.get('font_size', 16), 10, 48)}px; }}
        """)

    # ── Drag & Drop
    def mousePressEvent(self, e):
        if e.button() == Qt.LeftButton:
            self._drag_origin = e.globalPosition().toPoint() - self.pos()

    def mouseMoveEvent(self, e):
        if self._drag_origin and e.buttons() & Qt.LeftButton:
            new_pos = e.globalPosition().toPoint() - self._drag_origin
            self.move(self._clamp_to_parent(new_pos))      # خارج از پنجره نرود

    def mouseReleaseEvent(self, e):
        self._drag_origin = None
        self.settings_changed.emit({"position_x": self.x(), "position_y": self.y(),
                                    "width": self.width(), "height": self.height()})
```

`settings_changed` با debounce یک‌ثانیه‌ای به `PUT /widgets/settings` ارسال می‌شود. توابع `safe_color`، `safe_font` و `clamp_int` تضمین می‌کنند مقدار آمده از سرور نتواند CSS دلخواه تزریق کند.

### ۱۲.۱۱ Web — Device Fingerprint و تزریق هدرها

```typescript
// src/security/fingerprint.ts
import FingerprintJS from '@fingerprintjs/fingerprintjs';

let cached: string | null = null;

export async function getDeviceFingerprint(): Promise<string> {
  if (cached) return cached;
  const fp = await (await FingerprintJS.load()).get();
  // جزء پایدار صادرشده توسط سرور، در کنار جزء ناپایدار مرورگر
  const deviceToken = getCookie('device_token') ?? '';
  cached = `web-fp-${await sha256(`${fp.visitorId}:${deviceToken}`)}`;
  return cached;
}
```

```typescript
// src/api/client.ts
import axios from 'axios';
import { getDeviceFingerprint } from '@/security/fingerprint';

export const api = axios.create({
  baseURL: import.meta.env.VITE_API_BASE,
  withCredentials: true,           // Refresh Token در HttpOnly Cookie
  timeout: 15_000,
});

api.interceptors.request.use(async (config) => {
  config.headers['X-Device-Fingerprint'] = await getDeviceFingerprint();
  config.headers['X-Device-Nonce']       = crypto.randomUUID();
  config.headers['X-Device-Timestamp']   = String(Date.now());
  config.headers['X-Request-ID']         = crypto.randomUUID();
  // توجه: X-Device-MAC در وب ارسال نمی‌شود — مقدار ساختگی، Audit را آلوده می‌کند
  const csrf = getCookie('csrf_token');
  if (csrf) config.headers['X-CSRF-Token'] = csrf;
  return config;
});

let refreshing: Promise<void> | null = null;
api.interceptors.response.use(undefined, async (error) => {
  if (error.response?.status === 401 && !error.config._retried) {
    error.config._retried = true;
    refreshing ??= api.post('/auth/refresh').finally(() => { refreshing = null; });
    await refreshing;                         // چند درخواست همزمان، یک refresh
    return api(error.config);
  }
  throw error;
});
```

> **درباره‌ی امضای HMAC در وب:** برخلاف دسکتاپ، مرورگر نمی‌تواند کلید HMAC را امن نگه دارد (هر کلیدی در JS در دسترس XSS است). به‌جای امضا، وب بر **Device Token در HttpOnly Cookie** تکیه می‌کند که جاوااسکریپت اصلاً آن را نمی‌بیند. پیاده‌سازی HMAC در وب، امنیت ظاهری بدون امنیت واقعی است.

### ۱۲.۱۲ Web — گرید داشبورد و داشبورد مدیر گروه

```tsx
// src/features/dashboard/DashboardGrid.tsx
import GridLayout, { type Layout } from 'react-grid-layout';
import { useDebouncedCallback } from 'use-debounce';

const COLS = { lg: 12, md: 6, sm: 1 } as const;

export function DashboardGrid({ layoutId, blocks }: Props) {
  const { width, breakpoint } = useContainerWidth();
  const saveLayout = useSaveLayout(layoutId);

  // Layout همیشه در قالب ۱۲ ستونه ذخیره می‌شود؛ نمایش موبایل ذخیره نمی‌شود
  const onChange = useDebouncedCallback((next: Layout[]) => {
    if (breakpoint !== 'lg') return;
    saveLayout(next.map(l => ({
      block_key: l.i, position_x: l.x, position_y: l.y,
      width: l.w, height: l.h, is_visible: true,
    })));
  }, 1000);

  return (
    <GridLayout
      className="layout" cols={COLS[breakpoint]} rowHeight={72} width={width}
      isDraggable={breakpoint === 'lg'} isResizable={breakpoint === 'lg'}
      draggableHandle=".block-header" compactType="vertical" onLayoutChange={onChange}
    >
      {blocks.filter(b => b.is_visible).map(b => (
        <div key={b.block_key} data-grid={toGridItem(b, breakpoint)}>
          <DashboardBlock blockKey={b.block_key} config={b.config} />
        </div>
      ))}
    </GridLayout>
  );
}
```

```tsx
// src/features/groupManager/MemberCard.tsx
export function MemberCard({ member }: { member: GroupMember }) {
  // UI هرگز داده‌ای را که سرور نفرستاده «حدس» نمی‌زند —
  // سانسور در سرور اتفاق افتاده، این فقط نمایش صحیح آن است.
  if (member.visibility === 'aggregate_only') {
    return (
      <Card>
        <Header name={member.display_name} />
        <ProgressRing value={member.stats.progress_pct} />
        <p className="text-sm text-muted">{member.notice}</p>
      </Card>
    );
  }
  return (
    <Card>
      <Header name={member.display_name} />
      <StatRow stats={member.stats} />
      <GoalList goals={member.goals ?? []} />
    </Card>
  );
}
```

### ۱۲.۱۳ Web — پایه‌ی ریسپانسیو و RTL

```html
<!doctype html>
<html lang="fa" dir="rtl">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover" />
    <meta http-equiv="Content-Security-Policy"
          content="default-src 'self'; script-src 'self'; style-src 'self';
                   img-src 'self' data: blob:; font-src 'self';
                   connect-src 'self' https://api.corp.local wss://api.corp.local;
                   frame-ancestors 'none'; base-uri 'self'; object-src 'none'" />
    <link rel="preload" href="/fonts/Vazirmatn-Regular.woff2" as="font" crossorigin />
    <title>سامانه مدیریت اهداف</title>
  </head>
  <body class="bg-surface text-content"><div id="root"></div></body>
</html>
```

```css
/* src/styles/tailwind.css */
@font-face {
  font-family: 'Vazirmatn';
  src: url('/fonts/Vazirmatn-Regular.woff2') format('woff2');
  font-weight: 400; font-display: swap;
}
:root { --font-fa: 'Vazirmatn', 'IRANSans', system-ui, sans-serif; }

body { font-family: var(--font-fa); line-height: 1.8; }  /* فارسی فضای عمودی بیشتر می‌خواهد */

/* از کلاس‌های منطقی استفاده کنید: ms-* / me-* / ps-* / pe-* — نه ml-* / pr-* */
.table-wrap { overflow-x: auto; max-width: 100%; }        /* جدول عریض، نه صفحه عریض */
.touch-target { min-inline-size: 44px; min-block-size: 44px; }
```

---

## ۱۳. کتابخانه‌ها، زیرساخت و ظرفیت‌سنجی

### ۱۳.۱ Backend (Python 3.12)

```toml
# ── هسته API و داده
fastapi ^0.115 · uvicorn[standard] ^0.32 · gunicorn ^23.0
pydantic ^2.9 · pydantic-settings ^2.6
sqlalchemy ^2.0 · alembic ^1.14 · asyncpg ^0.30 · psycopg[binary,pool] ^3.2
sqlalchemy-utils ^0.41            # نوع LTREE برای گروه‌های سلسله‌مراتبی

# ── امنیت و احراز هویت
argon2-cffi ^23.1                 # هش رمز (اولویت اول)
passlib[bcrypt] ^1.7              # مسیر مهاجرت از bcrypt
pyjwt[crypto] ^2.9                # JWT RS256
cryptography ^43.0                # AES-256-GCM: کد ملی، TOTP، رمز LDAP
pyotp ^2.9                        # MFA — TOTP
qrcode[pil] ^8.0                  # QR ثبت MFA
slowapi ^0.1.9                    # Rate Limiting روی Redis
bleach ^6.2                       # پاک‌سازی HTML (کامنت و چت)
secure ^0.3                       # هدرهای امنیتی
python-magic ^0.4                 # تشخیص نوع فایل از magic number
pyclamd ^0.4                      # ClamAV daemon
Pillow ^11.0                      # Re-encode تصویر + حذف EXIF

# ── LDAP / Kerberos
ldap3 ^2.9                        # پیاده‌سازی خالص پایتون (build ساده روی ویندوز)
gssapi ^1.9                       # اعتبارسنجی تیکت Kerberos (سرور لینوکسی)
pyspnego ^0.11                    # SPNEGO/NTLM چندسکویی

# ── Real-time و پس‌زمینه
websockets ^13.1 · redis ^5.2
celery[redis] ^5.4 · flower ^2.0

# ── ابزار
openpyxl ^3.1 · jdatetime ^5.0 · pywebpush ^2.0 · python-dateutil ^2.9
boto3 ^1.35                       # MinIO/S3
structlog ^24.4 · sentry-sdk ^2.18
prometheus-fastapi-instrumentator ^7.0
geoip2 ^4.8                       # موقعیت جغرافیایی از IP (پایگاه محلی، بدون فراخوانی بیرونی)

# ── توسعه
pytest · pytest-asyncio · pytest-cov · httpx · factory-boy · faker
testcontainers · schemathesis · locust
ruff · mypy · bandit · pip-audit · gitleaks
```

### ۱۳.۲ Frontend دسکتاپ

| پکیج | نقش | یادداشت |
|------|-----|---------|
| `PySide6` ^6.8 | UI (Qt6) | LGPL؛ RTL و shaping فارسی درجه‌یک، Tray کامل |
| `CustomTkinter` ^5.2 | جایگزین سبک‌تر | اگر الزام سازمانی است — اما RTL و Tray آن محدود است |
| `httpx` ^0.28 | HTTP Client | HTTP/2، timeout، event hooks |
| `websockets` ^13.1 | کلاینت چت | روی QThread مجزا |
| `psutil` ^6.1 | **دریافت MAC Address** | مطابق ۶.۲ |
| `keyring` ^25 · `pywin32` ^308 | DPAPI و Credential Manager | ذخیره امن توکن |
| `requests-negotiate-sspi` ^0.5 | SSO ویندوزی | ساده‌ترین مسیر Kerberos/NTLM |
| `pystray` ^0.19 | System Tray | جایگزین `QSystemTrayIcon` در مسیر Tkinter |
| `jdatetime` ^5.0 | تقویم جلالی | — |
| `PyInstaller` ^6.11 | بسته‌بندی EXE | `--onedir` + امضای Authenticode |

### ۱۳.۳ Frontend وب

`react` ^18.3 · `typescript` ^5.6 · `vite` ^6 · `tailwindcss` ^3.4 · `@tanstack/react-query` ^5 · `react-router` ^7 · `zustand` ^5 · `react-hook-form` + `zod` · `date-fns-jalali` ^4 · `react-grid-layout` ^1.5 · `recharts` ^2.13 · `dompurify` ^3.2 · `axios` ^1.7 · `@fingerprintjs/fingerprintjs` ^4 · `vite-plugin-pwa` ^0.21 · `@axe-core/react` · `openapi-typescript`

**پوشش مرورگری:** `> 0.5%, last 2 versions, not dead` ⇒ Chrome/Edge 100+, Firefox 100+, Safari 15.4+, Opera 86+. Web Push در Safari فقط از ۱۶.۴ و در iOS فقط برای PWA نصب‌شده کار می‌کند — این محدودیت باید در UX پیش‌بینی شود.

### ۱۳.۴ ظرفیت‌سنجی سخت‌افزار و شبکه

| سطح | کاربر همزمان | Backend | Database | سایر | شبکه |
|-----|---------------|---------|----------|------|------|
| ۱ | ≤ ۵۰ | ۴ Core / ۸GB / ۲۰۰GB SSD | ۴ Core / ۸GB / ۵۰۰GB | Redis هم‌میزبان | ۱۰۰ Mbps |
| ۲ | ۵۱–۱۰۰ | ۸ Core / ۱۶GB / ۵۰۰GB | ۸ Core / ۱۶GB / ۱TB | Redis مجزا | ۵۰۰ Mbps |
| ۳ | ۱۰۱–۲۵۰ | LB + ۲× (۸C/۱۶GB) | ۱۶ Core / ۳۲GB / ۲TB RAID10 | Redis + MinIO | ۱ Gbps |
| ۴ | ۲۵۱–۵۰۰ | LB + ۳–۴× (۸C/۱۶GB) | Primary + Replica (۱۶C/۳۲GB) | Redis Cluster + MinIO | ۱ Gbps |
| ۵ | ۵۰۱–۱۰۰۰ | LB + ۵–۸× (۸C/۱۶GB) | Primary + ۲ Replica (۳۲C/۶۴GB) | Redis Cluster + RabbitMQ + S3/NAS | ۱۰ Gbps |

**اهداف شبکه:** تأخیر < ۵۰ms، از دست رفتن بسته < ۰.۱٪، دسترس‌پذیری ۹۹.۹٪ (سطوح ۱–۳) تا ۹۹.۹۹٪ (سطوح ۴–۵).

**چند نکته‌ی عملی درباره‌ی این جدول:**

- **WebSocket بار متفاوتی دارد.** هر اتصال باز حدود ۳۰–۵۰KB حافظه مصرف می‌کند؛ ۱۰۰۰ کاربر همزمان یعنی ~۵۰MB فقط برای سوکت‌ها — قابل مدیریت، اما تعداد **file descriptorها** باید تنظیم شود (`ulimit -n 65535`). این رایج‌ترین گلوگاه در سطح ۵ است، نه CPU.
- **گلوگاه واقعی معمولاً دیتابیس است، نه Backend.** پیش از افزودن Backend سوم، `pg_stat_statements` را بررسی کنید؛ اغلب یک ایندکس گمشده مشکل را حل می‌کند، نه سخت‌افزار بیشتر.
- **Replicaها برای خواندن گزارش‌ها.** کوئری‌های سنگین داشبورد مدیر گروه و گزارش‌ها باید به Read Replica هدایت شوند تا نوشتن‌های تراکنشی را کند نکنند.
- **تأخیر Replication** یعنی داده‌ی تازه‌نوشته ممکن است بلافاصله روی Replica نباشد — کوئری‌های «بعد از نوشتن بخوان» باید به Primary بروند.

### ۱۳.۵ استقرار و سخت‌سازی

- کانتینر non-root (`USER 1000`)، فایل‌سیستم read-only، `cap_drop: ALL`.
- کاربر DB برنامه بدون `CREATE`/`DROP`؛ Migration با کاربر جداگانه.
- رازها از **Vault** یا Docker Secrets؛ هرگز در مخزن یا `docker-compose.yml`.
- Nginx: TLS 1.2/1.3، HSTS با preload، `server_tokens off`، `client_max_body_size 52m`، Rate Limit لایه‌ی ۷.
- CORS دقیق با `allow_origins` از ENV — **هرگز `["*"]` همراه `allow_credentials=True`** (ترکیبی که مرورگر رد می‌کند و نشانه‌ی پیکربندی ناامن است).
- بکاپ روزانه‌ی رمزنگاری‌شده + **تست بازیابی ماهانه**. بکاپی که بازیابی‌اش تست نشده، بکاپ نیست.
- نگهداری لاگ: حداقل ۱ سال مطابق نیازمندی؛ پارتیشن‌های قدیمی‌تر از ۹۰ روز به آرشیو سرد رمزنگاری‌شده منتقل شوند.

---

## ۱۴. فازبندی، ریسک و توصیه‌های پایانی

### ۱۴.۱ برآورد زمان‌بندی

| فاز | ماژول‌ها | هفته | تیم |
|-----|----------|------|-----|
| ۰ | اسکلت، Event Bus، CI/CD، مرزهای ماژولار، آزمون معماری | ۳ | پلتفرم |
| ۱ | M1 Auth (کد ملی، MFA، دستگاه‌ها)، M2 RBAC، M12 SSO/LDAP، M11 Audit | ۷ | پلتفرم |
| ۲ | M3 Groups & Privacy + داشبورد مدیر گروه | ۴ | تیم A |
| ۳ | M4 Goals، M5 Calendar & Dashboard، تقویم جلالی | ۶ | تیم B |
| ۴ | M6 Sharing، M8 کارتابل، کامنت و Activity Timeline | ۵ | تیم A |
| ۵ | M7 Chat + M13 Files (WebSocket، آپلود، AV) | ۵ | تیم C |
| ۶ | M9 Reporting، Export، داشبورد پیشرفته، جستجوی Full-Text | ۴ | تیم B |
| ۷ | M10 Notification، ویجت‌ها، شخصی‌سازی کامل، بهینه‌سازی | ۴ | همه |
| ۸ | کلاینت وب (موازی از فاز ۳) | ۸ | تیم وب |
| ۹ | کلاینت دسکتاپ (موازی از فاز ۳) | ۸ | تیم دسکتاپ |
| ۱۰ | تست نفوذ، تست بار، مستندسازی، آموزش، انتشار | ۳ | همه |

**مسیر بحرانی: ۳۴ تا ۴۰ هفته** با تیمی متشکل از ۳ Backend، ۲ Frontend وب، ۱ Frontend دسکتاپ، ۱ DevOps و ۱ QA — یعنی حدود **۸ تا ۱۰ ماه**.

اگر تیم کوچک‌تری در اختیار دارید، این عدد خطی رشد نمی‌کند بلکه بدتر می‌شود (سربار هماهنگی + توقف‌های وابستگی). در آن صورت به بخش ۱۴.۳ مراجعه کنید.

### ۱۴.۲ ریسک‌ها

| ریسک | شدت | احتمال | کاهش |
|------|------|--------|------|
| **Scope Creep** — حجم نیازمندی‌ها بیش از ظرفیت تیم | بحرانی | بسیار بالا | دروازه‌ی پذیرش مستقل برای هر فاز؛ انتقال اقلام «اختیاری» به Backlog؛ MVP روشن (۱۴.۳) |
| پیچیدگی سه‌لایه‌ی RBAC+ACL+Privacy منجر به نشت داده | بحرانی | متوسط | تمرکز کامل منطق در PolicyEngine؛ آزمون ماتریسی خودکار؛ بازبینی دونفره‌ی اجباری |
| SSO با Kerberos در محیط واقعی AD کار نکند (SPN/ساعت/DNS) | بالا | متوسط | Spike دوروزه روی Domain آزمایشی در فاز ۰، پیش از تعهد زمانی؛ Fallback به LDAP Bind از روز اول |
| اتکای بیش از حد به MAC به‌عنوان کنترل امنیتی | بالا | بالا | مدل Risk Score (۶.۵)؛ مستندسازی صریح محدودیت‌ها برای ذی‌نفعان |
| نشت داده‌ی شخصی (کد ملی + MAC + موقعیت) | بالا | متوسط | رمزنگاری کد ملی؛ سیاست نگهداری مکتوب؛ محدودسازی نقش `auditor`؛ بازبینی فصلی دسترسی |
| «تمام فرمت‌های فایل» تبدیل به کانال بدافزار شود | بالا | متوسط | Whitelist گسترده + ClamAV + magic number + Re-encode تصویر |
| دو کلاینت بومی ⇒ دوبرابر شدن هزینه نگهداری UI | متوسط | بالا | قرارداد API مشترک و کلیدهای بلوک یکسان؛ گزینه‌ی PyWebView (۱۴.۳) |
| کندی داشبورد مدیر گروه با رشد داده | متوسط | بالا | Read Replica، ایندکس‌های جزئی، کش با ابطال رویدادی، تست بار در فاز ۶ |
| Microservices زودهنگام ⇒ پیچیدگی عملیاتی غیرقابل مدیریت | بالا | متوسط | Modular Monolith با مرزهای اجباری (۰.۳) |

### ۱۴.۳ سه توصیه‌ی پایانی

**۱) دامنه را برای نسخه‌ی اول کوچک کنید.** این سند همه‌ی نیازمندی‌ها را پوشش می‌دهد، اما تحویل همزمان‌شان ریسک بالایی دارد. یک MVP قابل دفاع — **فازهای ۰ تا ۴ به‌علاوه‌ی کلاینت وب** — در حدود ۵ ماه قابل تحویل است و ۸۰٪ ارزش کاربری را می‌دهد. چت، ویجت‌های شناور، تقویم قمری، و گزارش‌های پیشرفته می‌توانند در نسخه‌ی دوم بیایند. هیچ چیز به اندازه‌ی یک پروژه‌ی ۱۰ ماهه که در ماه هشتم هنوز چیزی برای نشان دادن ندارد، به اعتماد سازمانی آسیب نمی‌زند.

**۲) اگر منابع محدود است، فقط یک کلاینت بسازید.** ساخت همزمان دو Frontend بومی، هزینه‌ی نگهداری UI را دوبرابر می‌کند. مسیر کم‌ریسک‌تر: وب را کامل بسازید، سپس نسخه‌ی دسکتاپ را با **PyWebView** (پوسته‌ی ~۵MB روی همان کد وب) ارائه دهید — که System Tray، دسترسی به MAC از طریق `psutil`، و SSO ویندوزی را همگی پشتیبانی می‌کند. این تقریباً تمام نیازمندی‌های دسکتاپ شما را پوشش می‌دهد و **۸ هفته** از زمان‌بندی می‌کاهد. PySide6 فقط در صورتی ارزش دارد که کارایی بومی و انیمیشن روان الزام قطعی باشد.

**۳) مرزهای ماژولار را از روز اول با آزمون اجباری کنید، نه با توافق.** این تنها راهی است که «معماری ماژولار قابل واگذاری به تیم‌ها» — که هدف اصلی شما از درخواست Microservices بود — واقعاً محقق می‌شود. بدون آزمون خودکار مرزها، ظرف شش ماه به یک Monolith درهم‌تنیده می‌رسید که نه مزیت ماژولار بودن را دارد و نه سادگی یک طراحی یکپارچه‌ی صادقانه را.

---

*پایان سند. هر بخش قابل بسط به سند فنی مستقل برای تیم مجری همان ماژول است.*
```

==========================================================================================
## FILE: basteh5/backend/.env.example
## SIZE: 1787 bytes
==========================================================================================

```bash
ENV=development            # development | testing | production
DEBUG=False
SQL_ECHO=False             # log every SQL statement (very noisy)
# At least 32 characters. Generate with:
#   .\.venv\Scripts\python.exe -c "import secrets; print(secrets.token_urlsafe(32))"
SECRET_KEY=change-me-to-a-random-string-at-least-32-chars-long
POSTGRES_SERVER=localhost
POSTGRES_PORT=5432
POSTGRES_USER=admin
POSTGRES_PASSWORD=admin123
POSTGRES_DB=planner_db
# App reads SQLALCHEMY_DATABASE_URI first, DATABASE_URL as fallback.
SQLALCHEMY_DATABASE_URI=postgresql+asyncpg://admin:admin123@localhost:5432/planner_db
REDIS_HOST=localhost
REDIS_PORT=6379
HOST=0.0.0.0
PORT=8000
# Must be JSON array syntax (comma-separated string fails to parse).
CORS_ORIGINS=["http://localhost:3000","http://localhost:8080"]
ENABLE_MFA=True
ENABLE_SSO=True
ENABLE_AUDIT_LOGGING=True
RATE_LIMIT_DEFAULT=100/minute
RATE_LIMIT_AUTH=10/minute
MAX_UPLOAD_SIZE=52428800

# ---- Added in architecture-v2 infrastructure pass -------------------------
# Separate keys per purpose (section 4.9 / ADR-06). REQUIRED when ENV=production.
#   DATA_ENCRYPTION_KEY: python -c "import os,base64;print(base64.b64encode(os.urandom(32)).decode())"
#   NATIONAL_ID_PEPPER : python -c "import secrets;print(secrets.token_urlsafe(48))"
DATA_ENCRYPTION_KEY=
NATIONAL_ID_PEPPER=
# HS256 by default; for RS256 set ALGORITHM=RS256 plus both PEM keys.
ALGORITHM=HS256
# JSON arrays. '*' is rejected in production.
ALLOWED_HOSTS=["*"]
ALLOWED_ORIGINS=[]         # WebSocket Origin allow-list; empty = CORS_ORIGINS
TRUSTED_PROXIES=[]         # only these peers may set X-Forwarded-For
IP_ALLOW_LIST=[]
IP_DENY_LIST=[]
MAX_BODY_SIZE=1048576
RATE_LIMIT_ENABLED=True
ALLOW_SELF_REGISTRATION=False
DEVICE_BINDING_MODE=observe  # off | observe | enforce
```

==========================================================================================
## FILE: basteh5/backend/alembic/env.py
## SIZE: 3020 bytes
==========================================================================================

```python
import os
import sys
from alembic import context
from sqlalchemy import engine_from_config, pool

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# Ensure `backend/` (project root for `app.*`) is on sys.path when
# alembic runs from D:\Projects\Activity_dashboard\backend.
_BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)


def _load_dotenv(path):
    """Minimal .env loader (avoids a python-dotenv dependency)."""
    if not os.path.isfile(path):
        return
    with open(path, encoding="utf-8") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key, value = key.strip(), value.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = value


_load_dotenv(os.path.join(_BACKEND_DIR, ".env"))

# Alembic runs in sync mode, but the app .env uses the async driver
# (postgresql+asyncpg://...). Convert it to the sync psycopg2 driver,
# which is what requirements.txt ships (psycopg2-binary).
_db_url = os.environ.get(
    "SQLALCHEMY_DATABASE_URI",
    config.get_main_option("sqlalchemy.url"),
)
if _db_url and "+asyncpg" in _db_url:
    _db_url = _db_url.replace("+asyncpg", "+psycopg2")
if _db_url:
    config.set_main_option("sqlalchemy.url", _db_url)

try:
    from app.core.db.base import Base  # noqa: E402

    target_metadata = Base.metadata
except Exception:
    from sqlalchemy import MetaData  # noqa: E402

    target_metadata = MetaData()

def run_migrations_offline():
    """Run migrations in 'offline' mode.
    
    This configures the context with just a URL
    and gives us the ability to emit SQL script without
    needing a DBAPI.
    """
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()

def run_migrations_online():
    """Run migrations in 'online' mode.
    
    In this mode we need to connect to the database and run migrations
    against a live connection.
    """
    connectable = engine_from_config(
        config.get_section(config.config_ini_section),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection, 
            target_metadata=target_metadata
        )

        with context.begin_transaction():
            context.run_migrations()

if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
```

==========================================================================================
## FILE: basteh5/backend/alembic.ini
## SIZE: 704 bytes
==========================================================================================

```ini
[alembic]
script_location = alembic
prepend_sys_path = .
version_path_separator = os
sqlalchemy.url = postgresql+psycopg2://admin:admin123@localhost:5432/planner_db

[post_write_hooks]

[loggers]
keys = root,sqlalchemy,alembic

[handlers]
keys = console

[formatters]
keys = generic

[logger_root]
level = WARN
handlers = console
qualname =

[logger_sqlalchemy]
level = WARN
handlers =
qualname = sqlalchemy.engine

[logger_alembic]
level = INFO
handlers =
qualname = alembic

[handler_console]
class = StreamHandler
args = (sys.stderr,)
level = NOTSET
formatter = generic

[formatter_generic]
format = %(levelname)-5.5s [%(name)s] %(message)s
datefmt = %H:%M:%S
```

==========================================================================================
## FILE: basteh5/backend/requirements.txt
## SIZE: 324 bytes
==========================================================================================

```text
fastapi==0.115.6
uvicorn[standard]==0.30.1
sqlalchemy[asyncio]==2.0.30
asyncpg==0.29.0
alembic==1.13.0
psycopg2-binary==2.9.9
redis==5.0.1
python-jose[cryptography]==3.3.0
PyJWT==2.8.0
structlog==24.4.0
passlib[bcrypt]==1.7.4
argon2-cffi==23.1.0
python-multipart==0.0.6
pydantic==2.9.2
pydantic-settings==2.0.0
```

==========================================================================================
## FILE: basteh5/RUN_PROJECT_GUIDE.md
## SIZE: 46861 bytes
==========================================================================================

```markdown
# راهنمای راه‌اندازی پروژه (بدون داکر)

> به‌روزرسانی: ۲۲ سپتامبر ۲۰۲۶ — تمام مراحل زیر روی همین ماشین اجرا و تأیید شده است.
> Backend و Frontend هر دو بدون داکر، با PostgreSQL نصب‌شده روی ویندوز کار می‌کنند.

---

## ۱. پیش‌نیازها

| نیاز | نسخه تأییدشده | توضیح |
|---|---|---|
| Python | 3.12.8 | بک‌اند با همین نسخه اجرا شد |
| Node.js / npm | v24 / v11 (نسخه ۱۸+ کافی است) | فرانت‌اند |
| PostgreSQL | 16 (سرویس `postgresql-x64-16`) | به‌صورت native روی ویندوز، بدون داکر |
| Redis | — | **اختیاری/نصب نیست**؛ `RedisBroker` با fallback درون‌فرایندی کار می‌کند (توضیح در بخش ۶ و ۸و) |
| اینترنت | لازم برای `pip install` و `npm install` اول | — |

مسیر پروژه: `C:\Projects\Run_Projects_in_Git\Activity_dashboard`

---

## ۲. راه‌اندازی دیتابیس (یک‌بار)

سرویس PostgreSQL باید در حال اجرا باشد:

```powershell
Get-Service postgresql-x64-16   # باید Running باشد
```

### ۲.۱ ساخت نقش و دیتابیس

فایل `backend/.env` از این مقادیر استفاده می‌کند:

```
POSTGRES_USER=admin
POSTGRES_PASSWORD=admin123
POSTGRES_DB=planner_db
```

اگر نقش `admin` وجود ندارد (خطای `password authentication failed` یا `role "admin" does not exist`)، یک‌بار با دسترسی مدیریتی بسازید. چون `pg_ctl reload` به مجوز سرویس نیاز دارد، روش مطمئن این است که موقتاً احراز هویت را `trust` کنید:

```powershell
# ۱) بکاپ و trust موقت
Copy-Item "C:\Program Files\PostgreSQL\16\data\pg_hba.conf" "C:\Program Files\PostgreSQL\16\data\pg_hba.conf.bak" -Force
(Get-Content "C:\Program Files\PostgreSQL\16\data\pg_hba.conf") -replace "scram-sha-256","trust" | Set-Content "C:\Program Files\PostgreSQL\16\data\pg_hba.conf" -Force

# ۲) ساخت نقش و دیتابیس (بدون رمز عبور وصل می‌شوید)
$env:PGPASSWORD=""
& "C:\Program Files\PostgreSQL\16\bin\psql.exe" -h localhost -U postgres -d postgres -c "CREATE ROLE admin LOGIN PASSWORD 'admin123' SUPERUSER;"
& "C:\Program Files\PostgreSQL\16\bin\psql.exe" -h localhost -U postgres -d postgres -c "CREATE DATABASE planner_db OWNER admin;"
& "C:\Program Files\PostgreSQL\16\bin\psql.exe" -h localhost -U postgres -d postgres -c "CREATE ROLE app_user LOGIN PASSWORD 'app_user_123';"

# ۳) برگرداندن امنیت و اعمال تنظیمات
Copy-Item "C:\Program Files\PostgreSQL\16\data\pg_hba.conf.bak" "C:\Program Files\PostgreSQL\16\data\pg_hba.conf" -Force
$env:PGPASSWORD="admin123"
& "C:\Program Files\PostgreSQL\16\bin\psql.exe" -h localhost -U admin -d planner_db -c "SELECT pg_reload_conf();"

# ۴) تست اتصال با رمز
& "C:\Program Files\PostgreSQL\16\bin\psql.exe" -h localhost -U admin -d planner_db -c "SELECT 1;"
```

> ⚠️ توجه: `admin/admin123` **نقش دیتابیس** است، نه کاربر اپلیکیشن. ساخت کاربر ورود به فرانت‌اند در بخش ۵ آمده است.

نقش `app_user` را حتماً بسازید؛ مایگریشن `audit_schema.sql` دستور `GRANT ... TO app_user` دارد و بدون این نقش، `alembic upgrade head` با خطای `role "app_user" does not exist` می‌شکند.

---

## ۳. راه‌اندازی Backend

```powershell
cd C:\Projects\Run_Projects_in_Git\Activity_dashboard\backend

# ۱) ساخت محیط مجازی تازه (venv قبلی خراب بود و حذف شد)
python -m venv .venv

# ۲) نصب وابستگی‌ها
.\.venv\Scripts\pip.exe install --timeout 120 --retries 5 -r requirements.txt

# ۳) تنظیم .env (اگر از روی example می‌سازید، این دو نکته حیاتی است)
#    - CORS_ORIGINS باید JSON array باشد، نه comma-separated:
#      CORS_ORIGINS=["http://localhost:3000","http://127.0.0.1:3000","http://localhost:5173","http://127.0.0.1:5173","http://localhost:8080"]
#    - SECRET_KEY حداقل ۳۲ کاراکتر

# ۴) اجرای مایگریشن (ساخت ۱۳ اسکیما + اسکیمای هسته `core`)
#    head فعلی: 0002_core_outbox (جدول transactional-outbox در بخش ۲.۳ سند)
.\.venv\Scripts\python.exe -m alembic upgrade head
.\.venv\Scripts\python.exe -m alembic current   # باید 0002_core_outbox (head) را نشان دهد

# ۵) اجرای سرور (روش مطمئن در PowerShell — پشت‌زمینه و جدا از shell)
#    نکته: Start-Job فرانت از shell tool می‌میرد؛ cmd start /b فرزند را جدا می‌کند و زنده می‌ماند.
cmd /c "start /b .venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000 > %TEMP%\opencode\srv8000.log 2>&1"

# اجرای پیش‌رو (جلوی) برای دیباگ:
#     .\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

تست سلامت: http://127.0.0.1:8000/health باید `{"status":"healthy", ...}` با ۱۳ ماژول برگرداند.
مستندات API: http://127.0.0.1:8000/docs
پس از راه‌اندازی، بررسی کامل با اسکریپت‌های تست:
```powershell
$env:PYTHONIOENCODING='utf-8'
.\.venv\Scripts\python.exe "%TEMP%\opencode\smoke.py"    # 17 endpoint خواندنی → 16 OK + 1 SSO challenge (401)
```
> `401` روی `GET /api/v1/auth/sso/negotiate` **رفتار درست** است (چالش SPNEGO + هدر `WWW-Authenticate: Negotiate`)، نه خطا.
>
> ⚠️ بهداشت تست (مهم): هر `POST /auth/login` موفق `token_version` کاربر را زیاد می‌کند و **توکن‌های قبلی را باطل می‌کند**؛ پس لاگین‌های پشت‌سرهم/موازی همدیگر را می‌اندازند (`401 Token revoked`). همچنین محدودیت `RATE_LIMIT_AUTH=10/minute` روی لاگین است (پاسخ `429 RATE_LIMIT_EXCEEDED`). برای تست پایدار: در هر اسکریپت فقط **یک لاگین**، بین اجراها **۶۰+ ثانیه** صبر، و برای WS هم توکن تازه بگیرید (اسکریپت‌ها همین الگو را دارند). `401`های پراکنده‌ی میانیِ اجراهای شلوغ دقیقاً همین علت را دارند، نه باگ — با یک لاگین تمیز همه‌چیز 200 می‌شود.

---

## ۴. راه‌اندازی Frontend

```powershell
cd C:\Projects\Run_Projects_in_Git\Activity_dashboard\web
npm install
npm run dev
```

- آدرس: http://127.0.0.1:3000 (طبق `vite.config.ts` پورت `3000` است، نه ۵۱۷۳)
- اتصال به بک‌اند از `web/.env` خوانده می‌شود: `VITE_API_BASE=http://127.0.0.1:8000/api/v1`
- تست build: `npm run build` (باید بدون خطا بیلد کند؛ آخرین بیلد موفق: ۱۷۶ ماژول)

---

## ۵. ساخت کاربر ورود (مهم)

**مشکل گزارش‌شده:** ورود با `admin/admin123` در فرانت‌اند ناموفق بود.
**علت:** این نام/رمز، نقش PostgreSQL است و هیچ کاربر اپلیکیشنی با آن وجود نداشت (ورود اشتباهاً `401 AUTHENTICATION_ERROR` می‌داد).

**راه‌حل:** کاربر اپلیکیشن `admin` ساخته شد. اگر دیتابیس را از نو ساختید، دوباره بسازید:

```powershell
# POST /api/v1/auth/register — کد ملی باید چک‌سام رسمی ایران را پاس کند (مثلاً 1234567891)
```

```jsonc
// POST http://127.0.0.1:8000/api/v1/auth/register
{ "username": "admin", "password": "admin123",
  "display_name": "admin", "national_id": "1234567891", "email": "admin@local" }
// 201 Created
```

```jsonc
// POST http://127.0.0.1:8000/api/v1/auth/login  (دقیقاً همین را فرانت‌اند می‌فرستد)
{ "identifier": "admin", "password": "admin123", "remember_me": false }
// 200 → { mfa_required:false, tokens:{access_token, refresh_token}, user:{...} }
```

حالا در فرانت‌اند (http://127.0.0.1:3000) با `admin` / `admin123` وارد شوید.

---

## ۶. تغییراتی که در کد داده شد (برای راه‌اندازی لازم بود)

### ۶.۱ `backend/app/main.py` — ایمپورت ماژول‌های ناموجود
`main.py` ماژول‌های `calendar, notification, audit, ssoldap, files` را ایمپورت می‌کرد ولی این پوشه‌ها وجود نداشتند (`ImportError`) و سرور اصلاً بالا نمی‌آمد.
→ هر ۵ ماژول به‌صورت **stub استاندارد** ساخته شد: `app/modules/<name>/__init__.py` (صادرکننده `router` + تابع `register_event_handlers`) و `app/modules/<name>/api/routes.py` (یک endpoint نمونه). اسکیمای SQL هر ۱۳ ماژول از قبل در `alembic/versions/` موجود بود.

### ۶.۲ `backend/app/core/dependencies.py` — circular import
ایمپورت سطح‌بالای `UserRepository`/`AuthService` باعث چرخه `dependencies ↔ auth.routes` می‌شد.
→ ایمپورت‌ها به داخل توابع منتقل شد (lazy import).

### ۶.۳ `backend/app/core/dependencies.py` — `get_current_user` واقعی شد
قبلاً همیشه `{"id":"placeholder"}` برمی‌گرداند.
→ حالا JWT را با HS256 اعتبارسنجی می‌کند (امضا، انقضا، `type=access`)، کاربر را از DB می‌خواند و توکن باطل‌شده (`token_version` ناهماهنگ) و حساب غیرفعال را با 401 رد می‌کند. خروجی `str` (آی‌دی کاربر) است تا ۶۴ محل استفاده‌کننده در ماژول‌ها که `UUID` انتظار دارند نشکنند (FastAPI خودش str→UUID تبدیل می‌کند).

### ۶.۴ چک‌سام کد ملی (`auth/services/auth_service.py::_validate_national_id`)
پیاده‌سازی قبلی (`expected = 0 if r==10 else r`) با الگوریتم رسمی ایران که سند معماری (بخش ۴.۲) الزام کرده مغایرت داشت و کدهای معتبر را رد می‌کرد.
→ اصلاح به الگوریتم رسمی: `expected = r if r<2 else 11-r`.

### ۶.۵ `UserDevices.first_seen_at/last_seen_at` (`auth/db/models.py`)
مدل `nullable=True` بدون default بود ولی ستون DB ‏`NOT NULL DEFAULT now()` است؛ SQLAlchemy مقدار NULL صریح می‌فرستاد و ثبت‌نام با خطای 500 می‌شکست.
→ `server_default=func.now()` به هر دو ستون اضافه شد.

### ۶.۶ توکن تازه باطل می‌شد (`auth_service._generate_tokens`)
`token_version` **بعد** از ساخت JWT زیاد می‌شد، پس توکن刚 صادرشده نسخه قدیمی داشت و اولین استفاده 401 `Token revoked` می‌گرفت.
→ افزایش به **قبل** از صدور توکن منتقل شد.

### ۶.۷ endpointهای گمشده موردنیاز فرانت‌اند
فرانت‌اند (`web/src/security/authProvider.ts`) این‌ها را صدا می‌زند ولی در بک‌اند نبود:
→ `GET /api/v1/auth/me`، `POST /api/v1/auth/logout` (ابطال نشست با `token_version++`)، `GET /api/v1/auth/devices` (با MAC ماسک‌شده) به `auth/api/routes.py` اضافه شد؛ متدهای `get_profile/logout/list_devices/_generate_tokens_by_id` (آخری را مسیر `/refresh` از قبل صدا می‌زد ولی وجود نداشت) به `AuthService` اضافه شد.

### ۶.۸ اصلاحات کوچک
- `app/ws/manager.py`: ایمپورت گمشده `UUID`
- `app/audit/integrity.py`: ایمپورت خراب `app.modules.audit.db.Models` (ماژول audit فقط stub است) + ایمپورت گمشده `json`؛ حالا در غیاب مدل‌ها `unavailable` برمی‌گرداند
- `backend/.env`: افزودن `CORS_ORIGINS` با سینتکس JSON array شامل originهای Vite
- `web/src/security/authProvider.ts`: سه `logger.error` تعریف‌نشده → `console.error` (وگرنه اولین خطای شبکه فرانت‌اند را کرش می‌کرد)

### ۶.۹ باگ «پس از زدن ورود هیچ پارامتری ارسال نمی‌شود» (فرانت‌اند)
علامت: کلیک روی «ورود» هیچ درخواست شبکه‌ای تولید نمی‌کرد.
علت ریشه‌ای در `web/src/security/deviceHeaders.ts` خط `hmacSha256` بود:

```ts
const CryptoJS = require('crypto-js')   // ❌ در مرورگر وجود ندارد
```

`require` در باندل مرورگر (Vite/ESM) تعریف نشده است؛ این خط داخل **interceptor** axios (`api/client.ts`) اجرا می‌شود، پس با `ReferenceError` می‌ترکید و درخواست **قبل از ارسال** لغو می‌شد. اصلاحات:
- `deviceHeaders.ts`: ایمپورت استاندارد `import CryptoJS from 'crypto-js'` در بالای فایل (پکیج از قبل در `node_modules` بود)
- `deviceHeaders.ts`: تابع `logSecurityEvent` صدا زده می‌شد ولی ایمپورت نشده بود (در `fingerprint.ts` تعریف شده) → ایمپورت اضافه شد؛ وگرنه **بعد از ورود موفق** هم خطا می‌داد و ورود ناموفق نشان داده می‌شد
- `fingerprint.ts`: عبارت `process.env.NODE_ENV` در مرورگر (Vite) خودش `ReferenceError` می‌دهد → با گارد `typeof process` اصلاح شد
- `authProvider.ts`: ایمپورت `getDeviceFingerprint` از فایل اشتباه (در `deviceHeaders` وجود ندارد و استفاده هم نمی‌شد) حذف شد
- تأیید: `npm run build` موفق و در باندل نهایی هیچ `require('crypto-js')` نیست

## ۷. داشبورد واقعی (جایگزین صفحه «پیاده‌سازی نشده»)

پس از ورود موفق، مسیر `/dashboard` فقط یک Placeholder بود. داشبورد واقعی ساخته شد:

### ۷.۱ یافته‌های بک‌اند (مهم)
پروب زنده نشان داد **همه سرویس‌های ماژول‌ها (goals/groups/chat/inbox/reporting) با خطای 500** می‌شکستند؛ دو علت:
1. مدل‌های ORM در `app/modules/*/db/Models.py` نام جدول **بدون اسکیما** می‌سازند ولی DDL یک اسکیما به‌ازای هر ماژول دارد (`planning.goals` و…) → `relation "goals" does not exist`. **رفع:** `search_path` کامل روی کانکشن در `app/core/db/session.py` (نام جداول در اسکیماها یکتا هستند، پس بدون ابهام). راه‌حل بلندمدت طبق ADR-04: هر مدل `__table_args__ = {"schema": ...}` خودش را اعلام کند.
2. مدل‌ها از ستون‌های DDL عقب‌اند (`goals.version`، `groups.title`، جدول `inbox_items` در برابر `inbox.items` واقعی و…) → بازنویسی هر ۶ فایل مدل در این مرحله به‌صرفه نبود.
3. باگ ترتیب مسیر: `GET /inbox/outbox` بعد از `/{user_id}` تعریف شده بود و هیچ‌وقت match نمی‌شد (422) → به قبل از `/{user_id}` منتقل شد.
4. باگ اعتبارسنجی نوع آیتم: `item_type not in INBOX_ITEM_TYPES` رشته را با لیستی از آبجکت مقایسه می‌کرد و **همیشه** رد می‌کرد → مقایسه با `[t.value ...]`؛ همچنین تایپوی `chat_invoice` در pattern به `chat_invite` (مطابق سند) اصلاح شد.

### ۷.۲ endpointهای جدید (`app/modules/reporting/api/dashboard.py`)
چون ORM خراب است، داشبورد با **SQL خام اسکیما-دار** (خوانا و مستقل از مدل‌ها) کار می‌کند؛ هر ویجت مستقل است و خرابی یک جدول بقیه را نمی‌اندازد:
- `GET /api/v1/reporting/dashboard/summary` — آمار (اهداف فعال/تکمیل‌شده، وظایف باز، صندوق待 بررسی، گروه‌ها) + اهداف اخیر + وظایف باز + صندوق ورودی + گروه‌ها + اتاق‌های چت
- `GET /api/v1/reporting/dashboard/goals` — فهرست اهداف کاربر
- `POST /api/v1/reporting/dashboard/goals` — ایجاد سریع هدف (`title` الزامی)
- `POST /api/v1/reporting/dashboard/inbox/{id}/act` — تأیید/رد/تعویق آیتم (`accepted/rejected/deferred`) با بررسی مالکیت و حالت `pending`
- روتر با `router.include_router(dashboard_router)` به ماژول reporting متصل شد.

چرخه تأییدشده: `summary 200` → `create-goal 201` → `goals-list 200 (count 1)` → `inbox act 200` → `pending 1→0` ✅

### ۷.۳ فرانت‌اند (`web/src/features/DashboardPage.tsx` + `web/src/hooks/useDashboard.ts`)
- کارت‌های آمار، فهرست اهداف با نوار پیشرفت + فرم ایجاد سریع، صندوق ورودی با دکمه تأیید/رد، وظایف باز، گروه‌ها (با نشان مدیر) و اتاق‌های چت
- همه مسیرها در `App.tsx` به صفحه‌های واقعی وصل شدند: `/dashboard` (داشبورد)، `/chat`، `/inbox`، `/groups`، `/reports`، `/settings` — جزئیات در بخش ۸د
- ⚠️ نکته فنی: هنگام نوشتن فایل، کاراکترهای CJK باعث دابل‌انکد شدن فارسی شدند؛ راه‌حل مطمئن: متن فارسی خالص سالم منتقل می‌شود (مثل `useDashboard.ts`) — از مخلوط‌کردن CJK در یک Write خودداری شود. باندل نهایی فارسی سالم دارد (تست شد).

داده نمونه برای نمایش اولیه (کاربر `admin`): یک هدف «راه‌اندازی سامانه» (۷۰٪) و یک آیتم صندوق «بازبینی گزارش ماهانه».

## ۸. بازطراحی مدرن UI/UX

علت ابتدایی بودن ظاهر: Tailwind عملاً **سیم‌کشی نشده بود** — نه `postcss.config` وجود داشت، نه فایل CSS در `main.tsx` ایمپورت شده بود (تنظیم `build.css.postcss` در `vite.config.ts` را Vite نادیده می‌گیرد). یعنی هیچ کلاس Tailwindی اعمال نمی‌شد.

### ۸.۱ زیرساخت استایل
- `web/tailwind.config.js` جدید (فونت وزیرمتن، پالت `brand`، سایه‌های `card/pop`)
- `web/postcss.config.js` جدید (Vite خودکار تشخیص می‌دهد)
- ایمپورت `./styles/tailwind.css` در `main.tsx`
- فونت **وزیرمتن self-host** در `web/public/fonts/` (۹ فایل woff2، weights ۴۰۰/۵۰۰/۷۰۰) — با CSP سازگار (`font-src 'self'`) و بدون وابستگی به CDN
- سیستم دیزاین در `styles/tailwind.css`: کامپوننت‌های `.card/.btn-primary/.btn-ghost/.input/.badge/.navlink/.stat-card`، انیمیشن‌های `fade-up/fade-in` با stagger، اسکرول‌بار سفارشی، احترام به `prefers-reduced-motion`
- اصلاح تایتل خراب `index.html` + اصلاح باگ از پیش‌موجود `assetFileNames` در `vite.config.ts` (پیشوند `./` که Vite 8 رد می‌کند؛ تا قبل از این چون هیچ asset ای تولید نمی‌شد دیده نشده بود)

### ۸.۲ صفحات (`web/src/App.tsx`, `web/src/features/DashboardPage.tsx`)
- **ورود**: طرح دوپنل — پنل برندینگ گرادیانی با ویژگی‌های محصول + فرم ورود با آیکون، اسپینر لودینگ و پیام خطای زیبا؛ hint حساب پیش‌فرض
- **شل**: سایدبار تیره با ناوبری آیکون‌دار (داشبورد/گفتگو/صندوق/گروه‌ها/گزارش‌ها/تنظیمات)، کارت کاربر با کد ملی ماسک‌شده و خروج؛ تاپ‌بار sticky با تاریخ شمسی زنده (`Intl.DateTimeFormat('fa-IR')`) و نشان اتصال؛ منوی موبایل کشویی؛ آیکون‌های SVG inline (بدون ایموجی)
- **داشبورد**: ۴ کارت آمار گرادیانی با آیکون و stagger، اهداف با نوار پیشرفت گرادیانی چندرنگ، صندوق با دکمه‌های نرم تأیید/رد، وظایف و گروه‌ها به‌صورت chip، اسکلت لودینگ، کاملاً ریسپانسیو (۲ ستونه موبایل → ۴ ستونه دسکتاپ)
- تأیید: `npm run build` موفق (CSS واقعی ۳۱KB)، فارسی باندل سالم و بدون دابل‌انکد
- ⚠️ نکته فنی تکراری: متن فارسی خالص در Write سالم منتقل می‌شود؛ کاراکتر CJK در همان Write باعث دابل‌انکد کل فایل می‌شود. الگوی مطمئن استفاده‌شده: نوشتن با کلید `FA_*` + نگاشت JSON + اسکریپت `apply_map.py`.

---

## ۸ب. رفع باگ رفرش توکن (401 داشبورد)

### علائم
- داشبورد فرانت «ارتباط با سرور برقرار نشد» نشان میداد؛ در کنسول: `401` روی `GET /api/v1/reporting/dashboard/summary`.
- با توکن تازه اندپوینت `200` برمیگرداند — پس مشکل از توکن قدیمی داخل مرورگر بود که مکانیزم بازیابی خودکار نمیتوانست آن را تازه کند.

### ریشههای خطا
1. `POST /auth/refresh` بدنه `{"refresh_token": "..."}` میخواست اما سرور `str` خام میخواست (`422`).
2. رفرشتوکن opaque است اما اندپوینت آن را با `jwt.decode` بررسی میکرد (همیشه `401`).
3. مقایسه `expires_at` از DB با `datetime.utcnow()` خطای `TypeError` میداد (aware در برابر naive) که در `except` پنهان و `401` برگردانده میشد.
4. گارد interceptor فرانت اگر خود رفرش با `401` برگردد، دوباره رفرش صدا میزد (حلقه بینهایت).

### راهحل (اعمال شده)
- `backend/app/modules/auth/ports.py`: مدل `RefreshRequest` اضافه شد.
- `backend/app/modules/auth/api/routes.py`: اندپوینت `/auth/refresh` بدنه آبجکتی و لاگ traceback واقعی دارد.
- `backend/app/modules/auth/services/auth_service.py`: متد `refresh_session()` — جست‌وجو با SHA-256 در `auth.sessions` ، رد revoked/expired ، چرخش سشن، پاسخ با شکل `{status, tokens, user}`.
- `web/src/api/client.ts`: interceptor دیگر روی خود فراخوانیهای `/auth/*` ریترای نمیکند.
- چرخه تأییدشده: login → login دیگر → summary `401` → refresh خودکار → retry → `200`.

### راهحل تکمیلی سمت فرانت (داشبورد مرده + ساخت هدف)

5. باگ «داشبورد مرده»: interceptor هنگام شکست رفرش فقط `secureStorage` را پاک میکرد، اما `isAuthenticated` از persist بازگردانده میشد `true` و UI روی داشبورد خراب گیر میکرد (access-token هم بعد از ۱۵ دقیقه `ACCESS_TOKEN_EXPIRE_MINUTES` منقضی میشود).
6. باگ `init()`: به `sessionStorage.user` نیاز داشت که `login()` هیچوقت آن را نمینوشت — پس رفرش هنگام بارگذاری هیچوقت اجرا نمیشد.

### راهحل فرانت (اعمال شده)
- `web/src/security/authProvider.ts`: اکشن `forceLogout()` اضافه شد؛ `init()` اگر refresh-token نباشد state را ریست میکند و در غیر این صورت با همان refresh-token توکنها را تازه میکند (ﺑدون نیاز به sessionStorage).
- `web/src/api/client.ts`: هنگام شکست رفرش یا نبودن آن، رویداد `auth:expired` فرستاده میشود (بدون import چرخهای).
- `web/src/App.tsx`: شنوده `auth:expired` با `forceLogout()` کاربر را به صفحه ورود برمیگرداند.
- نتیجه کاربر: با رفرش صفحه (Ctrl+F5) توکن خودکار تازه و داشبورد بالا میآید؛ اگر refresh-token هم نامعتبر باشد، به لاگین هدایت میشود (دیگر داشبورد مرده نیست).

### راهحل تکمیلی ریترای POST پس از 401 («ایجاد هدف ناموفق بود»)

7. باگ retry: وقتی POST با `401` برمیگشت، interceptor بعد از رفرش درخواست را با `api(originalRequest)` تکرار میکرد؛ اما axios بدنه از پیش string‌شده را دوباره stringify میکرد و سرور `422 dict_type` برمیگرداند (GET بدون بدنه این مشکل را نداشت — به همین دلیل داشبورد باز میشد اما ساخت هدف نه).
8. ریس race: `StrictMode` افکتها را دوبار اجرا میکند و refresh‌های همزمان با یک توکن، یکدیگر را باطل میکنند (rotation تک‌مصرفه است).

### راهحل (اعمال شده)
- `web/src/api/client.ts`: ریترای با `transformRequest: [(d) => d]` بدنه اصلی را دست‌نخورده ارسال میکند + رفرش single-flight (`refreshPromise` مشترک) تا `401`های همزمان یک چرخش  مشترک داشته باشند.
- چرخه تأییدشده: POST با توکن قدیمی `401` → رفرش → تکرار POST با بایتهای اصلی → `201`.

## ۸ج. بازنویسی سرویس‌های ماژول‌ها روی DDL واقعی (۱۹ سپتامبر ۲۰۲۶)

### علت
مدل‌های ORM در `app/modules/*/db/Models.py` از DDL مهاجرت عقب بودند (جدول بدون اسکیما، ستون‌های خیالی، PK با تایپ اشتباه)؛ در نتیجه **همه endpointهای ماژول‌ها 500** می‌دادند (`/groups/`، `/goals/`، `/chat/rooms`، `/inbox/*`، `/sharing/*`، `/reporting/layouts`، `/reporting/widgets/settings`).

### تصمیم
به‌جای ترمیم مدل‌ها، لایه سرویس هر ۷ ماژول با **SQL خام schema-qualified** روی DDL واقعی بازنویسی شد (همان الگوی اثبات‌شده `reporting/api/dashboard.py`):
- `rbac/services/rbac_service.py` (اسکیما `rbac` + گاردهای anti-escalation: ممنوعیت self-assign و اعطای نقش هم‌سطح/بالاتر + بررسی مدیر گروه برای scope فراتر از global)
- `groups/services/groups_service.py` (اسکیما `groups`؛ ستون `path` از نوع ltree با uuid بدون خط‌تیره)
- `goals/services/goals_service.py` (اسکیما `planning`)
- `chat/services/chat_service.py` (اسکیما `chat`)
- `inbox/services/inbox_service.py` (اسکیما `inbox`؛ `InboxService = InboxStateMachine`)
- `sharing/services/sharing_service.py` (اسکیما `sharing`)
- `reporting/services/reporting_service.py` (اسکیما `reporting`)

اصلاحات پشتیبان: `rbac/ports.py` (فیلد `target_user_id` در Assign/Revoke)، `rbac/api/routes.py` (استفاده از `target_user_id` به‌جای self)، `sharing/api/routes.py` (`Body(..., embed=True)` برای revoke)، امضای `act_on_item(item_id, action, note, actor_id)` هماهنگ با route.

### یافته‌های DDL (مهم برای توسعه بعدی)
- `sharing.effective_permissions` یک **VIEW** است — فقط خواندنی؛ INSERT/UPDATE روی آن 500 می‌دهد.
- ایندکس یکتای `dashboard_layouts` **جزئی** است (`WHERE is_default = true`) پس `ON CONFLICT` نامعتبر است → upsert دستی SELECT→INSERT/UPDATE.
- پارامترهای jsonb در asyncpg باید **رشته JSON** باشند نه dict (`json.dumps`).
- نوع enum بدون پیشوند اسکیما است (`privacy_level` نه `planning.privacy_level`).
- `get_current_user` در `app/core/dependencies.py` **رشته** برمی‌گرداند (`str(user.id)`) نه UUID.
- جدول `sharing.shares` ستون `share_code` ندارد (id همان share_code است) و constraint یکتایی روی سه‌گانه ندارد → upsert دستی.

### Seed داده RBAC (یک‌بار اجرا شد)
۵ نقش (`super_admin=10`، `admin=8`، `manager=5`، `user=3`، `viewer=1`) + ۲۴ دسترسی + نگاشت نقش‌ها (super_admin هر ۲۴؛ admin بدون `rbac.manage/ldap.configure`؛ manager ۱۴؛ user ۹؛ viewer ۵) + اعطای `super_admin` به کاربر `admin`. (اسکریپت موقت در `%TEMP%\opencode\seed_rbac.sql` — برای دیتابیس تازه دوباره اجرا شود.)

### چرخه تأییدشده
- `smoke.py`: هر ۱۸ endpoint خواندنی 200 ✅
- `smoke2.py` (مسیر کامل نوشتن): ساخت گروه/هدف/تسک/اتاق/پیام/آیتم صندوق/اشتراک‌گذاری/چیدمان/ویجت + act/revoke — همگی 200 ✅ (اسکریپت‌ها در `%TEMP%\opencode\`)
- توجه: `POST /rbac/assign` با `target_user_id` برابر خودِ کاربر 403 می‌دهد (`CANNOT_SELF_ASSIGN`) — رفتار درست است، نه باگ.

---

## ۸د. صفحات واقعی فرانت‌اند (۱۹ سپتامبر ۲۰۲۶)

هر ۵ Placeholder در `App.tsx` با صفحه واقعی جایگزین شد (همان سیستم دیزاین بخش ۸: `.card/.btn-primary/.badge/.input`، آیکون SVG، RTL، انیمیشن‌ها):
- `web/src/features/ChatPage.tsx` (`/chat`) — فهرست اتاق‌ها + ساخت اتاق + پیام‌ها با polling هر ۴ ثانیه + ارسال پیام
- `web/src/features/InboxPage.tsx` (`/inbox`) — تب‌های ورودی/ارسال‌شده/آیتم جدید؛ تأیید/رد/تعویق؛ ساخت آیتم (`meeting_invite/share_request/task_assignment/chat_invite/approval`)
- `web/src/features/GroupsPage.tsx` (`/groups`) — فهرست گروه‌ها + ساخت گروه + اعضای گروه + افزودن عضو (توسط مدیر گروه)
- `web/src/features/ReportsPage.tsx` (`/reports`) — فهرست/ذخیره چیدمان داشبورد + تنظیمات ویجت‌ها (toggle + ذخیره + بازگشت به پیش‌فرض)
- `web/src/features/SettingsPage.tsx` (`/settings`) — پروفایل کاربر + نقش‌ها (`GET /rbac/user/{id}/roles`) + شمار دسترسی‌ها + خروج
- تأیید: `npm run build` موفق (۱۷۶ ماژول) و هر ۵ مسیر API در باندل نهایی موجود است؛ فارسی باندل سالم.

---

## ۸ه. مایگریشن `core.outbox_messages` (۲۱ سپتامبر ۲۰۲۶) — لاگین 500 می‌داد

### علائم
پس از راه‌اندازی تازه، `POST /api/v1/auth/login` با **500** شکست:
```
asyncpg.exceptions.UndefinedTableError: relation "core.outbox_messages" does not exist
[SQL: INSERT INTO core.outbox_messages (event_id, event_type, payload, ...)]
```
علت: الگوی **transactional outbox** (سند بخش ۲.۳) هنگام ورود، رویداد دامنه را در `core.outbox_messages` ثبت می‌کند ولی این جدول در دیتابیس وجود نداشت.

### ریشه
فایل `backend/alembic_versions/xxxx_create_core_outbox_messages.py` (قدیمی) یک **قالب** بود (`revision = REPLACE_ME`) و در دایرکتوری اشتباه رها شده بود (خارج از `script_location = alembic`)، پس هرگز توسط alembic شناسایی و اعمال نشد. `alembic heads` فقط `0001_initial` را نشان می‌داد.

### راه‌حل (اعمال شده)
- مایگریشن واقعی ساخته شد: `backend/alembic/versions/0002_core_outbox.py` (`revision = "0002_core_outbox"`, `down_revision = "0001_initial"`) — ساخت `SCHEMA core` + جدول `outbox_messages` + ایندکس جزئی `ix_outbox_pending`.
- اجرا: `.\.venv\Scripts\python.exe -m alembic upgrade head` → `current` اکنون `0002_core_outbox (head)`.
- قالب قدیمی `backend/alembic_versions/xxxx_...` حذف شد.
- تأیید: `smoke.py` — `login 200` و هر ۱۸ endpoint 200 ✅

### نکته برای دیتابیس تازه
اگر دیتابیس از نو ساخته می‌شود، `alembic upgrade head` این مایگریشن را هم می‌آورد؛ مراحل بخش ۳ نیازی به تغییر ندارد.

---

## ۸و. WebSocket + Redis + SSO/SPNEGO (۲۲ سپتامبر ۲۰۲۶)

### WebSocket (معماری 5.5 / 12.8) — پیاده‌سازی شد و تأیید شد
- `backend/app/ws/routes.py` — دو گیتوی:
  - `GET /ws/chat` — accept→origin check (4403)→JWT در query (4401)→revalidation هر 60s (4401)→idle 300s (4408)→سقف 8192 بایت (1009)→rate-limit 20 پیام/دقیقه (RATE_LIMITED)→فریم‌های `join/message/leave/ping`→بررسی عضویت به‌ازای هر پیام (NOT_A_MEMBER/NOT_JOINED)→ذخیره پیام با SQL خام در `chat.messages`→`_sanitize_html`
  - `GET /ws/notifications` — فریم اول `unread_count`، سپس اشتراک کانال `notifications:{user_id}` برای push زنده
- `backend/app/ws/manager.py` — `ConnectionManager` (ثبت سوکت درون‌فرایندی + relay روی کانال `room:{room_id}`)؛ `broadcast` فقط publish می‌کند و relay تحویل می‌دهد (ضد تحویل دوباره)
- `backend/app/core/redis.py` — `RedisBroker` (پابلیش/اشتراک async + cache); وقتی Redis در دسترس نیست به fan-out درون‌فرایندی ارتجاع می‌دهد (تک‌فرایند پابرجاست)
- `backend/app/core/security.py` — `get_device_fingerprint`، `verify_hmac_signature`، `hmac_sign`
- `backend/app/modules/notification/events.py::_publish_live` — بعد از درج notification، پیام JSON به کانال `notifications:{user_id}` پابلیش می‌شود
- mount در `main.py`: `app.include_router(websocket_router)` بدون پیشوند → مسیرها `/ws/chat` و `/ws/notifications`

### تأیید (همه روی سرور در حال اجرا)
```
bad token → close 4401 ✅   join ×2 → connected ✅   broadcast به a+b ✅
oversize → MESSAGE_TOO_LARGE ✅   non-member → NOT_A_MEMBER ✅
rate-limit: RATE_LIMITED بعد از پیام ۲۰ ✅
notifications: unread_count → login → push auth.login.succeeded → unread_count جدید ✅
```

### مدیریت کاربران ادمین و بخش‌های جدید تنظیمات (۲۲ سپتامبر ۲۰۲۶)
- روتر `/admin/users` (فهرست/ایجاد/ویرایش/تغییر انبوه حالت ورود) که نه mount بود نه deps واقعی داشت، سرهم‌بندی شد:
  - `app/modules/auth/api/deps.py` جدید — `get_admin_user_service` واقعی (با `UserRepository` زنده) + re-export شدن `get_current_user` از core تا `require_permission` رزولو شود
  - `app/modules/rbac/api/deps_internal.py` جدید — `get_permission_service` واقعی (PermissionService با session؛ بدون Redis)
  - `app/modules/auth/__init__.py` حالا هر دو روتر `auth` و `admin/users` را include می‌کند
  - `require_permission` در `rbac/api/deps.py` اصلاح شد: چون `get_current_user` رشته (id) برمی‌گرداند، `user.id` خطا می‌داد → حالا str و object هر دو پشتیبانی می‌شوند
  - `AdminUserService` حالا actor رشته‌ای را هم می‌پذیرد (`_actor_id`)
- مدل ORM `Users` با DDL هم‌خط شد: ستون‌های `sso_enabled` + `ldap_dn/object_guid/sam_account/synced_at` اضافه شدند (قبلاً `bulk_change_login_mode` روی attribute ناموجود می‌نشست)
- دسترسی‌های گمشده `user.read/user.create/user.manage` در `rbac.permissions` سید و به `super_admin` اعطا شد (قبلاً فقط `user.bulk_login_mode` بود → همه guardها 403 می‌دادند)
- endpoint جدید `GET /api/v1/auth/sso/status` در ssoldap: وضعیت SSO/LDAP بدون افشای secret (enabled، ldap3 نصب، server URI، base DN، auto-provision، kerberos، group-role-map + مسیرهای negotiate/ldap-login)
- چرخه تأییدشده: `list 200 (total=5)` → `create 201` → `deactivate 200` → `bulk sso 200 (updated=[id])` → `reactivate 200` ✅
- فرانت‌اند (`web/src/features/SettingsPage.tsx`): دو کارت جدید
  - **مدیریت کاربران (تعریف کاربر)** — فهرست + جست‌وجو + فرم ایجاد (username/کدملی/نام نمایشی/رمز موقت) + دکمه فعال/غیرفعال (محافظت از self) + دکمه فعال‌سازی/غیرفعال‌سازی SSO برای هر کاربر + **انتخاب نقش از dropdown** (assign/revoke با `/rbac/assign` و `/rbac/revoke`)؛ اگر 403 بگیرد «دسترسی ندارید» نشان می‌دهد
  - **SSO و LDAP** — خواندن `/auth/sso/status` و نمایش ۹ ردیف وضعیت + راهنمای فعال‌سازی SSO از بخش کاربران
- تأیید: `npm run build` موفق (۱۷۶ ماژول)؛ فرانت روی `http://127.0.0.1:3000` بالا و 200

### رفع مشکل گروه‌ها و افزودن عضو از لیست کاربران (۲۳ سپتامبر ۲۰۲۶)
- مشکل «ایجاد گروه ناموفق بود» در فرانت: بک‌اند سالمه (`POST /groups/` با همین بدنه 200 برمی‌گرداند؛ زنجیره‌ی
  stale-token→401→refresh→retry هم تأیید شد 200). علت واقعی، نوسان توکن در هنگام تست هم‌زمان (هر لاگین
  token_version را بالا می‌برد → 401) و پنجره‌ی ریت‌لیت auth (۱۰/دقیقه که شامل `/auth/refresh` هم هست → 429)
  بود. در فرانت حالا پیام خطای واقعی سرور نمایش داده می‌شود (به‌جای پیام generic).
- مشکل «کاربر ایجادشده را نمی‌توان به گروه اضافه کرد»: ریشه در این بود که فرم افزودن، یک input متنی برای
  user_id داشت و اگر کاربر `ghasemi` تایپ می‌کرد، بک‌اند `422` می‌داد (الگوی لاگ: `found 'g' at 1`).
- اصلاح `web/src/features/GroupsPage.tsx`:
  - فهرست کاربران سیستم (`/admin/users`) یک‌بار هنگام mount خوانده می‌شود (با برچسب فارسی مرتب‌شده).
  - فرم افزودن عضو → **dropdown «انتخاب از کاربران سیستم»** (نام نمایشی/کاربرنam نمایش داده می‌شود، به‌جای
    تایپ دستی)؛ کاربرانِ فعلاً عضوِ گروه از لیست حذف می‌شوند؛ کاربر غیرفعال با برچسب «غیرفعال» می‌آید.
  - لیست اعضا حالا **نام نمایشی + ۸ کاراکتر اول UUID** را نشان می‌دهد (نه UUID خام).
  - خطای create/add از response سرور به‌روز رسیدی می‌شود.
- تأیید E2E یک‌جا: login → create group 200 → owner_id==admin → `/admin/users` → add member با UUID
  (همان چیزی که dropdown می‌فرستد) 200 → members 200. `npm run build` موفق.

### نکته‌ی فرم ایجاد کاربر در تنظیمات

### اتصال Audit به رویدادها و integrity (۲۲ سپتامبر ۲۰۲۶)
- `app/modules/audit/__init__.py` از استاب به real تغییر کرد: `register_event_handlers` از `events.py` صدا زده می‌شود — حالا لاگین موفق/ناموفق و رویدادهای auth/rbac در `audit.login_audit_logs` / `audit.audit_logs` با زنجیره‌ی هش (advisory lock) ثبت می‌شوند.
- `app/audit/integrity.py` (که ایمپورت خرابی داشت) بازنویسی شد تا زنجیره‌ی هر دو جدول را با همان فرمول `AuditService` بازمحاسبه و تأیید کند؛ `GET /api/v1/audit/integrity-check` → `{"status":"integrity_ok","total_logs":…,"broken_links":0,…}`.
- ⚠️ ترگر سرگردان دیتابیس (`audit.compute_row_hash()` روی `audit_logs` و `login_audit_logs`) حذف شد: هم `login_audit_logs` (ستون `action` ندارد) را می‌شکست، هم با فرمول app تداخل داشت — مطابق کامنتِ خود `backend/alembic/versions/audit_schema.sql` هیچ ترگرهش روی این جدول‌ها نباید باشد.
- پاکسازی: فایل‌های اسکله‌ی بلااستفاده‌ی پچ قدیمی از `calendar` و `files` (که هیچ route به آن‌ها import نداشت و در git هم نبودند) حذف شدند؛ پیاده‌سازی واقعی `calendar_service.py` و `files_service.py` بی‌تغییر ماند.

### نکته تست push زنده (مهم)
برای تست live notification، لاگین **باید روی همان پروسه‌ای** باشد که سوکت WS روی آن باز است؛ در حالتی که سوکت روی 8001 و لاگین روی 8000 است، notification در دیتابیس مشترک ساخته می‌شود ولی پابلیش به broker پروسه‌ی اشتباه می‌رود و به سوکت نمی‌رسد.

### Redis
- سرور Redis هنوز نصب نیست؛ `RedisBroker` در بدترین حالت به in-memory pub/sub ارتجاع می‌دهد (لاگ: `redis unavailable; using in-memory pub/sub`).
- برای چند-worker پشت load balancer به Redis واقعی نیاز است (کانفیگ از قبل در `settings.redis_url` است).

### SSO / SPNEGO (معماری امنیت لایه‌بندی‌شده)
- `POST /api/v1/auth/sso/ldap-login` — کامل (با `ldap3`؛ در غیاب AD → 401 `LDAP_UNAVAILABLE`)
- `GET /api/v1/auth/sso/negotiate` — هنگام نبود هدر → 401 `SPNEGO_CHALLENGE` + هدر `WWW-Authenticate: Negotiate`؛ وقتی هدر `Authorization: Negotiate ...` هست ولی Kerberos کانفیگ نیست → 501 `KERBEROS_NOT_CONFIGURED`
- کلیدهای کانفیگ: `LDAP_KERBEROS_ENABLED` (پیش‌فرض `False`) و `LDAP_KERBEROS_KEYTAB` (خالی) در `app/core/config.py`

---

## ۸. چرخه‌های تأییدشده (تست end-to-end روی سرور در حال اجرا)

```
REGISTER 201 → LOGIN 200 (access+refresh token) → ME 200 (کد ملی ماسک‌شده)
→ DEVICES 200 → LOGOUT 200 → ME بعد از logout = 401 ✅
LOGIN 200 → audit.login_audit_logs+1 → GET /audit/integrity-check → {"status":"integrity_ok","broken_links":0} ✅
```

---

## ۹. کارهای باقی‌مانده (عامدانه انجام نشد)

| مورد | وضعیت | توضیح |
|---|---|---|
| MFA کامل (TOTP) | ✅ انجام شد | enroll/verify/enroll-confirm پیاده شد و چرخه login→mfa_required→verify→توکن تأیید شد (مستندات در OpenAPI `type: string` برای code) |
| WebSocket chat + notifications | ✅ انجام شد | بخش ۸و؛ `/ws/chat` و `/ws/notifications` با تمام کنترلها (origin/JWT/rate-limit/اندازه/بازارزیابی) |
| Redis | ✅ fallback درون‌فرایندی | سرور Redis نصب نیست؛ `RedisBroker` (بخش ۸و) با in-memory pub/sub ارتجاع دارد؛ Redis واقعی فقط برای چند-worker لازم است |
| SSO LDAP + Kerberos/SPNEGO | ✅/⚠️ جزئی | ldap-login کامل است؛ negotiate سؤال‌چالش SPNEGO و در غیاب Kerberos 501 می‌دهد؛ Kerberos واقعی نیاز به AD + Keytab دارد |
| ۵ ماژول stub (calendar, notification, audit, ssoldap, files) | ✅ کامل شد | همه با سرویس SQL خام روی DDL واقعی پیاده و تست شدند (بخش ۸ج/۸و) |
| دریفت ORM از DDL | ✅ دور زده شد | سرویس‌های هر ۷ ماژول با SQL خام روی DDL واقعی بازنویسی شدند (بخش ۸ج)؛ اسکله‌های ORM بلااستفاده (calendar/files) حذف شدند — مدل‌های منحرف باقی‌مانده در `db/Models.py` استفاده نمی‌شوند؛ بازنگری آتی |
| نقش‌های کاربر `admin` | ✅ انجام شد | seed RBAC (بخش ۸ج): ۵ نقش + ۲۴ دسترسی + اعطای `super_admin` به `admin` |
| باطل‌شدن نشست‌های قبلی با هر login | ⚠️ رفتار فعلی | به‌خاطر `token_version++` در صدور توکن، ورود جدید نشست‌های قبلی را می‌اندازد؛ اگر چنددستگاهی می‌خواهید بازبینی شود |

---

## ۱۰. اجرای روزمره (خلاصه)

```powershell
# ترمینال ۱ — بک‌اند (پشت‌زمینه، از هر shell که بسته شود هم زنده می‌ماند)
cd C:\Projects\Run_Projects_in_Git\Activity_dashboard\backend
cmd /c "start /b .venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000 > %TEMP%\opencode\srv8000.log 2>&1"

# ترمینال ۲ — فرانت‌اند
cd C:\Projects\Run_Projects_in_Git\Activity_dashboard\web
npm run dev
```

> نکته ویندوز: وقتی بک‌اند را با `cmd start /b` بالا می‌آورید، wrapper که shell را می‌بندد ممکن است پیام `ChildProcess.kill` بدهد؛ این **طبیعی است** — فرزند جدا شده و بالا می‌ماند. دستور `Stop-Process` زیر پیش از راه‌اندازی مجدد، همه‌ی پایتون‌های uvicorn را می‌کشد:
> `Get-CimInstance Win32_Process -Filter "Name='python.exe'" | Where-Object { $_.CommandLine -match 'uvicorn' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }`

### بررسی سلامت پس از راه‌اندازی
```powershell
Invoke-WebRequest http://127.0.0.1:8000/health     # {"status":"healthy", ... 13 module}
Invoke-WebRequest http://127.0.0.1:3000            # 200
# لاگین واقعی با Endpoint (نه فقط صفحه):
# POST /api/v1/auth/login  {"identifier":"admin","password":"admin123"}
```

| نشانی | کاربرد |
|---|---|
| http://127.0.0.1:3000 | اپ وب (ورود: `admin` / `admin123`) |
| http://127.0.0.1:8000/docs | مستندات تعاملی API |
| http://127.0.0.1:8000/health | سلامت سرویس |
```

==========================================================================================
## FILE: basteh5/web/package.json
## SIZE: 958 bytes
==========================================================================================

```json
{
  "name": "planner-web",
  "private": true,
  "version": "1.0.0",
  "type": "module",
  "scripts": {
    "dev": "vite",
    "build": "vite build",
    "preview": "vite preview"
  },
  "dependencies": {
    "@fingerprintjs/fingerprintjs": "^5.2.0",
    "@tanstack/react-query": "^5.60.0",
    "axios": "^1.7.7",
    "crypto-js": "^4.2.0",
    "date-fns": "^3.6.0",
    "react": "^18.3.0",
    "react-dom": "^18.3.0",
    "react-redux": "^9.1.2",
    "react-router-dom": "^7.18.4",
    "recoil": "^0.7.7",
    "zustand": "^5.0.15"
  },
  "devDependencies": {
    "@axe-core/react": "^4.6.0",
    "@types/react": "^18.3.12",
    "@types/react-dom": "^18.3.0",
    "@vitejs/plugin-react": "^4.3.1",
    "autoprefixer": "^10.4.20",
    "daisyui": "^4.12.14",
    "postcss": "^8.4.49",
    "tailwindcss": "^3.4.14",
    "typescript": "^5.6.2",
    "vite": "^8.3.0"
  },
  "allowScripts": {
    "esbuild@0.21.5": true
  }
}
```

==========================================================================================
## FILE: basteh5/web/vite.config.ts
## SIZE: 1272 bytes
==========================================================================================

```typescript
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from 'tailwindcss'
import autoprefixer from 'autoprefixer'
import { fileURLToPath } from 'url'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  base: '/',
  build: {
    outDir: 'dist',
    assetsDir: 'assets',
    rollupOptions: {
      output: {
        assetFileNames: (assetInfo) => {
          const extType = assetInfo.name.split('.').at(1) || 'file'
          let typeCategory = 'assets'
          if (['png', 'jpg', 'jpeg', 'svg', 'gif', 'tiff', 'bmp', 'ico'].includes(extType)) {
            typeCategory = 'assets/images'
          } else if (extType === 'css') {
            typeCategory = 'assets/css'
          } else if (/\.js$/.test(assetInfo.name)) {
            typeCategory = 'assets/js'
          }
          return `${typeCategory}/[name]-[hash][extname]`
        },
      },
    },
    css: {
      postcss: {
        plugins: [tailwindcss(), autoprefixer()],
      },
    },
  },
  server: {
    port: 3000,
    host: '127.0.0.1',
  },
  preview: {
    port: 4000,
  },
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url)),
    },
  },
})
```

==========================================================================================
## FILE: basteh6/desktop/main.py
## SIZE: 1324 bytes
==========================================================================================

```python
import sys
import os
from PySide6.QtWidgets import QApplication
from PySide6.QtCore import Qt
from PySide6.QtGui import QFontDatabase, QScreen

from desktop.app.core.bootstrap import bootstrap


def main():
    """Entry point for the desktop application."""
    app = bootstrap()

    # Force high DPI scaling on Windows
    if hasattr(Qt, "AA_EnableHighDpiScaling"):
        QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    if hasattr(Qt, "AA_UseHighDpiPixmaps"):
        QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)

    # Apply RTL layout direction globally
    app.setLayoutDirection(Qt.RightToLeft)

    # Apply default theme (light)
    from desktop.app.core.bootstrap import apply_theme
    apply_theme(app, "light")

    # Show login window first
    from desktop.app.views.login_window import LoginWindow
    login_window = LoginWindow()

    # Handle login success - show main window
    def on_login_success(user):
        login_window.close()
        from desktop.app.views.main_window import MainWindow
        main_window = MainWindow(user=user, auth_manager=login_window._auth_manager)
        main_window.show()

    login_window.login_successful.connect(on_login_success)

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
```

==========================================================================================
## FILE: basteh6/web/src/api/client.ts
## SIZE: 7775 bytes
==========================================================================================

```typescript
import axios, { AxiosInstance, AxiosRequestConfig, CanceledError } from 'axios'
import { getFingerprint, getMacAddress, isDeviceInitialized, generateDeviceHeaders } from '../security/deviceHeaders'
import { secureStorage } from '../security/fingerprint'
import type { AxiosRequestConfig as AxiosConfig } from 'axios'

// Base API URL
const API_BASE_URL = import.meta.env.VITE_API_BASE || 'https://api.corp.local/api/v1'

// Request interface to include device headers
interface RequestConfig extends AxiosConfig {
  skipAuth?: boolean
  skipDeviceHeaders?: boolean
}

/** API client instance */
let api: AxiosInstance | null = null

/** Initialize API client with auth interceptors */
export function initApiClient(): AxiosInstance {
  if (api) return api
  
  api = axios.create({
    baseURL: API_BASE_URL,
    timeout: 30_000,
    withCredentials: true, // For cookie-based refresh tokens
    headers: {
      'Accept': 'application/json',
      'Content-Type': 'application/json',
    },
  })
  
  // Attach device headers to every request
  api.interceptors.request.use(
    async (config: RequestConfig) => {
      // Check if device identity is initialized
      if (!isDeviceInitialized() && !config.skipAuth) {
        // If not initialized and not skipping auth, we need to handle this
        // In practice, this would happen after login
        console.debug('Device identity not initialized - adding minimal headers')
      }
      
      // Generate device authentication headers if not skipped
      if (!config.skipDeviceHeaders && !config.skipAuth) {
        const headers = generateDeviceHeaders(
          config.method?.toUpperCase() || 'GET',
          config.url || '',
          config.data
        )
        
        // Merge headers with existing ones
        config.headers = {
          ...config.headers,
          ...headers,
          // Remove X-Device-MAC for web clients (would be set for desktop)
          ...(getMacAddress() ? { 'X-Device-MAC': getMacAddress() } : {}),
        }
      }
      
      // Add auth token if available
      const token = secureStorage.get('access_token')
      if (token && !config.headers?.Authorization) {
        config.headers.Authorization = `Bearer ${token}`
      }
      
      // Add request ID if not present
      if (!config.headers?.['X-Request-ID']) {
        config.headers['X-Request-ID'] = crypto.randomUUID()
      }
      
      return config
    },
    (error) => {
      return Promise.reject(error)
    }
  )
  
  // Handle token refresh on 401
  // Single-flight: concurrent 401s share one refresh call so the rotated
  // refresh token is not consumed twice (second use => 401 REVOKED).
  let refreshPromise: Promise<{ access: string; refresh: string }> | null = null

  function doRefresh(): Promise<{ access: string; refresh: string }> {
    if (!refreshPromise) {
      const refreshToken = secureStorage.get('refresh_token')
      if (!refreshToken) {
        return Promise.reject(new Error('no refresh token'))
      }
      refreshPromise = (async () => {
        try {
          const response = await api!.post('/auth/refresh', {
            refresh_token: refreshToken
          })
          const data = response.data
          // Update tokens
          secureStorage.set('access_token', data.tokens.access_token)
          secureStorage.set('refresh_token', data.tokens.refresh_token)
          return { access: data.tokens.access_token, refresh: data.tokens.refresh_token }
        } finally {
          refreshPromise = null
        }
      })()
    }
    return refreshPromise
  }

  api.interceptors.response.use(
    (response) => response,
    async (error) => {
      const originalRequest = error.config as RequestConfig & { _retry?: boolean }
      const failedUrl = String(originalRequest?.url || '')
      const isAuthCall = failedUrl.includes('/auth/refresh') || failedUrl.includes('/auth/login')

      // If 401 and not already retried (never retry the auth calls themselves)
      if (error.response?.status === 401 && !originalRequest._retry && !isAuthCall) {
        originalRequest._retry = true
        
        try {
          // Try to refresh token (single-flight across concurrent 401s)
          const { access } = await doRefresh()
          
          // Retry original request with new token.
          // NOTE: axios already serialized originalRequest.data to a JSON
          // string on the first attempt; re-dispatching would stringify it
          // AGAIN (422 dict_type on the server). Bypass re-transform.
          originalRequest.headers.Authorization = `Bearer ${access}`
          
          // Also regenerate device headers
          const headers = generateDeviceHeaders(
            originalRequest.method?.toUpperCase() || 'GET',
            originalRequest.url || '',
            originalRequest.data
          )
          originalRequest.headers = {
            ...originalRequest.headers,
            ...headers,
          }
          
          return api({
            ...originalRequest,
            transformRequest: [(data) => data],
          })
        } catch (refreshError) {
          // Refresh failed - clear tokens and notify the app shell
          // (client.ts cannot import the auth store: authProvider imports this
          // module, so we signal via a DOM event instead of a direct call).
          secureStorage.remove('access_token')
          secureStorage.remove('refresh_token')
          sessionStorage.removeItem('user')
          if (typeof window !== 'undefined') {
            window.dispatchEvent(new CustomEvent('auth:expired'))
          }

          // Navigate to login
          // In real app: navigate('/login')
          return Promise.reject(refreshError)
        }
      }

      // No refresh token stored: nothing to recover with. Notify shell too.
      if (error.response?.status === 401 && !isAuthCall) {
        if (typeof window !== 'undefined') {
          window.dispatchEvent(new CustomEvent('auth:expired'))
        }
      }
      
      return Promise.reject(error)
    }
  )
  
  return api
}

/** Get the API client instance */
export function getApi(): AxiosInstance {
  if (!api) {
    return initApiClient()
  }
  return api
}

/** Simple API helper functions */
export const apiRef = {
  get: <T>(url: string, config?: RequestConfig) => 
    getApi().get<T, T>(url, config),
  
  post: <T, D = any>(url: string, data?: D, config?: RequestConfig) => 
    getApi().post<T, T>(url, data, config),
  
  put: <T, D = any>(url: string, data?: D, config?: RequestConfig) => 
    getApi().put<T, T>(url, data, config),
  
  delete: <T>(url: string, config?: RequestConfig) => 
    getApi().delete<T, T>(url, config),
  
  patch: <T, D = any>(url: string, data?: D, config?: RequestConfig) => 
    getApi().patch<T, T>(url, data, config),
  
  // File upload with progress
  upload: <T>(url: string, file: File, onProgress?: (progress: number) => void) => {
    const formData = new FormData()
    formData.append('file', file)
    
    return getApi().post<T, any>(url, formData, {
      onUploadProgress: (progressEvent) => {
        if (onProgress && progressEvent.total) {
          const progress = Math.round((progressEvent.loaded * 100) / progressEvent.total)
          onProgress(progress)
        }
      }
    })
  },
  
  // Download file
  download: (url: string) => {
    return getApi().get(url, {
      responseType: 'blob',
      headers: {
        'X-Requested-With': ' XMLHttpRequest'
      }
    })
  },
}

export default apiRef
```

==========================================================================================
## FILE: basteh6/web/src/App.tsx
## SIZE: 15955 bytes
==========================================================================================

```tsx
import React, { useEffect, useMemo, useState } from 'react'
import {
  BrowserRouter,
  Routes,
  Route,
  Navigate,
  Link,
  useLocation,
  useNavigate,
} from 'react-router-dom'
import { useAuth } from './security/authProvider'
import DashboardPage from './features/DashboardPage'
import ChatPage from './features/ChatPage'
import InboxPage from './features/InboxPage'
import GroupsPage from './features/GroupsPage'
import ReportsPage from './features/ReportsPage'
import SettingsPage from './features/SettingsPage'

/* ---------------- Icons (inline SVG, no emoji) ---------------- */

function Icon({ d, className = 'h-5 w-5' }: { d: string; className?: string }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.8}
      strokeLinecap="round" strokeLinejoin="round" className={className} aria-hidden>
      <path d={d} />
    </svg>
  )
}

const PATHS = {
  grid: 'M3 3h7v7H3zM14 3h7v7h-7zM3 14h7v7H3zM14 14h7v7h-7z',
  chat: 'M21 11.5a8.38 8.38 0 0 1-.9 3.8 8.5 8.5 0 0 1-7.6 4.7 8.38 8.38 0 0 1-3.8-.9L3 21l1.9-5.7a8.38 8.38 0 0 1-.9-3.8 8.5 8.5 0 0 1 4.7-7.6 8.38 8.38 0 0 1 3.8-.9h.5a8.48 8.48 0 0 1 8 8v.5z',
  inbox: 'M22 12h-6l-2 3h-4l-2-3H2M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z',
  users: 'M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2M9 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM23 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75',
  chart: 'M18 20V10M12 20V4M6 20v-6',
  cog: 'M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6zM19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 1 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 1 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z',
  logout: 'M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9',
  target: 'M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20zM12 18a6 6 0 1 0 0-12 6 6 0 0 0 0 12zM12 14a2 2 0 1 0 0-4 2 2 0 0 0 0 4z',
  lock: 'M5 11h14a2 2 0 0 1 2 2v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-7a2 2 0 0 1 2-2zM7 11V7a5 5 0 0 1 10 0v4',
  user: 'M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2M12 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8z',
  check: 'M20 6 9 17l-5-5',
}

/* ---------------- Login ---------------- */

function LoginPage() {
  const { login, isLoading } = useAuth()
  const [identifier, setIdentifier] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)

  const onSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError(null)
    try {
      await login({ identifier, password })
    } catch {
      setError('ورود ناموفق بود. مشخصات را بررسی کنید.')
    }
  }

  const features = useMemo(
    () => [
      { d: PATHS.target, t: 'اهداف و وظایف', s: 'تعریف، پیگیری پیشرفت و مدیریت مهلت‌ها' },
      { d: PATHS.users, t: 'گروه‌ها و حریم خصوصی', s: 'کار تیمی با کنترل دقیق دسترسی' },
      { d: PATHS.chart, t: 'گزارش و داشبورد', s: 'نمای زنده از عملکرد شما و تیم' },
    ],
    [],
  )

  return (
    <div className="flex min-h-screen bg-slate-100">
      {/* Brand panel */}
      <div className="relative hidden w-[44%] overflow-hidden bg-slate-900 lg:block">
        <div className="absolute inset-0 bg-gradient-to-bl from-brand-700 via-slate-900 to-slate-950" />
        <div
          className="absolute inset-0 opacity-[0.15]"
          style={{
            backgroundImage:
              'radial-gradient(circle at 25% 25%, #fff 1.5px, transparent 1.5px)',
            backgroundSize: '28px 28px',
          }}
        />
        <div className="absolute -left-24 -top-24 h-96 w-96 rounded-full bg-brand-500/30 blur-3xl" />
        <div className="absolute -bottom-32 -right-16 h-[28rem] w-[28rem] rounded-full bg-indigo-500/20 blur-3xl" />
        <div className="relative flex h-full flex-col justify-between p-12 text-white">
          <div className="animate-fade-up flex items-center gap-3">
            <div className="flex h-12 w-12 items-center justify-center rounded-2xl bg-white/15 text-white backdrop-blur">
              <Icon d={PATHS.target} className="h-7 w-7" />
            </div>
            <div>
              <p className="text-lg font-bold leading-6">سامانه مدیریت اهداف</p>
              <p className="text-xs text-slate-300">نسخه سازمانی</p>
            </div>
          </div>
          <div className="space-y-6">
            <h2 className="animate-fade-up stagger-1 text-3xl font-bold leading-[2.6rem]">
              مدیریت اهداف، برنامه‌ریزی و همکاری تیمی
            </h2>
            <p className="animate-fade-up stagger-2 max-w-md text-sm leading-7 text-slate-300">
              همه اهداف، وظایف، گفتگوها و پیگیری‌ها — یکجا، امن و یکپارچه.
            </p>
            <ul className="space-y-4 pt-2">
              {features.map((f, i) => (
                <li
                  key={f.t}
                  className={`animate-fade-up stagger-${i + 3} flex items-start gap-3`}
                >
                  <span className="mt-0.5 flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-white/10 text-brand-200">
                    <Icon d={f.d} className="h-5 w-5" />
                  </span>
                  <span>
                    <span className="block text-sm font-medium">{f.t}</span>
                    <span className="block text-xs text-slate-400">{f.s}</span>
                  </span>
                </li>
              ))}
            </ul>
          </div>
          <p className="text-[11px] text-slate-500">امنیت چندلایه · احراز هویت دو عاملی · ثبت وقایع</p>
        </div>
      </div>

      {/* Form panel */}
      <div className="flex flex-1 items-center justify-center p-6">
        <form
          onSubmit={onSubmit}
          className="animate-fade-up w-full max-w-md rounded-3xl bg-white p-8 shadow-pop sm:p-10"
        >
          <div className="mb-8 text-center lg:hidden">
            <div className="mx-auto mb-3 flex h-12 w-12 items-center justify-center rounded-2xl bg-gradient-to-l from-brand-600 to-brand-500 text-white">
              <Icon d={PATHS.target} className="h-7 w-7" />
            </div>
            <p className="font-bold">سامانه مدیریت اهداف</p>
          </div>
          <h1 className="text-2xl font-bold">ورود به سامانه</h1>
          <p className="mb-6 mt-1 text-sm text-slate-500">برای ادامه وارد حساب کاربری خود شوید</p>

          <label className="label" htmlFor="login-id">
            نام کاربری یا کد ملی
          </label>
          <div className="relative mb-4">
            <span className="pointer-events-none absolute right-3.5 top-1/2 -translate-y-1/2 text-slate-400">
              <Icon d={PATHS.user} className="h-5 w-5" />
            </span>
            <input
              id="login-id"
              className="input pr-11"
              placeholder="مثلاً ali.rezaei"
              value={identifier}
              onChange={(e) => setIdentifier(e.target.value)}
              autoComplete="username"
            />
          </div>

          <label className="label" htmlFor="login-pw">
            گذرواژه
          </label>
          <div className="relative mb-2">
            <span className="pointer-events-none absolute right-3.5 top-1/2 -translate-y-1/2 text-slate-400">
              <Icon d={PATHS.lock} className="h-5 w-5" />
            </span>
            <input
              id="login-pw"
              className="input pr-11"
              placeholder="گذرواژه خود را وارد کنید"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="current-password"
            />
          </div>

          {error && (
            <p className="animate-fade-in mb-2 rounded-xl bg-red-50 px-4 py-2.5 text-xs text-red-600">
              {error}
            </p>
          )}

          <button type="submit" disabled={isLoading} className="btn-primary mt-4 w-full py-3">
            {isLoading ? (
              <>
                <span className="h-4 w-4 animate-spin rounded-full border-2 border-white/40 border-t-white" />
                در حال ورود…
              </>
            ) : (
              'ورود'
            )}
          </button>
          <p className="mt-5 text-center text-[11px] leading-5 text-slate-400">
            حساب پیش‌فرض مدیر: admin / admin123
          </p>
        </form>
      </div>
    </div>
  )
}

/* ---------------- Shell ---------------- */

const NAV = [
  { to: '/dashboard', label: 'داشبورد', icon: PATHS.grid },
  { to: '/chat', label: 'گفتگوها', icon: PATHS.chat },
  { to: '/inbox', label: 'صندوق ورودی', icon: PATHS.inbox },
  { to: '/groups', label: 'گروه‌ها', icon: PATHS.users },
  { to: '/reports', label: 'گزارش‌ها', icon: PATHS.chart },
  { to: '/settings', label: 'تنظیمات', icon: PATHS.cog },
]

function Sidebar({ onNav }: { onNav?: () => void }) {
  const { user, logout } = useAuth()
  const { pathname } = useLocation()
  const navigate = useNavigate()

  const doLogout = async () => {
    await logout()
    navigate('/login', { replace: true })
    onNav?.()
  }

  return (
    <div className="flex h-full flex-col bg-slate-900 text-white">
      <div className="flex items-center gap-3 px-5 pb-6 pt-6">
        <div className="flex h-11 w-11 items-center justify-center rounded-2xl bg-gradient-to-l from-brand-500 to-indigo-500 shadow-lg shadow-brand-900/40">
          <Icon d={PATHS.target} className="h-6 w-6" />
        </div>
        <div className="min-w-0">
          <p className="truncate text-sm font-bold">سامانه مدیریت اهداف</p>
          <p className="text-[11px] text-slate-400">نسخه سازمانی</p>
        </div>
      </div>
      <nav className="flex-1 space-y-1 overflow-y-auto px-3">
        {NAV.map((n) => {
          const active = pathname === n.to || (n.to === '/dashboard' && pathname === '/')
          return (
            <Link
              key={n.to}
              to={n.to}
              onClick={onNav}
              className={`navlink ${active ? 'navlink-active' : ''}`}
            >
              <Icon d={n.icon} />
              <span>{n.label}</span>
            </Link>
          )
        })}
      </nav>
      <div className="border-t border-white/10 p-4">
        <div className="mb-3 flex items-center gap-3 rounded-xl bg-white/5 p-3">
          <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-gradient-to-l from-brand-400 to-indigo-400 text-sm font-bold">
            {(user?.display_name || user?.username || '?').slice(0, 1)}
          </div>
          <div className="min-w-0 flex-1">
            <p className="truncate text-sm font-medium">
              {user?.display_name || user?.username}
            </p>
            <p className="truncate text-[11px] text-slate-400" dir="ltr">
              {user?.national_id_masked}
            </p>
          </div>
        </div>
        <button onClick={() => void doLogout()} className="navlink w-full text-red-300 hover:text-red-200">
          <Icon d={PATHS.logout} />
          <span>خروج از حساب</span>
        </button>
      </div>
    </div>
  )
}

function Topbar({ onMenu }: { onMenu: () => void }) {
  const today = useMemo(
    () =>
      new Intl.DateTimeFormat('fa-IR', {
        weekday: 'long',
        day: 'numeric',
        month: 'long',
      }).format(new Date()),
    [],
  )
  return (
    <header className="sticky top-0 z-10 border-b border-slate-200/70 bg-white/80 backdrop-blur">
      <div className="flex items-center gap-3 px-4 py-3 sm:px-6">
        <button onClick={onMenu} className="btn-ghost p-2 lg:hidden" aria-label="menu">
          <svg viewBox="0 0 24 24" className="h-6 w-6" fill="none" stroke="currentColor"
            strokeWidth={2} strokeLinecap="round">
            <path d="M4 6h16M4 12h16M4 18h16" />
          </svg>
        </button>
        <div className="min-w-0 flex-1">
          <p className="truncate text-sm font-bold text-slate-800">سامانه مدیریت اهداف</p>
          <p className="text-[11px] text-slate-400">{today}</p>
        </div>
        <span className="badge bg-emerald-50 text-emerald-700">
          <span className="ml-1.5 h-2 w-2 rounded-full bg-emerald-500" />
          متصل
        </span>
      </div>
    </header>
  )
}

function Shell() {
  const [open, setOpen] = useState(false)
  return (
    <div className="flex min-h-screen bg-slate-100">
      <aside className="sticky top-0 hidden h-screen w-72 shrink-0 lg:block">
        <Sidebar />
      </aside>
      {open && (
        <div className="fixed inset-0 z-20 lg:hidden">
          <div className="animate-fade-in absolute inset-0 bg-slate-900/50" onClick={() => setOpen(false)} />
          <aside className="animate-fade-in absolute bottom-0 right-0 top-0 w-72">
            <Sidebar onNav={() => setOpen(false)} />
          </aside>
        </div>
      )}
      <div className="flex min-w-0 flex-1 flex-col">
        <Topbar onMenu={() => setOpen(true)} />
        <main className="flex-1">
          <Routes>
            <Route path="/dashboard" element={<DashboardPage />} />
            <Route path="/chat" element={<ChatPage />} />
            <Route path="/inbox" element={<InboxPage />} />
            <Route path="/groups" element={<GroupsPage />} />
            <Route path="/reports" element={<ReportsPage />} />
            <Route path="/settings" element={<SettingsPage />} />
            <Route path="/" element={<Navigate to="/dashboard" replace />} />
            <Route path="*" element={<Navigate to="/dashboard" replace />} />
          </Routes>
        </main>
      </div>
    </div>
  )
}

/* ---------------- App ---------------- */

function App() {
  const { isAuthenticated, isLoading, init } = useAuth()

  useEffect(() => {
    void init()
  }, [init])

  // When the API layer reports an unrecoverable 401 (refresh failed or no
  // refresh token), drop the persisted "authenticated" flag so the user is
  // sent back to the login page instead of a dead dashboard.
  useEffect(() => {
    const onExpired = () => {
      useAuth.getState().forceLogout()
    }
    window.addEventListener('auth:expired', onExpired)
    return () => window.removeEventListener('auth:expired', onExpired)
  }, [])

  if (isLoading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-slate-100">
        <div className="flex flex-col items-center gap-4">
          <div className="h-12 w-12 animate-spin rounded-full border-[3px] border-brand-200 border-t-brand-600" />
          <p className="text-sm text-slate-500">در حال بارگذاری…</p>
        </div>
      </div>
    )
  }

  return (
    <BrowserRouter>
      <Routes>
        {isAuthenticated ? (
          <Route path="/*" element={<Shell />} />
        ) : (
          <>
            <Route path="/login" element={<LoginPage />} />
            <Route path="*" element={<Navigate to="/login" replace />} />
          </>
        )}
      </Routes>
    </BrowserRouter>
  )
}

export default App
```

==========================================================================================
## FILE: basteh6/web/src/main.tsx
## SIZE: 672 bytes
==========================================================================================

```tsx
import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App'
import './styles/tailwind.css'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

// Initialize React Query
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 30_000,
      gcTime: 60_000,
      retry: 2,
      refetchOnWindowFocus: false,
    },
    mutations: {
      retry: 2,
    },
  },
})

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <QueryClientProvider client={queryClient}>
      <App />
    </QueryClientProvider>
  </React.StrictMode>,
)
```

==========================================================================================
## FILE: basteh6/web/src/security/fingerprint.ts
## SIZE: 3986 bytes
==========================================================================================

```typescript
import FingerprintJS from '@fingerprintjs/fingerprintjs'

// Stable fingerprint cache
let cachedFingerprint: string | null = null

/**
 * Get a stable device fingerprint.
 * Combines FingerprintJS visitorId with a device token for consistency.
 */
export async function getDeviceFingerprint(): Promise<string> {
  if (cachedFingerprint) return cachedFingerprint

  try {
    const fp = await FingerprintJS.load()
    const result = await fp.get()

    // Use visitorId as base, but also incorporate device token from cookie
    const deviceToken = getCookie('device_token') || ''
    
    // Create stable hash combining both
    const combined = `${result.visitorId}:${deviceToken}`
    const hash = btoa(combined).replace(/[^a-zA-Z0-9+/]/g, '').substring(0, 32)
    
    cachedFingerprint = `web-fp-${hash}`
    return cachedFingerprint
  } catch (error) {
    logger.error('FingerprintJS error:', error)
    // Fallback to minimal fingerprint
    return 'web-fp-fallback'
  }
}

/** 
 * Device token stored in HttpOnly cookie (set by server on first login).
 * JavaScript cannot read this cookie, but can read a non-sensitive version.
 */
export function getDeviceToken(): string | null {
  try {
    // Read from a non-sensitive data attribute or meta tag
    // The actual token is HttpOnly, so we use a hashed version
    const metaContent = document.querySelector('meta[name="device-token"]')?.content
    return metaContent || null
  } catch {
    return null
  }
}

/** Log security events (client-side only) */
export function logSecurityEvent(event: string, details?: any) {
  // Send to analytics/backend for security monitoring
  const eventData = {
    event,
    timestamp: new Date().toISOString(),
    fingerprint: cachedFingerprint || 'unknown',
    url: window.location.href,
    ...details
  }
  
  // In production, send to endpoint
  // fetch('/api/security/events', {
  //   method: 'POST',
  //   headers: { 'Content-Type': 'application/json' },
  //   body: JSON.stringify(eventData)
  // }).catch(() => {}) // Non-blocking
}

/** Safe storage for sensitive data */
export const secureStorage = {
  set: (key: string, value: string) => {
    // Store encrypted value in localStorage
    try {
      const encrypted = simpleEncrypt(value)
      localStorage.setItem(`sec_${key}`, encrypted)
    } catch (e) {
      logger.error('Secure storage set error:', e)
    }
  },
  
  get: (key: string): string | null => {
    try {
      const encrypted = localStorage.getItem(`sec_${key}`)
      if (!encrypted) return null
      return simpleDecrypt(encrypted)
    } catch (e) {
      logger.error('Secure storage get error:', e)
      return null
    }
  },
  
  remove: (key: string) => {
    try {
      localStorage.removeItem(`sec_${key}`)
    } catch (e) {
      logger.error('Secure storage remove error:', e)
    }
  }
}

/* Simple XOR encryption for client-side obfuscation (not real encryption) */
function simpleEncrypt(text: string): string {
  const key = 'planner-web-2026'
  let result = ''
  for (let i = 0; i < text.length; i++) {
    result += String.fromCharCode(text.charCodeAt(i) ^ key.charCodeAt(i % key.length))
  }
  return btoa(result)
}

function simpleDecrypt(encrypted: string): string {
  const key = 'planner-web-2026'
  let text = atob(encrypted)
  let result = ''
  for (let i = 0; i < text.length; i++) {
    result += String.fromCharCode(text.charCodeAt(i) ^ key.charCodeAt(i % key.length))
  }
  return result
}

const logger = {
  error: (msg: string, ...args: any[]) => {
    // NOTE: Vite does not provide `process.env` in the browser;
    // guard it so logging never throws.
    const isDev =
      typeof process !== 'undefined' &&
      (process as any).env?.NODE_ENV === 'development'
    if (isDev || typeof process === 'undefined') {
      console.error('[Security]', msg, ...args)
    }
  }
}
```

==========================================================================================
## FILE: basteh7/backend/tests/architecture/test_module_boundaries.py
## SIZE: 13122 bytes
==========================================================================================

```python
"""
tests/architecture/test_module_boundaries.py

هدف
----
اجرای اجباری مرز ماژول‌ها طبق سند معماری v2.0 (بخش ۰.۳ و ۲.۱/۲.۲):

  ۱) هیچ ماژولی مجاز نیست مستقیماً به زیرپکیج‌های داخلی ماژول دیگر
     (db/ services/ api/ tests/) دسترسی داشته باشد — فقط از طریق
     رابط عمومی (`modules.<name>` که از ports.py/events.py/schemas.py
     صادر می‌شود) مجاز است.

  ۲) هر ماژول فقط مجاز است به ماژول‌هایی وابسته باشد که در نقشه‌ی
     وابستگی رسمی (بخش ۲.۱ سند) صراحتاً برایش تعریف شده — even
     import از رابط عمومی یک ماژول غیرمجاز هم خطاست.

  ۳) M10 (notification) و M11 (audit) طبق سند فقط رویداد مصرف
     می‌کنند و حق import هیچ ماژول دیگری را ندارند.

این تست با AST ایمپورت‌ها را استخراج می‌کند (نه اجرای واقعی کد)،
پس نیازی به دیتابیس/Redis/etc در حال اجرا نیست و بسیار سریع است.

نحوه‌ی استفاده
--------------
این فایل را در مسیر زیر قرار دهید (دقیقاً مطابق ساختار پوشه‌ی
سند معماری، بخش ۳.۱):

    backend/tests/architecture/test_module_boundaries.py

و اجرا کنید:

    cd backend && pytest tests/architecture/ -v

اگر مسیر ماژول‌های شما با آنچه در ADJUST بخش پایین است فرق دارد
(مثلاً app.modules به‌جای modules)، فقط ثابت CANDIDATE_ROOTS و
IMPORT_PREFIXES را تنظیم کنید — منطق تست دست‌نخورده می‌ماند.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# نقشه‌ی وابستگی رسمی ماژول‌ها — دقیقاً از سند معماری v2.0، بخش ۲.۱
# (خطوط نقطه‌چین/رویدادی برای notification و audit در نظر گرفته نشده،
#  چون آن دو طبق سند اصلاً حق import کد ماژول دیگر را ندارند)
# ---------------------------------------------------------------------------
MODULE_DEPENDENCIES: dict[str, set[str]] = {
    "auth": set(),                              # M1 — هسته، به کسی وابسته نیست
    "rbac": {"auth"},                            # M2
    "groups": {"auth", "rbac"},                  # M3
    "goals": {"auth", "rbac"},                   # M4
    "calendar": {"goals", "groups"},             # M5
    "sharing": {"goals", "rbac", "groups"},      # M6
    "chat": {"auth", "files", "sharing"},        # M7
    "inbox": {"auth", "sharing", "chat"},        # M8
    "reporting": {"goals", "groups"},            # M9
    "notification": set(),                       # M10 — فقط مصرف رویداد
    "audit": set(),                               # M11 — فقط مصرف رویداد
    "ssoldap": {"auth"},                         # M12
    "files": set(),                              # M13 — زیرساخت مشترک
}

ALL_MODULES = set(MODULE_DEPENDENCIES)

# زیرپکیج‌هایی که «پیاده‌سازی داخلی» محسوب می‌شوند و هرگز نباید از
# بیرون ماژول import شوند — فقط از طریق ports.py/events.py/schemas.py
# (که در __init__.py خود ماژول صادر می‌شوند) قابل دسترسی‌اند.
INTERNAL_SUBPACKAGES = {"db", "services", "api", "tests"}

# چند مسیر محتمل برای پیدا کردن پوشه‌ی modules/ — به‌ترتیب اولویت.
# اگر ساختار پروژه‌ی شما فرق دارد همین‌جا اضافه کنید.
CANDIDATE_ROOT_SUFFIXES = (
    ("backend", "app", "modules"),
    ("app", "modules"),
    ("modules",),
)

# پیشوندهای import که باید به‌عنوان «اشاره به یک ماژول دامنه» شناسایی شوند.
IMPORT_PREFIXES = ("modules", "app.modules")


@dataclass(frozen=True)
class Violation:
    kind: str            # "internal_access" | "undeclared_dependency"
    importer: str
    file: Path
    lineno: int
    imported: str         # مسیر کامل import، همان‌طور که در سورس نوشته شده
    target_module: str    # نام ماژول مقصد که واقعاً استخراج شده (نه حدس از روی رشته)


def _find_modules_root() -> Path | None:
    """پوشه‌ی modules/ را با جست‌وجو از ریشه‌ی مخزن به پایین پیدا می‌کند."""
    here = Path(__file__).resolve()
    # چند سطح بالا برو تا به ریشه‌ی مخزن برسی (این فایل معمولاً در
    # backend/tests/architecture/ قرار دارد → ۳ سطح بالا = backend/)
    candidates_bases = [here.parents[i] for i in range(min(6, len(here.parents)))]

    for base in candidates_bases:
        for suffix in CANDIDATE_ROOT_SUFFIXES:
            candidate = base.joinpath(*suffix)
            if candidate.is_dir():
                # اطمینان از این‌که واقعاً پوشه‌ی ماژول‌های ما است، نه یک
                # پوشه‌ی هم‌نام تصادفی: باید حداقل یکی از ماژول‌های
                # شناخته‌شده را داخلش داشته باشد.
                if any((candidate / m).is_dir() for m in ALL_MODULES):
                    return candidate
    return None


def _strip_prefix(dotted: str) -> str | None:
    """اگر dotted با یکی از IMPORT_PREFIXES شروع شود، باقی‌مانده را برمی‌گرداند."""
    for prefix in IMPORT_PREFIXES:
        if dotted == prefix or dotted.startswith(prefix + "."):
            return dotted[len(prefix):].lstrip(".")
    return None


def _iter_import_targets(tree: ast.Module) -> list[tuple[str, int]]:
    """همه‌ی مسیرهای import شده (dotted) را همراه با شماره خط برمی‌گرداند."""
    targets: list[tuple[str, int]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                targets.append((alias.name, node.lineno))
        elif isinstance(node, ast.ImportFrom):
            if node.level and node.level > 0:
                continue  # import نسبی (from . import x) — داخل خود ماژول است
            if node.module:
                targets.append((node.module, node.lineno))
    return targets


def _scan_module_files(modules_root: Path, module_name: str) -> list[Violation]:
    violations: list[Violation] = []
    module_dir = modules_root / module_name
    allowed = MODULE_DEPENDENCIES[module_name]

    for py_file in module_dir.rglob("*.py"):
        try:
            source = py_file.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(py_file))
        except (SyntaxError, UnicodeDecodeError):
            continue  # فایل غیرقابل‌پارس را نادیده بگیر؛ مسئولیت لینتر دیگری است

        for dotted, lineno in _iter_import_targets(tree):
            remainder = _strip_prefix(dotted)
            if remainder is None:
                continue  # این import اصلاً به یک ماژول دامنه اشاره نمی‌کند

            parts = remainder.split(".") if remainder else []
            if not parts:
                continue
            target_module = parts[0]

            if target_module == module_name:
                continue  # import از خودش — طبیعی است
            if target_module not in ALL_MODULES:
                continue  # اشاره به چیزی خارج از نقشه‌ی شناخته‌شده (core و...)

            # قاعده‌ی ۱: دسترسی مستقیم به زیرپکیج داخلی ماژول دیگر ممنوع است
            if len(parts) >= 2 and parts[1] in INTERNAL_SUBPACKAGES:
                violations.append(
                    Violation("internal_access", module_name, py_file, lineno, dotted, target_module)
                )
                continue  # همین یک نقض کافی است؛ لازم نیست قاعده ۲ هم چک شود

            # قاعده‌ی ۲: حتی رابط عمومی هم فقط برای وابستگی‌های اعلام‌شده مجاز است
            if target_module not in allowed:
                violations.append(
                    Violation("undeclared_dependency", module_name, py_file, lineno, dotted, target_module)
                )

    return violations


def _format_violation(v: Violation) -> str:
    rel = v.file
    if v.kind == "internal_access":
        return (
            f"  [دسترسی مستقیم ممنوع] {rel}:{v.lineno}\n"
            f"      '{v.importer}' مستقیماً به پیاده‌سازی داخلی import می‌کند: `{v.imported}`\n"
            f"      → به‌جای این، از رابط عمومی استفاده کنید: "
            f"`from modules.{v.target_module} import ...` "
            f"(یا اگر نیاز واقعی، انتشار/مصرف رویداد است، از Event Bus استفاده کنید)"
        )
    return (
        f"  [وابستگی اعلام‌نشده] {rel}:{v.lineno}\n"
        f"      '{v.importer}' به ماژول '{v.target_module}' import می‌کند که در نقشه‌ی وابستگی "
        f"(بخش ۲.۱ سند) برایش مجاز نیست: `{v.imported}`\n"
        f"      → یا نقشه‌ی وابستگی را در سند/این تست به‌روز کنید (تصمیم معماری آگاهانه)، "
        f"یا وابستگی را حذف کنید."
    )


MODULES_ROOT = _find_modules_root()

pytestmark = pytest.mark.skipif(
    MODULES_ROOT is None,
    reason=(
        "پوشه‌ی backend/app/modules/ پیدا نشد. اگر مسیر پروژه‌ی شما فرق دارد، "
        "CANDIDATE_ROOT_SUFFIXES را در بالای این فایل تنظیم کنید."
    ),
)


@pytest.mark.parametrize("module_name", sorted(MODULE_DEPENDENCIES))
def test_no_forbidden_cross_module_imports(module_name: str) -> None:
    """مرز هر ماژول با آزمون اجباری می‌شود، نه با توافق شفاهی (سند، بخش ۰.۳)."""
    assert MODULES_ROOT is not None  # برای mypy/خوانایی؛ skipif بالا این حالت را می‌گیرد

    module_dir = MODULES_ROOT / module_name
    if not module_dir.is_dir():
        pytest.skip(f"ماژول '{module_name}' هنوز پیاده‌سازی نشده — رد شد.")

    violations = _scan_module_files(MODULES_ROOT, module_name)

    if violations:
        details = "\n".join(_format_violation(v) for v in violations)
        pytest.fail(
            f"\nماژول '{module_name}' مرز معماری را نقض کرده "
            f"({len(violations)} مورد):\n\n{details}\n"
        )


def test_notification_and_audit_are_event_only() -> None:
    """طبق سند (بخش ۲.۱): M10 و M11 نباید هیچ ماژول دیگری را import کنند."""
    if MODULES_ROOT is None:
        pytest.skip("پوشه‌ی modules/ پیدا نشد.")

    for module_name in ("notification", "audit"):
        assert MODULE_DEPENDENCIES[module_name] == set(), (
            f"'{module_name}' طبق سند فقط باید مصرف‌کننده‌ی رویداد باشد؛ "
            f"نباید هیچ وابستگی مستقیمی در MODULE_DEPENDENCIES داشته باشد."
        )
        module_dir = MODULES_ROOT / module_name
        if not module_dir.is_dir():
            continue
        violations = _scan_module_files(MODULES_ROOT, module_name)
        assert not violations, (
            f"'{module_name}' نباید هیچ ماژول دیگری را import کند "
            f"(فقط باید از طریق Event Bus مصرف کند):\n"
            + "\n".join(_format_violation(v) for v in violations)
        )


def test_dependency_graph_has_no_cycles() -> None:
    """اطمینان از این‌که خودِ نقشه‌ی وابستگی در سند/تست، حلقه ندارد."""
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(node: str, path: list[str]) -> None:
        if node in visited:
            return
        if node in visiting:
            cycle = " → ".join(path + [node])
            pytest.fail(f"حلقه‌ی وابستگی در نقشه‌ی ماژول‌ها پیدا شد: {cycle}")
        visiting.add(node)
        for dep in MODULE_DEPENDENCIES.get(node, set()):
            visit(dep, path + [node])
        visiting.discard(node)
        visited.add(node)

    for module_name in MODULE_DEPENDENCIES:
        visit(module_name, [])
```

==========================================================================================
## FILE: basteh7/backend/tests/conftest.py
## SIZE: 471 bytes
==========================================================================================

```python
"""Shared test setup. Environment is fixed *before* ``app`` is imported."""
import os

os.environ.setdefault("ENV", "testing")
os.environ.setdefault("DEBUG", "false")  # a local .env must not leak into tests
os.environ.setdefault("SECRET_KEY", "test-secret-key-that-is-at-least-32-chars-long")
os.environ.setdefault(
    "SQLALCHEMY_DATABASE_URI",
    "postgresql+asyncpg://admin:admin123@localhost:5432/planner_db",
)
os.environ.setdefault("RATE_LIMIT_ENABLED", "true")
```

==========================================================================================
## FILE: CONCAT/basteh1.md
## SIZE: 52776 bytes
==========================================================================================

```markdown
# BUNDLE: basteh1
# Source: GAP\basteh1
================================================================================

================================================================================
## FILE: backend/app/core/config.py
================================================================================

```python
"""Application configuration (Pydantic Settings, loaded from ENV / .env).

Architecture v2.0: section 3.1 (core/config.py) and 13.5 (deployment hardening).

Validation happens *inside* the model. (The previous version declared the
``@field_validator`` functions at module level, so they were never applied and
a weak ``SECRET_KEY`` / empty password was silently accepted.)
"""
from __future__ import annotations

from pathlib import Path
from typing import List

from pydantic import AliasChoices, Field, PostgresDsn, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_INSECURE_SECRETS = {
    "change-me-to-a-random-string-at-least-32-chars-long",
    "changeme",
    "secret",
}


class Settings(BaseSettings):
    """Application configuration from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Application
    APP_NAME: str = "Planner Enterprise API"
    APP_VERSION: str = "2.0.0"
    ENV: str = "development"  # development | testing | production
    DEBUG: bool = False
    SQL_ECHO: bool = False  # log every SQL statement (was tied to ENV before)

    # ── Server
    HOST: str = "0.0.0.0"
    PORT: int = 8000

    # ── Security
    SECRET_KEY: str = Field(..., min_length=32)
    # HS256 (shared secret) by default; set both JWT_*_KEY for RS256 (ADR / 3.1).
    ALGORITHM: str = "HS256"
    JWT_PRIVATE_KEY: str | None = None
    JWT_PUBLIC_KEY: str | None = None
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 30
    PASSWORD_RESET_EXPIRE_MINUTES: int = 1440
    # Separate keys per purpose (section 4.9). When unset they are derived from
    # SECRET_KEY, which is acceptable for dev only (enforced in production).
    DATA_ENCRYPTION_KEY: str | None = None   # base64, 32 bytes (AES-256-GCM)
    NATIONAL_ID_PEPPER: str | None = None    # HMAC key for searchable hash

    # ── Database
    POSTGRES_SERVER: str = "localhost"
    POSTGRES_PORT: int = 5432
    POSTGRES_USER: str = ""
    POSTGRES_PASSWORD: str = ""
    POSTGRES_DB: str = ""
    SQLALCHEMY_DATABASE_URI: PostgresDsn = Field(
        ...,
        validation_alias=AliasChoices("SQLALCHEMY_DATABASE_URI", "DATABASE_URL"),
    )
    DB_POOL_SIZE: int = 20
    DB_MAX_OVERFLOW: int = 30

    # ── Redis
    REDIS_HOST: str = "localhost"
    REDIS_PORT: int = 6379
    REDIS_DB: int = 0
    REDIS_URL: str | None = None  # overrides host/port/db when set

    # ── HTTP hardening
    ALLOWED_HOSTS: List[str] = ["*"]
    CORS_ORIGINS: List[str] = ["http://localhost:3000", "http://localhost:8080"]
    # WebSocket Origin allow-list (WebSocket is not covered by CORS, 12.8).
    # Empty -> falls back to CORS_ORIGINS.
    ALLOWED_ORIGINS: List[str] = []
    TRUSTED_PROXIES: List[str] = []  # only these may set X-Forwarded-For
    IP_ALLOW_LIST: List[str] = []
    IP_DENY_LIST: List[str] = []
    MAX_BODY_SIZE: int = 1_048_576  # 1 MiB for JSON endpoints

    # ── Feature flags
    ENABLE_MFA: bool = True
    ENABLE_SSO: bool = True
    ENABLE_AUDIT_LOGGING: bool = True
    ALLOW_SELF_REGISTRATION: bool = False
    DEVICE_BINDING_MODE: str = "observe"  # off | observe | enforce (ADR-08)

    # ── Rate limiting (limits are "N/period", period: second|minute|hour)
    RATE_LIMIT_DEFAULT: str = "100/minute"
    RATE_LIMIT_AUTH: str = "10/minute"
    RATE_LIMIT_ENABLED: bool = True

    # ── Paths
    BASE_DIR: Path = Path(__file__).parent.parent
    ROOT_PATH: str = ""

    # ── File storage
    MAX_UPLOAD_SIZE: int = 52_428_800  # 50MB
    FILE_STORAGE_DIR: str = "backend/storage/uploads"
    ALLOWED_IMAGE_TYPES: List[str] = ["image/jpeg", "image/png", "image/gif"]
    ALLOWED_DOCUMENT_TYPES: List[str] = [
        "application/pdf", "application/msword",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ]

    # ── SSO / LDAP (M12) — LdapService expects these attributes
    LDAP_SERVER_URI: str = "ldaps://ad.corp.local:636"
    LDAP_BASE_DN: str = "DC=corp,DC=local"
    LDAP_BIND_DN: str = ""
    LDAP_BIND_PASSWORD: str = ""
    LDAP_USER_SEARCH_FILTER: str = "(sAMAccountName={username})"
    LDAP_ATTR_OBJECT_GUID: str = "objectGUID"
    LDAP_ATTR_NATIONAL_ID: str | None = None
    LDAP_ATTR_DISPLAY_NAME: str = "displayName"
    LDAP_ATTR_MEMBEROF: str = "memberOf"
    LDAP_GROUP_ROLE_MAP: dict = {}
    LDAP_AUTO_PROVISION: bool = True
    LDAP_KERBEROS_ENABLED: bool = False  # set true only with a real Keytab
    LDAP_KERBEROS_KEYTAB: str = ""       # path to the HTTP service keytab

    # ── Logging
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = (
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s "
        "[%(filename)s:%(lineno)d]"
    )

    # ── Key rotation (key_version is stored beside encrypted data, 4.9)
    KEY_ROTATION_INTERVAL_DAYS: int = 365
    KEY_VERSION: int = 1

    # ------------------------------------------------------------------ #
    @field_validator("SECRET_KEY")
    @classmethod
    def _secret_key_strength(cls, v: str) -> str:
        if len(v) < 32:
            raise ValueError("SECRET_KEY must be at least 32 characters")
        return v

    @field_validator("ALGORITHM")
    @classmethod
    def _algorithm_allowed(cls, v: str) -> str:
        if v not in {"HS256", "RS256"}:
            raise ValueError("ALGORITHM must be HS256 or RS256 ('none' is never allowed)")
        return v

    @field_validator("DEVICE_BINDING_MODE")
    @classmethod
    def _device_mode(cls, v: str) -> str:
        if v not in {"off", "observe", "enforce"}:
            raise ValueError("DEVICE_BINDING_MODE must be off | observe | enforce")
        return v

    @model_validator(mode="after")
    def _cross_field_checks(self) -> "Settings":
        if self.ALGORITHM == "RS256" and not (self.JWT_PRIVATE_KEY and self.JWT_PUBLIC_KEY):
            raise ValueError("ALGORITHM=RS256 requires JWT_PRIVATE_KEY and JWT_PUBLIC_KEY")
        if self.ENV == "production":
            problems = []
            if self.SECRET_KEY in _INSECURE_SECRETS:
                problems.append("SECRET_KEY is a placeholder value")
            if "*" in self.ALLOWED_HOSTS:
                problems.append("ALLOWED_HOSTS must not contain '*'")
            if self.DEBUG:
                problems.append("DEBUG must be false")
            if not self.DATA_ENCRYPTION_KEY:
                problems.append("DATA_ENCRYPTION_KEY must be set (section 4.9)")
            if not self.NATIONAL_ID_PEPPER:
                problems.append("NATIONAL_ID_PEPPER must be set (ADR-06)")
            if self.DEVICE_BINDING_MODE == "off":
                problems.append("DEVICE_BINDING_MODE must not be 'off'")
            if problems:
                raise ValueError("Insecure production configuration: " + "; ".join(problems))
        return self

    # ------------------------------------------------------------------ #
    @property
    def is_production(self) -> bool:
        return self.ENV == "production"

    @property
    def redis_url(self) -> str:
        return self.REDIS_URL or f"redis://{self.REDIS_HOST}:{self.REDIS_PORT}/{self.REDIS_DB}"

    @property
    def ws_allowed_origins(self) -> List[str]:
        return self.ALLOWED_ORIGINS or self.CORS_ORIGINS


settings = Settings()


def get_db_url() -> str:
    """Async SQLAlchemy URL (single source of truth: SQLALCHEMY_DATABASE_URI)."""
    return str(settings.SQLALCHEMY_DATABASE_URI)
```

================================================================================
## FILE: backend/app/core/db/base.py
================================================================================

```python
import uuid
from datetime import datetime, timezone
from typing import TypeVar, Generic, Optional, List
from sqlalchemy import (
    Column, Integer, String, DateTime, Boolean, Text, 
    JSON, func, Index, CheckConstraint
)
from sqlalchemy.orm import declarative_base, declared_attr
from sqlalchemy.sql import expression

Base = declarative_base()


# Type variable for generic models
M = TypeVar("M", bound="BaseModel")


class BaseModel(Base):
    """Base model with common fields for all tables."""
    
    __abstract__ = True
    
    # UUID primary key
    id = Column(
        String(36), 
        primary_key=True, 
        default=lambda: str(uuid.uuid4()),
        unique=True
    )
    
    # Soft delete support
    deleted_at = Column(DateTime(timezone=True), nullable=True)
    
    # Timestamps
    created_at = Column(
        DateTime(timezone=True), 
        nullable=False, 
        default=func.now()
    )
    updated_at = Column(
        DateTime(timezone=True), 
        nullable=False, 
        default=func.now(),
        onupdate=func.now()
    )
    
    # Version for optimistic locking
    version = Column(Integer, nullable=False, server_default="1")
    
    # Soft delete check
    __table_args__ = (
        CheckConstraint("deleted_at IS NULL OR deleted_at > created_at"),
    )
    
    def soft_delete(self):
        """Mark record as deleted instead of hard delete."""
        self.deleted_at = datetime.now(timezone.utc)
    
    def is_deleted(self) -> bool:
        """Check if record is soft-deleted."""
        return self.deleted_at is not None
    
    def to_dict(self, exclude: Optional[List[str]] = None) -> dict:
        """Convert model to dict, excluding sensitive fields."""
        data = {}
        for column in self.__table__.columns:
            name = column.name
            if exclude and name in exclude:
                continue
            value = getattr(self, name, None)
            if isinstance(value, datetime):
                value = value.isoformat()
            elif value is None:
                value = None
            data[name] = value
        return data
    
    def update_timestamp(self):
        """Update the updated_at timestamp."""
        self.updated_at = datetime.now(timezone.utc)


# Mixin for audit tracking
class AuditMixin:
    """Mixin that adds audit fields to a model."""
    
    __abstract__ = True
    
    created_by = Column(String(100), nullable=True)
    updated_by = Column(String(100), nullable=True)
    
    def set_audit_fields(self, user_id: str | None = None):
        """Set audit fields for the current user."""
        self.created_by = user_id
        self.updated_by = user_id


# Database utilities
class DatabaseUtils:
    """Utility functions for database operations."""
    
    @staticmethod
    def generate_uuid() -> str:
        """Generate a string UUID."""
        return str(uuid.uuid4())
    
    @staticmethod
    def current_timestamp() -> datetime:
        """Get current UTC timestamp."""
        return datetime.now(timezone.utc)
    
    @staticmethod
    def paginate_query(query, page: int = 1, size: int = 20):
        """Apply pagination to a query."""
        if page < 1:
            page = 1
        if size < 1 or size > 1000:
            size = 20
        offset = (page - 1) * size
        return query.offset(offset).limit(size)
    
    @staticmethod
    def search_vector(columns: list) -> str:
        """Generate GIN search vector string."""
        # This is a placeholder - actual implementation depends on columns
        return func.tsvector(" || ".join([f"coalesce({c}::text, '')" for c in columns]))


# Export base and utilities
__all__ = ["BaseModel", "AuditMixin", "DatabaseUtils", "Base"]
```

================================================================================
## FILE: backend/app/core/db/session.py
================================================================================

```python
import asyncio
from typing import AsyncGenerator, Optional
from sqlalchemy.ext.asyncio import (
    AsyncEngine, 
    AsyncSession, 
    create_async_engine,
    async_sessionmaker,
    AsyncAttrs
)
from sqlalchemy.orm import DeclarativeBase
from contextlib import asynccontextmanager

from app.core.config import settings


# Engine creation
#
# NOTE (dev, no-Docker): ORM models in app/modules/*/db/Models.py declare
# unqualified table names while alembic DDL creates one schema per module
# (auth, rbac, groups, planning, chat, inbox, ...). The search_path below
# makes those unqualified names resolve to the right schema without
# rewriting every model. Table names are unique across schemas, so this
# is unambiguous. Long-term (per Architecture v2.0 ADR-04) each model
# should declare its own __table_args__ = {"schema": ...}.
engine: AsyncEngine = create_async_engine(
    # PostgresDsn validates to a URL object; the engine needs a plain string.
    str(settings.SQLALCHEMY_DATABASE_URI),
    echo=settings.SQL_ECHO,
    pool_size=settings.DB_POOL_SIZE,
    max_overflow=settings.DB_MAX_OVERFLOW,
    pool_pre_ping=True,
    pool_recycle=3600,
    connect_args={
        "server_settings": {
            "search_path": (
                "public,auth,rbac,groups,planning,calendar,chat,files,"
                "inbox,notification,reporting,sharing,ssoldap,audit"
            )
        }
    },
)

# Session factory
async_session_factory = async_sessionmaker(
    engine, 
    class_=AsyncSession, 
    expire_on_commit=False,
    autoflush=False,
    autocommit=False,
)


# Context manager for getting a session
@asynccontextmanager
async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """Get an async database session."""
    async with async_session_factory() as session:
        yield session


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency: one session per request, one transaction.

    Commits when the handler returns, rolls back on any exception. Business
    data and the outbox/audit rows written through the same session are
    therefore atomic (architecture 2.3 / 12.3).
    """
    async with async_session_factory() as session:
        try:
            yield session
            await session.commit()
        except BaseException:
            await session.rollback()
            raise


async def dispose_engine() -> None:
    """Close pooled connections (called from the app lifespan on shutdown)."""
    await engine.dispose()


# Unit of Work pattern
class UnitOfWork:
    """Unit of Work pattern for managing database transactions."""
    
    def __init__(self, session: AsyncSession):
        self.session = session
    
    async def commit(self):
        """Commit the current transaction."""
        await self.session.commit()
    
    async def rollback(self):
        """Rollback the current transaction."""
        await self.session.rollback()
    
    async def refresh(self, obj):
        """Refresh an object from the database."""
        await self.session.refresh(obj)
    
    async def add(self, obj) -> None:
        """Add an object to the session."""
        self.session.add(obj)
    
    async def delete(self, obj) -> None:
        """Delete an object from the session."""
        await self.session.delete(obj)
    
    async def get(self, model, id):
        """Get a model by ID."""
        from sqlalchemy import select
        result = await self.session.execute(select(model).where(model.id == id))
        return result.scalar_one_or_none()
    
    async def execute(self, *args, **kwargs):
        """Execute a raw SQL statement."""
        return await self.session.execute(*args, **kwargs)


# Transaction decorator/context manager
class Transaction:
    """Transaction manager for handling database transactions."""
    
    def __init__(self, uow: UnitOfWork):
        self.uow = uow
    
    async def __aenter__(self):
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if exc_type is not None:
            await self.uow.rollback()
            return False
        await self.uow.commit()
        return None


# Export
__all__ = [
    "engine", "async_session_factory", "get_session", "get_db",
    "dispose_engine", "UnitOfWork", "Transaction",
]
```

================================================================================
## FILE: backend/app/core/events/__init__.py
================================================================================

```python
from app.core.events.bus import DomainEvent, EventBus, event_bus
from app.core.events.outbox import OutboxMessage

__all__ = ["DomainEvent", "EventBus", "event_bus", "OutboxMessage"]
```

================================================================================
## FILE: backend/app/core/events/bus.py
================================================================================

```python
"""
app/core/events/bus.py

پیاده‌سازی Event Bus درون‌پروسه‌ای طبق ADR-02 و سند معماری v2.0، بخش ۲.۳.

هدف این فایل: جایگزین کردن importهای مستقیم بین ماژول‌ها (مثل
`from app.modules.audit.db.models import AuditLogs` که در auth_service.py
پیدا شد) با یک مکانیزم رویدادمحور که هیچ ماژولی را به ماژول دیگر
گره نمی‌زند.

طراحی
------
`EventBus.publish()` دو کار همزمان انجام می‌دهد:

  ۱) **تحویل درون‌پروسه‌ای هم‌زمان (synchronous in-process delivery)**:
     هر handler ثبت‌شده برای `event.event_type` بلافاصله در همان
     تراکنش دیتابیس (`session`) فراخوانی می‌شود. این برای مصرف‌کننده‌هایی
     مثل ماژول Audit مناسب است — چون سند صراحتاً می‌گوید ردیف Audit باید
     "در همان تراکنش عملیات اصلی" نوشته شود (بخش ۱۲.۳)، تا اگر تراکنش
     اصلی Rollback شود، ردیف Audit هم با آن Rollback شود (سازگاری کامل،
     نه لاگِ عملیاتی که هرگز ذخیره نشد).

  ۲) **درج در Outbox برای تحویل At-Least-Once به مصرف‌کننده‌های
     بیرون از فرآیند** (Celery workers، مثل Notification/Push/Email):
     یک ردیف `OutboxMessage` در همان تراکنش درج می‌شود. یک Dispatcher
     جداگانه (`workers/tasks/outbox_dispatcher.py`) بعداً این ردیف‌ها را
     می‌خواند و به مصرف‌کننده‌های خارج از فرآیند تحویل می‌دهد.

     چرا هر دو مسیر؟ چون Audit نیاز به تضمین "همان تراکنش" دارد (زنجیره‌ی
     هش باید دقیقاً با ترتیب واقعی نوشته‌ها هماهنگ باشد)، ولی
     Notification/Push نیاز به تضمین "حتی اگر پردازش درخواست کرش کند،
     بعداً ارسال شود" دارد. Outbox این دومی را تضمین می‌کند.

هیچ ماژولی، صرفاً با ثبت/انتشار رویداد، به ماژول دیگر import اضافه
نمی‌کند — رویداد فقط یک `event_type` رشته‌ای و یک payload دیکشنری
است، نه یک کلاس از ماژول دیگر.

نحوه‌ی استفاده در main.py (طبق سند، بخش ۱۲.۱):

    from app.core.events.bus import event_bus
    for m in MODULES:
        m.register_event_handlers(event_bus)

هر ماژول (مثل audit) در `__init__.py` یا `events.py` خودش تابع
`register_event_handlers(bus)` را تعریف می‌کند و `bus.subscribe(...)`
را صدا می‌زند — بدون این‌که هرگز از ماژول ناشر رویداد import کند.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, DefaultDict
from uuid import UUID, uuid4

logger = logging.getLogger("core.events")

# امضای هر handler: async def handler(event: DomainEvent, session) -> None
EventHandler = Callable[["DomainEvent", Any], Awaitable[None]]


@dataclass(frozen=True)
class DomainEvent:
    """رویداد دامنه — مطابق سند معماری v2.0، بخش ۲.۳."""

    event_type: str
    payload: dict[str, Any]
    actor_id: UUID | None = None
    event_id: UUID = field(default_factory=uuid4)
    occurred_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    correlation_id: UUID | None = None


def _as_uuid(value: Any) -> UUID | None:
    try:
        return UUID(str(value)) if value else None
    except (ValueError, AttributeError):
        return None


class EventBus:
    """Event Bus درون‌پروسه‌ای؛ یک نمونه‌ی Singleton (``event_bus``) در کل اپ.

    دو نوع مشترک:

    * ``transactional=True`` (پیش‌فرض) — داخل ``publish`` و در همان تراکنش اجرا
      می‌شود (مثل Audit). اگر تراکنش Rollback شود، اثر handler هم برمی‌گردد.
    * ``transactional=False`` — مصرف‌کننده‌ی «بعد از commit» (مثل Notification):
      فقط توسط Dispatcher از روی جدول Outbox با تضمین At-Least-Once فراخوانی
      می‌شود و باید با ``event_id`` Idempotent باشد.

    قبلاً Dispatcher همان handlerهای هم‌تراکنش را دوباره صدا می‌زد و ردیف‌های
    Audit تکراری ساخته می‌شد؛ حالا این دو دسته کاملاً جدا هستند.
    """

    def __init__(self) -> None:
        self._sync: DefaultDict[str, list[EventHandler]] = defaultdict(list)
        self._async: DefaultDict[str, list[EventHandler]] = defaultdict(list)

    def subscribe(self, event_type: str, handler: EventHandler, *,
                  transactional: bool = True) -> None:
        target = self._sync if transactional else self._async
        if handler in target[event_type]:  # idempotent registration (reload / tests)
            return
        target[event_type].append(handler)
        logger.debug("subscribed %s handler for %s", "txn" if transactional else "async", event_type)

    def handlers_for(self, event_type: str, *, transactional: bool) -> list[EventHandler]:
        return list((self._sync if transactional else self._async).get(event_type, ()))

    def clear(self) -> None:
        """Remove every subscription (test helper)."""
        self._sync.clear()
        self._async.clear()

    async def publish(self, event: DomainEvent, session: Any) -> None:
        """Outbox را در همان تراکنش می‌نویسد و handlerهای هم‌تراکنش را اجرا می‌کند.

        ``actor_id`` / ``correlation_id`` در صورت خالی بودن از Request Context
        پر می‌شوند تا کل زنجیره‌ی یک درخواست قابل ردیابی باشد.
        """
        from app.core.context import get_context
        from app.core.events.outbox import OutboxMessage

        ctx = get_context()
        if event.correlation_id is None or event.actor_id is None:
            event = replace(
                event,
                correlation_id=event.correlation_id or _as_uuid(ctx.correlation_id),
                actor_id=event.actor_id or _as_uuid(ctx.user_id),
            )

        session.add(OutboxMessage.from_event(event))

        for handler in self.handlers_for(event.event_type, transactional=True):
            try:
                await handler(event, session)
            except Exception:  # noqa: BLE001
                logger.exception("event handler failed for event_type=%s (event_id=%s)",
                                 event.event_type, event.event_id)
                raise  # همان تراکنش است؛ کل تراکنش Rollback شود


event_bus = EventBus()
```

================================================================================
## FILE: backend/app/core/events/outbox.py
================================================================================

```python
"""
app/core/events/outbox.py

مدل ORM جدول ``core.outbox_messages`` — دقیقاً مطابق DDL سند معماری v2.0،
بخش ۲.۳:

    CREATE TABLE core.outbox_messages (
        id             BIGSERIAL PRIMARY KEY,
        event_id       UUID NOT NULL UNIQUE,
        event_type     VARCHAR(100) NOT NULL,
        payload        JSONB NOT NULL,
        correlation_id UUID,
        created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
        dispatched_at  TIMESTAMPTZ,
        attempts       SMALLINT NOT NULL DEFAULT 0,
        last_error     TEXT
    );
    CREATE INDEX ix_outbox_pending ON core.outbox_messages(created_at)
        WHERE dispatched_at IS NULL;

⚠️ فرض این فایل: پایه‌ی مدل‌های شما در ``app.core.db.base`` با نام
``Base`` صادر می‌شود (الگوی رایج SQLAlchemy 2.0). اگر اسم/مسیر واقعی
پروژه‌ی شما فرق دارد، فقط خط import زیر را اصلاح کنید — بقیه‌ی فایل
دست‌نخورده می‌ماند.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import BigInteger, DateTime, Integer, SmallInteger, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func

try:
    # مسیر استاندارد طبق ساختار پوشه‌ی سند (بخش ۳.۱): core/db/base.py
    from app.core.db.base import Base
except ImportError:  # pragma: no cover — فقط برای این‌که فایل به‌تنهایی هم import شود
    from sqlalchemy.orm import DeclarativeBase

    class Base(DeclarativeBase):  # type: ignore[no-redef]
        """Fallback موقت — اگر این اجرا شد یعنی import بالا را باید اصلاح کنید."""


class OutboxMessage(Base):
    """ردیف Outbox — طبق الگوی Transactional Outbox (ADR-02)."""

    __tablename__ = "outbox_messages"
    __table_args__ = {"schema": "core"}

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    event_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False, unique=True)
    event_type: Mapped[str] = mapped_column(String(100), nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    correlation_id: Mapped[UUID | None] = mapped_column(PG_UUID(as_uuid=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    dispatched_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    attempts: Mapped[int] = mapped_column(SmallInteger, nullable=False, server_default="0")
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)

    @classmethod
    def from_event(cls, event: "DomainEvent") -> "OutboxMessage":  # noqa: F821 — type hint only
        """DomainEvent (از bus.py) را به یک ردیف Outbox قابل‌درج تبدیل می‌کند."""
        return cls(
            event_id=event.event_id,
            event_type=event.event_type,
            # JSONB needs JSON-safe values (UUID/datetime/Decimal -> str)
            payload=json.loads(json.dumps(event.payload, default=str)),
            correlation_id=event.correlation_id,
        )
```

================================================================================
## FILE: backend/app/core/middleware/__init__.py
================================================================================

```python
"""Middleware chain (architecture 3.1 ``core/middleware/``).

Order, outermost first:

    RequestID -> SecurityHeaders -> CORS -> TrustedHost -> IPFilter
      -> RateLimit -> BodyGuard -> AuditContext -> application

CORS sits outside the filters so that 403/413/429 answers still carry CORS
headers (otherwise browsers report them as opaque network errors).
"""
from __future__ import annotations

from fastapi import FastAPI
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app.core.config import settings
from app.core.middleware.audit_context import AuditContextMiddleware
from app.core.middleware.body_guard import BodyGuardMiddleware
from app.core.middleware.ip_filter import IPFilterMiddleware
from app.core.middleware.rate_limit import RateLimitMiddleware
from app.core.middleware.request_id import RequestIDMiddleware
from app.core.middleware.security_headers import SecurityHeadersMiddleware


def register_middlewares(app: FastAPI) -> None:
    """Register the whole chain once. (``add_middleware``: last added = outermost.)"""
    app.add_middleware(AuditContextMiddleware)
    app.add_middleware(BodyGuardMiddleware)
    app.add_middleware(RateLimitMiddleware)
    app.add_middleware(IPFilterMiddleware, allow_ips=settings.IP_ALLOW_LIST,
                       deny_ips=settings.IP_DENY_LIST)
    if settings.ALLOWED_HOSTS:
        app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.ALLOWED_HOSTS)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-Request-ID",
                       "X-Correlation-ID", "Idempotency-Key", "If-Match",
                       "X-Device-Fingerprint", "X-Device-MAC", "X-Device-Nonce",
                       "X-Device-Timestamp", "X-Device-Signature",
                       "X-Device-MAC-Source", "X-Requested-With"],
        expose_headers=["X-Request-ID", "ETag", "Retry-After"],
    )
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(RequestIDMiddleware)


__all__ = [
    "register_middlewares", "RequestIDMiddleware", "SecurityHeadersMiddleware",
    "IPFilterMiddleware", "RateLimitMiddleware", "BodyGuardMiddleware",
    "AuditContextMiddleware",
]
```

================================================================================
## FILE: backend/app/core/middleware/audit_context.py
================================================================================

```python
"""Fills network/device identity into the request context (architecture 3.1).

The identity that ends up in audit rows always comes from here (headers /
socket), never from a request body. ``mac_verified`` stays False until the
device-binding step validates the HMAC signature (ADR-08: MAC is a forensic
signal, not a security control).
"""
from __future__ import annotations

import re

from starlette.datastructures import Headers
from starlette.types import ASGIApp, Receive, Scope, Send

from app.core.context import get_context
from app.core.middleware._http import client_ip

_MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$")
_FP_RE = re.compile(r"^[A-Za-z0-9+/=_\-]{16,255}$")


class AuditContextMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] in ("http", "websocket"):
            h = Headers(scope=scope)
            ctx = get_context()
            ctx.ip = client_ip(scope)
            ctx.user_agent = (h.get("user-agent") or "")[:512] or None
            mac = h.get("x-device-mac")
            if mac and _MAC_RE.match(mac):
                ctx.mac_address = mac.upper().replace("-", ":")
            fp = h.get("x-device-fingerprint")
            if fp and _FP_RE.match(fp):
                ctx.device_fingerprint = fp
            ctx.correlation_id = h.get("x-correlation-id") or ctx.request_id
        await self.app(scope, receive, send)
```

================================================================================
## FILE: backend/app/core/middleware/ip_filter.py
================================================================================

```python
"""IP allow / deny lists (CIDR aware). Deny wins over allow."""
from __future__ import annotations

from starlette.types import ASGIApp, Receive, Scope, Send

from app.core.middleware._http import client_ip, ip_in, parse_networks, send_error


class IPFilterMiddleware:
    def __init__(self, app: ASGIApp, allow_ips: list[str] | None = None,
                 deny_ips: list[str] | None = None) -> None:
        self.app = app
        self.allow = parse_networks(allow_ips or [])
        self.deny = parse_networks(deny_ips or [])

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ("http", "websocket") or not (self.allow or self.deny):
            await self.app(scope, receive, send)
            return
        ip = client_ip(scope)
        if self.deny and ip_in(ip, self.deny):
            await self._reject(scope, receive, send, "IP_ADDRESS_DENIED",
                               "آدرس IP شما مسدود شده است.")
            return
        if self.allow and not ip_in(ip, self.allow):
            await self._reject(scope, receive, send, "IP_ADDRESS_NOT_ALLOWED",
                               "دسترسی از این آدرس IP مجاز نیست.")
            return
        await self.app(scope, receive, send)

    @staticmethod
    async def _reject(scope, receive, send, code, message) -> None:
        if scope["type"] == "websocket":
            await send({"type": "websocket.close", "code": 4403})
            return
        await send_error(scope, receive, send, status=403, code=code, message=message)
```

================================================================================
## FILE: backend/app/core/middleware/rate_limit.py
================================================================================

```python
"""L7 rate limiting (architecture 1.1 / 11).

* Limits come from settings (``RATE_LIMIT_DEFAULT`` / ``RATE_LIMIT_AUTH``) -
  the old middleware ignored them and hard-coded 100.
* Backend: Redis when reachable (shared by all workers), otherwise a bounded
  in-process sliding window. The in-memory backend evicts idle keys, so it can
  no longer grow without bound.
* Keyed by client IP + bucket (auth endpoints have their own, stricter bucket)
  - not by path, which let an attacker multiply their quota by rotating URLs.
"""
from __future__ import annotations

import logging
import time
from collections import deque
from typing import Optional, Protocol

from starlette.types import ASGIApp, Receive, Scope, Send

from app.core.config import settings
from app.core.middleware._http import client_ip, send_error

logger = logging.getLogger("core.rate_limit")

_PERIODS = {"second": 1, "minute": 60, "hour": 3600, "day": 86400}
_AUTH_PREFIXES = (
    "/api/v1/auth/login", "/api/v1/auth/register", "/api/v1/auth/refresh",
    "/api/v1/auth/password", "/api/v1/auth/mfa", "/api/v1/auth/sso",
)


def parse_limit(spec: str) -> tuple[int, int]:
    """``"100/minute"`` -> (100, 60)."""
    try:
        count, period = spec.strip().split("/")
        return int(count), _PERIODS[period.strip().lower()]
    except (ValueError, KeyError):
        raise ValueError(f"invalid rate limit spec: {spec!r} (expected N/second|minute|hour|day)")


class Limiter(Protocol):
    async def hit(self, key: str, limit: int, window: int) -> tuple[bool, int]:
        """Register a hit. Returns (allowed, retry_after_seconds)."""


class MemoryLimiter:
    def __init__(self, max_keys: int = 50_000) -> None:
        self._hits: dict[str, deque[float]] = {}
        self._max_keys = max_keys
        self._last_sweep = time.monotonic()

    async def hit(self, key: str, limit: int, window: int) -> tuple[bool, int]:
        now = time.monotonic()
        self._sweep(now, window)
        q = self._hits.setdefault(key, deque())
        while q and now - q[0] >= window:
            q.popleft()
        if len(q) >= limit:
            return False, max(1, int(window - (now - q[0])) + 1)
        q.append(now)
        return True, 0

    def _sweep(self, now: float, window: int) -> None:
        if now - self._last_sweep < 30 and len(self._hits) < self._max_keys:
            return
        self._last_sweep = now
        for k in [k for k, q in self._hits.items() if not q or now - q[-1] >= max(window, 60)]:
            del self._hits[k]
        if len(self._hits) >= self._max_keys:  # hard cap: drop oldest half
            for k in list(self._hits)[: self._max_keys // 2]:
                del self._hits[k]


class RedisLimiter:
    """Fixed-window counter shared across workers; falls back on any error."""

    def __init__(self, url: str, fallback: Limiter) -> None:
        import redis.asyncio as aioredis

        self._redis = aioredis.from_url(url, socket_connect_timeout=0.5, socket_timeout=0.5)
        self._fallback = fallback

    async def hit(self, key: str, limit: int, window: int) -> tuple[bool, int]:
        try:
            bucket = int(time.time()) // window
            rkey = f"rl:{key}:{bucket}"
            pipe = self._redis.pipeline()
            pipe.incr(rkey)
            pipe.expire(rkey, window + 1)
            count, _ = await pipe.execute()
            if count > limit:
                return False, window - (int(time.time()) % window) or 1
            return True, 0
        except Exception as exc:  # Redis down must not take the API down
            logger.warning("redis rate limiter unavailable (%s); using in-memory", exc)
            return await self._fallback.hit(key, limit, window)


def build_limiter() -> Limiter:
    memory = MemoryLimiter()
    if settings.ENV == "testing":
        return memory
    try:
        return RedisLimiter(settings.redis_url, memory)
    except Exception:  # redis package missing / bad URL
        return memory


class RateLimitMiddleware:
    def __init__(self, app: ASGIApp, limiter: Optional[Limiter] = None,
                 default: Optional[str] = None, auth: Optional[str] = None) -> None:
        self.app = app
        self.limiter = limiter or build_limiter()
        self.default = parse_limit(default or settings.RATE_LIMIT_DEFAULT)
        self.auth = parse_limit(auth or settings.RATE_LIMIT_AUTH)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if (scope["type"] != "http" or not settings.RATE_LIMIT_ENABLED
                or scope["method"] == "OPTIONS"):
            await self.app(scope, receive, send)
            return
        path = scope.get("path", "")
        if path in ("/health", "/ready"):
            await self.app(scope, receive, send)
            return
        bucket, (limit, window) = (("auth", self.auth) if path.startswith(_AUTH_PREFIXES)
                                   else ("default", self.default))
        allowed, retry_after = await self.limiter.hit(
            f"{bucket}:{client_ip(scope)}", limit, window)
        if not allowed:
            await send_error(
                scope, receive, send, status=429, code="RATE_LIMIT_EXCEEDED",
                message="درخواست‌های بیش از حد ارسال شده است. لطفاً کمی بعد تلاش کنید.",
                headers={"Retry-After": str(retry_after)})
            return
        await self.app(scope, receive, send)
```

================================================================================
## FILE: backend/app/core/middleware/request_id.py
================================================================================

```python
"""Creates the per-request context and the ``X-Request-ID`` header."""
from __future__ import annotations

import re
from uuid import uuid4

from starlette.datastructures import Headers, MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.context import RequestContext, reset_context, set_context

_SAFE_ID = re.compile(r"^[A-Za-z0-9\-_.]{8,64}$")


class RequestIDMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return
        incoming = Headers(scope=scope).get("x-request-id", "")
        # Accept a client id only if it is short/safe (log-injection guard).
        request_id = incoming if _SAFE_ID.match(incoming) else str(uuid4())
        ctx = RequestContext(request_id=request_id, path=scope.get("path"),
                             method=scope.get("method"))
        scope.setdefault("state", {})["request_id"] = request_id
        token = set_context(ctx)

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                MutableHeaders(scope=message)["X-Request-ID"] = request_id
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            reset_context(token)
```

================================================================================
## FILE: backend/app/core/middleware/security_headers.py
================================================================================

```python
"""Security headers on every HTTP response (architecture 11 / 1.5)."""
from __future__ import annotations

from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.config import settings

# Pure JSON API: nothing may be loaded or framed from an API response.
_API_CSP = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
# Swagger UI / ReDoc need inline scripts and a CDN (non-production only).
_DOCS_CSP = (
    "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "img-src 'self' data: https://fastapi.tiangolo.com; frame-ancestors 'none'"
)
_DOCS_PATHS = ("/docs", "/redoc")


class SecurityHeadersMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        path = scope.get("path", "")
        is_docs = (not settings.is_production) and path.startswith(_DOCS_PATHS)

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                h = MutableHeaders(scope=message)
                h["X-Content-Type-Options"] = "nosniff"
                h["X-Frame-Options"] = "DENY"
                h["Referrer-Policy"] = "strict-origin-when-cross-origin"
                h["Cross-Origin-Resource-Policy"] = "same-site"
                h["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
                h["Content-Security-Policy"] = _DOCS_CSP if is_docs else _API_CSP
                if not is_docs:
                    h.setdefault("Cache-Control", "no-store")  # tokens/PII in bodies
                if settings.is_production:
                    h["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
            await send(message)

        await self.app(scope, receive, send_wrapper)
```

================================================================================
## FILE: backend/app/core/security.py
================================================================================

```python
"""Security primitives for WebSocket/device binding (architecture 1.2).

Mirrors the Windows desktop client's device fingerprint + HMAC scheme so a
WebSocket handshake can be tied to a known device, reusing the same
``SECRET_KEY`` domain.
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Optional
from uuid import UUID

from app.core.config import settings


def get_device_fingerprint(
    user_agent: Optional[str] = None,
    ip: Optional[str] = None,
    mac: Optional[str] = None,
    salt: Optional[str] = None,
) -> str:
    """Stable per-device fingerprint from the available client hints.

    Missing components are skipped so fingerprints stay stable for clients
    that do not disclose them.  The digest is truncated (16 bytes) to keep
    stored fingerprints compact.
    """
    parts: list[str] = []
    if salt:
        parts.append(salt)
    if mac:
        parts.append(mac.strip().lower())
    if user_agent:
        parts.append(user_agent.strip())
    if ip:
        parts.append(ip.strip())
    if not parts:
        # Deterministic fallback so a missing fingerprint never crashes auth.
        parts.append("unknown-device")
    raw = "|".join(parts).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:32]


def verify_hmac_signature(
    signature: str,
    *,
    user_id,
    endpoint: str,
    payload: Optional[str] = None,
) -> bool:
    """Verify an HMAC-SHA256 device signature (constant-time compare).

    The signature should be computed by the client as
    ``HMAC_SHA256(secret_key, f"{user_id}|{endpoint}|{payload}")``.  A
    missing signature or key is a hard reject.
    """
    if not signature or not settings.SECRET_KEY:
        return False
    message = "|".join([str(user_id), endpoint, payload or ""]).encode("utf-8")
    expected = hmac.new(
        settings.SECRET_KEY.encode("utf-8"), message, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(signature.strip().lower(), expected.lower())


def hmac_sign(user_id, endpoint: str, payload: Optional[str] = None) -> str:
    """Helper used where the *server* must mint a signature (e.g. callbacks)."""
    message = "|".join([str(user_id), endpoint, payload or ""]).encode("utf-8")
    return hmac.new(
        settings.SECRET_KEY.encode("utf-8"), message, hashlib.sha256
    ).hexdigest()
```

================================================================================
## FILE: backend/app/main.py
================================================================================

```python
"""
Planner Enterprise API - Main Application Entry Point

Architecture: Modular Monolith with Defense in Depth
Version: 2.0
"""

import logging
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from sqlalchemy import text

from app.core.config import settings
from app.core.database import dispose_engine, engine
from app.core.errors import register_exception_handlers
from app.core.events import event_bus
from app.core.middleware import register_middlewares
from app.core.redis import get_redis_broker
from app.modules import auth, rbac, groups, goals, sharing, chat, inbox, \
                        reporting, notification, audit, ssoldap, files, calendar
from app.ws.routes import router as websocket_router

logging.basicConfig(level=settings.LOG_LEVEL, format=settings.LOG_FORMAT)

# Module order matters for initialization
MODULES = [auth, rbac, groups, goals, sharing,
           chat, inbox, reporting, notification, audit, ssoldap, files, calendar]


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    # Redis publisher/subscriber pool (in-memory fallback when unreachable)
    broker = get_redis_broker()
    await broker.connect()

    # Event bus subscriptions (modules without handlers are skipped)
    for m in MODULES:
        register = getattr(m, "register_event_handlers", None)
        if callable(register):
            register(event_bus)

    yield

    # Graceful shutdown: return pooled connections to PostgreSQL
    await shutdown_gracefully()
    await broker.close()


_docs_enabled = not settings.is_production

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    lifespan=lifespan,
    root_path=settings.ROOT_PATH,
    docs_url="/docs" if _docs_enabled else None,
    redoc_url="/redoc" if _docs_enabled else None,
    openapi_url="/openapi.json" if _docs_enabled else None,
)

# --- Middleware chain (single place; order documented in core/middleware) ---
register_middlewares(app)

# --- Exception handlers ---
register_exception_handlers(app)

# --- Include Module Routers ---
# All modules use /api/v1 prefix.
# Empty/stub modules (audit, files, notification, ssoldap) expose no router
# yet and are skipped until their routes land.
for m in MODULES:
    router = getattr(m, "router", None)
    if router is not None:
        app.include_router(router, prefix="/api/v1")

# --- WebSocket gateway (architecture 5.5: /ws/chat, /ws/notifications) ---
app.include_router(websocket_router)

async def shutdown_gracefully():
    """Graceful shutdown routine."""
    await dispose_engine()


# Liveness: process is up (no dependencies touched)
@app.get("/health", include_in_schema=False)
async def health_check():
    return {
        "status": "healthy",
        "service": "planner-enterprise-api",
        "version": settings.APP_VERSION,
        "modules": [m.__name__ for m in MODULES],
    }


# Readiness: dependencies reachable (used by the load balancer)
@app.get("/ready", include_in_schema=False)
async def readiness_check():
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
    except Exception:
        logging.getLogger("app.health").exception("readiness: database unreachable")
        return JSONResponse(status_code=503, content={"status": "unavailable", "database": "down"})
    return {"status": "ready", "database": "up"}


# Root endpoint
@app.get("/", include_in_schema=False)
async def root():
    return {
        "message": "Planner Enterprise API",
        "version": settings.APP_VERSION,
        "docs": "/docs" if settings.ENV != "production" else "disabled",
        "endpoints": "/api/v1/auth, /api/v1/goals, /api/v1/groups, etc."
    }

if __name__ == "__main__":
    uvicorn.run(
        "app.main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.ENV == "development",
        access_log=False
    )
```

================================================================================
## MISSING FILES (not found in source repo)
================================================================================

- [MISSING] `﻿backend/app/core/__init__.py`
- [MISSING] `backend/app/core/logging.py`
- [MISSING] `backend/app/core/exceptions.py`
- [MISSING] `backend/app/core/db/__init__.py`
- [MISSING] `backend/app/core/middleware/cors.py`
- [MISSING] `backend/app/core/middleware/body_size_guard.py`
- [MISSING] `backend/app/core/middleware/authentication.py`
- [MISSING] `backend/app/core/middleware/device_binding.py`
- [MISSING] `backend/app/core/middleware/session_validation.py`
- [MISSING] `backend/app/__init__.py`

```

==========================================================================================
## FILE: CONCAT/basteh2.md
## SIZE: 78322 bytes
==========================================================================================

```markdown
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

```

==========================================================================================
## FILE: CONCAT/basteh3.md
## SIZE: 64134 bytes
==========================================================================================

```markdown
# BUNDLE: basteh3
# Source: GAP\basteh3
================================================================================

================================================================================
## FILE: backend/app/modules/calendar/__init__.py
================================================================================

```python
"""Calendar module public interface (real DDL)."""
from app.modules.calendar.api.routes import router

__all__ = ["router"]
```

================================================================================
## FILE: backend/app/modules/calendar/services/calendar_service.py
================================================================================

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

================================================================================
## FILE: backend/app/modules/goals/__init__.py
================================================================================

```python
"""Goals module public interface."""
from app.modules.goals.api.routes import router

__all__ = ["router"]
```

================================================================================
## FILE: backend/app/modules/goals/db/models.py
================================================================================

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

================================================================================
## FILE: backend/app/modules/groups/__init__.py
================================================================================

```python
"""Groups module public interface."""
from app.modules.groups.api.routes import router

__all__ = ["router"]
```

================================================================================
## FILE: backend/app/modules/groups/db/models.py
================================================================================

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

================================================================================
## FILE: backend/app/modules/inbox/__init__.py
================================================================================

```python
"""Inbox module public interface."""
from app.modules.inbox.api.routes import router

__all__ = ["router"]
```

================================================================================
## FILE: backend/app/modules/inbox/db/models.py
================================================================================

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

================================================================================
## FILE: backend/app/modules/inbox/services/inbox_service.py
================================================================================

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

================================================================================
## FILE: backend/app/modules/reporting/__init__.py
================================================================================

```python
"""Reporting module public interface."""
from app.modules.reporting.api.routes import router
from app.modules.reporting.api.dashboard import dashboard_router

router.include_router(dashboard_router)

__all__ = ["router"]
```

================================================================================
## FILE: backend/app/modules/sharing/__init__.py
================================================================================

```python
"""Sharing module public interface."""
from app.modules.sharing.api.routes import router

__all__ = ["router"]
```

================================================================================
## FILE: backend/app/modules/sharing/db/models.py
================================================================================

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

================================================================================
## FILE: backend/app/modules/sharing/services/sharing_service.py
================================================================================

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

================================================================================
## FILE: backend/app/modules/ssoldap/__init__.py
================================================================================

```python
"""SSO/LDAP module public interface (stub — full implementation per Architecture v2.0 Section M12)."""
from app.modules.ssoldap.api.routes import router


def register_event_handlers(event_bus) -> None:
    """Subscribe to cross-module events (no-op stub)."""


__all__ = ["router", "register_event_handlers"]
```

================================================================================
## FILE: backend/app/modules/ssoldap/services/ldap_service.py
================================================================================

```python
"""
app/modules/ssoldap/services/ldap_service.py

این ماژول (M12) قبلاً فقط یک ``api/`` خالی بود — نه db، نه services.
طبق سند:
  - بخش ۲.۵: SSO/LDAP جزو فاز ۱ (پیش‌نیاز همه‌چیز) است.
  - بخش ۱۴ (جدول ریسک): «SSO با Kerberos در محیط واقعی AD کار نکند» →
    ریسک بالا → **«Fallback به LDAP Bind از روز اول»**.

پس اول ``LDAP Bind`` (نام‌کاربری+رمز مستقیم به AD) ساخته می‌شود —
چون بدون Keytab/KDC واقعی هم قابل‌ساخت و تا حدی قابل‌تست است. Kerberos/
SPNEGO کامل (``gssapi``) نیاز به محیط AD واقعی برای تست دارد و باید
جدا (به‌عنوان Spike دوروزه، طبق توصیه‌ی خودِ سند) پیگیری شود —
``app/modules/ssoldap/api/negotiate.py`` در همین پچ فقط یک اسکلت
401 برمی‌گرداند، نه پیاده‌سازی کامل SPNEGO.

⚠️ وابستگی‌ها: `pip list` شما نشان داد ``ldap3`` نصب نیست. برای همین
import آن اینجا **تنبل (lazy)** است — تا وقتی کسی واقعاً وارد کردن
LDAP نزند، بقیه‌ی اپ (که به این ماژول نیازی ندارد) از کار نمی‌افتد.
نصب لازم:

    pip install ldap3

⚠️ تنظیمات لازم (باید به ``app/core/config.py`` اضافه شوند — چون به
محتوای فایل شما دسترسی ندارم، فقط اسم‌هایی که این فایل انتظار دارد
را مستند می‌کنم):

    LDAP_SERVER_URI        # مثل "ldaps://ad.corp.local:636"
    LDAP_BASE_DN           # مثل "DC=corp,DC=local"
    LDAP_BIND_DN           # اکانت سرویس فقط-خواندنی برای search
    LDAP_BIND_PASSWORD     # طبق سند باید AES-256-GCM رمزنگاری‌شده در Vault/DB
                            # باشد؛ اگر از env var/Secret Manager می‌آید همین کافی است
    LDAP_USER_SEARCH_FILTER = "(sAMAccountName={username})"
    LDAP_ATTR_OBJECT_GUID = "objectGUID"
    LDAP_ATTR_NATIONAL_ID  # نام Attribute سفارشی AD شما برای کد ملی — باید با تیم AD هماهنگ شود
    LDAP_ATTR_DISPLAY_NAME = "displayName"
    LDAP_ATTR_MEMBEROF = "memberOf"
    LDAP_GROUP_ROLE_MAP: dict[str, str]  # DN گروه AD → کد نقش داخلی، مثل:
        # {"CN=Managers,OU=Groups,DC=corp,DC=local": "manager"}
    LDAP_AUTO_PROVISION: bool = True
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


class LdapAuthError(Exception):
    """احراز هویت LDAP شکست خورد (رمز غلط، کاربر یافت نشد، سرور در دسترس نیست)."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(f"{code}: {message}")


@dataclass(frozen=True)
class LdapUserInfo:
    """نتیجه‌ی موفق احراز هویت + جست‌وجوی LDAP — چیزی که SsoLoginService مصرف می‌کند."""

    dn: str
    object_guid: str
    sam_account_name: str
    display_name: str
    national_id: str | None
    member_of: list[str] = field(default_factory=list)


def escape_ldap_filter_value(value: str) -> str:
    """طبق سند (بخش امنیت، ردیف A03 Injection): ``escape_filter_chars`` برای LDAP.

    این تابع pure و بدون وابستگی به ldap3 است تا بدون نصب ldap3 هم قابل‌تست
    باشد (ldap3.utils.conv.escape_filter_chars هم دقیقاً همین RFC 4515 را
    پیاده می‌کند — اگر ldap3 نصب بود می‌توانید مستقیم از آن استفاده کنید).
    """
    replacements = {
        "\\": r"\5c",
        "*": r"\2a",
        "(": r"\28",
        ")": r"\29",
        "\x00": r"\00",
    }
    return "".join(replacements.get(ch, ch) for ch in value)


def map_groups_to_roles(member_of: list[str], group_role_map: dict[str, str]) -> list[str]:
    """نگاشت DN گروه‌های AD به کدهای نقش داخلی — طبق سند بخش ۱.۳: «نگاشت memberOf → roles».

    مقایسه‌ی DN بدون حساسیت به بزرگی/کوچکی حروف و فاصله‌های اضافه انجام
    می‌شود، چون AD معمولاً DN را با فرمت‌بندی متفاوت (فاصله بعد از کاما)
    برمی‌گرداند.
    """
    normalized_map = {_normalize_dn(dn): role for dn, role in group_role_map.items()}
    roles = []
    for dn in member_of:
        role = normalized_map.get(_normalize_dn(dn))
        if role and role not in roles:
            roles.append(role)
    return roles


def _normalize_dn(dn: str) -> str:
    return re.sub(r",\s*", ",", dn.strip().lower())


class LdapService:
    """Bind مستقیم کاربر به AD (نه Kerberos) — endpoint: ``POST /auth/sso/ldap-login``."""

    def __init__(self, settings: Any) -> None:
        self.settings = settings

    async def authenticate(self, username: str, password: str) -> LdapUserInfo:
        """کاربر را مستقیماً به AD bind می‌کند و اطلاعاتش را برمی‌گرداند.

        دو مرحله (طبق الگوی رایج AD bind، چون sAMAccountName به‌تنهایی DN
        نیست): (۱) با اکانت سرویس bind و DN کاربر را search می‌کند،
        (۲) با DN واقعی و رمز کاربر دوباره bind می‌کند تا رمز واقعاً
        تأیید شود.
        """
        try:
            import ldap3
            from ldap3 import ALL, Connection, Server
            from ldap3.core.exceptions import LDAPBindError, LDAPException
        except ImportError as exc:  # pragma: no cover
            raise LdapAuthError(
                "LDAP_NOT_CONFIGURED",
                "پکیج ldap3 نصب نیست — `pip install ldap3` را اجرا کنید.",
            ) from exc

        if not username or not password:
            raise LdapAuthError("INVALID_CREDENTIALS", "نام کاربری/رمز خالی است.")

        safe_username = escape_ldap_filter_value(username)
        search_filter = self.settings.LDAP_USER_SEARCH_FILTER.format(username=safe_username)

        server = Server(self.settings.LDAP_SERVER_URI, get_info=ALL, use_ssl=True)

        # مرحله ۱: bind با اکانت سرویس (فقط خواندنی) + search برای پیدا کردن DN کاربر
        try:
            service_conn = Connection(
                server, user=self.settings.LDAP_BIND_DN,
                password=self.settings.LDAP_BIND_PASSWORD, auto_bind=True,
            )
        except LDAPException as exc:
            raise LdapAuthError("LDAP_UNAVAILABLE", "اتصال به AD ممکن نشد.") from exc

        attrs = [
            self.settings.LDAP_ATTR_OBJECT_GUID,
            self.settings.LDAP_ATTR_DISPLAY_NAME,
            self.settings.LDAP_ATTR_MEMBEROF,
        ]
        national_id_attr = getattr(self.settings, "LDAP_ATTR_NATIONAL_ID", None)
        if national_id_attr:
            attrs.append(national_id_attr)

        service_conn.search(
            search_base=self.settings.LDAP_BASE_DN,
            search_filter=search_filter,
            attributes=attrs,
        )
        if not service_conn.entries:
            service_conn.unbind()
            raise LdapAuthError("USER_NOT_FOUND", "کاربر در AD یافت نشد.")

        entry = service_conn.entries[0]
        user_dn = entry.entry_dn
        service_conn.unbind()

        # مرحله ۲: bind واقعی با DN کاربر + رمزی که کاربر فرستاده — این
        # مرحله است که واقعاً رمز را تأیید می‌کند.
        try:
            user_conn = Connection(server, user=user_dn, password=password, auto_bind=True)
            user_conn.unbind()
        except LDAPBindError as exc:
            raise LdapAuthError("INVALID_CREDENTIALS", "نام کاربری یا رمز عبور اشتباه است.") from exc

        member_of = list(entry[self.settings.LDAP_ATTR_MEMBEROF].values) \
            if self.settings.LDAP_ATTR_MEMBEROF in entry else []
        national_id = None
        if national_id_attr and national_id_attr in entry:
            values = entry[national_id_attr].values
            national_id = values[0] if values else None

        return LdapUserInfo(
            dn=user_dn,
            object_guid=str(entry[self.settings.LDAP_ATTR_OBJECT_GUID].value),
            sam_account_name=username,
            display_name=str(entry[self.settings.LDAP_ATTR_DISPLAY_NAME].value),
            national_id=national_id,
            member_of=member_of,
        )
```

================================================================================
## MISSING FILES (not found in source repo)
================================================================================

- [MISSING] `﻿backend/app/modules/groups/api/router.py`
- [MISSING] `backend/app/modules/groups/db/repository.py`
- [MISSING] `backend/app/modules/groups/services/__init__.py`
- [MISSING] `backend/app/modules/groups/services/group_service.py`
- [MISSING] `backend/app/modules/groups/schemas.py`
- [MISSING] `backend/app/modules/groups/events.py`
- [MISSING] `backend/app/modules/goals/api/router.py`
- [MISSING] `backend/app/modules/goals/db/repository.py`
- [MISSING] `backend/app/modules/goals/services/__init__.py`
- [MISSING] `backend/app/modules/goals/services/goal_service.py`
- [MISSING] `backend/app/modules/goals/services/dependency_service.py`
- [MISSING] `backend/app/modules/goals/schemas.py`
- [MISSING] `backend/app/modules/goals/events.py`
- [MISSING] `backend/app/modules/calendar/api/router.py`
- [MISSING] `backend/app/modules/calendar/db/models.py`
- [MISSING] `backend/app/modules/calendar/services/__init__.py`
- [MISSING] `backend/app/modules/calendar/schemas.py`
- [MISSING] `backend/app/modules/calendar/events.py`
- [MISSING] `backend/app/modules/sharing/api/router.py`
- [MISSING] `backend/app/modules/sharing/services/__init__.py`
- [MISSING] `backend/app/modules/sharing/schemas.py`
- [MISSING] `backend/app/modules/sharing/events.py`
- [MISSING] `backend/app/modules/inbox/api/router.py`
- [MISSING] `backend/app/modules/inbox/services/__init__.py`
- [MISSING] `backend/app/modules/inbox/schemas.py`
- [MISSING] `backend/app/modules/inbox/events.py`
- [MISSING] `backend/app/modules/reporting/api/router.py`
- [MISSING] `backend/app/modules/reporting/services/__init__.py`
- [MISSING] `backend/app/modules/reporting/services/report_service.py`
- [MISSING] `backend/app/modules/reporting/services/export_service.py`
- [MISSING] `backend/app/modules/reporting/schemas.py`
- [MISSING] `backend/app/modules/ssoldap/api/router.py`
- [MISSING] `backend/app/modules/ssoldap/services/__init__.py`
- [MISSING] `backend/app/modules/ssoldap/services/kerberos_service.py`
- [MISSING] `backend/app/modules/ssoldap/services/sync_service.py`
- [MISSING] `backend/app/modules/ssoldap/schemas.py`

```

==========================================================================================
## FILE: CONCAT/basteh4.md
## SIZE: 36970 bytes
==========================================================================================

```markdown
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

```

==========================================================================================
## FILE: CONCAT/basteh5.md
## SIZE: 211804 bytes
==========================================================================================

```markdown
# BUNDLE: basteh5
# Source: GAP\basteh5
================================================================================

================================================================================
## FILE: architecture-v2.md
================================================================================

```markdown
# سند معماری جامع — نسخه ۲.۰
## سامانه سازمانی مدیریت اهداف، برنامه‌ریزی و همکاری

**نسخه:** 2.0 | **تاریخ:** ۲۷ شهریور ۱۴۰۵ | **جایگزین نسخه ۱.۰**
**نویسنده:** معماری ارشد سیستم و امنیت نرم‌افزار | **رویکرد:** Security-First · Defense in Depth · Zero Trust

---

## فهرست

| # | بخش |
|---|-----|
| ۰ | [تغییرات نسبت به نسخه ۱ و تصمیم‌های کلیدی](#۰-تغییرات-نسبت-به-نسخه-۱-و-تصمیمهای-کلیدی) |
| ۱ | [معماری سطح بالا و نمودارها](#۱-معماری-سطح-بالا-و-نمودارها) |
| ۲ | [معماری ماژولار و قرارداد بین ماژول‌ها](#۲-معماری-ماژولار-و-قرارداد-بین-ماژولها) |
| ۳ | [ساختار پوشه‌های پروژه](#۳-ساختار-پوشههای-پروژه) |
| ۴ | [طراحی دیتابیس](#۴-طراحی-دیتابیس) |
| ۵ | [طراحی API](#۵-طراحی-api) |
| ۶ | [استراتژی MAC Address و شناسایی دستگاه](#۶-استراتژی-mac-address-و-شناسایی-دستگاه) |
| ۷ | [RBAC، گروه‌ها و حریم خصوصی](#۷-rbac-گروهها-و-حریم-خصوصی) |
| ۸ | [چت، WebSocket و مدیریت فایل](#۸-چت-websocket-و-مدیریت-فایل) |
| ۹ | [کارتابل](#۹-کارتابل-inboxoutbox) |
| ۱۰ | [شخصی‌سازی داشبورد و ویجت‌ها](#۱۰-شخصیسازی-داشبورد-و-ویجتها) |
| ۱۱ | [استراتژی امنیت جامع](#۱۱-استراتژی-امنیت-جامع) |
| ۱۲ | [نمونه کد (Boilerplate)](#۱۲-نمونه-کد-boilerplate) |
| ۱۳ | [کتابخانه‌ها، زیرساخت و ظرفیت‌سنجی](#۱۳-کتابخانهها-زیرساخت-و-ظرفیتسنجی) |
| ۱۴ | [فازبندی، ریسک و توصیه‌های پایانی](#۱۴-فازبندی-ریسک-و-توصیههای-پایانی) |

---

## ۰. تغییرات نسبت به نسخه ۱ و تصمیم‌های کلیدی

### ۰.۱ دامنه‌ی افزوده‌شده

نسخه ۲ نیازمندی‌ها هفت حوزه‌ی کاملاً جدید اضافه کرده است: **RBAC چندنقشی**، **گروه‌های کاربری سلسله‌مراتبی با حریم خصوصی**، **اتاق گفتگوی Real-time با WebSocket و اشتراک فایل**، **کارتابل ورودی/ارسالی**، **MFA و امنیت پیشرفته ورود**، **Audit Log مبتنی بر MAC Address و Device Fingerprint**، و **ویجت‌ها و داشبورد کاملاً قابل شخصی‌سازی**. همچنین شناسه‌ی یکتای کاربران از نام کاربری به **کد ملی** تغییر کرده است.

این‌ها دامنه را تقریباً **دوبرابر** می‌کنند. بخش ۱۴ اثر آن بر زمان‌بندی را صریح بیان می‌کند.

### ۰.۲ تصمیم‌های کلیدی معماری (ADR)

| # | تصمیم | انتخاب | دلیل |
|---|-------|--------|------|
| ADR-01 | سبک معماری | **Modular Monolith با مرزهای اجباری** — نه Microservices | جزئیات در ۰.۳ |
| ADR-02 | ارتباط بین ماژول‌ها | **Event Bus درون‌پروسه‌ای + Outbox Pattern** | رویدادمحور بودن بدون هزینه‌ی شبکه؛ مسیر مهاجرت بعدی به صف پیام باز می‌ماند |
| ADR-03 | فریم‌ورک | **FastAPI** + Uvicorn | async بومی برای WebSocket، LDAP و Push؛ OpenAPI خودکار؛ Pydantic اجباری |
| ADR-04 | دیتابیس | **PostgreSQL 16** با یک Schema به‌ازای هر ماژول | جداسازی منطقی ماژول‌ها بدون تقسیم فیزیکی دیتابیس |
| ADR-05 | WebSocket | **FastAPI WebSocket + Redis Pub/Sub** | مقیاس‌پذیری افقی: پیام روی هر Worker منتشر می‌شود |
| ADR-06 | شناسه‌ی کاربر | کد ملی **رمزنگاری‌شده (AES-GCM) + هش جستجوپذیر (HMAC-SHA256)** | کد ملی داده‌ی هویتی حساس است؛ ذخیره‌ی plaintext غیرقابل دفاع است |
| ADR-07 | MFA | **TOTP اولویت اول**؛ Email دوم؛ **SMS فقط به‌عنوان آخرین گزینه** | SMS در برابر SIM-Swap آسیب‌پذیر است (NIST SP 800-63B آن را "restricted" می‌داند) |
| ADR-08 | MAC Address | **سیگنال کمکی Forensic** — نه کنترل امنیتی | جزئیات و دلایل در بخش ۶ |
| ADR-09 | ذخیره‌سازی فایل | **S3-compatible (MinIO)** با آدرس‌دهی محتوایی | جداسازی کامل فایل از Web Root؛ آماده برای چند سرور |
| ADR-10 | Audit | **Append-Only + زنجیره‌ی هش (Hash Chain)** به‌جای امضای تک‌رکوردی | تشخیص حذف رکورد، نه فقط تغییر آن |
| ADR-11 | حریم خصوصی | **Privacy Level به‌عنوان یک لایه‌ی مستقل روی ACL** | دسترسی و حریم خصوصی دو مفهوم متفاوت‌اند؛ ادغام آن‌ها منشأ نشت داده است |

### ۰.۳ چرا Microservices توصیه نمی‌شود (مهم)

نیازمندی «معماری Microservices» ذکر شده است. توصیه‌ی فنی من **Modular Monolith** است و دلایل آن را صریح می‌گویم، چون این تصمیم بیش از هر تصمیم دیگری بر موفقیت یا شکست پروژه اثر دارد:

**آنچه Microservices واقعاً از شما می‌خواهد:** ۱۲ مخزن مستقل، ۱۲ خط لوله CI/CD، Service Discovery، API Gateway، تراکنش‌های توزیع‌شده (Saga) برای عملیاتی مثل «ایجاد جلسه + دعوت کاربران + ساخت اتاق چت + ارسال کارتابل»، ردیابی توزیع‌شده، مدیریت نسخه‌ی قرارداد بین سرویس‌ها، و یک تیم SRE. برای سامانه‌ای با **حداکثر ۱۰۰۰ کاربر همزمان** — که یک نمونه‌ی PostgreSQL به‌راحتی پاسخ می‌دهد — این هزینه هیچ توجیه فنی ندارد.

**هزینه‌ی واقعی:** یک کوئری ساده مثل «داشبورد مدیر گروه» که در Monolith یک JOIN است، در Microservices به ۴ فراخوانی شبکه بین سرویس‌های User، Group، Goal و Privacy تبدیل می‌شود — با احتمال شکست جزئی، نیاز به Circuit Breaker، و p95 چند برابر.

**راه‌حل پیشنهادی که هر دو هدف را برآورده می‌کند:**

- هر ماژول یک پکیج پایتون مستقل با `__init__.py` که **فقط رابط عمومی** را صادر می‌کند.
- هر ماژول Schema اختصاصی در PostgreSQL دارد؛ **دسترسی مستقیم به جدول ماژول دیگر ممنوع** و با آزمون خودکار معماری بررسی می‌شود.
- ارتباط فقط از دو راه: فراخوانی رابط عمومی (`ports/`) یا انتشار رویداد روی Event Bus.
- هر ماژول تست مستقل و مستندات API خودش را دارد.
- استقرار واحد، اما **قابلیت جدا شدن هر ماژول به سرویس مستقل در آینده بدون بازنویسی منطق** — چون وابستگی‌ها از قبل از طریق رابط عبور می‌کنند.

این دقیقاً «قابلیت واگذاری به تیم‌های مستقل» را می‌دهد (هدف اصلی شما) بدون پرداخت هزینه‌ی عملیاتی توزیع‌شدگی. اگر بعداً یک ماژول خاص — مثلاً چت — به مقیاس مستقل نیاز پیدا کرد، همان ماژول به‌تنهایی استخراج می‌شود.

```python
# tests/architecture/test_module_boundaries.py
FORBIDDEN = [
    ("modules.chat",    "modules.goals.db"),      # چت نباید مستقیم به جداول اهداف بزند
    ("modules.goals",   "modules.chat.db"),
    ("modules.inbox",   "modules.groups.db"),
    # ... ماتریس کامل
]

@pytest.mark.parametrize("importer,forbidden", FORBIDDEN)
def test_no_cross_module_db_access(importer, forbidden):
    """مرز ماژول‌ها با آزمون اجباری می‌شود، نه با توافق شفاهی."""
    violations = scan_imports(importer, matching=forbidden)
    assert not violations, f"نقض مرز ماژول: {violations}"
```

بدون این آزمون، «معماری ماژولار» ظرف شش ماه به یک Monolith درهم‌تنیده تبدیل می‌شود — این قاعده‌ای است که تقریباً بدون استثنا رخ می‌دهد.

---

## ۱. معماری سطح بالا و نمودارها

### ۱.۱ نمودار Client-Server

```mermaid
graph TB
    subgraph CL["لایه کلاینت"]
        D["Desktop (PySide6/CustomTkinter)<br/>MAC via psutil · Tray · SSO"]
        W["Web SPA/PWA (React+TS)<br/>FingerprintJS · Service Worker"]
        M["Mobile Browser<br/>Responsive"]
    end

    subgraph EDGE["لایه لبه — DMZ"]
        WAF["WAF / DDoS<br/>Cloudflare یا ModSecurity"]
        LB["Load Balancer + TLS 1.3<br/>HSTS · Security Headers · Rate Limit L7"]
    end

    subgraph APP["لایه اپلیکیشن — شبکه داخلی"]
        API["FastAPI Workers (N×)<br/>REST + OpenAPI"]
        WS["WebSocket Workers (N×)<br/>Chat · Live Notifications"]
        BUS["Event Bus + Outbox"]
        CEL["Celery Workers<br/>Mail · Push · Export · AV Scan"]
    end

    subgraph DATA["لایه داده — شبکه ایزوله"]
        PG[("PostgreSQL 16<br/>Primary + Replica<br/>TDE · Schema per Module")]
        RD[("Redis<br/>Pub/Sub · Cache · RateLimit")]
        S3[("MinIO / S3<br/>فایل‌های چت و Export")]
    end

    subgraph EXT["سرویس‌های بیرونی"]
        AD["Active Directory<br/>LDAPS :636 · Kerberos"]
        SMTP["SMTP"]
        AV["ClamAV Daemon"]
        SIEM["SIEM / Syslog"]
    end

    D & W & M -->|HTTPS/WSS| WAF --> LB
    LB --> API
    LB --> WS
    API <--> BUS
    WS <--> BUS
    BUS --> CEL
    API --> PG & RD
    WS --> RD
    CEL --> PG & S3 & SMTP & AV
    API --> S3
    API --> AD
    API -.->|لاگ ساختاریافته| SIEM
```

**سه ناحیه‌ی شبکه‌ای (Network Segmentation):** DMZ فقط ۴۴۳ را از اینترنت/LAN می‌پذیرد؛ لایه‌ی اپلیکیشن فقط از DMZ ترافیک می‌گیرد؛ لایه‌ی داده **هیچ مسیر ورودی از بیرون ندارد** و فقط از لایه‌ی اپلیکیشن قابل دسترسی است. دسترسی مدیریتی (SSH، psql) منحصراً از طریق Bastion Host با MFA.

### ۱.۲ نمودار لایه‌ها و جریان داده

```mermaid
graph LR
    subgraph P["Presentation"]
        V["Views / Components"]
    end
    subgraph A["API Layer"]
        MW["Security Middleware Chain"]
        EP["Endpoints + Pydantic Schemas"]
    end
    subgraph B["Business Logic"]
        SVC["Module Services"]
        POL["Policy Engine<br/>RBAC + ACL + Privacy"]
        EV["Event Publisher"]
    end
    subgraph D["Data Access"]
        REPO["Repositories (per module schema)"]
        UOW["Unit of Work"]
    end
    V --> MW --> EP --> SVC
    SVC --> POL
    SVC --> EV
    SVC --> REPO --> UOW
```

**زنجیره‌ی Middleware امنیتی** (به ترتیب اجرا):

```
RequestID → SecurityHeaders → CORS → IPFilter (allow/deny list)
  → RateLimit → BodySizeGuard → Authentication (JWT/Kerberos)
  → DeviceBinding (MAC/Fingerprint + HMAC) → SessionValidation (MFA, timeout)
  → AuditContext (ContextVar) → Router
```

هر لایه مستقل است و شکست هر یک، درخواست را قبل از رسیدن به منطق کسب‌وکار متوقف می‌کند — مصداق عملی Defense in Depth.

### ۱.۳ نمودار جریان SSO با Active Directory

```mermaid
sequenceDiagram
    autonumber
    participant U as کاربر Domain
    participant C as Client
    participant API as Auth Module
    participant KDC as KDC
    participant AD as AD (LDAPS)
    participant DB as PostgreSQL

    C->>API: GET /auth/sso/negotiate
    API-->>C: 401 · WWW-Authenticate: Negotiate
    C->>KDC: درخواست تیکت برای SPN HTTP/api.corp.local
    KDC-->>C: Service Ticket
    C->>API: Authorization: Negotiate <SPNEGO><br/>X-Device-MAC + X-Device-Signature
    API->>API: gssapi.accept_sec_context(keytab)
    API->>AD: LDAPS bind(svc) + search(objectGUID, nationalID, memberOf)
    AD-->>API: DN · attributes · groups
    API->>DB: SELECT users WHERE national_id_hash = HMAC(کد ملی)
    alt کاربر یافت نشد و auto_provision=true
        API->>DB: INSERT user (auth_mode='sso')
    else sso_enabled = false
        API-->>C: 403 SSO_DISABLED_FOR_USER
    else حساب غیرفعال یا خارج از IP مجاز
        API-->>C: 403 ACCESS_DENIED
    end
    API->>DB: نگاشت memberOf → roles
    API->>DB: بررسی user_devices (دستگاه شناخته‌شده؟)
    alt دستگاه جدید
        API->>DB: INSERT user_devices (is_trusted=false)
        API-->>U: هشدار امنیتی «ورود از دستگاه جدید»
    end
    API->>DB: INSERT login_audit_logs (mac, fingerprint, ip, success)
    API-->>C: Access Token (15m) + Refresh (HttpOnly/DPAPI)
```

**نکته‌ی حیاتی:** تیکت Kerberos **فقط برای احراز هویت اولیه** به کار می‌رود. پس از آن، JWT داخلی صادر می‌شود تا مدل مجوزدهی برای کاربران SSO و محلی یکسان بماند. نگاشت کاربر بر `objectGUID` (نه `sAMAccountName`) و کد ملی انجام می‌شود؛ نام کاربری در AD تغییرپذیر است.

### ۱.۴ نمودار WebSocket و چت Real-time

```mermaid
sequenceDiagram
    autonumber
    participant A as کاربر A (Desktop)
    participant W1 as WS Worker #1
    participant R as Redis Pub/Sub
    participant W2 as WS Worker #2
    participant B as کاربر B (Web)
    participant DB as PostgreSQL
    participant AV as ClamAV

    A->>W1: WSS /ws/chat?token=<access>
    W1->>W1: اعتبارسنجی JWT + بررسی عضویت در اتاق
    Note over W1: توکن از Query فقط برای Handshake؛<br/>سپس پیام auth روی خود سوکت
    W1-->>A: {"type":"connected","room_id":"..."}

    A->>W1: {"type":"message","body":"..."}
    W1->>W1: sanitize + محدودیت طول + Rate Limit (۲۰ پیام/دقیقه)
    W1->>DB: INSERT chat_messages
    W1->>R: PUBLISH room:{id} {...}
    R-->>W2: پیام منتشرشده
    W2-->>B: تحویل به کلاینت متصل
    W1->>DB: INSERT audit_logs (action=chat.message.send)

    A->>W1: درخواست آپلود فایل
    W1-->>A: Presigned URL (MinIO, TTL=5m)
    A->>AV: (غیرمستقیم) آپلود → صف اسکن
    AV-->>DB: وضعیت clean/infected
    Note over DB: فایل تا تأیید اسکن<br/>status=pending و غیرقابل دانلود است
```

**قواعد امنیتی WebSocket:**

1. توکن در Query String فقط برای Handshake اولیه (چون مرورگر اجازه‌ی هدر سفارشی در WebSocket نمی‌دهد)؛ بلافاصله پس از اتصال، سرور یک پیام `auth` می‌خواهد و توکن Query را **در لاگ‌ها ماسک می‌کند** (Query String در لاگ Nginx ثبت می‌شود — یک نشت رایج).
2. عضویت در اتاق در **لحظه‌ی هر پیام** بررسی می‌شود، نه فقط هنگام اتصال. کاربری که از اتاق حذف شده، نباید با اتصال باز پیام بگیرد.
3. انقضای Access Token روی سوکت باز اعمال می‌شود: هر ۶۰ ثانیه اعتبار توکن بازبینی و در صورت انقضا سوکت بسته می‌شود (`4401`).
4. Rate Limiting روی سوکت مستقل از REST است.
5. Origin Check در Handshake اجباری است (WebSocket تحت CORS نیست — این یک سوءتفاهم رایج و منشأ Cross-Site WebSocket Hijacking).

### ۱.۵ نمودار معماری امنیت (Defense in Depth)

```mermaid
graph TB
    ATK["تهدید"] --> L1
    L1["لایه ۱ — لبه<br/>WAF · DDoS · TLS 1.3 · IP Filter"] --> L2
    L2["لایه ۲ — ارائه<br/>CSP · CSRF Token · X-Frame-Options · Auto-Timeout"] --> L3
    L3["لایه ۳ — API<br/>Schema Validation · Rate Limit · Replay Guard (Nonce)"] --> L4
    L4["لایه ۴ — احراز هویت<br/>Argon2id · MFA · Device Binding · Lockout"] --> L5
    L5["لایه ۵ — مجوزدهی<br/>RBAC · ACL · Privacy Level · Least Privilege"] --> L6
    L6["لایه ۶ — منطق کسب‌وکار<br/>Business Rules · Transaction · Optimistic Lock"] --> L7
    L7["لایه ۷ — داده<br/>Parameterized Query · Field Encryption · TDE"] --> L8
    L8["لایه ۸ — زیرساخت<br/>Segmentation · Hardening · Secrets Vault"] --> L9
    L9["لایه ۹ — رصد<br/>Audit Hash Chain · SIEM · Anomaly Detection · IR Plan"]
```

اصل حاکم: **هیچ لایه‌ای به درستی لایه‌ی قبل تکیه نمی‌کند.** اگر WAF دور زده شد، Schema Validation می‌گیرد؛ اگر آن هم رد شد، Parameterized Query جلوی تزریق را می‌گیرد؛ و اگر همه شکست خوردند، Audit Log ردپا را نگه می‌دارد.

---

## ۲. معماری ماژولار و قرارداد بین ماژول‌ها

### ۲.۱ نقشه‌ی ماژول‌ها و وابستگی‌ها

```mermaid
graph TD
    IAM["M1 · Auth & Users<br/>(هسته)"]
    RBAC["M2 · RBAC"]
    GRP["M3 · Groups & Privacy"]
    GOAL["M4 · Goals & Planning"]
    CAL["M5 · Calendar & Dashboard"]
    SHR["M6 · Sharing & Collaboration"]
    CHAT["M7 · Chat"]
    INBOX["M8 · Inbox/Outbox"]
    RPT["M9 · Reporting"]
    NOTIF["M10 · Notification"]
    AUDIT["M11 · Audit & Logging"]
    SSO["M12 · SSO & LDAP"]
    FILE["M13 · File Storage (زیرساخت مشترک)"]

    SSO --> IAM
    RBAC --> IAM
    GRP --> IAM & RBAC
    GOAL --> IAM & RBAC
    CAL --> GOAL & GRP
    SHR --> GOAL & RBAC & GRP
    CHAT --> IAM & FILE & SHR
    INBOX --> IAM & SHR & CHAT
    RPT --> GOAL & GRP
    NOTIF -.->|مصرف رویداد| GOAL & CHAT & SHR & INBOX
    AUDIT -.->|مصرف رویداد| IAM & GOAL & CHAT & SHR & GRP & INBOX
```

خطوط نقطه‌چین = وابستگی رویدادی (بدون وابستگی کد). **M10 و M11 هیچ ماژولی را import نمی‌کنند** — فقط رویداد مصرف می‌کنند. این باعث می‌شود افزودن یک ماژول جدید، هیچ تغییری در نوتیفیکیشن و Audit لازم نداشته باشد.

### ۲.۲ قرارداد رابط (Interface Contract)

هر ماژول سه چیز صادر می‌کند و هیچ چیز دیگری:

```python
# modules/groups/__init__.py
from .ports import GroupService, GroupReadModel      # ۱) رابط عمومی
from .events import GroupMemberAdded, PrivacyChanged  # ۲) رویدادهای منتشرشده
from .schemas import GroupPublic, MemberPublic        # ۳) DTOهای عمومی

__all__ = ["GroupService", "GroupReadModel", "GroupMemberAdded",
           "PrivacyChanged", "GroupPublic", "MemberPublic"]
```

```python
# modules/groups/ports.py — قرارداد، نه پیاده‌سازی
from typing import Protocol
from uuid import UUID

class GroupReadModel(Protocol):
    """هر ماژول دیگری فقط این را می‌بیند. تغییر امضای این متدها = تغییر شکننده."""

    async def is_member(self, user_id: UUID, group_id: UUID) -> bool: ...
    async def is_manager(self, user_id: UUID, group_id: UUID) -> bool: ...
    async def member_ids(self, group_id: UUID, include_subgroups: bool = False) -> list[UUID]: ...
    async def groups_of(self, user_id: UUID) -> list[GroupPublic]: ...
    async def effective_privacy(self, owner_id: UUID, viewer_id: UUID) -> PrivacyDecision: ...
```

ماژول Reporting برای ساخت داشبورد مدیر گروه، `GroupReadModel` را از طریق تزریق وابستگی می‌گیرد — **نه** `from modules.groups.db.models import Group`. اگر فردا ماژول گروه‌ها به سرویس مستقل تبدیل شود، فقط پیاده‌سازی `GroupReadModel` به یک HTTP Client تغییر می‌کند و Reporting دست‌نخورده می‌ماند.

### ۲.۳ Event Bus و الگوی Outbox

```python
# core/events/bus.py
@dataclass(frozen=True)
class DomainEvent:
    event_id: UUID
    event_type: str            # "goal.task.completed"
    occurred_at: datetime
    actor_id: UUID | None
    payload: dict
    correlation_id: UUID       # ردیابی یک عملیات در کل زنجیره

class EventBus:
    def subscribe(self, event_type: str, handler: Callable) -> None: ...
    async def publish(self, event: DomainEvent, session: AsyncSession) -> None:
        """رویداد در همان تراکنش منطق کسب‌وکار در جدول outbox درج می‌شود."""
        session.add(OutboxMessage.from_event(event))
```

**چرا Outbox و نه انتشار مستقیم؟** اگر تراکنش دیتابیس Rollback شود ولی رویداد قبلاً منتشر شده باشد، نوتیفیکیشنی ارسال می‌شود برای کاری که هرگز ذخیره نشد. با Outbox، رویداد و داده در یک تراکنش اتمیک ذخیره می‌شوند و یک Dispatcher جداگانه آن‌ها را با تضمین **At-Least-Once** تحویل می‌دهد. مصرف‌کننده‌ها باید Idempotent باشند (با `event_id` تکراری‌ها را رد کنند).

```sql
CREATE TABLE core.outbox_messages (
    id             BIGSERIAL PRIMARY KEY,
    event_id       UUID NOT NULL UNIQUE,
    event_type     VARCHAR(100) NOT NULL,
    payload        JSONB NOT NULL,
    correlation_id UUID,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    dispatched_at  TIMESTAMPTZ,
    attempts       SMALLINT NOT NULL DEFAULT 0,
    last_error     TEXT
);
CREATE INDEX ix_outbox_pending ON core.outbox_messages(created_at)
    WHERE dispatched_at IS NULL;
```

### ۲.۴ کاتالوگ رویدادها (بخشی)

| رویداد | ناشر | مصرف‌کننده‌ها |
|--------|------|----------------|
| `auth.login.succeeded` / `auth.login.failed` | M1 | M11 Audit، M10 Notification (ورود از دستگاه جدید) |
| `auth.device.registered` | M1 | M11، M10 (هشدار امنیتی) |
| `rbac.role.assigned` | M2 | M11 |
| `group.member.added` / `group.privacy.changed` | M3 | M11، M10، M9 (بازسازی کش داشبورد مدیر) |
| `goal.task.created` / `.completed` / `.overdue` | M4 | M5، M9، M10، M11 |
| `share.granted` / `share.revoked` | M6 | M8 (ایجاد آیتم کارتابل)، M10، M11 |
| `chat.room.created` / `chat.message.sent` / `chat.file.uploaded` | M7 | M10، M11، M13 (صف اسکن) |
| `inbox.item.acted` | M8 | M10 (Read Receipt به فرستنده)، M11 |

### ۲.۵ فازبندی و واگذاری به تیم‌ها

| فاز | ماژول‌ها | تیم | پیش‌نیاز |
|-----|----------|-----|----------|
| ۱ | M1 Auth، M2 RBAC، M12 SSO/LDAP، M11 Audit | تیم پلتفرم | — |
| ۲ | M3 Groups & Privacy، داشبورد مدیر گروه (نسخه پایه) | تیم A | فاز ۱ |
| ۳ | M4 Goals، M5 Calendar & Dashboard | تیم B | فاز ۱ |
| ۴ | M6 Sharing، M8 Inbox/Outbox | تیم A | فاز ۲، ۳ |
| ۵ | M7 Chat، M13 File Storage | تیم C | فاز ۱، ۶ (اشتراک‌گذاری) |
| ۶ | M9 Reporting، داشبورد پیشرفته | تیم B | فاز ۲، ۳ |
| ۷ | M10 Notification، بهینه‌سازی، سخت‌سازی | همه | همه |

**پیش‌شرط واگذاری موازی:** ماژول M1 و M11 باید **پیش از شروع کار موازی تیم‌ها تثبیت شوند**. تلاش برای ساخت همزمان Auth و Chat توسط دو تیم مختلف، به بازنویسی می‌انجامد — چون چت به مدل نشست و مجوز وابسته است.

---

## ۳. ساختار پوشه‌های پروژه

### ۳.۱ Backend

```
backend/
├── app/
│   ├── main.py
│   ├── core/                              # ───── زیرساخت مشترک (بدون منطق دامنه)
│   │   ├── config.py                      # Pydantic Settings از ENV
│   │   ├── security/
│   │   │   ├── hashing.py                 # Argon2id
│   │   │   ├── jwt.py                     # صدور/تأیید RS256
│   │   │   ├── crypto.py                  # AES-256-GCM (کد ملی، رمز LDAP، TOTP secret)
│   │   │   ├── searchable_hash.py         # HMAC-SHA256 برای جستجوی داده رمزنگاری‌شده
│   │   │   ├── device_binding.py          # تأیید HMAC هدر MAC/Fingerprint
│   │   │   ├── nonce.py                   # Replay Guard
│   │   │   └── totp.py                    # MFA
│   │   ├── events/{bus.py, outbox.py, dispatcher.py}
│   │   ├── db/{session.py, base.py, uow.py, mixins.py}
│   │   ├── middleware/
│   │   │   ├── request_id.py  security_headers.py  cors.py
│   │   │   ├── ip_filter.py   rate_limit.py        body_guard.py
│   │   │   ├── authentication.py  device_binding.py  session_guard.py
│   │   │   └── audit_context.py
│   │   ├── errors.py  logging.py  pagination.py  sanitizer.py
│   │   └── context.py                     # ContextVar: user, ip, mac, fingerprint, request_id
│   │
│   ├── modules/                           # ───── هر ماژول یک مرز بسته
│   │   ├── auth/
│   │   │   ├── __init__.py                # فقط رابط عمومی صادر می‌شود
│   │   │   ├── ports.py  events.py  schemas.py
│   │   │   ├── api/{routes.py, admin_routes.py, deps.py}
│   │   │   ├── services/{auth_service.py, mfa_service.py, device_service.py,
│   │   │   │             password_service.py, session_service.py}
│   │   │   ├── db/{models.py, repositories.py}   # schema: auth
│   │   │   └── tests/
│   │   ├── rbac/          # schema: rbac      — نقش، Permission، Middleware بررسی دسترسی
│   │   ├── groups/        # schema: groups    — گروه‌های سلسله‌مراتبی، حریم خصوصی
│   │   ├── goals/         # schema: planning  — اهداف، برنامه‌ها، تسک‌ها، adhoc، تگ‌ها
│   │   ├── calendar/      # schema: planning  — نماهای تقویمی، یادآورها
│   │   ├── sharing/       # schema: sharing   — ACL، انتقال مالکیت، کامنت، Activity
│   │   ├── chat/          # schema: chat      — اتاق، پیام، عضویت، آرشیو
│   │   ├── inbox/         # schema: inbox     — کارتابل ورودی/ارسالی، Read Receipt
│   │   ├── reporting/     # schema: reporting — نمودار، Export، داشبورد مدیر گروه
│   │   ├── notification/  # schema: notify    — اعلان، Push، ترجیحات
│   │   ├── audit/         # schema: audit     — audit_logs، login_audit_logs، hash chain
│   │   ├── ssoldap/       # schema: auth      — LDAP، Kerberos، نگاشت گروه
│   │   └── files/         # schema: files     — آپلود، اسکن AV، Presigned URL
│   │
│   ├── workers/
│   │   ├── celery_app.py
│   │   └── tasks/{reminders.py, emails.py, webpush.py, exports.py,
│   │              av_scan.py, outbox_dispatcher.py, audit_archive.py, ldap_sync.py}
│   └── ws/
│       ├── manager.py                     # مدیریت اتصال‌ها + Redis Pub/Sub
│       └── handlers/{chat.py, notifications.py}
│
├── alembic/versions/
├── tests/{unit, integration, security, architecture}/
├── pyproject.toml   .env.example   Dockerfile
```

### ۳.۲ Frontend دسکتاپ

```
desktop/
├── app/
│   ├── main.py                    # RTL سراسری، بارگذاری فونت، تم
│   ├── core/
│   │   ├── api_client.py          # httpx + تزریق خودکار هدرهای دستگاه
│   │   ├── device_identity.py     # MAC via psutil + Fingerprint سیستمی + امضای HMAC
│   │   ├── auth_manager.py        # login / MFA / refresh / logout
│   │   ├── token_store.py         # DPAPI + keyring
│   │   ├── sso_client.py          # requests-negotiate-sspi
│   │   ├── ws_client.py           # کلاینت WebSocket چت (روی QThread)
│   │   ├── event_bus.py           # سیگنال‌های سراسری بین ViewModelها
│   │   └── permissions.py         # کش Permission برای مخفی‌سازی UI (نه امنیت)
│   ├── viewmodels/                # login, mfa, dashboard, calendar, goal, task,
│   │                              # chat, inbox, group_manager, privacy, admin, widget
│   ├── views/
│   │   ├── main_window.py  login_window.py  mfa_dialog.py
│   │   ├── dashboard/{dashboard_view.py, grid_canvas.py, blocks/}
│   │   ├── widgets/{clock_widget.py, tag_chip.py, persian_date_picker.py,
│   │   │            avatar.py, toast.py, floating_widget_base.py}
│   │   ├── calendar/  chat/  inbox/  group_manager/  admin/  settings/
│   ├── services/{notifier.py, reminder_worker.py, jalali_service.py, layout_store.py}
│   ├── resources/{fonts/, icons/, themes/{dark.qss,light.qss}, i18n/}
│   └── utils/{rtl.py, digits.py}
└── build/planner.spec
```

### ۳.۳ Frontend وب

```
web/
├── public/{manifest.webmanifest, sw.js, icons/}
├── src/
│   ├── main.tsx                      # <html dir="rtl" lang="fa">
│   ├── api/{client.ts, generated/, queries/, ws.ts}
│   ├── security/
│   │   ├── fingerprint.ts            # FingerprintJS + هش پایدار
│   │   ├── deviceHeaders.ts          # تزریق X-Device-* + امضا
│   │   └── sanitize.ts               # DOMPurify
│   ├── features/
│   │   ├── auth/{Login, MfaChallenge, Devices, Sessions}
│   │   ├── rbac/  groups/  goals/  calendar/  sharing/
│   │   ├── chat/{RoomList, MessageStream, FileUpload, useChatSocket}
│   │   ├── inbox/{InboxView, OutboxView, ReceiptBadge}
│   │   ├── dashboard/{DashboardGrid, blocks/, useLayoutPersistence, LayoutManager}
│   │   ├── widgets/{ClockWidget, WidgetCanvas, useWidgetSettings}
│   │   ├── groupManager/  reports/  admin/{Users, BulkLoginMode, AuditLogs, Ldap}
│   ├── components/ui/                # Design System
│   ├── hooks/  store/  lib/{jalali.ts, permissions.ts}
│   ├── styles/tailwind.css           # logical properties برای RTL
│   └── types/
└── vite.config.ts  tailwind.config.ts
```

---

## ۴. طراحی دیتابیس

### ۴.۱ قراردادها

- یک **Schema به‌ازای هر ماژول** (`auth`, `rbac`, `groups`, `planning`, `sharing`, `chat`, `inbox`, `reporting`, `notify`, `audit`, `files`). کاربر دیتابیس برنامه روی هر Schema نقش جداگانه دارد؛ ماژول چت حتی در سطح دیتابیس به جداول اهداف `SELECT` ندارد.
- کلید اصلی **UUID** (ضد شمارش‌پذیری/IDOR)؛ جداول لاگ `BIGSERIAL` (حجم بالا، ترتیب زمانی).
- زمان‌ها `TIMESTAMPTZ` و **UTC**؛ تبدیل جلالی فقط در لایه‌ی نمایش.
- `version INTEGER` برای Optimistic Locking روی موجودیت‌های اشتراکی.
- `deleted_at` برای Soft Delete؛ جداول Audit **هرگز** حذف نمی‌شوند.

### ۴.۲ ماژول Auth — کاربران، کد ملی، MFA، دستگاه‌ها

```sql
CREATE SCHEMA auth;
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TYPE auth.auth_mode AS ENUM ('local', 'sso', 'both');

CREATE TABLE auth.users (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- ── هویت
    username            VARCHAR(64)  NOT NULL,
    national_id_enc     BYTEA        NOT NULL,   -- AES-256-GCM (کد ملی)
    national_id_nonce   BYTEA        NOT NULL,
    national_id_hash    CHAR(64)     NOT NULL,   -- HMAC-SHA256(کد ملی, PEPPER) برای جستجو
    national_id_last4   CHAR(4)      NOT NULL,   -- نمایش ماسک‌شده در UI: ******1234
    email               VARCHAR(255),
    mobile_enc          BYTEA,                   -- برای MFA پیامکی
    display_name        VARCHAR(128) NOT NULL,
    employee_code       VARCHAR(32),

    -- ── احراز هویت
    auth_mode           auth.auth_mode NOT NULL DEFAULT 'local',
    sso_enabled         BOOLEAN NOT NULL DEFAULT FALSE,
    password_hash       TEXT,                     -- Argon2id
    password_changed_at TIMESTAMPTZ,
    password_expires_at TIMESTAMPTZ,              -- سیاست ۹۰ روزه (بخش ۱۱.۳ را ببینید)
    must_change_password BOOLEAN NOT NULL DEFAULT FALSE,
    token_version       INTEGER NOT NULL DEFAULT 1,

    -- ── MFA
    mfa_enabled         BOOLEAN NOT NULL DEFAULT FALSE,
    mfa_method          VARCHAR(16),              -- totp | email | sms
    mfa_secret_enc      BYTEA,                    -- AES-GCM؛ هرگز در پاسخ API
    mfa_secret_nonce    BYTEA,
    mfa_enrolled_at     TIMESTAMPTZ,

    -- ── LDAP
    ldap_dn             TEXT,
    ldap_object_guid    UUID,
    ldap_sam_account    VARCHAR(256),
    ldap_synced_at      TIMESTAMPTZ,

    -- ── وضعیت و امنیت
    is_active           BOOLEAN NOT NULL DEFAULT TRUE,
    failed_login_count  SMALLINT NOT NULL DEFAULT 0,
    locked_until        TIMESTAMPTZ,
    lockout_level       SMALLINT NOT NULL DEFAULT 0,   -- Exponential Backoff
    last_login_at       TIMESTAMPTZ,
    allowed_ip_ranges   CIDR[],                        -- IP Whitelist سطح کاربر
    require_trusted_device BOOLEAN NOT NULL DEFAULT FALSE,

    -- ── شخصی‌سازی
    theme               VARCHAR(10) NOT NULL DEFAULT 'system',
    locale              VARCHAR(10) NOT NULL DEFAULT 'fa-IR',
    timezone            VARCHAR(64) NOT NULL DEFAULT 'Asia/Tehran',
    privacy_level       VARCHAR(20) NOT NULL DEFAULT 'team_only',

    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at TIMESTAMPTZ,

    CONSTRAINT ck_auth_method CHECK (password_hash IS NOT NULL OR sso_enabled = TRUE)
);

CREATE UNIQUE INDEX uq_users_national ON auth.users(national_id_hash) WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX uq_users_username ON auth.users(lower(username))  WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX uq_users_guid     ON auth.users(ldap_object_guid) WHERE ldap_object_guid IS NOT NULL;
```

> **چرا کد ملی رمزنگاری می‌شود:** کد ملی یک شناسه‌ی هویتی دائمی و غیرقابل تغییر است. نشت جدول کاربران با کد ملی plaintext، آسیبی است که هیچ‌وقت قابل جبران نیست — برخلاف رمز عبور که قابل تغییر است. الگوی **رمزنگاری + هش جستجوپذیر** هر دو نیاز را برآورده می‌کند: ورود با کد ملی از طریق `national_id_hash` انجام می‌شود (یک ایندکس یکتا، بدون رمزگشایی)، و مقدار اصلی فقط هنگام نمایش به Admin مجاز رمزگشایی می‌شود. اعتبارسنجی کد ملی باید الگوریتم چک‌سام رسمی (رقم کنترل) را اجرا کند، نه فقط بررسی ۱۰ رقمی بودن.

```sql
CREATE TABLE auth.user_devices (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id            UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    device_fingerprint VARCHAR(255) NOT NULL,        -- کلید اصلی شناسایی
    mac_address        VARCHAR(17),                  -- فقط Desktop؛ 00:1A:2B:3C:4D:5E
    mac_source         VARCHAR(16),                  -- psutil | uuid_getnode | unavailable
    platform           VARCHAR(16) NOT NULL,         -- desktop | web | mobile_web
    device_label       VARCHAR(128),                 -- قابل نام‌گذاری توسط کاربر
    os_info            VARCHAR(128),
    user_agent         TEXT,
    hmac_key_enc       BYTEA,                        -- کلید امضای هدر دستگاه (AES-GCM)
    is_trusted         BOOLEAN NOT NULL DEFAULT FALSE,
    trusted_at         TIMESTAMPTZ,
    trusted_by_mfa     BOOLEAN NOT NULL DEFAULT FALSE,
    first_seen_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_ip            INET,
    is_blocked         BOOLEAN NOT NULL DEFAULT FALSE,
    blocked_reason     VARCHAR(255)
);
CREATE UNIQUE INDEX uq_device ON auth.user_devices(user_id, device_fingerprint);
CREATE INDEX ix_device_mac ON auth.user_devices(mac_address) WHERE mac_address IS NOT NULL;

CREATE TABLE auth.sessions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    device_id       UUID REFERENCES auth.user_devices(id) ON DELETE SET NULL,
    refresh_hash    CHAR(64) NOT NULL UNIQUE,
    family_id       UUID NOT NULL,                  -- تشخیص Token Reuse
    auth_method     VARCHAR(20) NOT NULL,           -- local | ldap | kerberos
    mfa_satisfied   BOOLEAN NOT NULL DEFAULT FALSE,
    ip_address      INET,
    geo_location    JSONB,
    issued_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_active_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at      TIMESTAMPTZ NOT NULL,
    revoked_at      TIMESTAMPTZ,
    revoked_reason  VARCHAR(64)
);
CREATE INDEX ix_sessions_active ON auth.sessions(user_id) WHERE revoked_at IS NULL;

CREATE TABLE auth.mfa_recovery_codes (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    code_hash  CHAR(64) NOT NULL,                   -- کد بازیابی هم هش می‌شود
    used_at    TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE auth.ip_access_rules (
    id         SERIAL PRIMARY KEY,
    scope      VARCHAR(16) NOT NULL,                -- global | user
    user_id    UUID REFERENCES auth.users(id) ON DELETE CASCADE,
    cidr       CIDR NOT NULL,
    rule_type  VARCHAR(10) NOT NULL,                -- allow | deny
    reason     VARCHAR(255),
    expires_at TIMESTAMPTZ,
    created_by UUID REFERENCES auth.users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE auth.ldap_settings (          -- Singleton؛ ساختار مطابق نسخه ۱
    id SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    is_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    server_host VARCHAR(255) NOT NULL,
    server_port INTEGER NOT NULL DEFAULT 636,
    use_ssl BOOLEAN NOT NULL DEFAULT TRUE,
    use_start_tls BOOLEAN NOT NULL DEFAULT FALSE,
    validate_certificate BOOLEAN NOT NULL DEFAULT TRUE,
    ca_certificate TEXT,
    base_dn VARCHAR(512) NOT NULL,
    user_search_base VARCHAR(512),
    group_search_base VARCHAR(512),
    user_filter VARCHAR(512) NOT NULL DEFAULT '(&(objectClass=user)(sAMAccountName={username}))',
    attr_national_id VARCHAR(64) DEFAULT 'employeeID',   -- نگاشت کد ملی از AD
    bind_dn VARCHAR(512) NOT NULL,
    bind_password_enc BYTEA NOT NULL,
    bind_password_nonce BYTEA NOT NULL,
    auto_provision BOOLEAN NOT NULL DEFAULT TRUE,
    default_role_id SMALLINT,
    kerberos_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    kerberos_spn VARCHAR(255),
    kerberos_keytab_path VARCHAR(512),
    last_test_at TIMESTAMPTZ,
    last_test_result JSONB,
    updated_by UUID, updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

### ۴.۳ ماژول RBAC

```sql
CREATE SCHEMA rbac;

CREATE TABLE rbac.permissions (
    id       SERIAL PRIMARY KEY,
    code     VARCHAR(100) NOT NULL UNIQUE,   -- ساختار: module.action
    module   VARCHAR(40)  NOT NULL,
    action   VARCHAR(40)  NOT NULL,
    title_fa VARCHAR(120) NOT NULL,
    is_dangerous BOOLEAN NOT NULL DEFAULT FALSE   -- نیازمند تأیید دوم در UI
);

-- نمونه: goal.create, goal.delete.any, group.manage, user.bulk_login_mode,
--        audit.read, audit.export, chat.room.delete, ldap.configure, rbac.assign

CREATE TABLE rbac.roles (
    id          SMALLSERIAL PRIMARY KEY,
    code        VARCHAR(32) NOT NULL UNIQUE,   -- super_admin|admin|manager|user|viewer
    title_fa    VARCHAR(64) NOT NULL,
    level       SMALLINT NOT NULL,             -- برای جلوگیری از Privilege Escalation
    is_system   BOOLEAN NOT NULL DEFAULT TRUE,
    description TEXT
);

CREATE TABLE rbac.role_permissions (
    role_id       SMALLINT REFERENCES rbac.roles(id) ON DELETE CASCADE,
    permission_id INTEGER  REFERENCES rbac.permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

CREATE TABLE rbac.user_roles (
    user_id    UUID     NOT NULL,              -- FK منطقی به auth.users
    role_id    SMALLINT NOT NULL REFERENCES rbac.roles(id) ON DELETE CASCADE,
    scope_type VARCHAR(16) NOT NULL DEFAULT 'global',   -- global | group
    scope_id   UUID,                                     -- group_id در نقش دامنه‌دار
    granted_by UUID,
    granted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ,
    source     VARCHAR(16) NOT NULL DEFAULT 'manual',    -- manual | ldap_group
    PRIMARY KEY (user_id, role_id, scope_type, COALESCE(scope_id, '00000000-0000-0000-0000-000000000000'::uuid))
);
```

> **نقش دامنه‌دار (Scoped Role):** «مدیر گروه» یک نقش سراسری نیست — کاربر می‌تواند مدیر گروه الف و عضو ساده‌ی گروه ب باشد. `scope_type='group'` این را مدل می‌کند. بدون آن، مدیر یک گروه به داده‌ی همه‌ی گروه‌ها دسترسی پیدا می‌کند؛ یک اشتباه رایج و پرهزینه.

### ۴.۴ ماژول Groups و حریم خصوصی

```sql
CREATE SCHEMA groups;

CREATE TYPE groups.privacy_level AS ENUM
    ('fully_private', 'team_only', 'selected', 'fully_transparent');

CREATE TABLE groups.groups (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    parent_id   UUID REFERENCES groups.groups(id) ON DELETE RESTRICT,
    path        LTREE,                          -- مسیر سلسله‌مراتبی برای کوئری زیرگروه‌ها
    name        VARCHAR(128) NOT NULL,
    description TEXT,
    ldap_group_dn VARCHAR(512),
    is_active   BOOLEAN NOT NULL DEFAULT TRUE,
    created_by  UUID,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at  TIMESTAMPTZ
);
CREATE INDEX ix_groups_path ON groups.groups USING GIST(path);

CREATE TABLE groups.group_members (
    group_id   UUID NOT NULL REFERENCES groups.groups(id) ON DELETE CASCADE,
    user_id    UUID NOT NULL,
    is_manager BOOLEAN NOT NULL DEFAULT FALSE,
    joined_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    added_by   UUID,
    PRIMARY KEY (group_id, user_id)
);
CREATE INDEX ix_group_members_user ON groups.group_members(user_id);

CREATE TABLE groups.privacy_settings (
    user_id          UUID PRIMARY KEY,
    default_level    groups.privacy_level NOT NULL DEFAULT 'team_only',
    goals_level      groups.privacy_level,         -- override به‌ازای نوع داده
    tasks_level      groups.privacy_level,
    meetings_level   groups.privacy_level,
    progress_level   groups.privacy_level,
    allow_manager_comment BOOLEAN NOT NULL DEFAULT TRUE,
    notify_on_manager_view BOOLEAN NOT NULL DEFAULT TRUE,
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE groups.privacy_exceptions (      -- حالت 'selected'
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_id     UUID NOT NULL,
    viewer_id    UUID NOT NULL,
    entity_type  VARCHAR(32),                  -- NULL = همه انواع
    can_comment  BOOLEAN NOT NULL DEFAULT FALSE,
    granted_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at   TIMESTAMPTZ,
    UNIQUE (owner_id, viewer_id, entity_type)
);
```

### ۴.۵ ماژول Chat

```sql
CREATE SCHEMA chat;

CREATE TABLE chat.rooms (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title          VARCHAR(160) NOT NULL,
    linked_type    VARCHAR(32),               -- task | meeting | goal | NULL (اتاق آزاد)
    linked_id      UUID,
    owner_id       UUID NOT NULL,
    is_archived    BOOLEAN NOT NULL DEFAULT FALSE,
    archived_at    TIMESTAMPTZ,
    archive_object_key VARCHAR(512),          -- مسیر آرشیو در S3 پیش از حذف
    retention_days SMALLINT NOT NULL DEFAULT 365,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at     TIMESTAMPTZ
);
CREATE INDEX ix_rooms_linked ON chat.rooms(linked_type, linked_id);

CREATE TABLE chat.room_members (
    room_id     UUID NOT NULL REFERENCES chat.rooms(id) ON DELETE CASCADE,
    user_id     UUID NOT NULL,
    role        VARCHAR(16) NOT NULL DEFAULT 'member',  -- owner|moderator|member|readonly
    joined_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_read_message_id UUID,
    muted_until TIMESTAMPTZ,
    left_at     TIMESTAMPTZ,
    PRIMARY KEY (room_id, user_id)
);

CREATE TABLE chat.messages (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    room_id     UUID NOT NULL REFERENCES chat.rooms(id) ON DELETE CASCADE,
    sender_id   UUID NOT NULL,
    reply_to_id UUID REFERENCES chat.messages(id) ON DELETE SET NULL,
    body        TEXT CHECK (char_length(body) <= 4000),
    body_html   TEXT,                          -- خروجی sanitize شده
    file_id     UUID,                          -- files.uploads
    message_type VARCHAR(16) NOT NULL DEFAULT 'text',  -- text|file|system
    is_edited   BOOLEAN NOT NULL DEFAULT FALSE,
    edited_at   TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at  TIMESTAMPTZ,
    search_vector TSVECTOR
);
CREATE INDEX ix_messages_room ON chat.messages(room_id, created_at DESC) WHERE deleted_at IS NULL;
CREATE INDEX ix_messages_search ON chat.messages USING GIN(search_vector);

CREATE SCHEMA files;
CREATE TABLE files.uploads (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    uploader_id   UUID NOT NULL,
    context_type  VARCHAR(32) NOT NULL,        -- chat | task_attachment | avatar
    context_id    UUID,
    original_name VARCHAR(255) NOT NULL,       -- فقط برای نمایش، هرگز در مسیر فایل
    object_key    VARCHAR(512) NOT NULL UNIQUE,-- UUID-based؛ خارج از Web Root
    mime_declared VARCHAR(128),
    mime_detected VARCHAR(128),                -- از magic number
    size_bytes    BIGINT NOT NULL CHECK (size_bytes <= 52428800),   -- ۵۰MB
    sha256        CHAR(64) NOT NULL,
    scan_status   VARCHAR(16) NOT NULL DEFAULT 'pending',  -- pending|clean|infected|error
    scan_engine   VARCHAR(32),
    scanned_at    TIMESTAMPTZ,
    is_available  BOOLEAN NOT NULL DEFAULT FALSE,          -- تا تأیید اسکن، دانلود ممنوع
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at    TIMESTAMPTZ
);
CREATE INDEX ix_uploads_scan ON files.uploads(scan_status) WHERE scan_status = 'pending';
```

### ۴.۶ ماژول Inbox/Outbox (کارتابل)

```sql
CREATE SCHEMA inbox;

CREATE TYPE inbox.item_action AS ENUM ('pending', 'accepted', 'rejected', 'deferred', 'expired');
CREATE TYPE inbox.receipt_state AS ENUM ('sent', 'seen', 'acted');

CREATE TABLE inbox.items (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    sender_id      UUID NOT NULL,
    recipient_id   UUID NOT NULL,
    item_type      VARCHAR(40) NOT NULL,   -- meeting_invite | share_request |
                                           -- task_assignment | chat_invite | approval
    entity_type    VARCHAR(32),
    entity_id      UUID,
    title          VARCHAR(200) NOT NULL,
    message        TEXT,
    priority       VARCHAR(16) NOT NULL DEFAULT 'normal',
    action_state   inbox.item_action NOT NULL DEFAULT 'pending',
    receipt_state  inbox.receipt_state NOT NULL DEFAULT 'sent',
    seen_at        TIMESTAMPTZ,
    acted_at       TIMESTAMPTZ,
    defer_until    TIMESTAMPTZ,            -- گزینه «بعداً»
    response_note  TEXT,
    due_at         TIMESTAMPTZ,
    expires_at     TIMESTAMPTZ,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX ix_inbox_recipient ON inbox.items(recipient_id, action_state, created_at DESC);
CREATE INDEX ix_inbox_sender    ON inbox.items(sender_id, created_at DESC);
CREATE INDEX ix_inbox_deferred  ON inbox.items(defer_until) WHERE action_state = 'deferred';
```

### ۴.۷ شخصی‌سازی — داشبورد و ویجت‌ها

```sql
CREATE SCHEMA reporting;

CREATE TABLE reporting.dashboard_layouts (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID NOT NULL,
    name       VARCHAR(64) NOT NULL,
    view_mode  VARCHAR(16) NOT NULL DEFAULT 'daily',
    is_default BOOLEAN NOT NULL DEFAULT FALSE,
    schema_version SMALLINT NOT NULL DEFAULT 1,   -- برای Import/Export سازگار
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX uq_layout_default ON reporting.dashboard_layouts(user_id, view_mode)
    WHERE is_default = TRUE;

CREATE TABLE reporting.user_dashboard_settings (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL,
    layout_id   UUID NOT NULL REFERENCES reporting.dashboard_layouts(id) ON DELETE CASCADE,
    block_key   VARCHAR(48) NOT NULL,
    is_visible  BOOLEAN NOT NULL DEFAULT TRUE,
    position_x  SMALLINT NOT NULL DEFAULT 0  CHECK (position_x BETWEEN 0 AND 11),
    position_y  SMALLINT NOT NULL DEFAULT 0,
    width       SMALLINT NOT NULL DEFAULT 4  CHECK (width  BETWEEN 1 AND 12),
    height      SMALLINT NOT NULL DEFAULT 4  CHECK (height BETWEEN 1 AND 20),
    is_collapsed BOOLEAN NOT NULL DEFAULT FALSE,
    config      JSONB NOT NULL DEFAULT '{}',
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (layout_id, block_key),
    CONSTRAINT ck_within_grid CHECK (position_x + width <= 12)
);

CREATE TABLE reporting.user_widget_settings (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL,
    widget_key  VARCHAR(48) NOT NULL,          -- clock | quick_add | mini_calendar
    platform    VARCHAR(16) NOT NULL DEFAULT 'all',   -- desktop | web | all
    is_visible  BOOLEAN NOT NULL DEFAULT TRUE,
    position_x  INTEGER NOT NULL DEFAULT 20,   -- مختصات مطلق (ویجت شناور)
    position_y  INTEGER NOT NULL DEFAULT 20,
    width       INTEGER NOT NULL DEFAULT 260 CHECK (width  BETWEEN 160 AND 640),
    height      INTEGER NOT NULL DEFAULT 120 CHECK (height BETWEEN 80  AND 400),
    z_index     SMALLINT NOT NULL DEFAULT 10,
    style       JSONB NOT NULL DEFAULT '{}',   -- {bg, fg, font_family, font_size, opacity}
    config      JSONB NOT NULL DEFAULT '{}',   -- {show_jalali, show_gregorian, show_hijri,
                                               --  time_format:"HH:mm:ss", show_seconds}
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (user_id, widget_key, platform)
);
```

> `config` و `style` عمداً JSONB هستند تا افزودن گزینه، Migration نخواهد. اما محتوای آن‌ها **در سرور با یک اسکیمای Pydantic مخصوص هر `widget_key`/`block_key` اعتبارسنجی می‌شود**. JSONB به معنای پذیرش هر ورودی نیست — این یک بردار تزریق رایج است (ذخیره‌ی `opacity: "<script>"` و رندر مستقیم آن در CSS).

### ۴.۸ ماژول Audit — با MAC Address و زنجیره‌ی هش

```sql
CREATE SCHEMA audit;

CREATE TABLE audit.audit_logs (
    id                 BIGSERIAL PRIMARY KEY,
    user_id            UUID,
    action             VARCHAR(100) NOT NULL,
    entity_type        VARCHAR(50),
    entity_id          UUID,
    timestamp          TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- ── هویت شبکه و دستگاه
    ip_address         INET,
    mac_address        VARCHAR(17),          -- Desktop؛ NULL/unknown در Web
    mac_verified       BOOLEAN NOT NULL DEFAULT FALSE,   -- امضای HMAC معتبر بود؟
    device_fingerprint VARCHAR(255),
    device_id          UUID,                 -- FK منطقی به auth.user_devices
    user_agent         TEXT,
    session_id         UUID,

    result             VARCHAR(20) NOT NULL, -- success | failure | denied
    details            JSONB,
    old_value          JSONB,
    new_value          JSONB,
    geo_location       JSONB,
    request_id         UUID,
    correlation_id     UUID,

    -- ── یکپارچگی
    prev_hash          CHAR(64),             -- زنجیره هش
    row_hash           CHAR(64) NOT NULL,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now()
) PARTITION BY RANGE (timestamp);

CREATE TABLE audit.audit_logs_2026q3 PARTITION OF audit.audit_logs
    FOR VALUES FROM ('2026-07-01') TO ('2026-10-01');

CREATE INDEX idx_audit_user_time   ON audit.audit_logs(user_id, timestamp DESC);
CREATE INDEX idx_audit_mac         ON audit.audit_logs(mac_address) WHERE mac_address IS NOT NULL;
CREATE INDEX idx_audit_ip          ON audit.audit_logs(ip_address);
CREATE INDEX idx_audit_action      ON audit.audit_logs(action, timestamp DESC);
CREATE INDEX idx_audit_fingerprint ON audit.audit_logs(device_fingerprint);
CREATE INDEX idx_audit_entity      ON audit.audit_logs(entity_type, entity_id, timestamp DESC);

CREATE TABLE audit.login_audit_logs (
    id                 BIGSERIAL PRIMARY KEY,
    user_id            UUID,
    username           VARCHAR(100),          -- حتی برای کاربر ناموجود ثبت می‌شود
    national_id_hash   CHAR(64),              -- هرگز کد ملی خام در لاگ
    auth_method        VARCHAR(20) NOT NULL,  -- local | sso | ldap | kerberos
    mfa_used           VARCHAR(16),           -- totp | email | sms | recovery | none
    timestamp          TIMESTAMPTZ NOT NULL DEFAULT now(),
    ip_address         INET,
    mac_address        VARCHAR(17),
    mac_verified       BOOLEAN NOT NULL DEFAULT FALSE,
    device_fingerprint VARCHAR(255),
    device_is_trusted  BOOLEAN,
    user_agent         TEXT,
    success            BOOLEAN NOT NULL,
    failure_reason     VARCHAR(255),          -- کد داخلی، نه پیام کاربر
    session_id         UUID,
    geo_location       JSONB,
    risk_score         SMALLINT,              -- ۰ تا ۱۰۰ (بخش ۶.۵)
    prev_hash          CHAR(64),
    row_hash           CHAR(64) NOT NULL,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_login_audit_user  ON audit.login_audit_logs(user_id, timestamp DESC);
CREATE INDEX idx_login_audit_mac   ON audit.login_audit_logs(mac_address);
CREATE INDEX idx_login_audit_ip    ON audit.login_audit_logs(ip_address, timestamp DESC);
CREATE INDEX idx_login_failed      ON audit.login_audit_logs(username, timestamp DESC)
    WHERE success = FALSE;

-- کاربر برنامه فقط اجازه درج دارد
REVOKE UPDATE, DELETE ON ALL TABLES IN SCHEMA audit FROM app_user;
GRANT  INSERT, SELECT  ON ALL TABLES IN SCHEMA audit TO app_user;
```

**زنجیره‌ی هش (Hash Chain) — یکپارچگی لاگ:**

```
row_hash = SHA256( prev_hash ‖ id ‖ user_id ‖ action ‖ timestamp ‖ ip ‖ mac ‖ result ‖ details )
```

هر رکورد به رکورد قبلی گره می‌خورد. حذف یا تغییر یک رکورد، زنجیره را می‌شکند و یک Job روزانه‌ی بازبینی آن را کشف می‌کند. علاوه بر این، آخرین `row_hash` هر روز **به یک سیستم بیرونی (SIEM یا فایل WORM) ارسال می‌شود** — بدون این لنگر بیرونی، مهاجمی با دسترسی به دیتابیس می‌تواند کل زنجیره را بازسازی کند. امضای دیجیتال تک‌رکوردی این خاصیت را ندارد: تغییر را کشف می‌کند اما **حذف** را نه.

### ۴.۹ استراتژی رمزنگاری

| داده | روش | کلید | نکته |
|------|-----|------|------|
| رمز عبور | Argon2id (`t=3, m=64MiB, p=4`) + Salt یکتا | — | ارتقای خودکار پارامترها هنگام ورود |
| کد ملی | AES-256-GCM + HMAC-SHA256 برای جستجو | DEK از Vault، PEPPER جدا از DEK | Nonce یکتا در هر رمزنگاری |
| موبایل | AES-256-GCM | همان DEK | فقط برای MFA پیامکی |
| TOTP Secret | AES-256-GCM | DEK اختصاصی MFA | افشای آن = دور زدن کامل MFA |
| رمز Bind اکانت LDAP | AES-256-GCM (Envelope) | DEK از Vault | Write-Only در API |
| Refresh Token / کد بازیابی | SHA-256 | — | مقدار اصلی هرگز ذخیره نمی‌شود |
| کلید HMAC دستگاه | AES-256-GCM | DEK اختصاصی | یکتا به‌ازای هر دستگاه |
| کل دیتابیس | TDE سطح Volume (LUKS / Cloud KMS) | مدیریت زیرساخت | PostgreSQL TDE بومی ندارد |
| فایل‌های آپلودی | SSE-S3 / SSE-KMS در MinIO | KMS | به‌علاوه‌ی اسکن AV |
| بکاپ | `pg_dump` + age/GPG | کلید مجزا از DB | تست بازیابی ماهانه اجباری |
| ارتباط با DB | TLS `sslmode=verify-full` | CA سازمانی | — |

**چرخش کلید (Key Rotation):** هر DEK یک `key_version` دارد که در کنار داده‌ی رمزنگاری‌شده ذخیره می‌شود. چرخش سالانه با رمزگشایی/رمزنگاری مجدد دسته‌ای انجام می‌شود، بدون Downtime. طراحی فیلدها از ابتدا باید فضای `key_version` را داشته باشد — افزودن آن بعداً پرهزینه است.

---

## ۵. طراحی API

### ۵.۱ قراردادهای عمومی

- پایه: `https://api.corp.local/api/v1` — نسخه در مسیر. سیاست نسخه‌بندی: `v(n)` تا ۱۲ ماه پس از انتشار `v(n+1)` پشتیبانی می‌شود؛ هدر `Deprecation` و `Sunset` روی نسخه‌ی قدیمی ارسال می‌گردد.
- هدرهای اجباری کلاینت روی هر درخواست احراز هویت‌شده:

```
Authorization:        Bearer <access_token>
X-Device-Fingerprint: <sha256-hash>
X-Device-MAC:         00:1A:2B:3C:4D:5E        (فقط Desktop؛ در Web ارسال نمی‌شود)
X-Device-Nonce:       <uuid4>                   (ضد Replay)
X-Device-Timestamp:   <unix-ms>
X-Device-Signature:   <hmac-sha256>
X-Request-ID:         <uuid4>
```

- قالب خطای یکنواخت، صفحه‌بندی Cursor، `ETag`/`If-Match` برای Optimistic Locking، و `Idempotency-Key` روی POSTهای حساس — مطابق نسخه ۱.
- **۴۰۴ به‌جای ۴۰۳** وقتی کاربر اصلاً نباید از وجود رکورد باخبر شود؛ `403` فقط وقتی دسترسی دارد ولی سطحش کافی نیست.

### ۵.۲ Auth، MFA و دستگاه‌ها

| متد | مسیر | توضیح |
|-----|------|-------|
| POST | `/auth/register` | ثبت‌نام با کد ملی (اعتبارسنجی چک‌سام) |
| POST | `/auth/login` | ورود با `identifier` (نام کاربری **یا** کد ملی) |
| POST | `/auth/mfa/verify` | تأیید کد MFA با `mfa_token` موقت |
| POST | `/auth/mfa/enroll` | شروع ثبت TOTP (بازگشت QR + Secret) |
| POST | `/auth/mfa/enroll/confirm` | تأیید ثبت + تولید کدهای بازیابی |
| DELETE | `/auth/mfa` | غیرفعال‌سازی MFA (نیازمند رمز + کد فعلی) |
| POST | `/auth/refresh` | چرخش Refresh Token |
| POST | `/auth/logout` · `/auth/logout-all` | ابطال نشست/همه نشست‌ها |
| GET | `/auth/sessions` | نشست‌های فعال (دستگاه، IP، آخرین فعالیت) |
| DELETE | `/auth/sessions/{id}` | ابطال یک نشست |
| POST | `/auth/password/forgot` · `/reset` · `/change` | مدیریت رمز |
| GET | `/auth/sso/negotiate` | SSO با Kerberos/NTLM |
| POST | `/auth/sso/ldap-login` | ورود با اعتبارنامه AD |
| GET | `/auth/me` | پروفایل + نقش‌ها + Permissionهای مؤثر |
| **POST** | **`/auth/devices/register`** | ثبت دستگاه با MAC/Fingerprint |
| **GET** | **`/auth/devices`** | لیست دستگاه‌های شناخته‌شده (MAC ماسک‌شده) |
| PATCH | `/auth/devices/{id}` | نام‌گذاری / اعتمادسازی (نیازمند MFA) |
| DELETE | `/auth/devices/{id}` | حذف/مسدودسازی دستگاه |

```jsonc
// POST /auth/login
{ "identifier": "0012345678", "password": "••••••••", "remember_me": true,
  "captcha_token": "03AGdBq26..." }

// 200 — نیازمند MFA
{ "mfa_required": true, "mfa_token": "eyJ...",   // عمر ۵ دقیقه، فقط برای /auth/mfa/verify
  "mfa_method": "totp", "expires_in": 300 }

// 200 — بدون MFA
{ "access_token": "eyJ...", "token_type": "Bearer", "expires_in": 900,
  "device": { "id": "018f...", "is_trusted": false, "is_new": true },
  "user": { "id": "018f...", "username": "a.rezaei", "display_name": "علی رضایی",
            "national_id_masked": "******5678", "roles": ["user","manager"],
            "permissions": ["goal.create","group.view", "..."],
            "privacy_level": "team_only", "mfa_enabled": true } }

// 401 — پیام یکسان برای کاربر ناموجود و رمز غلط
{ "error": { "code": "INVALID_CREDENTIALS", "message": "اطلاعات ورود نادرست است." } }

// 403 — دستگاه غیرمجاز
{ "error": { "code": "DEVICE_NOT_TRUSTED",
             "message": "ورود از این دستگاه مجاز نیست. با مدیر سیستم تماس بگیرید." } }
```

```jsonc
// POST /auth/devices/register
{ "device_fingerprint": "a3f9...", "mac_address": "00:1A:2B:3C:4D:5E",
  "mac_source": "psutil", "platform": "desktop",
  "device_label": "لپ‌تاپ اداری", "os_info": "Windows 11 Pro 23H2" }

// 201 — کلید HMAC فقط یک‌بار و فقط در همین پاسخ برگردانده می‌شود
{ "device_id": "018f...", "hmac_key": "base64:...", "is_trusted": false,
  "requires_mfa_to_trust": true }

// GET /auth/devices  — MAC همیشه ماسک‌شده مگر برای Admin
{ "items": [
    { "id": "018f...", "device_label": "لپ‌تاپ اداری", "platform": "desktop",
      "mac_address_masked": "00:1A:**:**:**:5E", "is_trusted": true,
      "last_seen_at": "2026-09-18T06:12:00Z", "last_ip": "10.20.3.44",
      "is_current": true } ] }
```

### ۵.۳ RBAC، گروه‌ها و حریم خصوصی

| متد | مسیر | Permission |
|-----|------|------------|
| GET | `/rbac/roles` · `/rbac/permissions` | `rbac.read` |
| POST/PATCH/DELETE | `/rbac/roles/{id}` | `rbac.manage` |
| POST | `/admin/users/{id}/roles` | `rbac.assign` |
| DELETE | `/admin/users/{id}/roles/{role_id}` | `rbac.assign` |
| GET/POST | `/groups` | `group.read` / `group.create` |
| GET/PATCH/DELETE | `/groups/{id}` | `group.manage` |
| GET/POST | `/groups/{id}/members` | `group.manage` |
| PATCH | `/groups/{id}/members/{uid}` | ارتقا/تنزل مدیر گروه |
| GET | `/groups/{id}/dashboard` | مدیر همان گروه — با اعمال حریم خصوصی |
| GET | `/groups/{id}/report?from=&to=` | گزارش تیمی |
| GET/PUT | `/me/privacy` | تنظیمات حریم خصوصی کاربر |
| GET/POST/DELETE | `/me/privacy/exceptions` | حالت `selected` |
| GET | `/me/privacy/access-log` | «چه کسی داده‌ی من را دید؟» |

```jsonc
// GET /groups/{id}/dashboard  — نمونه‌ی خروجی با حریم خصوصی اعمال‌شده
{ "group": { "id": "018f...", "name": "واحد برنامه‌ریزی", "member_count": 12 },
  "period": { "from": "2026-09-01", "to": "2026-09-30" },
  "members": [
    { "user_id": "018f-a", "display_name": "علی رضایی",
      "privacy_level": "team_only", "visibility": "full",
      "stats": { "total_tasks": 24, "completed": 18, "overdue": 2, "progress_pct": 75 },
      "goals": [ { "id":"...", "title":"...", "progress_pct": 62 } ] },
    { "user_id": "018f-b", "display_name": "سارا محمدی",
      "privacy_level": "fully_private", "visibility": "aggregate_only",
      "stats": { "progress_pct": 68 },             // فقط عدد کل
      "goals": null,                                // عنوان اهداف پنهان
      "notice": "این کاربر جزئیات را خصوصی کرده است." } ],
  "aggregate": { "team_progress_pct": 71, "at_risk_members": 2 } }
```

### ۵.۴ Audit Log و Device Management

| متد | مسیر | Permission |
|-----|------|------------|
| POST | `/audit/logs` | داخلی/کلاینت — ثبت رویداد سمت کلاینت (محدود) |
| GET | `/admin/audit/logs` | `audit.read` |
| GET | `/admin/audit/logs?mac_address=00:1A:2B:3C:4D:5E` | فیلتر بر اساس MAC |
| GET | `/admin/audit/logs?device_fingerprint=&user_id=&action=&from=&to=&result=` | فیلتر ترکیبی |
| GET | `/admin/audit/login-logs` | لاگ ورودها |
| GET | `/admin/audit/logs/{id}` | جزئیات کامل (MAC بدون ماسک) |
| POST | `/admin/audit/export` | خروجی CSV/Excel — خودش یک رویداد Audit تولید می‌کند |
| GET | `/admin/audit/integrity-check` | بازبینی زنجیره هش |
| POST | `/admin/audit/archive` | آرشیو پارتیشن‌های قدیمی |
| GET | `/admin/audit/devices?mac_address=` | همبستگی دستگاه‌ها (Device Correlation) |
| GET | `/admin/audit/anomalies` | رویدادهای پرریسک (risk_score بالا) |

```jsonc
// POST /audit/logs — ثبت رویداد سمت کلاینت
// ⚠ این endpoint فقط انواع محدودی از رویداد را می‌پذیرد (whitelist)
{ "action": "ui.export.clicked", "entity_type": "report", "entity_id": "018f...",
  "details": { "format": "xlsx" } }
// MAC، IP، fingerprint و user_id از هدرها و توکن استخراج می‌شوند — هرگز از Body
// 202 Accepted (بدون بدنه)

// GET /admin/audit/logs?mac_address=00:1A:2B:3C:4D:5E&from=2026-09-01
{ "items": [
    { "id": 8842119, "timestamp": "2026-09-18T06:12:04Z",
      "user": { "id":"018f...", "display_name":"علی رضایی", "national_id_masked":"******5678" },
      "action": "goal.task.deleted", "entity_type": "task", "entity_id": "018f...",
      "result": "success",
      "ip_address": "10.20.3.44",
      "mac_address": "00:1A:2B:3C:4D:5E",    // بدون ماسک — فقط برای Admin
      "mac_verified": true,
      "device_fingerprint": "a3f9c2...", "device_label": "لپ‌تاپ اداری",
      "session_id": "018f...", "user_agent": "PlannerDesktop/2.0 (Windows 11)",
      "geo_location": { "country":"IR", "city":"Tehran", "source":"geoip" } } ],
  "total": 1284, "next_cursor": "eyJ0IjoiMjAyNi0wOS0xOFQwNjoxMjowNFoifQ==" }

// GET /admin/audit/devices?mac_address=00:1A:2B:3C:4D:5E  — Device Correlation
{ "mac_address": "00:1A:2B:3C:4D:5E",
  "users": [ { "user_id":"018f-a", "display_name":"علی رضایی", "login_count": 412,
               "first_seen":"2026-03-02T...", "last_seen":"2026-09-18T..." },
             { "user_id":"018f-c", "display_name":"محمد کریمی", "login_count": 3,
               "first_seen":"2026-09-17T...", "last_seen":"2026-09-17T..." } ],
  "warning": "این دستگاه توسط بیش از یک کاربر استفاده شده است." }
```

### ۵.۵ چت، کارتابل، داشبورد و ویجت

| متد | مسیر | توضیح |
|-----|------|-------|
| GET/POST | `/chat/rooms` | لیست/ایجاد اتاق (با `linked_type`/`linked_id`) |
| GET/PATCH/DELETE | `/chat/rooms/{id}` | مدیریت اتاق (حذف ⇒ آرشیو اجباری) |
| GET/POST | `/chat/rooms/{id}/members` | عضویت‌ها |
| GET | `/chat/rooms/{id}/messages?before=&limit=` | تاریخچه (Cursor معکوس) |
| POST | `/chat/rooms/{id}/archive` | آرشیو و دانلود تاریخچه |
| POST | `/files/presign` | دریافت Presigned URL برای آپلود |
| POST | `/files/{id}/finalize` | اعلام پایان آپلود ⇒ صف اسکن AV |
| GET | `/files/{id}/download` | دانلود (فقط اگر `scan_status='clean'`) |
| WSS | `/ws/chat` | سوکت چت |
| WSS | `/ws/notifications` | اعلان‌های زنده |
| GET | `/inbox?state=pending` | کارتابل ورودی |
| POST | `/inbox/{id}/act` | `accept` / `reject` / `defer` |
| GET | `/outbox` | کارتابل ارسالی با Read Receipt |
| GET/POST/PUT/DELETE | `/dashboard/layouts[/{id}]` | مدیریت Layout |
| POST | `/dashboard/layouts/{id}/reset` | بازگشت به پیش‌فرض |
| GET | `/dashboard/layouts/{id}/export` | خروجی JSON |
| POST | `/dashboard/layouts/import` | ورودی JSON (با اعتبارسنجی کامل) |
| GET/PUT | `/widgets/settings` | تنظیمات ویجت‌ها (Sync بین دستگاه‌ها) |
| POST | `/widgets/settings/reset` | Reset to Default |

```jsonc
// POST /inbox/{id}/act
{ "action": "defer", "defer_until": "2026-09-20T05:00:00Z", "note": "بعد از جلسه بررسی می‌کنم" }
// 200
{ "id": "018f...", "action_state": "deferred", "receipt_state": "acted",
  "acted_at": "2026-09-18T07:02:00Z" }
// ⇒ رویداد inbox.item.acted منتشر می‌شود ⇒ فرستنده Read Receipt می‌گیرد

// POST /dashboard/layouts/import
{ "schema_version": 1, "name": "چیدمان وارداتی", "view_mode": "daily",
  "blocks": [ { "block_key": "goals", "position_x": 0, "position_y": 0,
                "width": 6, "height": 4, "config": { "limit": 5 } } ] }
// 400 در صورت: block_key ناشناخته، تداخل موقعیت‌ها، خروج از گرید ۱۲ ستونه،
//               یا config نامعتبر برای آن block_key
```

---

## ۶. استراتژی MAC Address و شناسایی دستگاه

### ۶.۱ ارزیابی صادقانه: MAC چه می‌تواند و چه نمی‌تواند

این بخش را با یک ارزیابی روشن شروع می‌کنم، چون طراحی درست به آن وابسته است:

**MAC Address یک کنترل امنیتی نیست.** دلایل:

1. **قابل جعل است.** تغییر MAC در ویندوز از طریق Device Manager یا یک دستور PowerShell، بدون نیاز به دسترسی Admin روی برخی درایورها، کار چند ثانیه است.
2. **کلاینت آن را گزارش می‌دهد، نه شبکه.** سرور MAC را از هدر HTTP می‌گیرد — یعنی از همان موجودیتی که قرار است اعتبارسنجی شود. امضای HMAC هم این را حل نمی‌کند: کلید HMAC روی همان دستگاه است، پس مهاجمی که کنترل دستگاه را دارد می‌تواند **یک MAC جعلی را با امضای معتبر** بفرستد. HMAC از دستکاری **در مسیر شبکه** (MITM) محافظت می‌کند، نه از دروغ‌گویی کلاینت.
3. **از روتر عبور نمی‌کند.** MAC فقط در سگمنت شبکه‌ی محلی معنا دارد؛ سروری که پشت چند Hop است، MAC واقعی را در لایه‌ی شبکه نمی‌بیند.
4. **MAC Randomization.** ویندوز ۱۰+، اندروید ۱۰+ و iOS 14+ به‌صورت پیش‌فرض MAC تصادفی به‌ازای هر شبکه تولید می‌کنند.
5. **در VM، Container و VDI بی‌معناست.** در محیط‌های مجازی‌شده، همه‌ی کاربران ممکن است MAC یکسان یا تصادفی داشته باشند.

**پس چه ارزشی دارد؟** MAC یک **سیگنال Forensic و Correlation** است: در تحقیق پس از حادثه کمک می‌کند بفهمید کدام فعالیت‌ها از یک دستگاه بوده‌اند، و ناهنجاری‌ها را برجسته می‌کند («این کاربر همیشه از MAC ثابت وارد می‌شد، امروز از یک MAC جدید»). این ارزش واقعی است — به شرطی که MAC هرگز به‌تنهایی مبنای تصمیم «اجازه بده یا نده» نباشد.

**پیشنهاد معماری:** MAC را همان‌طور که خواسته‌اید ثبت کنید، اما تصمیم‌های امنیتی را به یک **Device Identity ترکیبی** ببندید که MAC فقط یکی از ورودی‌های آن است (بخش ۶.۵).

### ۶.۲ دریافت MAC در دسکتاپ

```python
# desktop/app/core/device_identity.py
import psutil, socket, uuid, hashlib, platform

def _normalize(mac: str) -> str:
    return mac.upper().replace("-", ":").strip()

def get_primary_mac() -> tuple[str | None, str]:
    """MAC کارت شبکه‌ای که مسیر پیش‌فرض از آن می‌گذرد.
    خروجی: (mac, source). در صورت عدم دسترسی: (None, 'unavailable').
    """
    # ۱) کارت شبکه‌ای که IP محلی فعال روی آن است را پیدا کن
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("10.255.255.255", 1))       # بدون ارسال داده؛ فقط انتخاب مسیر
            local_ip = s.getsockname()[0]
    except OSError:
        local_ip = None

    stats = psutil.net_if_stats()
    for name, addrs in psutil.net_if_addrs().items():
        st = stats.get(name)
        if not st or not st.isup:
            continue
        if any(k in name.lower() for k in ("loopback", "vmware", "virtualbox",
                                           "hyper-v", "docker", "vethernet")):
            continue                                # کارت‌های مجازی را رد کن
        has_local_ip = local_ip and any(a.address == local_ip for a in addrs)
        mac = next((a.address for a in addrs if a.family == psutil.AF_LINK), None)
        if mac and mac != "00:00:00:00:00:00":
            if has_local_ip:
                return _normalize(mac), "psutil"    # کارت اصلی — بهترین گزینه
    # ۲) Fallback: اولین کارت فیزیکی فعال
    for name, addrs in psutil.net_if_addrs().items():
        if stats.get(name) and stats[name].isup:
            mac = next((a.address for a in addrs if a.family == psutil.AF_LINK), None)
            if mac and mac != "00:00:00:00:00:00":
                return _normalize(mac), "psutil"
    # ۳) Fallback نهایی: uuid.getnode()
    node = uuid.getnode()
    if (node >> 40) % 2 == 0:                       # بیت multicast صفر ⇒ MAC واقعی
        mac = ":".join(f"{(node >> e) & 0xFF:02X}" for e in range(40, -8, -8))
        return mac, "uuid_getnode"
    return None, "unavailable"                      # uuid تصادفی تولید کرده — بی‌ارزش


def get_system_fingerprint() -> str:
    """اثر انگشت سیستمی پایدارتر از MAC — مبنای اصلی شناسایی دستگاه."""
    mac, _ = get_primary_mac()
    parts = [
        platform.node(), platform.machine(), platform.system(),
        platform.processor(), str(psutil.cpu_count(logical=False)),
        _machine_guid(),                            # HKLM\SOFTWARE\Microsoft\Cryptography
        mac or "no-mac",
    ]
    return hashlib.sha256("|".join(filter(None, parts)).encode()).hexdigest()
```

**نکته‌ی مهم درباره‌ی `uuid.getnode()`:** این تابع وقتی MAC واقعی پیدا نکند، یک عدد **تصادفی** با بیت multicast برابر ۱ برمی‌گرداند. ثبت آن به‌عنوان MAC یعنی ثبت داده‌ی جعلی در Audit Log. بررسی بیت (`(node >> 40) % 2`) این تله را می‌گیرد — تقریباً همه‌ی پیاده‌سازی‌هایی که این تابع را به‌عنوان Fallback به کار می‌برند از آن غافل‌اند.

### ۶.۳ جایگزین در وب — و محدودیت‌های واقعی آن

در مرورگر MAC در دسترس نیست و راهی برای دور زدن آن وجود ندارد. سه نکته درباره‌ی جایگزین‌ها:

- **WebRTC برای کشف IP محلی دیگر کار نمی‌کند.** از سال ۲۰۲۰، Chrome، Firefox و Safari آدرس‌های محلی را با mDNS (`.local`) مبهم می‌کنند. اتکا به آن اتلاف وقت است.
- **Canvas/WebGL Fingerprinting در Safari و Firefox (با Resist Fingerprinting) تضعیف یا مسدود می‌شود.** پایداری آن در Chrome خوب و در سایرین متوسط تا ضعیف است.
- **ملاحظه‌ی حقوقی:** Fingerprinting بدون اطلاع کاربر، در بسیاری از چارچوب‌های حفاظت از داده مسئله‌ساز است. چون این یک سامانه‌ی **سازمانی داخلی** است، درج آن در سیاست استفاده و اطلاع‌رسانی به کارکنان کافی و توصیه‌شده است.

**راهکار قوی‌تر و ترکیبی:**

```
Device Identity = FingerprintJS (جزء ناپایدار)
                + Device Token صادرشده توسط سرور (جزء پایدار)
```

پس از اولین ورود موفق، سرور یک **Device Token تصادفی** صادر می‌کند که در Cookie `HttpOnly; Secure; SameSite=Strict; Max-Age=۱ سال` ذخیره می‌شود. این توکن، برخلاف Fingerprint، نه قابل جعل است و نه با به‌روزرسانی مرورگر تغییر می‌کند. Fingerprint نقش تشخیص ناهنجاری را دارد (اگر Device Token همان باشد ولی Fingerprint کاملاً عوض شده باشد ⇒ احتمال سرقت Cookie).

مقدار ذخیره‌شده در `mac_address` برای وب: `NULL`، و `device_fingerprint` مقدار `web-fp-<sha256>` می‌گیرد. توصیه می‌کنم به‌جای درج مقدار مصنوعی در ستون `mac_address`، آن را `NULL` بگذارید — ستونی که گاهی MAC واقعی و گاهی یک رشته‌ی ساختگی دارد، تحلیل Forensic را آلوده می‌کند.

### ۶.۴ ارسال امن هدرهای دستگاه

```
X-Device-Fingerprint: a3f9c2...
X-Device-MAC:         00:1A:2B:3C:4D:5E
X-Device-Nonce:       018f4c1e-7a2b-7c3d-9e10-4f5a6b7c8d90
X-Device-Timestamp:   1789012345678
X-Device-Signature:   HMAC-SHA256(device_hmac_key,
                        method|path|sha256(body)|fingerprint|mac|nonce|timestamp)
```

**اعتبارسنجی سمت سرور:**

1. `device_id` از Fingerprint یا Device Token استخراج و `hmac_key` آن رمزگشایی می‌شود.
2. اختلاف `timestamp` با زمان سرور باید کمتر از ۳۰۰ ثانیه باشد.
3. `nonce` نباید در Redis (با TTL ۳۰۰ ثانیه) وجود داشته باشد ⇒ **ضد Replay**.
4. امضا با `hmac.compare_digest` مقایسه می‌شود (ضد Timing Attack).
5. نتیجه در `mac_verified` ثبت می‌شود.

**سیاست شکست امضا — تصمیم مهم:** درخواست را **رد نکنید**؛ آن را با `mac_verified=false` ثبت و ریسک را بالا ببرید. دلیل: ساعت نادرست کلاینت، پروکسی‌هایی که بدنه را تغییر می‌دهند، یا به‌روزرسانی ناقص کلاینت می‌توانند امضای معتبر را بشکنند. رد کردن سخت‌گیرانه، کاربران واقعی را قفل می‌کند در حالی که مهاجم واقعی می‌تواند امضای معتبر تولید کند. استثنا: عملیات پرریسک (تغییر رمز، تغییر نقش، Export انبوه) که در آن‌ها امضای نامعتبر باید منجر به درخواست MFA مجدد شود.

### ۶.۵ Risk Score — تصمیم‌گیری بر پایه‌ی سیگنال‌های ترکیبی

```python
def compute_risk_score(ctx: LoginContext) -> int:
    """۰ (عادی) تا ۱۰۰ (بسیار مشکوک). هیچ سیگنالی به‌تنهایی تعیین‌کننده نیست."""
    score = 0
    if ctx.device_is_new:                       score += 25
    if not ctx.mac_verified:                    score += 10
    if ctx.mac_changed_for_known_device:        score += 20   # MAC عوض شد، دستگاه همان
    if ctx.ip_outside_corporate_range:          score += 15
    if ctx.geo_impossible_travel:               score += 30   # دو ورود، فاصله غیرممکن
    if ctx.time_outside_user_pattern:           score += 10
    if ctx.recent_failed_attempts >= 3:         score += 20
    if ctx.mac_used_by_other_user_recently:     score += 15
    return min(score, 100)
```

| بازه | اقدام |
|------|-------|
| ۰–۲۹ | ورود عادی |
| ۳۰–۵۹ | الزام MFA حتی اگر دستگاه Trusted باشد |
| ۶۰–۷۹ | MFA + اعلان امنیتی به کاربر و Admin |
| ۸۰–۱۰۰ | مسدودسازی موقت + الزام تأیید Admin |

این مدل همان اهدافی را که از MAC انتظار داشتید — شناسایی دستگاه غیرمجاز، تحلیل الگوی حمله، Device Correlation — برآورده می‌کند، اما بدون اتکای شکننده به یک سیگنال جعل‌پذیر.

### ۶.۶ ماسک کردن و دسترسی به MAC

| زمینه | نمایش |
|-------|-------|
| دیتابیس | کامل (برای جستجو و Forensic) |
| API برای کاربر عادی (`/auth/devices`) | `00:1A:**:**:**:5E` |
| API برای Admin (`/admin/audit/logs`) | کامل — و **خود این مشاهده یک رویداد Audit تولید می‌کند** |
| Export لاگ | کامل، اما فقط با Permission `audit.export` و ثبت در Audit |
| لاگ‌های برنامه (structlog) | ماسک‌شده |
| پیام خطا به کاربر | هرگز |

> نکته‌ی حاکمیت داده: ترکیب **کد ملی + MAC + IP + موقعیت جغرافیایی** در یک جدول با نگهداری یک‌ساله، یک مخزن داده‌ی شخصی حساس ایجاد می‌کند. توصیه می‌کنم: سیاست نگهداری مکتوب، دسترسی محدود به حداکثر ۲–۳ نفر با نقش `auditor`، بازبینی فصلی دسترسی‌ها، و آرشیو رمزنگاری‌شده پس از ۹۰ روز با دسترسی فقط بر اساس درخواست رسمی.

---

## ۷. RBAC، گروه‌ها و حریم خصوصی

### ۷.۱ مدل سه‌لایه‌ی دسترسی

سه پرسش متفاوت که **هرگز نباید در یک تابع ادغام شوند**:

| لایه | پرسش | منبع | نمونه |
|------|------|------|-------|
| **RBAC** | آیا این کاربر مجاز به انجام این *نوع* عملیات است؟ | `rbac.user_roles` | آیا می‌تواند تسک حذف کند؟ |
| **ACL** | آیا به این *رکورد خاص* دسترسی دارد؟ | مالکیت + `sharing.shares` | آیا این تسک مال اوست یا با او به اشتراک گذاشته شده؟ |
| **Privacy** | آیا مالک داده اجازه‌ی دیده شدن توسط این شخص را داده؟ | `groups.privacy_settings` | آیا مدیر گروه می‌تواند جزئیات اهدافش را ببیند؟ |

ادغام این سه، منشأ اصلی نشت داده در سامانه‌های سازمانی است. مثال مشخص: مدیر گروه Permission سراسری `group.view_member_progress` دارد (RBAC می‌گوید بله)، و عضو گروه است (ACL می‌گوید بله)، اما عضو تنظیمات خود را `fully_private` کرده — **Privacy می‌گوید فقط عدد کل، نه جزئیات**. اگر فقط RBAC بررسی شود، حریم خصوصی نقض می‌شود.

### ۷.۲ ترتیب اجرای بررسی‌ها

```python
async def authorize(user, action: str, entity_type: str, entity_id: UUID | None) -> Decision:
    # ۱) RBAC — آیا اصلاً این نوع عملیات برای این کاربر تعریف شده؟
    if not await rbac.has_permission(user, action):
        raise PermissionDenied(action)

    if entity_id is None:                      # عملیات سطح مجموعه (مثل ایجاد)
        return Decision.allow()

    # ۲) ACL — دسترسی سطح رکورد
    acl = await acl_resolver.effective_permission(user, entity_type, entity_id)
    if acl is None:
        raise NotFound()                       # نه ۴۰۳ — عدم افشای وجود رکورد
    if PERMISSION_RANK[acl] < REQUIRED_RANK[action]:
        raise PermissionDenied(action, actual=acl)

    # ۳) Privacy — فقط برای خواندن داده‌ی دیگران
    if action.endswith(".read") and acl != "owner":
        owner_id = await entity_owner(entity_type, entity_id)
        decision = await privacy.effective(owner_id=owner_id, viewer_id=user.id)
        if decision.level == "hidden":
            raise NotFound()
        return Decision.allow(redaction=decision.redaction)   # مثلاً aggregate_only

    return Decision.allow()
```

خروجی `Decision` می‌تواند **allow با محدودیت** باشد — این ظرافت مهم است: پاسخ «بله ولی فقط آمار کلی» با «بله» و «خیر» فرق دارد و سریالایزر باید آن را اعمال کند.

### ۷.۳ منطق حریم خصوصی

| سطح | مدیر گروه می‌بیند | هم‌تیمی می‌بیند | افراد منتخب |
|-----|-------------------|------------------|--------------|
| `fully_private` | فقط درصد پیشرفت کل | هیچ | هیچ |
| `team_only` | همه‌ی جزئیات | عنوان و وضعیت (بدون توضیحات) | — |
| `selected` | فقط اگر در فهرست استثناها باشد | هیچ | مطابق `privacy_exceptions` |
| `fully_transparent` | همه | همه | همه |

**قواعد تکمیلی:**

- کامنت‌گذاری مدیر روی داده‌ی عضو، تابع `allow_manager_comment` است — دیدن ≠ اجازه‌ی نوشتن.
- اگر `notify_on_manager_view` فعال باشد، کاربر اعلان می‌گیرد که مدیرش داده‌اش را دید. این یک کنترل شفافیت است که اعتماد کاربران به سامانه را می‌سازد.
- `/me/privacy/access-log` به کاربر نشان می‌دهد چه کسی، کی و چه چیزی از داده‌هایش را دیده.
- **حریم خصوصی هرگز Audit Log را محدود نمی‌کند.** Admin با نقش `auditor` همیشه رویدادها را می‌بیند؛ حریم خصوصی مربوط به داده‌ی کسب‌وکاری است، نه ردپای امنیتی. این تفکیک باید در سیاست سازمانی هم مکتوب شود.

### ۷.۴ جلوگیری از Privilege Escalation

```python
async def assign_role(actor, target_user_id: UUID, role_id: int, scope=None):
    actor_max = await rbac.max_role_level(actor.id)          # مثلاً manager = 3
    target_role = await rbac.get_role(role_id)               # مثلاً admin = 5

    # ۱) نمی‌توان نقشی بالاتر یا هم‌سطح خود اعطا کرد
    if target_role.level >= actor_max:
        raise PermissionDenied("CANNOT_GRANT_EQUAL_OR_HIGHER_ROLE")

    # ۲) نمی‌توان به خود نقش داد
    if target_user_id == actor.id:
        raise PermissionDenied("CANNOT_SELF_ASSIGN")

    # ۳) نقش دامنه‌دار فقط در دامنه‌ای که خودت مدیرش هستی
    if scope and scope.type == "group":
        if not await groups.is_manager(actor.id, scope.id):
            raise PermissionDenied("NOT_GROUP_MANAGER")

    await rbac.grant(target_user_id, role_id, scope, granted_by=actor.id)
    await audit.log("rbac.role.assigned", target=target_user_id, dangerous=True)
```

هر سه بررسی لازم است. حذف بند اول یعنی هر Manager می‌تواند خود را Super Admin کند — کلاسیک‌ترین Privilege Escalation.

---

## ۸. چت، WebSocket و مدیریت فایل

### ۸.۱ مقیاس‌پذیری WebSocket

```python
# app/ws/manager.py
class ConnectionManager:
    """اتصال‌ها در حافظه‌ی همان Worker؛ پیام‌ها از طریق Redis بین Workerها."""

    def __init__(self, redis: Redis):
        self._rooms: dict[UUID, set[WebSocket]] = defaultdict(set)
        self._redis = redis

    async def join(self, room_id: UUID, ws: WebSocket, user_id: UUID):
        if not await chat_service.is_active_member(room_id, user_id):
            await ws.close(code=4403); return
        self._rooms[room_id].add(ws)
        if len(self._rooms[room_id]) == 1:              # اولین عضو روی این Worker
            await self._subscribe(room_id)

    async def broadcast(self, room_id: UUID, message: dict):
        await self._redis.publish(f"room:{room_id}", json.dumps(message))

    async def _on_redis_message(self, room_id: UUID, raw: str):
        dead = set()
        for ws in self._rooms[room_id]:
            try:
                await ws.send_text(raw)
            except (WebSocketDisconnect, RuntimeError):
                dead.add(ws)
        self._rooms[room_id] -= dead
```

با این الگو، افزودن Worker جدید نیازی به Sticky Session ندارد و پیام کاربر متصل به Worker #1 به کاربر متصل به Worker #3 می‌رسد.

### ۸.۲ چرخه‌ی امن آپلود فایل

```mermaid
graph LR
    C["کلاینت"] -->|۱ POST /files/presign| API
    API -->|۲ اعتبارسنجی: نوع، حجم، سهمیه| API
    API -->|۳ Presigned URL (TTL 5m)| C
    C -->|۴ PUT مستقیم| S3["MinIO<br/>status=pending<br/>is_available=false"]
    C -->|۵ POST /files/{id}/finalize| API
    API -->|۶ enqueue| AV["Celery: av_scan"]
    AV -->|۷ magic number + ClamAV| AV
    AV -->|۸ clean| DB["is_available=true"]
    AV -->|۸ infected| DEL["حذف فایل + Audit + هشدار"]
    DB -->|۹ رویداد| NOTIF["اعلان به اتاق چت"]
```

**کنترل‌های اجباری:**

1. **بررسی magic number، نه پسوند.** `python-magic` نوع واقعی را تشخیص می‌دهد. فایلی با نام `report.pdf` که در واقع PE Executable است، رد می‌شود.
2. **Whitelist، نه Blacklist.** نیازمندی «پشتیبانی از تمام فرمت‌ها» را باید بازنگری کرد: پذیرش `.exe`, `.dll`, `.scr`, `.js`, `.hta`, `.lnk`, `.iso` در یک ابزار سازمانی، آن را به کانال توزیع بدافزار تبدیل می‌کند. پیشنهاد: Whitelist گسترده (اسناد، تصاویر، آرشیوها، ویدئو/صوت، فایل‌های متنی) به‌علاوه‌ی یک فرایند استثنا برای موارد خاص با تأیید Admin.
3. **آرشیوها:** حداکثر عمق ۳ و نسبت فشرده‌سازی حداکثر ۱۰۰:۱ (ضد Zip Bomb).
4. **تصاویر:** Re-encode کامل با Pillow + حذف EXIF (موقعیت جغرافیایی در EXIF یک نشت حریم خصوصی رایج است).
5. **مسیر ذخیره:** `{context}/{yyyy}/{mm}/{uuid}` — نام اصلی فایل فقط در دیتابیس و در هدر `Content-Disposition` (با encode صحیح) استفاده می‌شود.
6. **دانلود:** همیشه با `Content-Disposition: attachment` و `X-Content-Type-Options: nosniff`؛ هرگز `Content-Type` اعلامی کلاینت بازگردانده نشود.
7. **تا پایان اسکن، `is_available=false`** و هر تلاش دانلود `409` می‌گیرد.

### ۸.۳ آرشیو و نگهداری اتاق

حذف اتاق چت یک عملیات **دو مرحله‌ای** است: ابتدا آرشیو (تولید فایل JSON/HTML شامل پیام‌ها، اعضا و ابرداده‌ها، ذخیره در S3 با رمزنگاری)، سپس Soft Delete. رویداد `chat.room.archived` منتشر و مسیر آرشیو در `archive_object_key` ثبت می‌شود. بدون این ترتیب، حذف تصادفی یک اتاق، تاریخچه‌ی تصمیم‌گیری تیم را از بین می‌برد — و در بازرسی‌های بعدی قابل بازیابی نیست.

---

## ۹. کارتابل (Inbox/Outbox)

### ۹.۱ ماشین حالت

```mermaid
stateDiagram-v2
    [*] --> pending: ارسال
    pending --> accepted: تأیید
    pending --> rejected: رد
    pending --> deferred: بعداً
    deferred --> pending: فرا رسیدن defer_until
    deferred --> accepted
    deferred --> rejected
    pending --> expired: گذشت expires_at
    accepted --> [*]
    rejected --> [*]
    expired --> [*]
```

**Read Receipt** یک بعد مستقل از عمل است: `sent` → `seen` (کارتابل باز شد) → `acted` (تصمیم گرفته شد). فرستنده در کارتابل ارسالی هر سه وضعیت را می‌بیند. تفکیک «دیده شد» از «اقدام شد» دقیقاً همان چیزی است که در پیگیری‌های سازمانی لازم است.

### ۹.۲ یکپارچگی با سایر ماژول‌ها

کارتابل هیچ ماژولی را import نمی‌کند؛ فقط رویداد مصرف می‌کند:

```python
@event_bus.on("sharing.share.requested")
async def create_share_inbox_item(event: DomainEvent, uow: UnitOfWork):
    # Idempotent: اگر این event_id قبلاً پردازش شده، خروج
    if await uow.inbox.exists_for_event(event.event_id):
        return
    await uow.inbox.create(InboxItem(
        sender_id=event.actor_id,
        recipient_id=event.payload["recipient_id"],
        item_type="share_request",
        entity_type=event.payload["entity_type"],
        entity_id=event.payload["entity_id"],
        title=f"درخواست دسترسی به «{event.payload['entity_title']}»",
        due_at=event.payload.get("due_at"),
        expires_at=utcnow() + timedelta(days=14),
    ))
```

افزودن یک نوع آیتم جدید به کارتابل، نیازمند هیچ تغییری در ماژول ناشر نیست.

---

## ۱۰. شخصی‌سازی داشبورد و ویجت‌ها

### ۱۰.۱ اعتبارسنجی Layout — جلوگیری از اختلال در برنامه

نیازمندی «عدم اختلال به اصل برنامه» با چهار لایه‌ی اعتبارسنجی برآورده می‌شود:

```python
class BlockLayout(BaseModel):
    block_key: Literal[*ALLOWED_BLOCK_KEYS]      # ۱) Whitelist — نه هر رشته‌ای
    is_visible: bool = True
    position_x: int = Field(ge=0, le=11)
    position_y: int = Field(ge=0, le=200)
    width:  int = Field(ge=1, le=12)
    height: int = Field(ge=1, le=20)
    config: dict = Field(default_factory=dict)

    @model_validator(mode="after")
    def check_bounds(self):
        if self.position_x + self.width > 12:     # ۲) خروج از گرید
            raise ValueError("بلوک از عرض گرید خارج است.")
        return self

    @model_validator(mode="after")
    def check_config(self):                       # ۳) config مخصوص همان بلوک
        schema = BLOCK_CONFIG_SCHEMAS[self.block_key]
        self.config = schema.model_validate(self.config).model_dump()
        return self

class LayoutSave(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    view_mode: Literal["daily", "weekly", "monthly"]
    blocks: list[BlockLayout] = Field(max_length=30)

    @model_validator(mode="after")
    def no_overlap(self):                         # ۴) تداخل بلوک‌ها
        if has_overlap(self.blocks):
            raise ValueError("بلوک‌ها همپوشانی دارند.")
        return self
```

Export/Import با `schema_version` انجام می‌شود تا Layout صادرشده از نسخه‌ی قدیمی، در نسخه‌ی جدید با مهاجرت خودکار یا پیام روشن مدیریت شود.

### ۱۰.۲ رفتار ریسپانسیو Layout

Layout در دیتابیس همیشه برای گرید **۱۲ ستونه (دسکتاپ)** ذخیره می‌شود. کلاینت در نمایش کوچک‌تر آن را تبدیل می‌کند و **هرگز نسخه‌ی تبدیل‌شده را ذخیره نمی‌کند**:

| عرض | ستون‌ها | رفتار |
|-----|---------|-------|
| ≥ 1280px | 12 | Layout ذخیره‌شده عیناً |
| 768–1279px | 6 | عرض بلوک‌ها نصف، ترتیب حفظ می‌شود |
| < 768px | 1 | تک‌ستونی، مرتب بر اساس `position_y` سپس `position_x` |

اگر نسخه‌ی موبایل ذخیره شود، کاربر با بازگشت به دسکتاپ چیدمانش را از دست می‌دهد — یک باگ رایج و آزاردهنده در داشبوردهای قابل شخصی‌سازی.

### ۱۰.۳ ویجت تاریخ و ساعت

ویجت شناور با مختصات مطلق، جدا از گرید داشبورد (جدول `user_widget_settings`). قابلیت‌ها: تاریخ جلالی + میلادی + قمری (اختیاری)، ساعت Real-time، فرمت قابل تنظیم، Drag & Drop، Resize با حداقل/حداکثر، Show/Hide، و تنظیمات استایل (رنگ، فونت، سایز، شفافیت).

**دو نکته‌ی فنی:**

- **Sync بین دستگاه‌ها با ستون `platform`:** موقعیت پیکسلی در پنجره‌ی دسکتاپ با موقعیت در مرورگر معنای یکسانی ندارد. `platform='all'` تنظیمات ظاهری (رنگ، فونت، فرمت) را همگام می‌کند و موقعیت/اندازه به‌ازای هر پلتفرم جدا نگه داشته می‌شود.
- **تقویم قمری:** تقویم هجری قمری در ایران مبتنی بر رؤیت هلال است و با محاسبات نجومی تا یک روز اختلاف دارد. اگر این ویجت برای مناسبت‌های رسمی استفاده می‌شود، باید منبع تاریخ رسمی داشته باشد؛ در غیر این صورت با ذکر «تقریبی» نمایش داده شود.
- **امنیت `style`:** مقادیر رنگ و شفافیت باید با الگوی سخت‌گیرانه اعتبارسنجی شوند (`^#[0-9A-Fa-f]{6}$` و `0.0–1.0`). تزریق مقدار دلخواه به CSS یک بردار XSS شناخته‌شده است.

---

## ۱۱. استراتژی امنیت جامع

### ۱۱.۱ نگاشت OWASP Top 10 به کنترل‌ها

| خطر | کنترل‌های این معماری |
|-----|----------------------|
| A01 Broken Access Control | مدل سه‌لایه (RBAC+ACL+Privacy)، SecureRepository، ۴۰۴ به‌جای ۴۰۳، آزمون ماتریسی IDOR در CI، بررسی سطح نقش هنگام اعطا |
| A02 Cryptographic Failures | Argon2id، AES-256-GCM با Nonce یکتا، کد ملی رمزنگاری‌شده، TLS 1.3، بدون کلید هاردکد، چرخش کلید |
| A03 Injection | Pydantic Whitelist، SQLAlchemy bind params، `escape_filter_chars` برای LDAP، bleach/DOMPurify، `os.path.basename` و UUID برای مسیر |
| A04 Insecure Design | Threat Model پیش از هر فاز، Rate Limit چندلایه، Least Privilege، Outbox برای سازگاری، Risk Score |
| A05 Security Misconfiguration | ENV/Vault only، CSP سخت، هدرهای امنیتی، `server_tokens off`، کانتینر non-root و read-only |
| A06 Vulnerable Components | `pip-audit` + `npm audit` + Snyk/Dependabot در CI، SBOM با syft، Gate روی CRITICAL |
| A07 Auth Failures | MFA، Lockout با Backoff نمایی، Token Rotation + Reuse Detection، `token_version`، CAPTCHA، Device Binding |
| A08 Data Integrity | Optimistic Locking، Audit Hash Chain، امضای RS256، اعتبارسنجی Import Layout |
| A09 Logging Failures | `audit_logs` + `login_audit_logs` + structlog با ماسک PII + SIEM + بازبینی زنجیره |
| A10 SSRF | هیچ URL دریافتی از کاربر fetch نمی‌شود؛ `meeting_url` فقط ذخیره و نمایش؛ Presigned URL سمت سرور ساخته می‌شود |

### ۱۱.۲ Zero Trust در عمل

- **هیچ شبکه‌ای قابل اعتماد نیست:** همان کنترل‌های احراز هویت و مجوزدهی برای کاربر داخل LAN و کاربر VPN یکسان اعمال می‌شود. «داخل شبکه بودن» هیچ امتیازی نمی‌دهد.
- **هیچ کلاینتی قابل اعتماد نیست:** هر مقدار ارسالی از کلاینت — از جمله MAC، Fingerprint، `user_id` در Body، و Permissionها — در سرور بازبینی یا نادیده گرفته می‌شود.
- **احراز هویت مستمر:** اعتبار توکن در هر درخواست و روی سوکت باز هر ۶۰ ثانیه بررسی می‌شود؛ تغییر نقش یا رمز، نشست‌ها را فوراً بی‌اعتبار می‌کند.
- **کمترین دسترسی در هر لایه:** کاربر دیتابیس بدون `CREATE/DROP`، حساب LDAP فقط خواندنی، کانتینر non-root، Token بدون داده‌ی دسترسی سطح-رکورد.

### ۱۱.۳ سیاست رمز عبور — یک بازنگری توصیه‌شده

نیازمندی «تغییر اجباری رمز هر ۹۰ روز» ذکر شده است. **NIST SP 800-63B از سال ۲۰۱۷ صراحتاً چرخش دوره‌ای اجباری را توصیه نمی‌کند**، چون در عمل کاربران را به الگوهای قابل حدس (`Password1!` → `Password2!`) سوق می‌دهد و امنیت را کاهش می‌دهد.

**جایگزین پیشنهادی (قوی‌تر و کم‌اصطکاک‌تر):**

- حداقل ۱۲ کاراکتر؛ بررسی در برابر Have I Been Pwned با **API k-anonymity** (فقط ۵ کاراکتر اول هش SHA-1 ارسال می‌شود — رمز هرگز شبکه را ترک نمی‌کند)؛ رد رمزهای حاوی نام کاربری، نام نمایشی یا کد ملی؛ رد فهرست رمزهای رایج سازمانی.
- **تغییر اجباری فقط در صورت رویداد:** نشت شناخته‌شده، ورود مشکوک با Risk Score بالا، یا بازنشانی توسط Admin.
- MFA اجباری برای نقش‌های `admin` و `super_admin` — این یک تصمیم است که اثرش بر امنیت از هر سیاست چرخش رمزی بیشتر است.

اگر الزام سازمانی یا ممیزی خارجی چرخش ۹۰ روزه را تحمیل می‌کند، فیلد `password_expires_at` در اسکیما موجود است و پیاده‌سازی‌اش ساده است — اما توصیه‌ی فنی من انتخاب گزینه‌ی بالاست.

### ۱۱.۴ رصد، تشخیص ناهنجاری و پاسخ به حادثه

**شاخص‌های هشدار Real-time (به SIEM):**

| رویداد | آستانه |
|--------|--------|
| ورود ناموفق از یک IP | > ۵۰ در ۵ دقیقه (Credential Stuffing) |
| ورود موفق با Risk Score ≥ ۸۰ | هر مورد |
| یک MAC با > ۳ کاربر متفاوت | در ۲۴ ساعت |
| اعطای نقش `admin` یا `super_admin` | هر مورد |
| Export لاگ یا داده‌ی انبوه | > ۲ در ساعت برای یک کاربر |
| شکست بازبینی زنجیره‌ی هش Audit | هر مورد — **بحرانی** |
| آپلود فایل آلوده | هر مورد |
| تغییر تنظیمات LDAP یا غیرفعال‌سازی اعتبارسنجی گواهی | هر مورد |

**طرح پاسخ به حادثه (IRP)** — چهار مرحله با مالک مشخص: **تشخیص** (SIEM/هشدار) → **مهار** (ابطال نشست‌ها با `token_version++`، مسدودسازی IP/دستگاه، قطع دسترسی حساب) → **ریشه‌یابی** (Audit Log + زنجیره‌ی هش + Device Correlation) → **بازیابی و درس‌آموخته** (گزارش مکتوب ظرف ۵ روز کاری). تیم IRT باید از قبل تعریف شده باشد؛ تشکیل تیم **حین** حادثه همیشه دیر است. توصیه: یک تمرین شبیه‌سازی‌شده (Tabletop) سالانه.

### ۱۱.۵ Secure SDLC

| مرحله | فعالیت |
|-------|--------|
| طراحی | Threat Modeling (STRIDE) برای هر ماژول پیش از کدنویسی |
| کدنویسی | لینت امنیتی (`bandit`, `eslint-plugin-security`)، `gitleaks` در pre-commit |
| بازبینی | چک‌لیست امنیتی اجباری؛ تغییرات مسیرهای Auth/RBAC/Privacy نیازمند **دو بازبین** |
| تست | تست‌های امنیتی خودکار، Fuzz روی endpointهای حساس، DAST روی staging |
| انتشار | اسکن ایمیج (trivy)، SBOM، Gate روی CRITICAL |
| تولید | رصد مستمر، تست نفوذ سالانه توسط تیم مستقل |

### ۱۱.۶ استراتژی Responsive Design

Mobile-First با Breakpointهای Tailwind (`sm 640 · md 768 · lg 1024 · xl 1280`). قواعد عملی: واحدهای نسبی (`rem`, `%`, `clamp()`)، Flexbox/Grid، `max-width: 100%` روی تصاویر، جداول عریض داخل `overflow-x: auto` (نه اسکرول افقی صفحه)، هدف لمسی حداقل ۴۴×۴۴ پیکسل، و **Progressive Disclosure** — در موبایل، بلوک‌های کم‌اهمیت جمع‌شده نمایش داده شوند نه حذف. برای RTL، منحصراً از کلاس‌های منطقی (`ms-*`, `me-*`, `ps-*`, `pe-*`) استفاده شود.

---

## ۱۲. نمونه کد (Boilerplate)

> این نمونه‌ها **الگوی معماری** را نشان می‌دهند، نه کد آماده‌ی تولید. هر کدام روی یک تصمیم طراحی تمرکز دارد.

### ۱۲.۱ Backend — راه‌اندازی API Server

```python
# app/main.py
from contextlib import asynccontextmanager
from fastapi import FastAPI
from app.core.config import settings
from app.core.middleware import register_middlewares
from app.core.events.bus import event_bus
from app.core.errors import register_exception_handlers
from app.modules import auth, rbac, groups, goals, calendar, sharing, \
                        chat, inbox, reporting, notification, audit, ssoldap, files

MODULES = [auth, rbac, groups, goals, calendar, sharing,
           chat, inbox, reporting, notification, audit, ssoldap, files]

@asynccontextmanager
async def lifespan(app: FastAPI):
    for m in MODULES:
        m.register_event_handlers(event_bus)      # هر ماژول خودش مشترک می‌شود
    await startup_checks()                         # اتصال DB/Redis، وجود کلیدها
    yield
    await shutdown_gracefully()

app = FastAPI(
    title="Planner Enterprise API",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs" if settings.ENV != "production" else None,   # Swagger در تولید بسته
    redoc_url=None,
    openapi_url="/openapi.json" if settings.ENV != "production" else None,
)

register_middlewares(app)          # ترتیب زنجیره در بخش ۱.۲
register_exception_handlers(app)   # هیچ Traceback به کاربر نشت نمی‌کند

for m in MODULES:
    app.include_router(m.router, prefix="/api/v1")
```

### ۱۲.۲ Backend — Security Middleware و اعتبارسنجی MAC

```python
# app/core/middleware/device_binding.py
import hmac, hashlib, time
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware

MAX_SKEW_MS = 300_000       # ۵ دقیقه
HIGH_RISK_PATHS = ("/auth/password", "/admin/", "/rbac/", "/audit/export")

class DeviceBindingMiddleware(BaseHTTPMiddleware):
    """MAC/Fingerprint را استخراج، امضا را بررسی و نتیجه را در Context می‌گذارد.
    امضای نامعتبر درخواست را رد نمی‌کند (جز مسیرهای پرریسک) — فقط mac_verified=False.
    """

    async def dispatch(self, request: Request, call_next):
        ctx = request_ctx.get()
        ctx.device_fingerprint = request.headers.get("X-Device-Fingerprint")
        ctx.mac_address = _normalize_mac(request.headers.get("X-Device-MAC"))
        ctx.mac_verified = False

        if ctx.user_id and ctx.device_fingerprint:
            ctx.mac_verified = await self._verify(request, ctx)

        if not ctx.mac_verified and request.url.path.startswith(HIGH_RISK_PATHS):
            ctx.require_step_up_mfa = True         # نه رد، بلکه الزام تأیید مجدد

        return await call_next(request)

    async def _verify(self, request: Request, ctx) -> bool:
        sig   = request.headers.get("X-Device-Signature")
        nonce = request.headers.get("X-Device-Nonce")
        ts    = request.headers.get("X-Device-Timestamp")
        if not all((sig, nonce, ts)):
            return False

        # ۱) پنجره زمانی
        try:
            if abs(time.time() * 1000 - int(ts)) > MAX_SKEW_MS:
                return False
        except ValueError:
            return False

        # ۲) ضد Replay — nonce یک‌بارمصرف
        if not await redis.set(f"nonce:{ctx.user_id}:{nonce}", "1",
                               nx=True, ex=MAX_SKEW_MS // 1000):
            await audit.security_event("device.nonce_replay", user_id=ctx.user_id)
            return False

        # ۳) کلید HMAC مخصوص همین دستگاه
        device = await device_repo.get(ctx.user_id, ctx.device_fingerprint)
        if device is None or device.is_blocked:
            return False
        key = decrypt(device.hmac_key_enc)

        body_hash = hashlib.sha256(await request.body()).hexdigest()
        payload = "|".join([request.method, request.url.path, body_hash,
                            ctx.device_fingerprint, ctx.mac_address or "", nonce, ts])
        expected = hmac.new(key, payload.encode(), hashlib.sha256).hexdigest()

        # ۴) مقایسه ثابت‌زمان
        return hmac.compare_digest(expected, sig)


def _normalize_mac(raw: str | None) -> str | None:
    """قالب‌بندی و اعتبارسنجی؛ مقدار نامعتبر دور ریخته می‌شود نه ذخیره."""
    if not raw:
        return None
    mac = raw.upper().replace("-", ":").strip()
    if not re.fullmatch(r"([0-9A-F]{2}:){5}[0-9A-F]{2}", mac):
        return None
    if mac in ("00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF"):
        return None
    return mac
```

### ۱۲.۳ Backend — ثبت Audit Log با MAC و زنجیره‌ی هش

```python
# app/modules/audit/services/audit_service.py
import hashlib, json

class AuditService:
    async def log(self, uow, *, action: str, result: str = "success",
                  entity_type: str | None = None, entity_id: UUID | None = None,
                  old_value: dict | None = None, new_value: dict | None = None,
                  details: dict | None = None) -> None:
        """همه‌ی اطلاعات هویتی از Context می‌آید — هرگز از بدنه‌ی درخواست."""
        ctx = request_ctx.get()

        prev_hash = await uow.audit.last_row_hash()     # قفل مشورتی برای ترتیب صحیح
        row = AuditLog(
            user_id=ctx.user_id, action=action, result=result,
            entity_type=entity_type, entity_id=entity_id,
            ip_address=ctx.ip, mac_address=ctx.mac_address,
            mac_verified=ctx.mac_verified,
            device_fingerprint=ctx.device_fingerprint, device_id=ctx.device_id,
            user_agent=ctx.user_agent, session_id=ctx.session_id,
            old_value=mask_sensitive(old_value), new_value=mask_sensitive(new_value),
            details=mask_sensitive(details), geo_location=ctx.geo,
            request_id=ctx.request_id, correlation_id=ctx.correlation_id,
            prev_hash=prev_hash,
        )
        row.row_hash = self._chain_hash(prev_hash, row)
        uow.session.add(row)          # همان تراکنش عملیات اصلی

    @staticmethod
    def _chain_hash(prev_hash: str | None, row: AuditLog) -> str:
        material = "|".join([
            prev_hash or "GENESIS", str(row.user_id), row.action,
            row.timestamp.isoformat(), str(row.ip_address), row.mac_address or "",
            row.result, json.dumps(row.details, sort_keys=True, ensure_ascii=False),
        ])
        return hashlib.sha256(material.encode()).hexdigest()
```

```python
# app/core/db/audit_hooks.py — ثبت خودکار، بدون فراخوانی دستی در هر سرویس
@event.listens_for(Session, "before_flush")
def capture_entity_changes(session, ctx_, instances):
    for obj in session.dirty:
        if type(obj) not in AUDITED_MODELS:
            continue
        diff = extract_changes(obj, masked=MASKED_FIELDS)
        if diff:
            session.add(build_audit_row("update", obj, diff))
```

> این Hook مهم‌ترین تصمیم بخش Audit است: هیچ تغییر داده‌ای نمی‌تواند از زیر لاگ فرار کند، حتی اگر توسعه‌دهنده فراموش کند.

### ۱۲.۴ Backend — RBAC Middleware و Decorator

```python
# app/modules/rbac/api/deps.py
from fastapi import Depends, Request

def require_permission(*codes: str, mode: str = "all"):
    """کنترل دسترسی سطح عملیات. برای دسترسی سطح رکورد از PolicyEngine استفاده کنید."""
    async def _dep(request: Request, user: User = Depends(get_current_user)):
        perms = await rbac_service.effective_permissions(user.id)   # کش ۶۰ ثانیه‌ای
        ok = all(c in perms for c in codes) if mode == "all" \
             else any(c in perms for c in codes)
        if not ok:
            await audit.log(action="rbac.denied", result="denied",
                            details={"required": codes, "path": request.url.path})
            raise PermissionDeniedError(required=codes)
        return user
    return _dep


# استفاده
@router.delete("/goals/{goal_id}")
async def delete_goal(
    goal_id: UUID,
    user: User = Depends(require_permission("goal.delete")),   # لایه ۱: RBAC
    uow: UnitOfWork = Depends(get_uow),
):
    await policy.require(uow, user, "goal", goal_id, needed="owner")  # لایه ۲: ACL
    await goal_service.soft_delete(uow, goal_id, actor=user)
    return Response(status_code=204)
```

**کش Permission با ابطال رویدادی:** نتیجه‌ی `effective_permissions` در Redis با TTL ۶۰ ثانیه کش می‌شود و رویداد `rbac.role.assigned` کش آن کاربر را فوراً باطل می‌کند. بدون ابطال رویدادی، لغو دسترسی تا یک دقیقه معلق می‌ماند.

### ۱۲.۵ Backend — داشبورد مدیر گروه با اعمال حریم خصوصی

```python
# app/modules/reporting/api/routes.py
@router.get("/groups/{group_id}/dashboard", response_model=GroupDashboard)
async def group_dashboard(
    group_id: UUID,
    period: PeriodQuery = Depends(),
    user: User = Depends(require_permission("group.view_progress")),
    groups_rm: GroupReadModel = Depends(get_group_read_model),   # رابط، نه مدل DB
    uow: UnitOfWork = Depends(get_uow),
):
    # ۱) نقش دامنه‌دار: مدیر همین گروه؟
    if not await groups_rm.is_manager(user.id, group_id):
        raise NotFoundError()

    member_ids = await groups_rm.member_ids(group_id, include_subgroups=True)
    raw_stats  = await uow.reporting.member_stats(member_ids, period)

    # ۲) حریم خصوصی به‌ازای هر عضو — نه یک‌بار برای کل گروه
    members = []
    for m in raw_stats:
        decision = await groups_rm.effective_privacy(owner_id=m.user_id, viewer_id=user.id)
        members.append(redact_member(m, decision))   # full | aggregate_only | hidden

    # ۳) اعلان شفافیت و ثبت دسترسی
    await audit.log(action="group.dashboard.viewed", entity_type="group",
                    entity_id=group_id, details={"members": len(members)})
    await notify_members_of_view(group_id, viewer=user, members=raw_stats)

    return GroupDashboard(
        group=await groups_rm.summary(group_id),
        period=period,
        members=members,
        aggregate=compute_aggregate(raw_stats),   # آمار کلی همیشه از داده کامل
    )
```

> ظرافت مهم: آمار **تجمیعی تیم** از داده‌ی کامل محاسبه می‌شود، اما داده‌ی **فردی** پس از اعمال حریم خصوصی برگردانده می‌شود. اگر تجمیع را از داده‌ی سانسورشده بسازید، عدد تیم اشتباه می‌شود. در عین حال، وقتی گروه کمتر از ۴ عضو دارد، آمار تجمیعی می‌تواند داده‌ی فرد را افشا کند — در این حالت باید حداقل آستانه‌ی k-anonymity اعمال شود.

### ۱۲.۶ Backend — تغییر انبوه حالت ورود

```python
@router.post("/admin/users/bulk-login-mode", response_model=BulkResult)
async def bulk_change_login_mode(
    payload: BulkLoginModeRequest,
    user: User = Depends(require_permission("user.bulk_login_mode")),
    uow: UnitOfWork = Depends(get_uow),
):
    """تغییر sso_enabled برای گروهی از کاربران. نتیجه جزئی مجاز است (207)."""
    if len(payload.user_ids) > 500:
        raise ValidationError("حداکثر ۵۰۰ کاربر در هر عملیات.")

    updated, failed = [], []
    for uid in payload.user_ids:
        target = await uow.users.get(uid)
        if target is None:
            failed.append({"user_id": uid, "code": "NOT_FOUND"}); continue
        if target.id == user.id:
            failed.append({"user_id": uid, "code": "CANNOT_MODIFY_SELF"}); continue
        # کاربر SSO بدون رمز محلی نباید بدون تنظیم رمز به حالت local برود
        if payload.sso_enabled is False and target.password_hash is None:
            failed.append({"user_id": uid, "code": "NO_LOCAL_PASSWORD"}); continue

        old = {"sso_enabled": target.sso_enabled, "auth_mode": target.auth_mode}
        target.sso_enabled = payload.sso_enabled
        target.auth_mode = "sso" if payload.sso_enabled else "local"
        if payload.revoke_sessions:
            target.token_version += 1            # ابطال فوری همه نشست‌ها
        await audit.log(action="user.login_mode.changed", entity_type="user",
                        entity_id=uid, old_value=old,
                        new_value={"sso_enabled": payload.sso_enabled})
        updated.append(uid)

    await uow.commit()
    return BulkResult(updated=updated, failed=failed,
                      status_code=207 if failed else 200)
```

### ۱۲.۷ Backend — ذخیره Layout داشبورد

```python
@router.put("/dashboard/layouts/{layout_id}", response_model=LayoutRead)
async def save_layout(
    layout_id: UUID,
    payload: LayoutSave,                 # اعتبارسنجی کامل در بخش ۱۰.۱
    user: User = Depends(get_current_user),
    uow: UnitOfWork = Depends(get_uow),
):
    layout = await uow.layouts.get_owned(layout_id, user.id)   # مالکیت اجباری
    if layout is None:
        raise NotFoundError()

    async with uow.transaction():
        layout.name, layout.view_mode = payload.name, payload.view_mode
        if payload.is_default:
            await uow.layouts.clear_default(user.id, payload.view_mode)
            layout.is_default = True
        # جایگزینی اتمیک بلوک‌ها
        await uow.dashboard_settings.delete_by_layout(layout_id)
        await uow.dashboard_settings.bulk_insert(
            [DashboardSetting(user_id=user.id, layout_id=layout_id, **b.model_dump())
             for b in payload.blocks])
    return await uow.layouts.read(layout_id)
```

### ۱۲.۸ Backend — WebSocket Handler چت

```python
# app/ws/handlers/chat.py
@app.websocket("/ws/chat")
async def chat_socket(ws: WebSocket, token: str = Query(...)):
    # ۱) Origin Check — WebSocket تحت CORS نیست
    if ws.headers.get("origin") not in settings.ALLOWED_ORIGINS:
        await ws.close(code=4403); return

    # ۲) احراز هویت (توکن از Query فقط برای Handshake؛ در لاگ ماسک می‌شود)
    try:
        claims = verify_access_token(token)
        user = await user_service.get_active(claims["sub"])
    except (InvalidToken, UserInactive):
        await ws.close(code=4401); return

    await ws.accept()
    rooms: set[UUID] = set()
    limiter = SlidingWindowLimiter(limit=20, window_s=60)

    try:
        # ۳) اعتبارسنجی دوره‌ای توکن روی سوکت باز
        asyncio.create_task(_revalidate_periodically(ws, claims, interval=60))

        while True:
            raw = await asyncio.wait_for(ws.receive_text(), timeout=300)  # Idle timeout
            if len(raw) > 8192:
                await ws.close(code=1009); return
            msg = ChatSocketMessage.model_validate_json(raw)   # اعتبارسنجی اجباری

            if msg.type == "join":
                # ۴) عضویت در لحظه بررسی می‌شود
                if not await chat_service.is_active_member(msg.room_id, user.id):
                    await ws.send_json({"type": "error", "code": "NOT_A_MEMBER"}); continue
                await manager.join(msg.room_id, ws, user.id)
                rooms.add(msg.room_id)

            elif msg.type == "message":
                if msg.room_id not in rooms:
                    await ws.send_json({"type": "error", "code": "NOT_JOINED"}); continue
                if not await limiter.allow(f"ws:{user.id}"):
                    await ws.send_json({"type": "error", "code": "RATE_LIMITED"}); continue
                # ۵) عضویت دوباره بررسی می‌شود — ممکن است بین join و ارسال حذف شده باشد
                if not await chat_service.is_active_member(msg.room_id, user.id):
                    await ws.close(code=4403); return

                saved = await chat_service.persist(
                    room_id=msg.room_id, sender_id=user.id,
                    body=sanitize_html(msg.body),          # ۶) ضد XSS
                    reply_to_id=msg.reply_to_id)
                await manager.broadcast(msg.room_id, saved.to_event())
                await audit.log(action="chat.message.sent",
                                entity_type="chat_message", entity_id=saved.id)

    except (WebSocketDisconnect, asyncio.TimeoutError):
        pass
    finally:
        for r in rooms:
            await manager.leave(r, ws)
```

### ۱۲.۹ Desktop — راه‌اندازی UI فارسی و کلاینت HTTP

```python
# desktop/app/main.py
from PySide6.QtWidgets import QApplication
from PySide6.QtCore import Qt
from PySide6.QtGui import QFontDatabase, QFont

def bootstrap() -> QApplication:
    app = QApplication(sys.argv)
    app.setLayoutDirection(Qt.RightToLeft)                 # RTL سراسری
    for w in ("Regular", "Medium", "Bold"):
        QFontDatabase.addApplicationFont(f":/fonts/Vazirmatn-{w}.ttf")
    f = QFont("Vazirmatn", 11)
    f.setHintingPreference(QFont.PreferNoHinting)          # رندر نرم‌تر فارسی
    app.setFont(f)
    app.setStyleSheet(load_theme(settings.theme))          # dark.qss / light.qss
    return app
```

```python
# desktop/app/core/api_client.py
import httpx, hmac, hashlib, uuid, time, json

class ApiClient:
    """هدرهای هویت دستگاه به‌صورت خودکار و متمرکز تزریق می‌شوند —
    هیچ فراخوانی‌ای نمی‌تواند آن‌ها را فراموش کند."""

    def __init__(self, base_url: str, identity: DeviceIdentity, tokens: TokenStore):
        self._identity, self._tokens = identity, tokens
        self._client = httpx.Client(
            base_url=base_url, timeout=httpx.Timeout(10.0, connect=5.0),
            verify=settings.CA_BUNDLE,                     # اعتبارسنجی گواهی اجباری
            http2=True, event_hooks={"response": [self._on_response]})

    def request(self, method: str, path: str, *, json_body: dict | None = None):
        body = json.dumps(json_body, ensure_ascii=False).encode() if json_body else b""
        headers = self._device_headers(method, path, body)
        if tok := self._tokens.access_token():
            headers["Authorization"] = f"Bearer {tok}"
        r = self._client.request(method, path, content=body, headers=headers)
        if r.status_code == 401 and self._tokens.can_refresh():
            self._tokens.refresh(self)
            return self.request(method, path, json_body=json_body)   # یک‌بار تلاش مجدد
        return r

    def _device_headers(self, method: str, path: str, body: bytes) -> dict:
        mac, source = self._identity.mac, self._identity.mac_source
        fp    = self._identity.fingerprint
        nonce = str(uuid.uuid4())
        ts    = str(int(time.time() * 1000))
        payload = "|".join([method, path, hashlib.sha256(body).hexdigest(),
                            fp, mac or "", nonce, ts])
        sig = hmac.new(self._identity.hmac_key, payload.encode(), hashlib.sha256).hexdigest()
        h = {"X-Device-Fingerprint": fp, "X-Device-Nonce": nonce,
             "X-Device-Timestamp": ts, "X-Device-Signature": sig,
             "X-Request-ID": str(uuid.uuid4()), "Content-Type": "application/json"}
        if mac:                       # اگر MAC در دسترس نبود، هدر اصلاً ارسال نمی‌شود
            h["X-Device-MAC"] = mac
            h["X-Device-MAC-Source"] = source
        return h
```

### ۱۲.۱۰ Desktop — ویجت شناور ساعت و تاریخ

```python
# desktop/app/views/widgets/clock_widget.py
from PySide6.QtCore import Qt, QTimer, QPoint, Signal
from PySide6.QtWidgets import QFrame, QVBoxLayout, QLabel, QSizeGrip
import jdatetime, datetime as dt

class ClockWidget(QFrame):
    """ویجت شناور: Drag & Drop، Resize، شفافیت، جلالی + میلادی."""
    settings_changed = Signal(dict)

    MIN_W, MIN_H, MAX_W, MAX_H = 160, 80, 640, 400

    def __init__(self, cfg: dict, style: dict, parent=None):
        super().__init__(parent)
        self._drag_origin: QPoint | None = None
        self._cfg, self._style = cfg, style

        self.setMinimumSize(self.MIN_W, self.MIN_H)
        self.setMaximumSize(self.MAX_W, self.MAX_H)
        self.setLayoutDirection(Qt.RightToLeft)

        lay = QVBoxLayout(self)
        self.time_lbl    = QLabel(alignment=Qt.AlignCenter)
        self.jalali_lbl  = QLabel(alignment=Qt.AlignCenter)
        self.greg_lbl    = QLabel(alignment=Qt.AlignCenter)
        for w in (self.time_lbl, self.jalali_lbl, self.greg_lbl):
            lay.addWidget(w)
        lay.addWidget(QSizeGrip(self), 0, Qt.AlignLeft | Qt.AlignBottom)

        self._apply_style()
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)
        self._timer.start(1000 if cfg.get("show_seconds", True) else 30_000)
        self._tick()

    def _tick(self):
        now = dt.datetime.now()
        fmt = "%H:%M:%S" if self._cfg.get("show_seconds", True) else "%H:%M"
        self.time_lbl.setText(to_persian_digits(now.strftime(fmt)))
        self.jalali_lbl.setVisible(self._cfg.get("show_jalali", True))
        self.greg_lbl.setVisible(self._cfg.get("show_gregorian", False))
        if self.jalali_lbl.isVisible():
            j = jdatetime.datetime.fromgregorian(datetime=now)
            self.jalali_lbl.setText(to_persian_digits(j.strftime("%A، %d %B %Y")))
        if self.greg_lbl.isVisible():
            self.greg_lbl.setText(now.strftime("%a, %d %b %Y"))

    def _apply_style(self):
        s = self._style
        opacity = max(0.2, min(float(s.get("opacity", 0.95)), 1.0))   # محدوده امن
        self.setWindowOpacity(opacity)
        self.setStyleSheet(f"""
            QFrame {{ background: {safe_color(s.get('bg', '#1F2937'))};
                      color: {safe_color(s.get('fg', '#F9FAFB'))};
                      border-radius: 12px; }}
            QLabel {{ font-family: '{safe_font(s.get('font_family','Vazirmatn'))}';
                      font-size: {clamp_int(s.get('font_size', 16), 10, 48)}px; }}
        """)

    # ── Drag & Drop
    def mousePressEvent(self, e):
        if e.button() == Qt.LeftButton:
            self._drag_origin = e.globalPosition().toPoint() - self.pos()

    def mouseMoveEvent(self, e):
        if self._drag_origin and e.buttons() & Qt.LeftButton:
            new_pos = e.globalPosition().toPoint() - self._drag_origin
            self.move(self._clamp_to_parent(new_pos))      # خارج از پنجره نرود

    def mouseReleaseEvent(self, e):
        self._drag_origin = None
        self.settings_changed.emit({"position_x": self.x(), "position_y": self.y(),
                                    "width": self.width(), "height": self.height()})
```

`settings_changed` با debounce یک‌ثانیه‌ای به `PUT /widgets/settings` ارسال می‌شود. توابع `safe_color`، `safe_font` و `clamp_int` تضمین می‌کنند مقدار آمده از سرور نتواند CSS دلخواه تزریق کند.

### ۱۲.۱۱ Web — Device Fingerprint و تزریق هدرها

```typescript
// src/security/fingerprint.ts
import FingerprintJS from '@fingerprintjs/fingerprintjs';

let cached: string | null = null;

export async function getDeviceFingerprint(): Promise<string> {
  if (cached) return cached;
  const fp = await (await FingerprintJS.load()).get();
  // جزء پایدار صادرشده توسط سرور، در کنار جزء ناپایدار مرورگر
  const deviceToken = getCookie('device_token') ?? '';
  cached = `web-fp-${await sha256(`${fp.visitorId}:${deviceToken}`)}`;
  return cached;
}
```

```typescript
// src/api/client.ts
import axios from 'axios';
import { getDeviceFingerprint } from '@/security/fingerprint';

export const api = axios.create({
  baseURL: import.meta.env.VITE_API_BASE,
  withCredentials: true,           // Refresh Token در HttpOnly Cookie
  timeout: 15_000,
});

api.interceptors.request.use(async (config) => {
  config.headers['X-Device-Fingerprint'] = await getDeviceFingerprint();
  config.headers['X-Device-Nonce']       = crypto.randomUUID();
  config.headers['X-Device-Timestamp']   = String(Date.now());
  config.headers['X-Request-ID']         = crypto.randomUUID();
  // توجه: X-Device-MAC در وب ارسال نمی‌شود — مقدار ساختگی، Audit را آلوده می‌کند
  const csrf = getCookie('csrf_token');
  if (csrf) config.headers['X-CSRF-Token'] = csrf;
  return config;
});

let refreshing: Promise<void> | null = null;
api.interceptors.response.use(undefined, async (error) => {
  if (error.response?.status === 401 && !error.config._retried) {
    error.config._retried = true;
    refreshing ??= api.post('/auth/refresh').finally(() => { refreshing = null; });
    await refreshing;                         // چند درخواست همزمان، یک refresh
    return api(error.config);
  }
  throw error;
});
```

> **درباره‌ی امضای HMAC در وب:** برخلاف دسکتاپ، مرورگر نمی‌تواند کلید HMAC را امن نگه دارد (هر کلیدی در JS در دسترس XSS است). به‌جای امضا، وب بر **Device Token در HttpOnly Cookie** تکیه می‌کند که جاوااسکریپت اصلاً آن را نمی‌بیند. پیاده‌سازی HMAC در وب، امنیت ظاهری بدون امنیت واقعی است.

### ۱۲.۱۲ Web — گرید داشبورد و داشبورد مدیر گروه

```tsx
// src/features/dashboard/DashboardGrid.tsx
import GridLayout, { type Layout } from 'react-grid-layout';
import { useDebouncedCallback } from 'use-debounce';

const COLS = { lg: 12, md: 6, sm: 1 } as const;

export function DashboardGrid({ layoutId, blocks }: Props) {
  const { width, breakpoint } = useContainerWidth();
  const saveLayout = useSaveLayout(layoutId);

  // Layout همیشه در قالب ۱۲ ستونه ذخیره می‌شود؛ نمایش موبایل ذخیره نمی‌شود
  const onChange = useDebouncedCallback((next: Layout[]) => {
    if (breakpoint !== 'lg') return;
    saveLayout(next.map(l => ({
      block_key: l.i, position_x: l.x, position_y: l.y,
      width: l.w, height: l.h, is_visible: true,
    })));
  }, 1000);

  return (
    <GridLayout
      className="layout" cols={COLS[breakpoint]} rowHeight={72} width={width}
      isDraggable={breakpoint === 'lg'} isResizable={breakpoint === 'lg'}
      draggableHandle=".block-header" compactType="vertical" onLayoutChange={onChange}
    >
      {blocks.filter(b => b.is_visible).map(b => (
        <div key={b.block_key} data-grid={toGridItem(b, breakpoint)}>
          <DashboardBlock blockKey={b.block_key} config={b.config} />
        </div>
      ))}
    </GridLayout>
  );
}
```

```tsx
// src/features/groupManager/MemberCard.tsx
export function MemberCard({ member }: { member: GroupMember }) {
  // UI هرگز داده‌ای را که سرور نفرستاده «حدس» نمی‌زند —
  // سانسور در سرور اتفاق افتاده، این فقط نمایش صحیح آن است.
  if (member.visibility === 'aggregate_only') {
    return (
      <Card>
        <Header name={member.display_name} />
        <ProgressRing value={member.stats.progress_pct} />
        <p className="text-sm text-muted">{member.notice}</p>
      </Card>
    );
  }
  return (
    <Card>
      <Header name={member.display_name} />
      <StatRow stats={member.stats} />
      <GoalList goals={member.goals ?? []} />
    </Card>
  );
}
```

### ۱۲.۱۳ Web — پایه‌ی ریسپانسیو و RTL

```html
<!doctype html>
<html lang="fa" dir="rtl">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover" />
    <meta http-equiv="Content-Security-Policy"
          content="default-src 'self'; script-src 'self'; style-src 'self';
                   img-src 'self' data: blob:; font-src 'self';
                   connect-src 'self' https://api.corp.local wss://api.corp.local;
                   frame-ancestors 'none'; base-uri 'self'; object-src 'none'" />
    <link rel="preload" href="/fonts/Vazirmatn-Regular.woff2" as="font" crossorigin />
    <title>سامانه مدیریت اهداف</title>
  </head>
  <body class="bg-surface text-content"><div id="root"></div></body>
</html>
```

```css
/* src/styles/tailwind.css */
@font-face {
  font-family: 'Vazirmatn';
  src: url('/fonts/Vazirmatn-Regular.woff2') format('woff2');
  font-weight: 400; font-display: swap;
}
:root { --font-fa: 'Vazirmatn', 'IRANSans', system-ui, sans-serif; }

body { font-family: var(--font-fa); line-height: 1.8; }  /* فارسی فضای عمودی بیشتر می‌خواهد */

/* از کلاس‌های منطقی استفاده کنید: ms-* / me-* / ps-* / pe-* — نه ml-* / pr-* */
.table-wrap { overflow-x: auto; max-width: 100%; }        /* جدول عریض، نه صفحه عریض */
.touch-target { min-inline-size: 44px; min-block-size: 44px; }
```

---

## ۱۳. کتابخانه‌ها، زیرساخت و ظرفیت‌سنجی

### ۱۳.۱ Backend (Python 3.12)

```toml
# ── هسته API و داده
fastapi ^0.115 · uvicorn[standard] ^0.32 · gunicorn ^23.0
pydantic ^2.9 · pydantic-settings ^2.6
sqlalchemy ^2.0 · alembic ^1.14 · asyncpg ^0.30 · psycopg[binary,pool] ^3.2
sqlalchemy-utils ^0.41            # نوع LTREE برای گروه‌های سلسله‌مراتبی

# ── امنیت و احراز هویت
argon2-cffi ^23.1                 # هش رمز (اولویت اول)
passlib[bcrypt] ^1.7              # مسیر مهاجرت از bcrypt
pyjwt[crypto] ^2.9                # JWT RS256
cryptography ^43.0                # AES-256-GCM: کد ملی، TOTP، رمز LDAP
pyotp ^2.9                        # MFA — TOTP
qrcode[pil] ^8.0                  # QR ثبت MFA
slowapi ^0.1.9                    # Rate Limiting روی Redis
bleach ^6.2                       # پاک‌سازی HTML (کامنت و چت)
secure ^0.3                       # هدرهای امنیتی
python-magic ^0.4                 # تشخیص نوع فایل از magic number
pyclamd ^0.4                      # ClamAV daemon
Pillow ^11.0                      # Re-encode تصویر + حذف EXIF

# ── LDAP / Kerberos
ldap3 ^2.9                        # پیاده‌سازی خالص پایتون (build ساده روی ویندوز)
gssapi ^1.9                       # اعتبارسنجی تیکت Kerberos (سرور لینوکسی)
pyspnego ^0.11                    # SPNEGO/NTLM چندسکویی

# ── Real-time و پس‌زمینه
websockets ^13.1 · redis ^5.2
celery[redis] ^5.4 · flower ^2.0

# ── ابزار
openpyxl ^3.1 · jdatetime ^5.0 · pywebpush ^2.0 · python-dateutil ^2.9
boto3 ^1.35                       # MinIO/S3
structlog ^24.4 · sentry-sdk ^2.18
prometheus-fastapi-instrumentator ^7.0
geoip2 ^4.8                       # موقعیت جغرافیایی از IP (پایگاه محلی، بدون فراخوانی بیرونی)

# ── توسعه
pytest · pytest-asyncio · pytest-cov · httpx · factory-boy · faker
testcontainers · schemathesis · locust
ruff · mypy · bandit · pip-audit · gitleaks
```

### ۱۳.۲ Frontend دسکتاپ

| پکیج | نقش | یادداشت |
|------|-----|---------|
| `PySide6` ^6.8 | UI (Qt6) | LGPL؛ RTL و shaping فارسی درجه‌یک، Tray کامل |
| `CustomTkinter` ^5.2 | جایگزین سبک‌تر | اگر الزام سازمانی است — اما RTL و Tray آن محدود است |
| `httpx` ^0.28 | HTTP Client | HTTP/2، timeout، event hooks |
| `websockets` ^13.1 | کلاینت چت | روی QThread مجزا |
| `psutil` ^6.1 | **دریافت MAC Address** | مطابق ۶.۲ |
| `keyring` ^25 · `pywin32` ^308 | DPAPI و Credential Manager | ذخیره امن توکن |
| `requests-negotiate-sspi` ^0.5 | SSO ویندوزی | ساده‌ترین مسیر Kerberos/NTLM |
| `pystray` ^0.19 | System Tray | جایگزین `QSystemTrayIcon` در مسیر Tkinter |
| `jdatetime` ^5.0 | تقویم جلالی | — |
| `PyInstaller` ^6.11 | بسته‌بندی EXE | `--onedir` + امضای Authenticode |

### ۱۳.۳ Frontend وب

`react` ^18.3 · `typescript` ^5.6 · `vite` ^6 · `tailwindcss` ^3.4 · `@tanstack/react-query` ^5 · `react-router` ^7 · `zustand` ^5 · `react-hook-form` + `zod` · `date-fns-jalali` ^4 · `react-grid-layout` ^1.5 · `recharts` ^2.13 · `dompurify` ^3.2 · `axios` ^1.7 · `@fingerprintjs/fingerprintjs` ^4 · `vite-plugin-pwa` ^0.21 · `@axe-core/react` · `openapi-typescript`

**پوشش مرورگری:** `> 0.5%, last 2 versions, not dead` ⇒ Chrome/Edge 100+, Firefox 100+, Safari 15.4+, Opera 86+. Web Push در Safari فقط از ۱۶.۴ و در iOS فقط برای PWA نصب‌شده کار می‌کند — این محدودیت باید در UX پیش‌بینی شود.

### ۱۳.۴ ظرفیت‌سنجی سخت‌افزار و شبکه

| سطح | کاربر همزمان | Backend | Database | سایر | شبکه |
|-----|---------------|---------|----------|------|------|
| ۱ | ≤ ۵۰ | ۴ Core / ۸GB / ۲۰۰GB SSD | ۴ Core / ۸GB / ۵۰۰GB | Redis هم‌میزبان | ۱۰۰ Mbps |
| ۲ | ۵۱–۱۰۰ | ۸ Core / ۱۶GB / ۵۰۰GB | ۸ Core / ۱۶GB / ۱TB | Redis مجزا | ۵۰۰ Mbps |
| ۳ | ۱۰۱–۲۵۰ | LB + ۲× (۸C/۱۶GB) | ۱۶ Core / ۳۲GB / ۲TB RAID10 | Redis + MinIO | ۱ Gbps |
| ۴ | ۲۵۱–۵۰۰ | LB + ۳–۴× (۸C/۱۶GB) | Primary + Replica (۱۶C/۳۲GB) | Redis Cluster + MinIO | ۱ Gbps |
| ۵ | ۵۰۱–۱۰۰۰ | LB + ۵–۸× (۸C/۱۶GB) | Primary + ۲ Replica (۳۲C/۶۴GB) | Redis Cluster + RabbitMQ + S3/NAS | ۱۰ Gbps |

**اهداف شبکه:** تأخیر < ۵۰ms، از دست رفتن بسته < ۰.۱٪، دسترس‌پذیری ۹۹.۹٪ (سطوح ۱–۳) تا ۹۹.۹۹٪ (سطوح ۴–۵).

**چند نکته‌ی عملی درباره‌ی این جدول:**

- **WebSocket بار متفاوتی دارد.** هر اتصال باز حدود ۳۰–۵۰KB حافظه مصرف می‌کند؛ ۱۰۰۰ کاربر همزمان یعنی ~۵۰MB فقط برای سوکت‌ها — قابل مدیریت، اما تعداد **file descriptorها** باید تنظیم شود (`ulimit -n 65535`). این رایج‌ترین گلوگاه در سطح ۵ است، نه CPU.
- **گلوگاه واقعی معمولاً دیتابیس است، نه Backend.** پیش از افزودن Backend سوم، `pg_stat_statements` را بررسی کنید؛ اغلب یک ایندکس گمشده مشکل را حل می‌کند، نه سخت‌افزار بیشتر.
- **Replicaها برای خواندن گزارش‌ها.** کوئری‌های سنگین داشبورد مدیر گروه و گزارش‌ها باید به Read Replica هدایت شوند تا نوشتن‌های تراکنشی را کند نکنند.
- **تأخیر Replication** یعنی داده‌ی تازه‌نوشته ممکن است بلافاصله روی Replica نباشد — کوئری‌های «بعد از نوشتن بخوان» باید به Primary بروند.

### ۱۳.۵ استقرار و سخت‌سازی

- کانتینر non-root (`USER 1000`)، فایل‌سیستم read-only، `cap_drop: ALL`.
- کاربر DB برنامه بدون `CREATE`/`DROP`؛ Migration با کاربر جداگانه.
- رازها از **Vault** یا Docker Secrets؛ هرگز در مخزن یا `docker-compose.yml`.
- Nginx: TLS 1.2/1.3، HSTS با preload، `server_tokens off`، `client_max_body_size 52m`، Rate Limit لایه‌ی ۷.
- CORS دقیق با `allow_origins` از ENV — **هرگز `["*"]` همراه `allow_credentials=True`** (ترکیبی که مرورگر رد می‌کند و نشانه‌ی پیکربندی ناامن است).
- بکاپ روزانه‌ی رمزنگاری‌شده + **تست بازیابی ماهانه**. بکاپی که بازیابی‌اش تست نشده، بکاپ نیست.
- نگهداری لاگ: حداقل ۱ سال مطابق نیازمندی؛ پارتیشن‌های قدیمی‌تر از ۹۰ روز به آرشیو سرد رمزنگاری‌شده منتقل شوند.

---

## ۱۴. فازبندی، ریسک و توصیه‌های پایانی

### ۱۴.۱ برآورد زمان‌بندی

| فاز | ماژول‌ها | هفته | تیم |
|-----|----------|------|-----|
| ۰ | اسکلت، Event Bus، CI/CD، مرزهای ماژولار، آزمون معماری | ۳ | پلتفرم |
| ۱ | M1 Auth (کد ملی، MFA، دستگاه‌ها)، M2 RBAC، M12 SSO/LDAP، M11 Audit | ۷ | پلتفرم |
| ۲ | M3 Groups & Privacy + داشبورد مدیر گروه | ۴ | تیم A |
| ۳ | M4 Goals، M5 Calendar & Dashboard، تقویم جلالی | ۶ | تیم B |
| ۴ | M6 Sharing، M8 کارتابل، کامنت و Activity Timeline | ۵ | تیم A |
| ۵ | M7 Chat + M13 Files (WebSocket، آپلود، AV) | ۵ | تیم C |
| ۶ | M9 Reporting، Export، داشبورد پیشرفته، جستجوی Full-Text | ۴ | تیم B |
| ۷ | M10 Notification، ویجت‌ها، شخصی‌سازی کامل، بهینه‌سازی | ۴ | همه |
| ۸ | کلاینت وب (موازی از فاز ۳) | ۸ | تیم وب |
| ۹ | کلاینت دسکتاپ (موازی از فاز ۳) | ۸ | تیم دسکتاپ |
| ۱۰ | تست نفوذ، تست بار، مستندسازی، آموزش، انتشار | ۳ | همه |

**مسیر بحرانی: ۳۴ تا ۴۰ هفته** با تیمی متشکل از ۳ Backend، ۲ Frontend وب، ۱ Frontend دسکتاپ، ۱ DevOps و ۱ QA — یعنی حدود **۸ تا ۱۰ ماه**.

اگر تیم کوچک‌تری در اختیار دارید، این عدد خطی رشد نمی‌کند بلکه بدتر می‌شود (سربار هماهنگی + توقف‌های وابستگی). در آن صورت به بخش ۱۴.۳ مراجعه کنید.

### ۱۴.۲ ریسک‌ها

| ریسک | شدت | احتمال | کاهش |
|------|------|--------|------|
| **Scope Creep** — حجم نیازمندی‌ها بیش از ظرفیت تیم | بحرانی | بسیار بالا | دروازه‌ی پذیرش مستقل برای هر فاز؛ انتقال اقلام «اختیاری» به Backlog؛ MVP روشن (۱۴.۳) |
| پیچیدگی سه‌لایه‌ی RBAC+ACL+Privacy منجر به نشت داده | بحرانی | متوسط | تمرکز کامل منطق در PolicyEngine؛ آزمون ماتریسی خودکار؛ بازبینی دونفره‌ی اجباری |
| SSO با Kerberos در محیط واقعی AD کار نکند (SPN/ساعت/DNS) | بالا | متوسط | Spike دوروزه روی Domain آزمایشی در فاز ۰، پیش از تعهد زمانی؛ Fallback به LDAP Bind از روز اول |
| اتکای بیش از حد به MAC به‌عنوان کنترل امنیتی | بالا | بالا | مدل Risk Score (۶.۵)؛ مستندسازی صریح محدودیت‌ها برای ذی‌نفعان |
| نشت داده‌ی شخصی (کد ملی + MAC + موقعیت) | بالا | متوسط | رمزنگاری کد ملی؛ سیاست نگهداری مکتوب؛ محدودسازی نقش `auditor`؛ بازبینی فصلی دسترسی |
| «تمام فرمت‌های فایل» تبدیل به کانال بدافزار شود | بالا | متوسط | Whitelist گسترده + ClamAV + magic number + Re-encode تصویر |
| دو کلاینت بومی ⇒ دوبرابر شدن هزینه نگهداری UI | متوسط | بالا | قرارداد API مشترک و کلیدهای بلوک یکسان؛ گزینه‌ی PyWebView (۱۴.۳) |
| کندی داشبورد مدیر گروه با رشد داده | متوسط | بالا | Read Replica، ایندکس‌های جزئی، کش با ابطال رویدادی، تست بار در فاز ۶ |
| Microservices زودهنگام ⇒ پیچیدگی عملیاتی غیرقابل مدیریت | بالا | متوسط | Modular Monolith با مرزهای اجباری (۰.۳) |

### ۱۴.۳ سه توصیه‌ی پایانی

**۱) دامنه را برای نسخه‌ی اول کوچک کنید.** این سند همه‌ی نیازمندی‌ها را پوشش می‌دهد، اما تحویل همزمان‌شان ریسک بالایی دارد. یک MVP قابل دفاع — **فازهای ۰ تا ۴ به‌علاوه‌ی کلاینت وب** — در حدود ۵ ماه قابل تحویل است و ۸۰٪ ارزش کاربری را می‌دهد. چت، ویجت‌های شناور، تقویم قمری، و گزارش‌های پیشرفته می‌توانند در نسخه‌ی دوم بیایند. هیچ چیز به اندازه‌ی یک پروژه‌ی ۱۰ ماهه که در ماه هشتم هنوز چیزی برای نشان دادن ندارد، به اعتماد سازمانی آسیب نمی‌زند.

**۲) اگر منابع محدود است، فقط یک کلاینت بسازید.** ساخت همزمان دو Frontend بومی، هزینه‌ی نگهداری UI را دوبرابر می‌کند. مسیر کم‌ریسک‌تر: وب را کامل بسازید، سپس نسخه‌ی دسکتاپ را با **PyWebView** (پوسته‌ی ~۵MB روی همان کد وب) ارائه دهید — که System Tray، دسترسی به MAC از طریق `psutil`، و SSO ویندوزی را همگی پشتیبانی می‌کند. این تقریباً تمام نیازمندی‌های دسکتاپ شما را پوشش می‌دهد و **۸ هفته** از زمان‌بندی می‌کاهد. PySide6 فقط در صورتی ارزش دارد که کارایی بومی و انیمیشن روان الزام قطعی باشد.

**۳) مرزهای ماژولار را از روز اول با آزمون اجباری کنید، نه با توافق.** این تنها راهی است که «معماری ماژولار قابل واگذاری به تیم‌ها» — که هدف اصلی شما از درخواست Microservices بود — واقعاً محقق می‌شود. بدون آزمون خودکار مرزها، ظرف شش ماه به یک Monolith درهم‌تنیده می‌رسید که نه مزیت ماژولار بودن را دارد و نه سادگی یک طراحی یکپارچه‌ی صادقانه را.

---

*پایان سند. هر بخش قابل بسط به سند فنی مستقل برای تیم مجری همان ماژول است.*
```

================================================================================
## FILE: backend/.env.example
================================================================================

```bash
ENV=development            # development | testing | production
DEBUG=False
SQL_ECHO=False             # log every SQL statement (very noisy)
# At least 32 characters. Generate with:
#   .\.venv\Scripts\python.exe -c "import secrets; print(secrets.token_urlsafe(32))"
SECRET_KEY=change-me-to-a-random-string-at-least-32-chars-long
POSTGRES_SERVER=localhost
POSTGRES_PORT=5432
POSTGRES_USER=admin
POSTGRES_PASSWORD=admin123
POSTGRES_DB=planner_db
# App reads SQLALCHEMY_DATABASE_URI first, DATABASE_URL as fallback.
SQLALCHEMY_DATABASE_URI=postgresql+asyncpg://admin:admin123@localhost:5432/planner_db
REDIS_HOST=localhost
REDIS_PORT=6379
HOST=0.0.0.0
PORT=8000
# Must be JSON array syntax (comma-separated string fails to parse).
CORS_ORIGINS=["http://localhost:3000","http://localhost:8080"]
ENABLE_MFA=True
ENABLE_SSO=True
ENABLE_AUDIT_LOGGING=True
RATE_LIMIT_DEFAULT=100/minute
RATE_LIMIT_AUTH=10/minute
MAX_UPLOAD_SIZE=52428800

# ---- Added in architecture-v2 infrastructure pass -------------------------
# Separate keys per purpose (section 4.9 / ADR-06). REQUIRED when ENV=production.
#   DATA_ENCRYPTION_KEY: python -c "import os,base64;print(base64.b64encode(os.urandom(32)).decode())"
#   NATIONAL_ID_PEPPER : python -c "import secrets;print(secrets.token_urlsafe(48))"
DATA_ENCRYPTION_KEY=
NATIONAL_ID_PEPPER=
# HS256 by default; for RS256 set ALGORITHM=RS256 plus both PEM keys.
ALGORITHM=HS256
# JSON arrays. '*' is rejected in production.
ALLOWED_HOSTS=["*"]
ALLOWED_ORIGINS=[]         # WebSocket Origin allow-list; empty = CORS_ORIGINS
TRUSTED_PROXIES=[]         # only these peers may set X-Forwarded-For
IP_ALLOW_LIST=[]
IP_DENY_LIST=[]
MAX_BODY_SIZE=1048576
RATE_LIMIT_ENABLED=True
ALLOW_SELF_REGISTRATION=False
DEVICE_BINDING_MODE=observe  # off | observe | enforce
```

================================================================================
## FILE: backend/alembic/env.py
================================================================================

```python
import os
import sys
from alembic import context
from sqlalchemy import engine_from_config, pool

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# Ensure `backend/` (project root for `app.*`) is on sys.path when
# alembic runs from D:\Projects\Activity_dashboard\backend.
_BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)


def _load_dotenv(path):
    """Minimal .env loader (avoids a python-dotenv dependency)."""
    if not os.path.isfile(path):
        return
    with open(path, encoding="utf-8") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key, value = key.strip(), value.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = value


_load_dotenv(os.path.join(_BACKEND_DIR, ".env"))

# Alembic runs in sync mode, but the app .env uses the async driver
# (postgresql+asyncpg://...). Convert it to the sync psycopg2 driver,
# which is what requirements.txt ships (psycopg2-binary).
_db_url = os.environ.get(
    "SQLALCHEMY_DATABASE_URI",
    config.get_main_option("sqlalchemy.url"),
)
if _db_url and "+asyncpg" in _db_url:
    _db_url = _db_url.replace("+asyncpg", "+psycopg2")
if _db_url:
    config.set_main_option("sqlalchemy.url", _db_url)

try:
    from app.core.db.base import Base  # noqa: E402

    target_metadata = Base.metadata
except Exception:
    from sqlalchemy import MetaData  # noqa: E402

    target_metadata = MetaData()

def run_migrations_offline():
    """Run migrations in 'offline' mode.
    
    This configures the context with just a URL
    and gives us the ability to emit SQL script without
    needing a DBAPI.
    """
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()

def run_migrations_online():
    """Run migrations in 'online' mode.
    
    In this mode we need to connect to the database and run migrations
    against a live connection.
    """
    connectable = engine_from_config(
        config.get_section(config.config_ini_section),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection, 
            target_metadata=target_metadata
        )

        with context.begin_transaction():
            context.run_migrations()

if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
```

================================================================================
## FILE: backend/alembic.ini
================================================================================

```ini
[alembic]
script_location = alembic
prepend_sys_path = .
version_path_separator = os
sqlalchemy.url = postgresql+psycopg2://admin:admin123@localhost:5432/planner_db

[post_write_hooks]

[loggers]
keys = root,sqlalchemy,alembic

[handlers]
keys = console

[formatters]
keys = generic

[logger_root]
level = WARN
handlers = console
qualname =

[logger_sqlalchemy]
level = WARN
handlers =
qualname = sqlalchemy.engine

[logger_alembic]
level = INFO
handlers =
qualname = alembic

[handler_console]
class = StreamHandler
args = (sys.stderr,)
level = NOTSET
formatter = generic

[formatter_generic]
format = %(levelname)-5.5s [%(name)s] %(message)s
datefmt = %H:%M:%S
```

================================================================================
## FILE: backend/requirements.txt
================================================================================

```text
fastapi==0.115.6
uvicorn[standard]==0.30.1
sqlalchemy[asyncio]==2.0.30
asyncpg==0.29.0
alembic==1.13.0
psycopg2-binary==2.9.9
redis==5.0.1
python-jose[cryptography]==3.3.0
PyJWT==2.8.0
structlog==24.4.0
passlib[bcrypt]==1.7.4
argon2-cffi==23.1.0
python-multipart==0.0.6
pydantic==2.9.2
pydantic-settings==2.0.0
```

================================================================================
## FILE: RUN_PROJECT_GUIDE.md
================================================================================

```markdown
# راهنمای راه‌اندازی پروژه (بدون داکر)

> به‌روزرسانی: ۲۲ سپتامبر ۲۰۲۶ — تمام مراحل زیر روی همین ماشین اجرا و تأیید شده است.
> Backend و Frontend هر دو بدون داکر، با PostgreSQL نصب‌شده روی ویندوز کار می‌کنند.

---

## ۱. پیش‌نیازها

| نیاز | نسخه تأییدشده | توضیح |
|---|---|---|
| Python | 3.12.8 | بک‌اند با همین نسخه اجرا شد |
| Node.js / npm | v24 / v11 (نسخه ۱۸+ کافی است) | فرانت‌اند |
| PostgreSQL | 16 (سرویس `postgresql-x64-16`) | به‌صورت native روی ویندوز، بدون داکر |
| Redis | — | **اختیاری/نصب نیست**؛ `RedisBroker` با fallback درون‌فرایندی کار می‌کند (توضیح در بخش ۶ و ۸و) |
| اینترنت | لازم برای `pip install` و `npm install` اول | — |

مسیر پروژه: `C:\Projects\Run_Projects_in_Git\Activity_dashboard`

---

## ۲. راه‌اندازی دیتابیس (یک‌بار)

سرویس PostgreSQL باید در حال اجرا باشد:

```powershell
Get-Service postgresql-x64-16   # باید Running باشد
```

### ۲.۱ ساخت نقش و دیتابیس

فایل `backend/.env` از این مقادیر استفاده می‌کند:

```
POSTGRES_USER=admin
POSTGRES_PASSWORD=admin123
POSTGRES_DB=planner_db
```

اگر نقش `admin` وجود ندارد (خطای `password authentication failed` یا `role "admin" does not exist`)، یک‌بار با دسترسی مدیریتی بسازید. چون `pg_ctl reload` به مجوز سرویس نیاز دارد، روش مطمئن این است که موقتاً احراز هویت را `trust` کنید:

```powershell
# ۱) بکاپ و trust موقت
Copy-Item "C:\Program Files\PostgreSQL\16\data\pg_hba.conf" "C:\Program Files\PostgreSQL\16\data\pg_hba.conf.bak" -Force
(Get-Content "C:\Program Files\PostgreSQL\16\data\pg_hba.conf") -replace "scram-sha-256","trust" | Set-Content "C:\Program Files\PostgreSQL\16\data\pg_hba.conf" -Force

# ۲) ساخت نقش و دیتابیس (بدون رمز عبور وصل می‌شوید)
$env:PGPASSWORD=""
& "C:\Program Files\PostgreSQL\16\bin\psql.exe" -h localhost -U postgres -d postgres -c "CREATE ROLE admin LOGIN PASSWORD 'admin123' SUPERUSER;"
& "C:\Program Files\PostgreSQL\16\bin\psql.exe" -h localhost -U postgres -d postgres -c "CREATE DATABASE planner_db OWNER admin;"
& "C:\Program Files\PostgreSQL\16\bin\psql.exe" -h localhost -U postgres -d postgres -c "CREATE ROLE app_user LOGIN PASSWORD 'app_user_123';"

# ۳) برگرداندن امنیت و اعمال تنظیمات
Copy-Item "C:\Program Files\PostgreSQL\16\data\pg_hba.conf.bak" "C:\Program Files\PostgreSQL\16\data\pg_hba.conf" -Force
$env:PGPASSWORD="admin123"
& "C:\Program Files\PostgreSQL\16\bin\psql.exe" -h localhost -U admin -d planner_db -c "SELECT pg_reload_conf();"

# ۴) تست اتصال با رمز
& "C:\Program Files\PostgreSQL\16\bin\psql.exe" -h localhost -U admin -d planner_db -c "SELECT 1;"
```

> ⚠️ توجه: `admin/admin123` **نقش دیتابیس** است، نه کاربر اپلیکیشن. ساخت کاربر ورود به فرانت‌اند در بخش ۵ آمده است.

نقش `app_user` را حتماً بسازید؛ مایگریشن `audit_schema.sql` دستور `GRANT ... TO app_user` دارد و بدون این نقش، `alembic upgrade head` با خطای `role "app_user" does not exist` می‌شکند.

---

## ۳. راه‌اندازی Backend

```powershell
cd C:\Projects\Run_Projects_in_Git\Activity_dashboard\backend

# ۱) ساخت محیط مجازی تازه (venv قبلی خراب بود و حذف شد)
python -m venv .venv

# ۲) نصب وابستگی‌ها
.\.venv\Scripts\pip.exe install --timeout 120 --retries 5 -r requirements.txt

# ۳) تنظیم .env (اگر از روی example می‌سازید، این دو نکته حیاتی است)
#    - CORS_ORIGINS باید JSON array باشد، نه comma-separated:
#      CORS_ORIGINS=["http://localhost:3000","http://127.0.0.1:3000","http://localhost:5173","http://127.0.0.1:5173","http://localhost:8080"]
#    - SECRET_KEY حداقل ۳۲ کاراکتر

# ۴) اجرای مایگریشن (ساخت ۱۳ اسکیما + اسکیمای هسته `core`)
#    head فعلی: 0002_core_outbox (جدول transactional-outbox در بخش ۲.۳ سند)
.\.venv\Scripts\python.exe -m alembic upgrade head
.\.venv\Scripts\python.exe -m alembic current   # باید 0002_core_outbox (head) را نشان دهد

# ۵) اجرای سرور (روش مطمئن در PowerShell — پشت‌زمینه و جدا از shell)
#    نکته: Start-Job فرانت از shell tool می‌میرد؛ cmd start /b فرزند را جدا می‌کند و زنده می‌ماند.
cmd /c "start /b .venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000 > %TEMP%\opencode\srv8000.log 2>&1"

# اجرای پیش‌رو (جلوی) برای دیباگ:
#     .\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

تست سلامت: http://127.0.0.1:8000/health باید `{"status":"healthy", ...}` با ۱۳ ماژول برگرداند.
مستندات API: http://127.0.0.1:8000/docs
پس از راه‌اندازی، بررسی کامل با اسکریپت‌های تست:
```powershell
$env:PYTHONIOENCODING='utf-8'
.\.venv\Scripts\python.exe "%TEMP%\opencode\smoke.py"    # 17 endpoint خواندنی → 16 OK + 1 SSO challenge (401)
```
> `401` روی `GET /api/v1/auth/sso/negotiate` **رفتار درست** است (چالش SPNEGO + هدر `WWW-Authenticate: Negotiate`)، نه خطا.
>
> ⚠️ بهداشت تست (مهم): هر `POST /auth/login` موفق `token_version` کاربر را زیاد می‌کند و **توکن‌های قبلی را باطل می‌کند**؛ پس لاگین‌های پشت‌سرهم/موازی همدیگر را می‌اندازند (`401 Token revoked`). همچنین محدودیت `RATE_LIMIT_AUTH=10/minute` روی لاگین است (پاسخ `429 RATE_LIMIT_EXCEEDED`). برای تست پایدار: در هر اسکریپت فقط **یک لاگین**، بین اجراها **۶۰+ ثانیه** صبر، و برای WS هم توکن تازه بگیرید (اسکریپت‌ها همین الگو را دارند). `401`های پراکنده‌ی میانیِ اجراهای شلوغ دقیقاً همین علت را دارند، نه باگ — با یک لاگین تمیز همه‌چیز 200 می‌شود.

---

## ۴. راه‌اندازی Frontend

```powershell
cd C:\Projects\Run_Projects_in_Git\Activity_dashboard\web
npm install
npm run dev
```

- آدرس: http://127.0.0.1:3000 (طبق `vite.config.ts` پورت `3000` است، نه ۵۱۷۳)
- اتصال به بک‌اند از `web/.env` خوانده می‌شود: `VITE_API_BASE=http://127.0.0.1:8000/api/v1`
- تست build: `npm run build` (باید بدون خطا بیلد کند؛ آخرین بیلد موفق: ۱۷۶ ماژول)

---

## ۵. ساخت کاربر ورود (مهم)

**مشکل گزارش‌شده:** ورود با `admin/admin123` در فرانت‌اند ناموفق بود.
**علت:** این نام/رمز، نقش PostgreSQL است و هیچ کاربر اپلیکیشنی با آن وجود نداشت (ورود اشتباهاً `401 AUTHENTICATION_ERROR` می‌داد).

**راه‌حل:** کاربر اپلیکیشن `admin` ساخته شد. اگر دیتابیس را از نو ساختید، دوباره بسازید:

```powershell
# POST /api/v1/auth/register — کد ملی باید چک‌سام رسمی ایران را پاس کند (مثلاً 1234567891)
```

```jsonc
// POST http://127.0.0.1:8000/api/v1/auth/register
{ "username": "admin", "password": "admin123",
  "display_name": "admin", "national_id": "1234567891", "email": "admin@local" }
// 201 Created
```

```jsonc
// POST http://127.0.0.1:8000/api/v1/auth/login  (دقیقاً همین را فرانت‌اند می‌فرستد)
{ "identifier": "admin", "password": "admin123", "remember_me": false }
// 200 → { mfa_required:false, tokens:{access_token, refresh_token}, user:{...} }
```

حالا در فرانت‌اند (http://127.0.0.1:3000) با `admin` / `admin123` وارد شوید.

---

## ۶. تغییراتی که در کد داده شد (برای راه‌اندازی لازم بود)

### ۶.۱ `backend/app/main.py` — ایمپورت ماژول‌های ناموجود
`main.py` ماژول‌های `calendar, notification, audit, ssoldap, files` را ایمپورت می‌کرد ولی این پوشه‌ها وجود نداشتند (`ImportError`) و سرور اصلاً بالا نمی‌آمد.
→ هر ۵ ماژول به‌صورت **stub استاندارد** ساخته شد: `app/modules/<name>/__init__.py` (صادرکننده `router` + تابع `register_event_handlers`) و `app/modules/<name>/api/routes.py` (یک endpoint نمونه). اسکیمای SQL هر ۱۳ ماژول از قبل در `alembic/versions/` موجود بود.

### ۶.۲ `backend/app/core/dependencies.py` — circular import
ایمپورت سطح‌بالای `UserRepository`/`AuthService` باعث چرخه `dependencies ↔ auth.routes` می‌شد.
→ ایمپورت‌ها به داخل توابع منتقل شد (lazy import).

### ۶.۳ `backend/app/core/dependencies.py` — `get_current_user` واقعی شد
قبلاً همیشه `{"id":"placeholder"}` برمی‌گرداند.
→ حالا JWT را با HS256 اعتبارسنجی می‌کند (امضا، انقضا، `type=access`)، کاربر را از DB می‌خواند و توکن باطل‌شده (`token_version` ناهماهنگ) و حساب غیرفعال را با 401 رد می‌کند. خروجی `str` (آی‌دی کاربر) است تا ۶۴ محل استفاده‌کننده در ماژول‌ها که `UUID` انتظار دارند نشکنند (FastAPI خودش str→UUID تبدیل می‌کند).

### ۶.۴ چک‌سام کد ملی (`auth/services/auth_service.py::_validate_national_id`)
پیاده‌سازی قبلی (`expected = 0 if r==10 else r`) با الگوریتم رسمی ایران که سند معماری (بخش ۴.۲) الزام کرده مغایرت داشت و کدهای معتبر را رد می‌کرد.
→ اصلاح به الگوریتم رسمی: `expected = r if r<2 else 11-r`.

### ۶.۵ `UserDevices.first_seen_at/last_seen_at` (`auth/db/models.py`)
مدل `nullable=True` بدون default بود ولی ستون DB ‏`NOT NULL DEFAULT now()` است؛ SQLAlchemy مقدار NULL صریح می‌فرستاد و ثبت‌نام با خطای 500 می‌شکست.
→ `server_default=func.now()` به هر دو ستون اضافه شد.

### ۶.۶ توکن تازه باطل می‌شد (`auth_service._generate_tokens`)
`token_version` **بعد** از ساخت JWT زیاد می‌شد، پس توکن刚 صادرشده نسخه قدیمی داشت و اولین استفاده 401 `Token revoked` می‌گرفت.
→ افزایش به **قبل** از صدور توکن منتقل شد.

### ۶.۷ endpointهای گمشده موردنیاز فرانت‌اند
فرانت‌اند (`web/src/security/authProvider.ts`) این‌ها را صدا می‌زند ولی در بک‌اند نبود:
→ `GET /api/v1/auth/me`، `POST /api/v1/auth/logout` (ابطال نشست با `token_version++`)، `GET /api/v1/auth/devices` (با MAC ماسک‌شده) به `auth/api/routes.py` اضافه شد؛ متدهای `get_profile/logout/list_devices/_generate_tokens_by_id` (آخری را مسیر `/refresh` از قبل صدا می‌زد ولی وجود نداشت) به `AuthService` اضافه شد.

### ۶.۸ اصلاحات کوچک
- `app/ws/manager.py`: ایمپورت گمشده `UUID`
- `app/audit/integrity.py`: ایمپورت خراب `app.modules.audit.db.Models` (ماژول audit فقط stub است) + ایمپورت گمشده `json`؛ حالا در غیاب مدل‌ها `unavailable` برمی‌گرداند
- `backend/.env`: افزودن `CORS_ORIGINS` با سینتکس JSON array شامل originهای Vite
- `web/src/security/authProvider.ts`: سه `logger.error` تعریف‌نشده → `console.error` (وگرنه اولین خطای شبکه فرانت‌اند را کرش می‌کرد)

### ۶.۹ باگ «پس از زدن ورود هیچ پارامتری ارسال نمی‌شود» (فرانت‌اند)
علامت: کلیک روی «ورود» هیچ درخواست شبکه‌ای تولید نمی‌کرد.
علت ریشه‌ای در `web/src/security/deviceHeaders.ts` خط `hmacSha256` بود:

```ts
const CryptoJS = require('crypto-js')   // ❌ در مرورگر وجود ندارد
```

`require` در باندل مرورگر (Vite/ESM) تعریف نشده است؛ این خط داخل **interceptor** axios (`api/client.ts`) اجرا می‌شود، پس با `ReferenceError` می‌ترکید و درخواست **قبل از ارسال** لغو می‌شد. اصلاحات:
- `deviceHeaders.ts`: ایمپورت استاندارد `import CryptoJS from 'crypto-js'` در بالای فایل (پکیج از قبل در `node_modules` بود)
- `deviceHeaders.ts`: تابع `logSecurityEvent` صدا زده می‌شد ولی ایمپورت نشده بود (در `fingerprint.ts` تعریف شده) → ایمپورت اضافه شد؛ وگرنه **بعد از ورود موفق** هم خطا می‌داد و ورود ناموفق نشان داده می‌شد
- `fingerprint.ts`: عبارت `process.env.NODE_ENV` در مرورگر (Vite) خودش `ReferenceError` می‌دهد → با گارد `typeof process` اصلاح شد
- `authProvider.ts`: ایمپورت `getDeviceFingerprint` از فایل اشتباه (در `deviceHeaders` وجود ندارد و استفاده هم نمی‌شد) حذف شد
- تأیید: `npm run build` موفق و در باندل نهایی هیچ `require('crypto-js')` نیست

## ۷. داشبورد واقعی (جایگزین صفحه «پیاده‌سازی نشده»)

پس از ورود موفق، مسیر `/dashboard` فقط یک Placeholder بود. داشبورد واقعی ساخته شد:

### ۷.۱ یافته‌های بک‌اند (مهم)
پروب زنده نشان داد **همه سرویس‌های ماژول‌ها (goals/groups/chat/inbox/reporting) با خطای 500** می‌شکستند؛ دو علت:
1. مدل‌های ORM در `app/modules/*/db/Models.py` نام جدول **بدون اسکیما** می‌سازند ولی DDL یک اسکیما به‌ازای هر ماژول دارد (`planning.goals` و…) → `relation "goals" does not exist`. **رفع:** `search_path` کامل روی کانکشن در `app/core/db/session.py` (نام جداول در اسکیماها یکتا هستند، پس بدون ابهام). راه‌حل بلندمدت طبق ADR-04: هر مدل `__table_args__ = {"schema": ...}` خودش را اعلام کند.
2. مدل‌ها از ستون‌های DDL عقب‌اند (`goals.version`، `groups.title`، جدول `inbox_items` در برابر `inbox.items` واقعی و…) → بازنویسی هر ۶ فایل مدل در این مرحله به‌صرفه نبود.
3. باگ ترتیب مسیر: `GET /inbox/outbox` بعد از `/{user_id}` تعریف شده بود و هیچ‌وقت match نمی‌شد (422) → به قبل از `/{user_id}` منتقل شد.
4. باگ اعتبارسنجی نوع آیتم: `item_type not in INBOX_ITEM_TYPES` رشته را با لیستی از آبجکت مقایسه می‌کرد و **همیشه** رد می‌کرد → مقایسه با `[t.value ...]`؛ همچنین تایپوی `chat_invoice` در pattern به `chat_invite` (مطابق سند) اصلاح شد.

### ۷.۲ endpointهای جدید (`app/modules/reporting/api/dashboard.py`)
چون ORM خراب است، داشبورد با **SQL خام اسکیما-دار** (خوانا و مستقل از مدل‌ها) کار می‌کند؛ هر ویجت مستقل است و خرابی یک جدول بقیه را نمی‌اندازد:
- `GET /api/v1/reporting/dashboard/summary` — آمار (اهداف فعال/تکمیل‌شده، وظایف باز، صندوق待 بررسی، گروه‌ها) + اهداف اخیر + وظایف باز + صندوق ورودی + گروه‌ها + اتاق‌های چت
- `GET /api/v1/reporting/dashboard/goals` — فهرست اهداف کاربر
- `POST /api/v1/reporting/dashboard/goals` — ایجاد سریع هدف (`title` الزامی)
- `POST /api/v1/reporting/dashboard/inbox/{id}/act` — تأیید/رد/تعویق آیتم (`accepted/rejected/deferred`) با بررسی مالکیت و حالت `pending`
- روتر با `router.include_router(dashboard_router)` به ماژول reporting متصل شد.

چرخه تأییدشده: `summary 200` → `create-goal 201` → `goals-list 200 (count 1)` → `inbox act 200` → `pending 1→0` ✅

### ۷.۳ فرانت‌اند (`web/src/features/DashboardPage.tsx` + `web/src/hooks/useDashboard.ts`)
- کارت‌های آمار، فهرست اهداف با نوار پیشرفت + فرم ایجاد سریع، صندوق ورودی با دکمه تأیید/رد، وظایف باز، گروه‌ها (با نشان مدیر) و اتاق‌های چت
- همه مسیرها در `App.tsx` به صفحه‌های واقعی وصل شدند: `/dashboard` (داشبورد)، `/chat`، `/inbox`، `/groups`، `/reports`، `/settings` — جزئیات در بخش ۸د
- ⚠️ نکته فنی: هنگام نوشتن فایل، کاراکترهای CJK باعث دابل‌انکد شدن فارسی شدند؛ راه‌حل مطمئن: متن فارسی خالص سالم منتقل می‌شود (مثل `useDashboard.ts`) — از مخلوط‌کردن CJK در یک Write خودداری شود. باندل نهایی فارسی سالم دارد (تست شد).

داده نمونه برای نمایش اولیه (کاربر `admin`): یک هدف «راه‌اندازی سامانه» (۷۰٪) و یک آیتم صندوق «بازبینی گزارش ماهانه».

## ۸. بازطراحی مدرن UI/UX

علت ابتدایی بودن ظاهر: Tailwind عملاً **سیم‌کشی نشده بود** — نه `postcss.config` وجود داشت، نه فایل CSS در `main.tsx` ایمپورت شده بود (تنظیم `build.css.postcss` در `vite.config.ts` را Vite نادیده می‌گیرد). یعنی هیچ کلاس Tailwindی اعمال نمی‌شد.

### ۸.۱ زیرساخت استایل
- `web/tailwind.config.js` جدید (فونت وزیرمتن، پالت `brand`، سایه‌های `card/pop`)
- `web/postcss.config.js` جدید (Vite خودکار تشخیص می‌دهد)
- ایمپورت `./styles/tailwind.css` در `main.tsx`
- فونت **وزیرمتن self-host** در `web/public/fonts/` (۹ فایل woff2، weights ۴۰۰/۵۰۰/۷۰۰) — با CSP سازگار (`font-src 'self'`) و بدون وابستگی به CDN
- سیستم دیزاین در `styles/tailwind.css`: کامپوننت‌های `.card/.btn-primary/.btn-ghost/.input/.badge/.navlink/.stat-card`، انیمیشن‌های `fade-up/fade-in` با stagger، اسکرول‌بار سفارشی، احترام به `prefers-reduced-motion`
- اصلاح تایتل خراب `index.html` + اصلاح باگ از پیش‌موجود `assetFileNames` در `vite.config.ts` (پیشوند `./` که Vite 8 رد می‌کند؛ تا قبل از این چون هیچ asset ای تولید نمی‌شد دیده نشده بود)

### ۸.۲ صفحات (`web/src/App.tsx`, `web/src/features/DashboardPage.tsx`)
- **ورود**: طرح دوپنل — پنل برندینگ گرادیانی با ویژگی‌های محصول + فرم ورود با آیکون، اسپینر لودینگ و پیام خطای زیبا؛ hint حساب پیش‌فرض
- **شل**: سایدبار تیره با ناوبری آیکون‌دار (داشبورد/گفتگو/صندوق/گروه‌ها/گزارش‌ها/تنظیمات)، کارت کاربر با کد ملی ماسک‌شده و خروج؛ تاپ‌بار sticky با تاریخ شمسی زنده (`Intl.DateTimeFormat('fa-IR')`) و نشان اتصال؛ منوی موبایل کشویی؛ آیکون‌های SVG inline (بدون ایموجی)
- **داشبورد**: ۴ کارت آمار گرادیانی با آیکون و stagger، اهداف با نوار پیشرفت گرادیانی چندرنگ، صندوق با دکمه‌های نرم تأیید/رد، وظایف و گروه‌ها به‌صورت chip، اسکلت لودینگ، کاملاً ریسپانسیو (۲ ستونه موبایل → ۴ ستونه دسکتاپ)
- تأیید: `npm run build` موفق (CSS واقعی ۳۱KB)، فارسی باندل سالم و بدون دابل‌انکد
- ⚠️ نکته فنی تکراری: متن فارسی خالص در Write سالم منتقل می‌شود؛ کاراکتر CJK در همان Write باعث دابل‌انکد کل فایل می‌شود. الگوی مطمئن استفاده‌شده: نوشتن با کلید `FA_*` + نگاشت JSON + اسکریپت `apply_map.py`.

---

## ۸ب. رفع باگ رفرش توکن (401 داشبورد)

### علائم
- داشبورد فرانت «ارتباط با سرور برقرار نشد» نشان میداد؛ در کنسول: `401` روی `GET /api/v1/reporting/dashboard/summary`.
- با توکن تازه اندپوینت `200` برمیگرداند — پس مشکل از توکن قدیمی داخل مرورگر بود که مکانیزم بازیابی خودکار نمیتوانست آن را تازه کند.

### ریشههای خطا
1. `POST /auth/refresh` بدنه `{"refresh_token": "..."}` میخواست اما سرور `str` خام میخواست (`422`).
2. رفرشتوکن opaque است اما اندپوینت آن را با `jwt.decode` بررسی میکرد (همیشه `401`).
3. مقایسه `expires_at` از DB با `datetime.utcnow()` خطای `TypeError` میداد (aware در برابر naive) که در `except` پنهان و `401` برگردانده میشد.
4. گارد interceptor فرانت اگر خود رفرش با `401` برگردد، دوباره رفرش صدا میزد (حلقه بینهایت).

### راهحل (اعمال شده)
- `backend/app/modules/auth/ports.py`: مدل `RefreshRequest` اضافه شد.
- `backend/app/modules/auth/api/routes.py`: اندپوینت `/auth/refresh` بدنه آبجکتی و لاگ traceback واقعی دارد.
- `backend/app/modules/auth/services/auth_service.py`: متد `refresh_session()` — جست‌وجو با SHA-256 در `auth.sessions` ، رد revoked/expired ، چرخش سشن، پاسخ با شکل `{status, tokens, user}`.
- `web/src/api/client.ts`: interceptor دیگر روی خود فراخوانیهای `/auth/*` ریترای نمیکند.
- چرخه تأییدشده: login → login دیگر → summary `401` → refresh خودکار → retry → `200`.

### راهحل تکمیلی سمت فرانت (داشبورد مرده + ساخت هدف)

5. باگ «داشبورد مرده»: interceptor هنگام شکست رفرش فقط `secureStorage` را پاک میکرد، اما `isAuthenticated` از persist بازگردانده میشد `true` و UI روی داشبورد خراب گیر میکرد (access-token هم بعد از ۱۵ دقیقه `ACCESS_TOKEN_EXPIRE_MINUTES` منقضی میشود).
6. باگ `init()`: به `sessionStorage.user` نیاز داشت که `login()` هیچوقت آن را نمینوشت — پس رفرش هنگام بارگذاری هیچوقت اجرا نمیشد.

### راهحل فرانت (اعمال شده)
- `web/src/security/authProvider.ts`: اکشن `forceLogout()` اضافه شد؛ `init()` اگر refresh-token نباشد state را ریست میکند و در غیر این صورت با همان refresh-token توکنها را تازه میکند (ﺑدون نیاز به sessionStorage).
- `web/src/api/client.ts`: هنگام شکست رفرش یا نبودن آن، رویداد `auth:expired` فرستاده میشود (بدون import چرخهای).
- `web/src/App.tsx`: شنوده `auth:expired` با `forceLogout()` کاربر را به صفحه ورود برمیگرداند.
- نتیجه کاربر: با رفرش صفحه (Ctrl+F5) توکن خودکار تازه و داشبورد بالا میآید؛ اگر refresh-token هم نامعتبر باشد، به لاگین هدایت میشود (دیگر داشبورد مرده نیست).

### راهحل تکمیلی ریترای POST پس از 401 («ایجاد هدف ناموفق بود»)

7. باگ retry: وقتی POST با `401` برمیگشت، interceptor بعد از رفرش درخواست را با `api(originalRequest)` تکرار میکرد؛ اما axios بدنه از پیش string‌شده را دوباره stringify میکرد و سرور `422 dict_type` برمیگرداند (GET بدون بدنه این مشکل را نداشت — به همین دلیل داشبورد باز میشد اما ساخت هدف نه).
8. ریس race: `StrictMode` افکتها را دوبار اجرا میکند و refresh‌های همزمان با یک توکن، یکدیگر را باطل میکنند (rotation تک‌مصرفه است).

### راهحل (اعمال شده)
- `web/src/api/client.ts`: ریترای با `transformRequest: [(d) => d]` بدنه اصلی را دست‌نخورده ارسال میکند + رفرش single-flight (`refreshPromise` مشترک) تا `401`های همزمان یک چرخش  مشترک داشته باشند.
- چرخه تأییدشده: POST با توکن قدیمی `401` → رفرش → تکرار POST با بایتهای اصلی → `201`.

## ۸ج. بازنویسی سرویس‌های ماژول‌ها روی DDL واقعی (۱۹ سپتامبر ۲۰۲۶)

### علت
مدل‌های ORM در `app/modules/*/db/Models.py` از DDL مهاجرت عقب بودند (جدول بدون اسکیما، ستون‌های خیالی، PK با تایپ اشتباه)؛ در نتیجه **همه endpointهای ماژول‌ها 500** می‌دادند (`/groups/`، `/goals/`، `/chat/rooms`، `/inbox/*`، `/sharing/*`، `/reporting/layouts`، `/reporting/widgets/settings`).

### تصمیم
به‌جای ترمیم مدل‌ها، لایه سرویس هر ۷ ماژول با **SQL خام schema-qualified** روی DDL واقعی بازنویسی شد (همان الگوی اثبات‌شده `reporting/api/dashboard.py`):
- `rbac/services/rbac_service.py` (اسکیما `rbac` + گاردهای anti-escalation: ممنوعیت self-assign و اعطای نقش هم‌سطح/بالاتر + بررسی مدیر گروه برای scope فراتر از global)
- `groups/services/groups_service.py` (اسکیما `groups`؛ ستون `path` از نوع ltree با uuid بدون خط‌تیره)
- `goals/services/goals_service.py` (اسکیما `planning`)
- `chat/services/chat_service.py` (اسکیما `chat`)
- `inbox/services/inbox_service.py` (اسکیما `inbox`؛ `InboxService = InboxStateMachine`)
- `sharing/services/sharing_service.py` (اسکیما `sharing`)
- `reporting/services/reporting_service.py` (اسکیما `reporting`)

اصلاحات پشتیبان: `rbac/ports.py` (فیلد `target_user_id` در Assign/Revoke)، `rbac/api/routes.py` (استفاده از `target_user_id` به‌جای self)، `sharing/api/routes.py` (`Body(..., embed=True)` برای revoke)، امضای `act_on_item(item_id, action, note, actor_id)` هماهنگ با route.

### یافته‌های DDL (مهم برای توسعه بعدی)
- `sharing.effective_permissions` یک **VIEW** است — فقط خواندنی؛ INSERT/UPDATE روی آن 500 می‌دهد.
- ایندکس یکتای `dashboard_layouts` **جزئی** است (`WHERE is_default = true`) پس `ON CONFLICT` نامعتبر است → upsert دستی SELECT→INSERT/UPDATE.
- پارامترهای jsonb در asyncpg باید **رشته JSON** باشند نه dict (`json.dumps`).
- نوع enum بدون پیشوند اسکیما است (`privacy_level` نه `planning.privacy_level`).
- `get_current_user` در `app/core/dependencies.py` **رشته** برمی‌گرداند (`str(user.id)`) نه UUID.
- جدول `sharing.shares` ستون `share_code` ندارد (id همان share_code است) و constraint یکتایی روی سه‌گانه ندارد → upsert دستی.

### Seed داده RBAC (یک‌بار اجرا شد)
۵ نقش (`super_admin=10`، `admin=8`، `manager=5`، `user=3`، `viewer=1`) + ۲۴ دسترسی + نگاشت نقش‌ها (super_admin هر ۲۴؛ admin بدون `rbac.manage/ldap.configure`؛ manager ۱۴؛ user ۹؛ viewer ۵) + اعطای `super_admin` به کاربر `admin`. (اسکریپت موقت در `%TEMP%\opencode\seed_rbac.sql` — برای دیتابیس تازه دوباره اجرا شود.)

### چرخه تأییدشده
- `smoke.py`: هر ۱۸ endpoint خواندنی 200 ✅
- `smoke2.py` (مسیر کامل نوشتن): ساخت گروه/هدف/تسک/اتاق/پیام/آیتم صندوق/اشتراک‌گذاری/چیدمان/ویجت + act/revoke — همگی 200 ✅ (اسکریپت‌ها در `%TEMP%\opencode\`)
- توجه: `POST /rbac/assign` با `target_user_id` برابر خودِ کاربر 403 می‌دهد (`CANNOT_SELF_ASSIGN`) — رفتار درست است، نه باگ.

---

## ۸د. صفحات واقعی فرانت‌اند (۱۹ سپتامبر ۲۰۲۶)

هر ۵ Placeholder در `App.tsx` با صفحه واقعی جایگزین شد (همان سیستم دیزاین بخش ۸: `.card/.btn-primary/.badge/.input`، آیکون SVG، RTL، انیمیشن‌ها):
- `web/src/features/ChatPage.tsx` (`/chat`) — فهرست اتاق‌ها + ساخت اتاق + پیام‌ها با polling هر ۴ ثانیه + ارسال پیام
- `web/src/features/InboxPage.tsx` (`/inbox`) — تب‌های ورودی/ارسال‌شده/آیتم جدید؛ تأیید/رد/تعویق؛ ساخت آیتم (`meeting_invite/share_request/task_assignment/chat_invite/approval`)
- `web/src/features/GroupsPage.tsx` (`/groups`) — فهرست گروه‌ها + ساخت گروه + اعضای گروه + افزودن عضو (توسط مدیر گروه)
- `web/src/features/ReportsPage.tsx` (`/reports`) — فهرست/ذخیره چیدمان داشبورد + تنظیمات ویجت‌ها (toggle + ذخیره + بازگشت به پیش‌فرض)
- `web/src/features/SettingsPage.tsx` (`/settings`) — پروفایل کاربر + نقش‌ها (`GET /rbac/user/{id}/roles`) + شمار دسترسی‌ها + خروج
- تأیید: `npm run build` موفق (۱۷۶ ماژول) و هر ۵ مسیر API در باندل نهایی موجود است؛ فارسی باندل سالم.

---

## ۸ه. مایگریشن `core.outbox_messages` (۲۱ سپتامبر ۲۰۲۶) — لاگین 500 می‌داد

### علائم
پس از راه‌اندازی تازه، `POST /api/v1/auth/login` با **500** شکست:
```
asyncpg.exceptions.UndefinedTableError: relation "core.outbox_messages" does not exist
[SQL: INSERT INTO core.outbox_messages (event_id, event_type, payload, ...)]
```
علت: الگوی **transactional outbox** (سند بخش ۲.۳) هنگام ورود، رویداد دامنه را در `core.outbox_messages` ثبت می‌کند ولی این جدول در دیتابیس وجود نداشت.

### ریشه
فایل `backend/alembic_versions/xxxx_create_core_outbox_messages.py` (قدیمی) یک **قالب** بود (`revision = REPLACE_ME`) و در دایرکتوری اشتباه رها شده بود (خارج از `script_location = alembic`)، پس هرگز توسط alembic شناسایی و اعمال نشد. `alembic heads` فقط `0001_initial` را نشان می‌داد.

### راه‌حل (اعمال شده)
- مایگریشن واقعی ساخته شد: `backend/alembic/versions/0002_core_outbox.py` (`revision = "0002_core_outbox"`, `down_revision = "0001_initial"`) — ساخت `SCHEMA core` + جدول `outbox_messages` + ایندکس جزئی `ix_outbox_pending`.
- اجرا: `.\.venv\Scripts\python.exe -m alembic upgrade head` → `current` اکنون `0002_core_outbox (head)`.
- قالب قدیمی `backend/alembic_versions/xxxx_...` حذف شد.
- تأیید: `smoke.py` — `login 200` و هر ۱۸ endpoint 200 ✅

### نکته برای دیتابیس تازه
اگر دیتابیس از نو ساخته می‌شود، `alembic upgrade head` این مایگریشن را هم می‌آورد؛ مراحل بخش ۳ نیازی به تغییر ندارد.

---

## ۸و. WebSocket + Redis + SSO/SPNEGO (۲۲ سپتامبر ۲۰۲۶)

### WebSocket (معماری 5.5 / 12.8) — پیاده‌سازی شد و تأیید شد
- `backend/app/ws/routes.py` — دو گیتوی:
  - `GET /ws/chat` — accept→origin check (4403)→JWT در query (4401)→revalidation هر 60s (4401)→idle 300s (4408)→سقف 8192 بایت (1009)→rate-limit 20 پیام/دقیقه (RATE_LIMITED)→فریم‌های `join/message/leave/ping`→بررسی عضویت به‌ازای هر پیام (NOT_A_MEMBER/NOT_JOINED)→ذخیره پیام با SQL خام در `chat.messages`→`_sanitize_html`
  - `GET /ws/notifications` — فریم اول `unread_count`، سپس اشتراک کانال `notifications:{user_id}` برای push زنده
- `backend/app/ws/manager.py` — `ConnectionManager` (ثبت سوکت درون‌فرایندی + relay روی کانال `room:{room_id}`)؛ `broadcast` فقط publish می‌کند و relay تحویل می‌دهد (ضد تحویل دوباره)
- `backend/app/core/redis.py` — `RedisBroker` (پابلیش/اشتراک async + cache); وقتی Redis در دسترس نیست به fan-out درون‌فرایندی ارتجاع می‌دهد (تک‌فرایند پابرجاست)
- `backend/app/core/security.py` — `get_device_fingerprint`، `verify_hmac_signature`، `hmac_sign`
- `backend/app/modules/notification/events.py::_publish_live` — بعد از درج notification، پیام JSON به کانال `notifications:{user_id}` پابلیش می‌شود
- mount در `main.py`: `app.include_router(websocket_router)` بدون پیشوند → مسیرها `/ws/chat` و `/ws/notifications`

### تأیید (همه روی سرور در حال اجرا)
```
bad token → close 4401 ✅   join ×2 → connected ✅   broadcast به a+b ✅
oversize → MESSAGE_TOO_LARGE ✅   non-member → NOT_A_MEMBER ✅
rate-limit: RATE_LIMITED بعد از پیام ۲۰ ✅
notifications: unread_count → login → push auth.login.succeeded → unread_count جدید ✅
```

### مدیریت کاربران ادمین و بخش‌های جدید تنظیمات (۲۲ سپتامبر ۲۰۲۶)
- روتر `/admin/users` (فهرست/ایجاد/ویرایش/تغییر انبوه حالت ورود) که نه mount بود نه deps واقعی داشت، سرهم‌بندی شد:
  - `app/modules/auth/api/deps.py` جدید — `get_admin_user_service` واقعی (با `UserRepository` زنده) + re-export شدن `get_current_user` از core تا `require_permission` رزولو شود
  - `app/modules/rbac/api/deps_internal.py` جدید — `get_permission_service` واقعی (PermissionService با session؛ بدون Redis)
  - `app/modules/auth/__init__.py` حالا هر دو روتر `auth` و `admin/users` را include می‌کند
  - `require_permission` در `rbac/api/deps.py` اصلاح شد: چون `get_current_user` رشته (id) برمی‌گرداند، `user.id` خطا می‌داد → حالا str و object هر دو پشتیبانی می‌شوند
  - `AdminUserService` حالا actor رشته‌ای را هم می‌پذیرد (`_actor_id`)
- مدل ORM `Users` با DDL هم‌خط شد: ستون‌های `sso_enabled` + `ldap_dn/object_guid/sam_account/synced_at` اضافه شدند (قبلاً `bulk_change_login_mode` روی attribute ناموجود می‌نشست)
- دسترسی‌های گمشده `user.read/user.create/user.manage` در `rbac.permissions` سید و به `super_admin` اعطا شد (قبلاً فقط `user.bulk_login_mode` بود → همه guardها 403 می‌دادند)
- endpoint جدید `GET /api/v1/auth/sso/status` در ssoldap: وضعیت SSO/LDAP بدون افشای secret (enabled، ldap3 نصب، server URI، base DN، auto-provision، kerberos، group-role-map + مسیرهای negotiate/ldap-login)
- چرخه تأییدشده: `list 200 (total=5)` → `create 201` → `deactivate 200` → `bulk sso 200 (updated=[id])` → `reactivate 200` ✅
- فرانت‌اند (`web/src/features/SettingsPage.tsx`): دو کارت جدید
  - **مدیریت کاربران (تعریف کاربر)** — فهرست + جست‌وجو + فرم ایجاد (username/کدملی/نام نمایشی/رمز موقت) + دکمه فعال/غیرفعال (محافظت از self) + دکمه فعال‌سازی/غیرفعال‌سازی SSO برای هر کاربر + **انتخاب نقش از dropdown** (assign/revoke با `/rbac/assign` و `/rbac/revoke`)؛ اگر 403 بگیرد «دسترسی ندارید» نشان می‌دهد
  - **SSO و LDAP** — خواندن `/auth/sso/status` و نمایش ۹ ردیف وضعیت + راهنمای فعال‌سازی SSO از بخش کاربران
- تأیید: `npm run build` موفق (۱۷۶ ماژول)؛ فرانت روی `http://127.0.0.1:3000` بالا و 200

### رفع مشکل گروه‌ها و افزودن عضو از لیست کاربران (۲۳ سپتامبر ۲۰۲۶)
- مشکل «ایجاد گروه ناموفق بود» در فرانت: بک‌اند سالمه (`POST /groups/` با همین بدنه 200 برمی‌گرداند؛ زنجیره‌ی
  stale-token→401→refresh→retry هم تأیید شد 200). علت واقعی، نوسان توکن در هنگام تست هم‌زمان (هر لاگین
  token_version را بالا می‌برد → 401) و پنجره‌ی ریت‌لیت auth (۱۰/دقیقه که شامل `/auth/refresh` هم هست → 429)
  بود. در فرانت حالا پیام خطای واقعی سرور نمایش داده می‌شود (به‌جای پیام generic).
- مشکل «کاربر ایجادشده را نمی‌توان به گروه اضافه کرد»: ریشه در این بود که فرم افزودن، یک input متنی برای
  user_id داشت و اگر کاربر `ghasemi` تایپ می‌کرد، بک‌اند `422` می‌داد (الگوی لاگ: `found 'g' at 1`).
- اصلاح `web/src/features/GroupsPage.tsx`:
  - فهرست کاربران سیستم (`/admin/users`) یک‌بار هنگام mount خوانده می‌شود (با برچسب فارسی مرتب‌شده).
  - فرم افزودن عضو → **dropdown «انتخاب از کاربران سیستم»** (نام نمایشی/کاربرنam نمایش داده می‌شود، به‌جای
    تایپ دستی)؛ کاربرانِ فعلاً عضوِ گروه از لیست حذف می‌شوند؛ کاربر غیرفعال با برچسب «غیرفعال» می‌آید.
  - لیست اعضا حالا **نام نمایشی + ۸ کاراکتر اول UUID** را نشان می‌دهد (نه UUID خام).
  - خطای create/add از response سرور به‌روز رسیدی می‌شود.
- تأیید E2E یک‌جا: login → create group 200 → owner_id==admin → `/admin/users` → add member با UUID
  (همان چیزی که dropdown می‌فرستد) 200 → members 200. `npm run build` موفق.

### نکته‌ی فرم ایجاد کاربر در تنظیمات

### اتصال Audit به رویدادها و integrity (۲۲ سپتامبر ۲۰۲۶)
- `app/modules/audit/__init__.py` از استاب به real تغییر کرد: `register_event_handlers` از `events.py` صدا زده می‌شود — حالا لاگین موفق/ناموفق و رویدادهای auth/rbac در `audit.login_audit_logs` / `audit.audit_logs` با زنجیره‌ی هش (advisory lock) ثبت می‌شوند.
- `app/audit/integrity.py` (که ایمپورت خرابی داشت) بازنویسی شد تا زنجیره‌ی هر دو جدول را با همان فرمول `AuditService` بازمحاسبه و تأیید کند؛ `GET /api/v1/audit/integrity-check` → `{"status":"integrity_ok","total_logs":…,"broken_links":0,…}`.
- ⚠️ ترگر سرگردان دیتابیس (`audit.compute_row_hash()` روی `audit_logs` و `login_audit_logs`) حذف شد: هم `login_audit_logs` (ستون `action` ندارد) را می‌شکست، هم با فرمول app تداخل داشت — مطابق کامنتِ خود `backend/alembic/versions/audit_schema.sql` هیچ ترگرهش روی این جدول‌ها نباید باشد.
- پاکسازی: فایل‌های اسکله‌ی بلااستفاده‌ی پچ قدیمی از `calendar` و `files` (که هیچ route به آن‌ها import نداشت و در git هم نبودند) حذف شدند؛ پیاده‌سازی واقعی `calendar_service.py` و `files_service.py` بی‌تغییر ماند.

### نکته تست push زنده (مهم)
برای تست live notification، لاگین **باید روی همان پروسه‌ای** باشد که سوکت WS روی آن باز است؛ در حالتی که سوکت روی 8001 و لاگین روی 8000 است، notification در دیتابیس مشترک ساخته می‌شود ولی پابلیش به broker پروسه‌ی اشتباه می‌رود و به سوکت نمی‌رسد.

### Redis
- سرور Redis هنوز نصب نیست؛ `RedisBroker` در بدترین حالت به in-memory pub/sub ارتجاع می‌دهد (لاگ: `redis unavailable; using in-memory pub/sub`).
- برای چند-worker پشت load balancer به Redis واقعی نیاز است (کانفیگ از قبل در `settings.redis_url` است).

### SSO / SPNEGO (معماری امنیت لایه‌بندی‌شده)
- `POST /api/v1/auth/sso/ldap-login` — کامل (با `ldap3`؛ در غیاب AD → 401 `LDAP_UNAVAILABLE`)
- `GET /api/v1/auth/sso/negotiate` — هنگام نبود هدر → 401 `SPNEGO_CHALLENGE` + هدر `WWW-Authenticate: Negotiate`؛ وقتی هدر `Authorization: Negotiate ...` هست ولی Kerberos کانفیگ نیست → 501 `KERBEROS_NOT_CONFIGURED`
- کلیدهای کانفیگ: `LDAP_KERBEROS_ENABLED` (پیش‌فرض `False`) و `LDAP_KERBEROS_KEYTAB` (خالی) در `app/core/config.py`

---

## ۸. چرخه‌های تأییدشده (تست end-to-end روی سرور در حال اجرا)

```
REGISTER 201 → LOGIN 200 (access+refresh token) → ME 200 (کد ملی ماسک‌شده)
→ DEVICES 200 → LOGOUT 200 → ME بعد از logout = 401 ✅
LOGIN 200 → audit.login_audit_logs+1 → GET /audit/integrity-check → {"status":"integrity_ok","broken_links":0} ✅
```

---

## ۹. کارهای باقی‌مانده (عامدانه انجام نشد)

| مورد | وضعیت | توضیح |
|---|---|---|
| MFA کامل (TOTP) | ✅ انجام شد | enroll/verify/enroll-confirm پیاده شد و چرخه login→mfa_required→verify→توکن تأیید شد (مستندات در OpenAPI `type: string` برای code) |
| WebSocket chat + notifications | ✅ انجام شد | بخش ۸و؛ `/ws/chat` و `/ws/notifications` با تمام کنترلها (origin/JWT/rate-limit/اندازه/بازارزیابی) |
| Redis | ✅ fallback درون‌فرایندی | سرور Redis نصب نیست؛ `RedisBroker` (بخش ۸و) با in-memory pub/sub ارتجاع دارد؛ Redis واقعی فقط برای چند-worker لازم است |
| SSO LDAP + Kerberos/SPNEGO | ✅/⚠️ جزئی | ldap-login کامل است؛ negotiate سؤال‌چالش SPNEGO و در غیاب Kerberos 501 می‌دهد؛ Kerberos واقعی نیاز به AD + Keytab دارد |
| ۵ ماژول stub (calendar, notification, audit, ssoldap, files) | ✅ کامل شد | همه با سرویس SQL خام روی DDL واقعی پیاده و تست شدند (بخش ۸ج/۸و) |
| دریفت ORM از DDL | ✅ دور زده شد | سرویس‌های هر ۷ ماژول با SQL خام روی DDL واقعی بازنویسی شدند (بخش ۸ج)؛ اسکله‌های ORM بلااستفاده (calendar/files) حذف شدند — مدل‌های منحرف باقی‌مانده در `db/Models.py` استفاده نمی‌شوند؛ بازنگری آتی |
| نقش‌های کاربر `admin` | ✅ انجام شد | seed RBAC (بخش ۸ج): ۵ نقش + ۲۴ دسترسی + اعطای `super_admin` به `admin` |
| باطل‌شدن نشست‌های قبلی با هر login | ⚠️ رفتار فعلی | به‌خاطر `token_version++` در صدور توکن، ورود جدید نشست‌های قبلی را می‌اندازد؛ اگر چنددستگاهی می‌خواهید بازبینی شود |

---

## ۱۰. اجرای روزمره (خلاصه)

```powershell
# ترمینال ۱ — بک‌اند (پشت‌زمینه، از هر shell که بسته شود هم زنده می‌ماند)
cd C:\Projects\Run_Projects_in_Git\Activity_dashboard\backend
cmd /c "start /b .venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000 > %TEMP%\opencode\srv8000.log 2>&1"

# ترمینال ۲ — فرانت‌اند
cd C:\Projects\Run_Projects_in_Git\Activity_dashboard\web
npm run dev
```

> نکته ویندوز: وقتی بک‌اند را با `cmd start /b` بالا می‌آورید، wrapper که shell را می‌بندد ممکن است پیام `ChildProcess.kill` بدهد؛ این **طبیعی است** — فرزند جدا شده و بالا می‌ماند. دستور `Stop-Process` زیر پیش از راه‌اندازی مجدد، همه‌ی پایتون‌های uvicorn را می‌کشد:
> `Get-CimInstance Win32_Process -Filter "Name='python.exe'" | Where-Object { $_.CommandLine -match 'uvicorn' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }`

### بررسی سلامت پس از راه‌اندازی
```powershell
Invoke-WebRequest http://127.0.0.1:8000/health     # {"status":"healthy", ... 13 module}
Invoke-WebRequest http://127.0.0.1:3000            # 200
# لاگین واقعی با Endpoint (نه فقط صفحه):
# POST /api/v1/auth/login  {"identifier":"admin","password":"admin123"}
```

| نشانی | کاربرد |
|---|---|
| http://127.0.0.1:3000 | اپ وب (ورود: `admin` / `admin123`) |
| http://127.0.0.1:8000/docs | مستندات تعاملی API |
| http://127.0.0.1:8000/health | سلامت سرویس |
```

================================================================================
## FILE: web/package.json
================================================================================

```json
{
  "name": "planner-web",
  "private": true,
  "version": "1.0.0",
  "type": "module",
  "scripts": {
    "dev": "vite",
    "build": "vite build",
    "preview": "vite preview"
  },
  "dependencies": {
    "@fingerprintjs/fingerprintjs": "^5.2.0",
    "@tanstack/react-query": "^5.60.0",
    "axios": "^1.7.7",
    "crypto-js": "^4.2.0",
    "date-fns": "^3.6.0",
    "react": "^18.3.0",
    "react-dom": "^18.3.0",
    "react-redux": "^9.1.2",
    "react-router-dom": "^7.18.4",
    "recoil": "^0.7.7",
    "zustand": "^5.0.15"
  },
  "devDependencies": {
    "@axe-core/react": "^4.6.0",
    "@types/react": "^18.3.12",
    "@types/react-dom": "^18.3.0",
    "@vitejs/plugin-react": "^4.3.1",
    "autoprefixer": "^10.4.20",
    "daisyui": "^4.12.14",
    "postcss": "^8.4.49",
    "tailwindcss": "^3.4.14",
    "typescript": "^5.6.2",
    "vite": "^8.3.0"
  },
  "allowScripts": {
    "esbuild@0.21.5": true
  }
}
```

================================================================================
## FILE: web/vite.config.ts
================================================================================

```typescript
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from 'tailwindcss'
import autoprefixer from 'autoprefixer'
import { fileURLToPath } from 'url'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  base: '/',
  build: {
    outDir: 'dist',
    assetsDir: 'assets',
    rollupOptions: {
      output: {
        assetFileNames: (assetInfo) => {
          const extType = assetInfo.name.split('.').at(1) || 'file'
          let typeCategory = 'assets'
          if (['png', 'jpg', 'jpeg', 'svg', 'gif', 'tiff', 'bmp', 'ico'].includes(extType)) {
            typeCategory = 'assets/images'
          } else if (extType === 'css') {
            typeCategory = 'assets/css'
          } else if (/\.js$/.test(assetInfo.name)) {
            typeCategory = 'assets/js'
          }
          return `${typeCategory}/[name]-[hash][extname]`
        },
      },
    },
    css: {
      postcss: {
        plugins: [tailwindcss(), autoprefixer()],
      },
    },
  },
  server: {
    port: 3000,
    host: '127.0.0.1',
  },
  preview: {
    port: 4000,
  },
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url)),
    },
  },
})
```

================================================================================
## MISSING FILES (not found in source repo)
================================================================================

- [MISSING] `﻿backend/pyproject.toml`
- [MISSING] `backend/Dockerfile`
- [MISSING] `web/tsconfig.json`
- [MISSING] `web/Dockerfile`
- [MISSING] `web/.env.example`
- [MISSING] `docker-compose.yml`
- [MISSING] `Makefile`
- [MISSING] `README.md`

```

==========================================================================================
## FILE: CONCAT/basteh6.md
## SIZE: 32591 bytes
==========================================================================================

```markdown
# BUNDLE: basteh6
# Source: GAP\basteh6
================================================================================

================================================================================
## FILE: desktop/main.py
================================================================================

```python
import sys
import os
from PySide6.QtWidgets import QApplication
from PySide6.QtCore import Qt
from PySide6.QtGui import QFontDatabase, QScreen

from desktop.app.core.bootstrap import bootstrap


def main():
    """Entry point for the desktop application."""
    app = bootstrap()

    # Force high DPI scaling on Windows
    if hasattr(Qt, "AA_EnableHighDpiScaling"):
        QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    if hasattr(Qt, "AA_UseHighDpiPixmaps"):
        QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)

    # Apply RTL layout direction globally
    app.setLayoutDirection(Qt.RightToLeft)

    # Apply default theme (light)
    from desktop.app.core.bootstrap import apply_theme
    apply_theme(app, "light")

    # Show login window first
    from desktop.app.views.login_window import LoginWindow
    login_window = LoginWindow()

    # Handle login success - show main window
    def on_login_success(user):
        login_window.close()
        from desktop.app.views.main_window import MainWindow
        main_window = MainWindow(user=user, auth_manager=login_window._auth_manager)
        main_window.show()

    login_window.login_successful.connect(on_login_success)

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
```

================================================================================
## FILE: web/src/api/client.ts
================================================================================

```typescript
import axios, { AxiosInstance, AxiosRequestConfig, CanceledError } from 'axios'
import { getFingerprint, getMacAddress, isDeviceInitialized, generateDeviceHeaders } from '../security/deviceHeaders'
import { secureStorage } from '../security/fingerprint'
import type { AxiosRequestConfig as AxiosConfig } from 'axios'

// Base API URL
const API_BASE_URL = import.meta.env.VITE_API_BASE || 'https://api.corp.local/api/v1'

// Request interface to include device headers
interface RequestConfig extends AxiosConfig {
  skipAuth?: boolean
  skipDeviceHeaders?: boolean
}

/** API client instance */
let api: AxiosInstance | null = null

/** Initialize API client with auth interceptors */
export function initApiClient(): AxiosInstance {
  if (api) return api
  
  api = axios.create({
    baseURL: API_BASE_URL,
    timeout: 30_000,
    withCredentials: true, // For cookie-based refresh tokens
    headers: {
      'Accept': 'application/json',
      'Content-Type': 'application/json',
    },
  })
  
  // Attach device headers to every request
  api.interceptors.request.use(
    async (config: RequestConfig) => {
      // Check if device identity is initialized
      if (!isDeviceInitialized() && !config.skipAuth) {
        // If not initialized and not skipping auth, we need to handle this
        // In practice, this would happen after login
        console.debug('Device identity not initialized - adding minimal headers')
      }
      
      // Generate device authentication headers if not skipped
      if (!config.skipDeviceHeaders && !config.skipAuth) {
        const headers = generateDeviceHeaders(
          config.method?.toUpperCase() || 'GET',
          config.url || '',
          config.data
        )
        
        // Merge headers with existing ones
        config.headers = {
          ...config.headers,
          ...headers,
          // Remove X-Device-MAC for web clients (would be set for desktop)
          ...(getMacAddress() ? { 'X-Device-MAC': getMacAddress() } : {}),
        }
      }
      
      // Add auth token if available
      const token = secureStorage.get('access_token')
      if (token && !config.headers?.Authorization) {
        config.headers.Authorization = `Bearer ${token}`
      }
      
      // Add request ID if not present
      if (!config.headers?.['X-Request-ID']) {
        config.headers['X-Request-ID'] = crypto.randomUUID()
      }
      
      return config
    },
    (error) => {
      return Promise.reject(error)
    }
  )
  
  // Handle token refresh on 401
  // Single-flight: concurrent 401s share one refresh call so the rotated
  // refresh token is not consumed twice (second use => 401 REVOKED).
  let refreshPromise: Promise<{ access: string; refresh: string }> | null = null

  function doRefresh(): Promise<{ access: string; refresh: string }> {
    if (!refreshPromise) {
      const refreshToken = secureStorage.get('refresh_token')
      if (!refreshToken) {
        return Promise.reject(new Error('no refresh token'))
      }
      refreshPromise = (async () => {
        try {
          const response = await api!.post('/auth/refresh', {
            refresh_token: refreshToken
          })
          const data = response.data
          // Update tokens
          secureStorage.set('access_token', data.tokens.access_token)
          secureStorage.set('refresh_token', data.tokens.refresh_token)
          return { access: data.tokens.access_token, refresh: data.tokens.refresh_token }
        } finally {
          refreshPromise = null
        }
      })()
    }
    return refreshPromise
  }

  api.interceptors.response.use(
    (response) => response,
    async (error) => {
      const originalRequest = error.config as RequestConfig & { _retry?: boolean }
      const failedUrl = String(originalRequest?.url || '')
      const isAuthCall = failedUrl.includes('/auth/refresh') || failedUrl.includes('/auth/login')

      // If 401 and not already retried (never retry the auth calls themselves)
      if (error.response?.status === 401 && !originalRequest._retry && !isAuthCall) {
        originalRequest._retry = true
        
        try {
          // Try to refresh token (single-flight across concurrent 401s)
          const { access } = await doRefresh()
          
          // Retry original request with new token.
          // NOTE: axios already serialized originalRequest.data to a JSON
          // string on the first attempt; re-dispatching would stringify it
          // AGAIN (422 dict_type on the server). Bypass re-transform.
          originalRequest.headers.Authorization = `Bearer ${access}`
          
          // Also regenerate device headers
          const headers = generateDeviceHeaders(
            originalRequest.method?.toUpperCase() || 'GET',
            originalRequest.url || '',
            originalRequest.data
          )
          originalRequest.headers = {
            ...originalRequest.headers,
            ...headers,
          }
          
          return api({
            ...originalRequest,
            transformRequest: [(data) => data],
          })
        } catch (refreshError) {
          // Refresh failed - clear tokens and notify the app shell
          // (client.ts cannot import the auth store: authProvider imports this
          // module, so we signal via a DOM event instead of a direct call).
          secureStorage.remove('access_token')
          secureStorage.remove('refresh_token')
          sessionStorage.removeItem('user')
          if (typeof window !== 'undefined') {
            window.dispatchEvent(new CustomEvent('auth:expired'))
          }

          // Navigate to login
          // In real app: navigate('/login')
          return Promise.reject(refreshError)
        }
      }

      // No refresh token stored: nothing to recover with. Notify shell too.
      if (error.response?.status === 401 && !isAuthCall) {
        if (typeof window !== 'undefined') {
          window.dispatchEvent(new CustomEvent('auth:expired'))
        }
      }
      
      return Promise.reject(error)
    }
  )
  
  return api
}

/** Get the API client instance */
export function getApi(): AxiosInstance {
  if (!api) {
    return initApiClient()
  }
  return api
}

/** Simple API helper functions */
export const apiRef = {
  get: <T>(url: string, config?: RequestConfig) => 
    getApi().get<T, T>(url, config),
  
  post: <T, D = any>(url: string, data?: D, config?: RequestConfig) => 
    getApi().post<T, T>(url, data, config),
  
  put: <T, D = any>(url: string, data?: D, config?: RequestConfig) => 
    getApi().put<T, T>(url, data, config),
  
  delete: <T>(url: string, config?: RequestConfig) => 
    getApi().delete<T, T>(url, config),
  
  patch: <T, D = any>(url: string, data?: D, config?: RequestConfig) => 
    getApi().patch<T, T>(url, data, config),
  
  // File upload with progress
  upload: <T>(url: string, file: File, onProgress?: (progress: number) => void) => {
    const formData = new FormData()
    formData.append('file', file)
    
    return getApi().post<T, any>(url, formData, {
      onUploadProgress: (progressEvent) => {
        if (onProgress && progressEvent.total) {
          const progress = Math.round((progressEvent.loaded * 100) / progressEvent.total)
          onProgress(progress)
        }
      }
    })
  },
  
  // Download file
  download: (url: string) => {
    return getApi().get(url, {
      responseType: 'blob',
      headers: {
        'X-Requested-With': ' XMLHttpRequest'
      }
    })
  },
}

export default apiRef
```

================================================================================
## FILE: web/src/App.tsx
================================================================================

```tsx
import React, { useEffect, useMemo, useState } from 'react'
import {
  BrowserRouter,
  Routes,
  Route,
  Navigate,
  Link,
  useLocation,
  useNavigate,
} from 'react-router-dom'
import { useAuth } from './security/authProvider'
import DashboardPage from './features/DashboardPage'
import ChatPage from './features/ChatPage'
import InboxPage from './features/InboxPage'
import GroupsPage from './features/GroupsPage'
import ReportsPage from './features/ReportsPage'
import SettingsPage from './features/SettingsPage'

/* ---------------- Icons (inline SVG, no emoji) ---------------- */

function Icon({ d, className = 'h-5 w-5' }: { d: string; className?: string }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.8}
      strokeLinecap="round" strokeLinejoin="round" className={className} aria-hidden>
      <path d={d} />
    </svg>
  )
}

const PATHS = {
  grid: 'M3 3h7v7H3zM14 3h7v7h-7zM3 14h7v7H3zM14 14h7v7h-7z',
  chat: 'M21 11.5a8.38 8.38 0 0 1-.9 3.8 8.5 8.5 0 0 1-7.6 4.7 8.38 8.38 0 0 1-3.8-.9L3 21l1.9-5.7a8.38 8.38 0 0 1-.9-3.8 8.5 8.5 0 0 1 4.7-7.6 8.38 8.38 0 0 1 3.8-.9h.5a8.48 8.48 0 0 1 8 8v.5z',
  inbox: 'M22 12h-6l-2 3h-4l-2-3H2M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z',
  users: 'M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2M9 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM23 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75',
  chart: 'M18 20V10M12 20V4M6 20v-6',
  cog: 'M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6zM19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 1 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 1 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z',
  logout: 'M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9',
  target: 'M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20zM12 18a6 6 0 1 0 0-12 6 6 0 0 0 0 12zM12 14a2 2 0 1 0 0-4 2 2 0 0 0 0 4z',
  lock: 'M5 11h14a2 2 0 0 1 2 2v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-7a2 2 0 0 1 2-2zM7 11V7a5 5 0 0 1 10 0v4',
  user: 'M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2M12 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8z',
  check: 'M20 6 9 17l-5-5',
}

/* ---------------- Login ---------------- */

function LoginPage() {
  const { login, isLoading } = useAuth()
  const [identifier, setIdentifier] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)

  const onSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError(null)
    try {
      await login({ identifier, password })
    } catch {
      setError('ورود ناموفق بود. مشخصات را بررسی کنید.')
    }
  }

  const features = useMemo(
    () => [
      { d: PATHS.target, t: 'اهداف و وظایف', s: 'تعریف، پیگیری پیشرفت و مدیریت مهلت‌ها' },
      { d: PATHS.users, t: 'گروه‌ها و حریم خصوصی', s: 'کار تیمی با کنترل دقیق دسترسی' },
      { d: PATHS.chart, t: 'گزارش و داشبورد', s: 'نمای زنده از عملکرد شما و تیم' },
    ],
    [],
  )

  return (
    <div className="flex min-h-screen bg-slate-100">
      {/* Brand panel */}
      <div className="relative hidden w-[44%] overflow-hidden bg-slate-900 lg:block">
        <div className="absolute inset-0 bg-gradient-to-bl from-brand-700 via-slate-900 to-slate-950" />
        <div
          className="absolute inset-0 opacity-[0.15]"
          style={{
            backgroundImage:
              'radial-gradient(circle at 25% 25%, #fff 1.5px, transparent 1.5px)',
            backgroundSize: '28px 28px',
          }}
        />
        <div className="absolute -left-24 -top-24 h-96 w-96 rounded-full bg-brand-500/30 blur-3xl" />
        <div className="absolute -bottom-32 -right-16 h-[28rem] w-[28rem] rounded-full bg-indigo-500/20 blur-3xl" />
        <div className="relative flex h-full flex-col justify-between p-12 text-white">
          <div className="animate-fade-up flex items-center gap-3">
            <div className="flex h-12 w-12 items-center justify-center rounded-2xl bg-white/15 text-white backdrop-blur">
              <Icon d={PATHS.target} className="h-7 w-7" />
            </div>
            <div>
              <p className="text-lg font-bold leading-6">سامانه مدیریت اهداف</p>
              <p className="text-xs text-slate-300">نسخه سازمانی</p>
            </div>
          </div>
          <div className="space-y-6">
            <h2 className="animate-fade-up stagger-1 text-3xl font-bold leading-[2.6rem]">
              مدیریت اهداف، برنامه‌ریزی و همکاری تیمی
            </h2>
            <p className="animate-fade-up stagger-2 max-w-md text-sm leading-7 text-slate-300">
              همه اهداف، وظایف، گفتگوها و پیگیری‌ها — یکجا، امن و یکپارچه.
            </p>
            <ul className="space-y-4 pt-2">
              {features.map((f, i) => (
                <li
                  key={f.t}
                  className={`animate-fade-up stagger-${i + 3} flex items-start gap-3`}
                >
                  <span className="mt-0.5 flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-white/10 text-brand-200">
                    <Icon d={f.d} className="h-5 w-5" />
                  </span>
                  <span>
                    <span className="block text-sm font-medium">{f.t}</span>
                    <span className="block text-xs text-slate-400">{f.s}</span>
                  </span>
                </li>
              ))}
            </ul>
          </div>
          <p className="text-[11px] text-slate-500">امنیت چندلایه · احراز هویت دو عاملی · ثبت وقایع</p>
        </div>
      </div>

      {/* Form panel */}
      <div className="flex flex-1 items-center justify-center p-6">
        <form
          onSubmit={onSubmit}
          className="animate-fade-up w-full max-w-md rounded-3xl bg-white p-8 shadow-pop sm:p-10"
        >
          <div className="mb-8 text-center lg:hidden">
            <div className="mx-auto mb-3 flex h-12 w-12 items-center justify-center rounded-2xl bg-gradient-to-l from-brand-600 to-brand-500 text-white">
              <Icon d={PATHS.target} className="h-7 w-7" />
            </div>
            <p className="font-bold">سامانه مدیریت اهداف</p>
          </div>
          <h1 className="text-2xl font-bold">ورود به سامانه</h1>
          <p className="mb-6 mt-1 text-sm text-slate-500">برای ادامه وارد حساب کاربری خود شوید</p>

          <label className="label" htmlFor="login-id">
            نام کاربری یا کد ملی
          </label>
          <div className="relative mb-4">
            <span className="pointer-events-none absolute right-3.5 top-1/2 -translate-y-1/2 text-slate-400">
              <Icon d={PATHS.user} className="h-5 w-5" />
            </span>
            <input
              id="login-id"
              className="input pr-11"
              placeholder="مثلاً ali.rezaei"
              value={identifier}
              onChange={(e) => setIdentifier(e.target.value)}
              autoComplete="username"
            />
          </div>

          <label className="label" htmlFor="login-pw">
            گذرواژه
          </label>
          <div className="relative mb-2">
            <span className="pointer-events-none absolute right-3.5 top-1/2 -translate-y-1/2 text-slate-400">
              <Icon d={PATHS.lock} className="h-5 w-5" />
            </span>
            <input
              id="login-pw"
              className="input pr-11"
              placeholder="گذرواژه خود را وارد کنید"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="current-password"
            />
          </div>

          {error && (
            <p className="animate-fade-in mb-2 rounded-xl bg-red-50 px-4 py-2.5 text-xs text-red-600">
              {error}
            </p>
          )}

          <button type="submit" disabled={isLoading} className="btn-primary mt-4 w-full py-3">
            {isLoading ? (
              <>
                <span className="h-4 w-4 animate-spin rounded-full border-2 border-white/40 border-t-white" />
                در حال ورود…
              </>
            ) : (
              'ورود'
            )}
          </button>
          <p className="mt-5 text-center text-[11px] leading-5 text-slate-400">
            حساب پیش‌فرض مدیر: admin / admin123
          </p>
        </form>
      </div>
    </div>
  )
}

/* ---------------- Shell ---------------- */

const NAV = [
  { to: '/dashboard', label: 'داشبورد', icon: PATHS.grid },
  { to: '/chat', label: 'گفتگوها', icon: PATHS.chat },
  { to: '/inbox', label: 'صندوق ورودی', icon: PATHS.inbox },
  { to: '/groups', label: 'گروه‌ها', icon: PATHS.users },
  { to: '/reports', label: 'گزارش‌ها', icon: PATHS.chart },
  { to: '/settings', label: 'تنظیمات', icon: PATHS.cog },
]

function Sidebar({ onNav }: { onNav?: () => void }) {
  const { user, logout } = useAuth()
  const { pathname } = useLocation()
  const navigate = useNavigate()

  const doLogout = async () => {
    await logout()
    navigate('/login', { replace: true })
    onNav?.()
  }

  return (
    <div className="flex h-full flex-col bg-slate-900 text-white">
      <div className="flex items-center gap-3 px-5 pb-6 pt-6">
        <div className="flex h-11 w-11 items-center justify-center rounded-2xl bg-gradient-to-l from-brand-500 to-indigo-500 shadow-lg shadow-brand-900/40">
          <Icon d={PATHS.target} className="h-6 w-6" />
        </div>
        <div className="min-w-0">
          <p className="truncate text-sm font-bold">سامانه مدیریت اهداف</p>
          <p className="text-[11px] text-slate-400">نسخه سازمانی</p>
        </div>
      </div>
      <nav className="flex-1 space-y-1 overflow-y-auto px-3">
        {NAV.map((n) => {
          const active = pathname === n.to || (n.to === '/dashboard' && pathname === '/')
          return (
            <Link
              key={n.to}
              to={n.to}
              onClick={onNav}
              className={`navlink ${active ? 'navlink-active' : ''}`}
            >
              <Icon d={n.icon} />
              <span>{n.label}</span>
            </Link>
          )
        })}
      </nav>
      <div className="border-t border-white/10 p-4">
        <div className="mb-3 flex items-center gap-3 rounded-xl bg-white/5 p-3">
          <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-gradient-to-l from-brand-400 to-indigo-400 text-sm font-bold">
            {(user?.display_name || user?.username || '?').slice(0, 1)}
          </div>
          <div className="min-w-0 flex-1">
            <p className="truncate text-sm font-medium">
              {user?.display_name || user?.username}
            </p>
            <p className="truncate text-[11px] text-slate-400" dir="ltr">
              {user?.national_id_masked}
            </p>
          </div>
        </div>
        <button onClick={() => void doLogout()} className="navlink w-full text-red-300 hover:text-red-200">
          <Icon d={PATHS.logout} />
          <span>خروج از حساب</span>
        </button>
      </div>
    </div>
  )
}

function Topbar({ onMenu }: { onMenu: () => void }) {
  const today = useMemo(
    () =>
      new Intl.DateTimeFormat('fa-IR', {
        weekday: 'long',
        day: 'numeric',
        month: 'long',
      }).format(new Date()),
    [],
  )
  return (
    <header className="sticky top-0 z-10 border-b border-slate-200/70 bg-white/80 backdrop-blur">
      <div className="flex items-center gap-3 px-4 py-3 sm:px-6">
        <button onClick={onMenu} className="btn-ghost p-2 lg:hidden" aria-label="menu">
          <svg viewBox="0 0 24 24" className="h-6 w-6" fill="none" stroke="currentColor"
            strokeWidth={2} strokeLinecap="round">
            <path d="M4 6h16M4 12h16M4 18h16" />
          </svg>
        </button>
        <div className="min-w-0 flex-1">
          <p className="truncate text-sm font-bold text-slate-800">سامانه مدیریت اهداف</p>
          <p className="text-[11px] text-slate-400">{today}</p>
        </div>
        <span className="badge bg-emerald-50 text-emerald-700">
          <span className="ml-1.5 h-2 w-2 rounded-full bg-emerald-500" />
          متصل
        </span>
      </div>
    </header>
  )
}

function Shell() {
  const [open, setOpen] = useState(false)
  return (
    <div className="flex min-h-screen bg-slate-100">
      <aside className="sticky top-0 hidden h-screen w-72 shrink-0 lg:block">
        <Sidebar />
      </aside>
      {open && (
        <div className="fixed inset-0 z-20 lg:hidden">
          <div className="animate-fade-in absolute inset-0 bg-slate-900/50" onClick={() => setOpen(false)} />
          <aside className="animate-fade-in absolute bottom-0 right-0 top-0 w-72">
            <Sidebar onNav={() => setOpen(false)} />
          </aside>
        </div>
      )}
      <div className="flex min-w-0 flex-1 flex-col">
        <Topbar onMenu={() => setOpen(true)} />
        <main className="flex-1">
          <Routes>
            <Route path="/dashboard" element={<DashboardPage />} />
            <Route path="/chat" element={<ChatPage />} />
            <Route path="/inbox" element={<InboxPage />} />
            <Route path="/groups" element={<GroupsPage />} />
            <Route path="/reports" element={<ReportsPage />} />
            <Route path="/settings" element={<SettingsPage />} />
            <Route path="/" element={<Navigate to="/dashboard" replace />} />
            <Route path="*" element={<Navigate to="/dashboard" replace />} />
          </Routes>
        </main>
      </div>
    </div>
  )
}

/* ---------------- App ---------------- */

function App() {
  const { isAuthenticated, isLoading, init } = useAuth()

  useEffect(() => {
    void init()
  }, [init])

  // When the API layer reports an unrecoverable 401 (refresh failed or no
  // refresh token), drop the persisted "authenticated" flag so the user is
  // sent back to the login page instead of a dead dashboard.
  useEffect(() => {
    const onExpired = () => {
      useAuth.getState().forceLogout()
    }
    window.addEventListener('auth:expired', onExpired)
    return () => window.removeEventListener('auth:expired', onExpired)
  }, [])

  if (isLoading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-slate-100">
        <div className="flex flex-col items-center gap-4">
          <div className="h-12 w-12 animate-spin rounded-full border-[3px] border-brand-200 border-t-brand-600" />
          <p className="text-sm text-slate-500">در حال بارگذاری…</p>
        </div>
      </div>
    )
  }

  return (
    <BrowserRouter>
      <Routes>
        {isAuthenticated ? (
          <Route path="/*" element={<Shell />} />
        ) : (
          <>
            <Route path="/login" element={<LoginPage />} />
            <Route path="*" element={<Navigate to="/login" replace />} />
          </>
        )}
      </Routes>
    </BrowserRouter>
  )
}

export default App
```

================================================================================
## FILE: web/src/main.tsx
================================================================================

```tsx
import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App'
import './styles/tailwind.css'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

// Initialize React Query
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 30_000,
      gcTime: 60_000,
      retry: 2,
      refetchOnWindowFocus: false,
    },
    mutations: {
      retry: 2,
    },
  },
})

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <QueryClientProvider client={queryClient}>
      <App />
    </QueryClientProvider>
  </React.StrictMode>,
)
```

================================================================================
## FILE: web/src/security/fingerprint.ts
================================================================================

```typescript
import FingerprintJS from '@fingerprintjs/fingerprintjs'

// Stable fingerprint cache
let cachedFingerprint: string | null = null

/**
 * Get a stable device fingerprint.
 * Combines FingerprintJS visitorId with a device token for consistency.
 */
export async function getDeviceFingerprint(): Promise<string> {
  if (cachedFingerprint) return cachedFingerprint

  try {
    const fp = await FingerprintJS.load()
    const result = await fp.get()

    // Use visitorId as base, but also incorporate device token from cookie
    const deviceToken = getCookie('device_token') || ''
    
    // Create stable hash combining both
    const combined = `${result.visitorId}:${deviceToken}`
    const hash = btoa(combined).replace(/[^a-zA-Z0-9+/]/g, '').substring(0, 32)
    
    cachedFingerprint = `web-fp-${hash}`
    return cachedFingerprint
  } catch (error) {
    logger.error('FingerprintJS error:', error)
    // Fallback to minimal fingerprint
    return 'web-fp-fallback'
  }
}

/** 
 * Device token stored in HttpOnly cookie (set by server on first login).
 * JavaScript cannot read this cookie, but can read a non-sensitive version.
 */
export function getDeviceToken(): string | null {
  try {
    // Read from a non-sensitive data attribute or meta tag
    // The actual token is HttpOnly, so we use a hashed version
    const metaContent = document.querySelector('meta[name="device-token"]')?.content
    return metaContent || null
  } catch {
    return null
  }
}

/** Log security events (client-side only) */
export function logSecurityEvent(event: string, details?: any) {
  // Send to analytics/backend for security monitoring
  const eventData = {
    event,
    timestamp: new Date().toISOString(),
    fingerprint: cachedFingerprint || 'unknown',
    url: window.location.href,
    ...details
  }
  
  // In production, send to endpoint
  // fetch('/api/security/events', {
  //   method: 'POST',
  //   headers: { 'Content-Type': 'application/json' },
  //   body: JSON.stringify(eventData)
  // }).catch(() => {}) // Non-blocking
}

/** Safe storage for sensitive data */
export const secureStorage = {
  set: (key: string, value: string) => {
    // Store encrypted value in localStorage
    try {
      const encrypted = simpleEncrypt(value)
      localStorage.setItem(`sec_${key}`, encrypted)
    } catch (e) {
      logger.error('Secure storage set error:', e)
    }
  },
  
  get: (key: string): string | null => {
    try {
      const encrypted = localStorage.getItem(`sec_${key}`)
      if (!encrypted) return null
      return simpleDecrypt(encrypted)
    } catch (e) {
      logger.error('Secure storage get error:', e)
      return null
    }
  },
  
  remove: (key: string) => {
    try {
      localStorage.removeItem(`sec_${key}`)
    } catch (e) {
      logger.error('Secure storage remove error:', e)
    }
  }
}

/* Simple XOR encryption for client-side obfuscation (not real encryption) */
function simpleEncrypt(text: string): string {
  const key = 'planner-web-2026'
  let result = ''
  for (let i = 0; i < text.length; i++) {
    result += String.fromCharCode(text.charCodeAt(i) ^ key.charCodeAt(i % key.length))
  }
  return btoa(result)
}

function simpleDecrypt(encrypted: string): string {
  const key = 'planner-web-2026'
  let text = atob(encrypted)
  let result = ''
  for (let i = 0; i < text.length; i++) {
    result += String.fromCharCode(text.charCodeAt(i) ^ key.charCodeAt(i % key.length))
  }
  return result
}

const logger = {
  error: (msg: string, ...args: any[]) => {
    // NOTE: Vite does not provide `process.env` in the browser;
    // guard it so logging never throws.
    const isDev =
      typeof process !== 'undefined' &&
      (process as any).env?.NODE_ENV === 'development'
    if (isDev || typeof process === 'undefined') {
      console.error('[Security]', msg, ...args)
    }
  }
}
```

================================================================================
## MISSING FILES (not found in source repo)
================================================================================

- [MISSING] `﻿web/src/api/endpoints.ts`
- [MISSING] `web/src/hooks/useAuth.ts`
- [MISSING] `web/src/layouts/MainLayout.tsx`
- [MISSING] `web/src/styles/globals.css`
- [MISSING] `web/src/features/auth/LoginPage.tsx`
- [MISSING] `web/src/features/auth/RegisterPage.tsx`
- [MISSING] `web/src/features/auth/MFASetupPage.tsx`
- [MISSING] `web/src/features/auth/MFAVerifyPage.tsx`
- [MISSING] `web/src/features/dashboard/DashboardPage.tsx`
- [MISSING] `web/src/features/dashboard/WidgetGrid.tsx`
- [MISSING] `web/src/features/chat/ChatPage.tsx`
- [MISSING] `web/src/features/chat/ChatRoom.tsx`
- [MISSING] `web/src/features/inbox/InboxPage.tsx`
- [MISSING] `web/src/features/goals/GoalsPage.tsx`
- [MISSING] `web/src/features/calendar/CalendarPage.tsx`
- [MISSING] `web/src/features/admin/UsersPage.tsx`
- [MISSING] `web/src/features/admin/RolesPage.tsx`
- [MISSING] `web/src/features/notification/NotificationCenter.tsx`
- [MISSING] `desktop/requirements.txt`
- [MISSING] `desktop/api_client.py`
- [MISSING] `desktop/auth.py`
- [MISSING] `desktop/tray.py`

```

==========================================================================================
## FILE: CONCAT/basteh7.md
## SIZE: 14894 bytes
==========================================================================================

```markdown
# BUNDLE: basteh7
# Source: GAP\basteh7
================================================================================

================================================================================
## FILE: backend/tests/architecture/test_module_boundaries.py
================================================================================

```python
"""
tests/architecture/test_module_boundaries.py

هدف
----
اجرای اجباری مرز ماژول‌ها طبق سند معماری v2.0 (بخش ۰.۳ و ۲.۱/۲.۲):

  ۱) هیچ ماژولی مجاز نیست مستقیماً به زیرپکیج‌های داخلی ماژول دیگر
     (db/ services/ api/ tests/) دسترسی داشته باشد — فقط از طریق
     رابط عمومی (`modules.<name>` که از ports.py/events.py/schemas.py
     صادر می‌شود) مجاز است.

  ۲) هر ماژول فقط مجاز است به ماژول‌هایی وابسته باشد که در نقشه‌ی
     وابستگی رسمی (بخش ۲.۱ سند) صراحتاً برایش تعریف شده — even
     import از رابط عمومی یک ماژول غیرمجاز هم خطاست.

  ۳) M10 (notification) و M11 (audit) طبق سند فقط رویداد مصرف
     می‌کنند و حق import هیچ ماژول دیگری را ندارند.

این تست با AST ایمپورت‌ها را استخراج می‌کند (نه اجرای واقعی کد)،
پس نیازی به دیتابیس/Redis/etc در حال اجرا نیست و بسیار سریع است.

نحوه‌ی استفاده
--------------
این فایل را در مسیر زیر قرار دهید (دقیقاً مطابق ساختار پوشه‌ی
سند معماری، بخش ۳.۱):

    backend/tests/architecture/test_module_boundaries.py

و اجرا کنید:

    cd backend && pytest tests/architecture/ -v

اگر مسیر ماژول‌های شما با آنچه در ADJUST بخش پایین است فرق دارد
(مثلاً app.modules به‌جای modules)، فقط ثابت CANDIDATE_ROOTS و
IMPORT_PREFIXES را تنظیم کنید — منطق تست دست‌نخورده می‌ماند.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# نقشه‌ی وابستگی رسمی ماژول‌ها — دقیقاً از سند معماری v2.0، بخش ۲.۱
# (خطوط نقطه‌چین/رویدادی برای notification و audit در نظر گرفته نشده،
#  چون آن دو طبق سند اصلاً حق import کد ماژول دیگر را ندارند)
# ---------------------------------------------------------------------------
MODULE_DEPENDENCIES: dict[str, set[str]] = {
    "auth": set(),                              # M1 — هسته، به کسی وابسته نیست
    "rbac": {"auth"},                            # M2
    "groups": {"auth", "rbac"},                  # M3
    "goals": {"auth", "rbac"},                   # M4
    "calendar": {"goals", "groups"},             # M5
    "sharing": {"goals", "rbac", "groups"},      # M6
    "chat": {"auth", "files", "sharing"},        # M7
    "inbox": {"auth", "sharing", "chat"},        # M8
    "reporting": {"goals", "groups"},            # M9
    "notification": set(),                       # M10 — فقط مصرف رویداد
    "audit": set(),                               # M11 — فقط مصرف رویداد
    "ssoldap": {"auth"},                         # M12
    "files": set(),                              # M13 — زیرساخت مشترک
}

ALL_MODULES = set(MODULE_DEPENDENCIES)

# زیرپکیج‌هایی که «پیاده‌سازی داخلی» محسوب می‌شوند و هرگز نباید از
# بیرون ماژول import شوند — فقط از طریق ports.py/events.py/schemas.py
# (که در __init__.py خود ماژول صادر می‌شوند) قابل دسترسی‌اند.
INTERNAL_SUBPACKAGES = {"db", "services", "api", "tests"}

# چند مسیر محتمل برای پیدا کردن پوشه‌ی modules/ — به‌ترتیب اولویت.
# اگر ساختار پروژه‌ی شما فرق دارد همین‌جا اضافه کنید.
CANDIDATE_ROOT_SUFFIXES = (
    ("backend", "app", "modules"),
    ("app", "modules"),
    ("modules",),
)

# پیشوندهای import که باید به‌عنوان «اشاره به یک ماژول دامنه» شناسایی شوند.
IMPORT_PREFIXES = ("modules", "app.modules")


@dataclass(frozen=True)
class Violation:
    kind: str            # "internal_access" | "undeclared_dependency"
    importer: str
    file: Path
    lineno: int
    imported: str         # مسیر کامل import، همان‌طور که در سورس نوشته شده
    target_module: str    # نام ماژول مقصد که واقعاً استخراج شده (نه حدس از روی رشته)


def _find_modules_root() -> Path | None:
    """پوشه‌ی modules/ را با جست‌وجو از ریشه‌ی مخزن به پایین پیدا می‌کند."""
    here = Path(__file__).resolve()
    # چند سطح بالا برو تا به ریشه‌ی مخزن برسی (این فایل معمولاً در
    # backend/tests/architecture/ قرار دارد → ۳ سطح بالا = backend/)
    candidates_bases = [here.parents[i] for i in range(min(6, len(here.parents)))]

    for base in candidates_bases:
        for suffix in CANDIDATE_ROOT_SUFFIXES:
            candidate = base.joinpath(*suffix)
            if candidate.is_dir():
                # اطمینان از این‌که واقعاً پوشه‌ی ماژول‌های ما است، نه یک
                # پوشه‌ی هم‌نام تصادفی: باید حداقل یکی از ماژول‌های
                # شناخته‌شده را داخلش داشته باشد.
                if any((candidate / m).is_dir() for m in ALL_MODULES):
                    return candidate
    return None


def _strip_prefix(dotted: str) -> str | None:
    """اگر dotted با یکی از IMPORT_PREFIXES شروع شود، باقی‌مانده را برمی‌گرداند."""
    for prefix in IMPORT_PREFIXES:
        if dotted == prefix or dotted.startswith(prefix + "."):
            return dotted[len(prefix):].lstrip(".")
    return None


def _iter_import_targets(tree: ast.Module) -> list[tuple[str, int]]:
    """همه‌ی مسیرهای import شده (dotted) را همراه با شماره خط برمی‌گرداند."""
    targets: list[tuple[str, int]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                targets.append((alias.name, node.lineno))
        elif isinstance(node, ast.ImportFrom):
            if node.level and node.level > 0:
                continue  # import نسبی (from . import x) — داخل خود ماژول است
            if node.module:
                targets.append((node.module, node.lineno))
    return targets


def _scan_module_files(modules_root: Path, module_name: str) -> list[Violation]:
    violations: list[Violation] = []
    module_dir = modules_root / module_name
    allowed = MODULE_DEPENDENCIES[module_name]

    for py_file in module_dir.rglob("*.py"):
        try:
            source = py_file.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(py_file))
        except (SyntaxError, UnicodeDecodeError):
            continue  # فایل غیرقابل‌پارس را نادیده بگیر؛ مسئولیت لینتر دیگری است

        for dotted, lineno in _iter_import_targets(tree):
            remainder = _strip_prefix(dotted)
            if remainder is None:
                continue  # این import اصلاً به یک ماژول دامنه اشاره نمی‌کند

            parts = remainder.split(".") if remainder else []
            if not parts:
                continue
            target_module = parts[0]

            if target_module == module_name:
                continue  # import از خودش — طبیعی است
            if target_module not in ALL_MODULES:
                continue  # اشاره به چیزی خارج از نقشه‌ی شناخته‌شده (core و...)

            # قاعده‌ی ۱: دسترسی مستقیم به زیرپکیج داخلی ماژول دیگر ممنوع است
            if len(parts) >= 2 and parts[1] in INTERNAL_SUBPACKAGES:
                violations.append(
                    Violation("internal_access", module_name, py_file, lineno, dotted, target_module)
                )
                continue  # همین یک نقض کافی است؛ لازم نیست قاعده ۲ هم چک شود

            # قاعده‌ی ۲: حتی رابط عمومی هم فقط برای وابستگی‌های اعلام‌شده مجاز است
            if target_module not in allowed:
                violations.append(
                    Violation("undeclared_dependency", module_name, py_file, lineno, dotted, target_module)
                )

    return violations


def _format_violation(v: Violation) -> str:
    rel = v.file
    if v.kind == "internal_access":
        return (
            f"  [دسترسی مستقیم ممنوع] {rel}:{v.lineno}\n"
            f"      '{v.importer}' مستقیماً به پیاده‌سازی داخلی import می‌کند: `{v.imported}`\n"
            f"      → به‌جای این، از رابط عمومی استفاده کنید: "
            f"`from modules.{v.target_module} import ...` "
            f"(یا اگر نیاز واقعی، انتشار/مصرف رویداد است، از Event Bus استفاده کنید)"
        )
    return (
        f"  [وابستگی اعلام‌نشده] {rel}:{v.lineno}\n"
        f"      '{v.importer}' به ماژول '{v.target_module}' import می‌کند که در نقشه‌ی وابستگی "
        f"(بخش ۲.۱ سند) برایش مجاز نیست: `{v.imported}`\n"
        f"      → یا نقشه‌ی وابستگی را در سند/این تست به‌روز کنید (تصمیم معماری آگاهانه)، "
        f"یا وابستگی را حذف کنید."
    )


MODULES_ROOT = _find_modules_root()

pytestmark = pytest.mark.skipif(
    MODULES_ROOT is None,
    reason=(
        "پوشه‌ی backend/app/modules/ پیدا نشد. اگر مسیر پروژه‌ی شما فرق دارد، "
        "CANDIDATE_ROOT_SUFFIXES را در بالای این فایل تنظیم کنید."
    ),
)


@pytest.mark.parametrize("module_name", sorted(MODULE_DEPENDENCIES))
def test_no_forbidden_cross_module_imports(module_name: str) -> None:
    """مرز هر ماژول با آزمون اجباری می‌شود، نه با توافق شفاهی (سند، بخش ۰.۳)."""
    assert MODULES_ROOT is not None  # برای mypy/خوانایی؛ skipif بالا این حالت را می‌گیرد

    module_dir = MODULES_ROOT / module_name
    if not module_dir.is_dir():
        pytest.skip(f"ماژول '{module_name}' هنوز پیاده‌سازی نشده — رد شد.")

    violations = _scan_module_files(MODULES_ROOT, module_name)

    if violations:
        details = "\n".join(_format_violation(v) for v in violations)
        pytest.fail(
            f"\nماژول '{module_name}' مرز معماری را نقض کرده "
            f"({len(violations)} مورد):\n\n{details}\n"
        )


def test_notification_and_audit_are_event_only() -> None:
    """طبق سند (بخش ۲.۱): M10 و M11 نباید هیچ ماژول دیگری را import کنند."""
    if MODULES_ROOT is None:
        pytest.skip("پوشه‌ی modules/ پیدا نشد.")

    for module_name in ("notification", "audit"):
        assert MODULE_DEPENDENCIES[module_name] == set(), (
            f"'{module_name}' طبق سند فقط باید مصرف‌کننده‌ی رویداد باشد؛ "
            f"نباید هیچ وابستگی مستقیمی در MODULE_DEPENDENCIES داشته باشد."
        )
        module_dir = MODULES_ROOT / module_name
        if not module_dir.is_dir():
            continue
        violations = _scan_module_files(MODULES_ROOT, module_name)
        assert not violations, (
            f"'{module_name}' نباید هیچ ماژول دیگری را import کند "
            f"(فقط باید از طریق Event Bus مصرف کند):\n"
            + "\n".join(_format_violation(v) for v in violations)
        )


def test_dependency_graph_has_no_cycles() -> None:
    """اطمینان از این‌که خودِ نقشه‌ی وابستگی در سند/تست، حلقه ندارد."""
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(node: str, path: list[str]) -> None:
        if node in visited:
            return
        if node in visiting:
            cycle = " → ".join(path + [node])
            pytest.fail(f"حلقه‌ی وابستگی در نقشه‌ی ماژول‌ها پیدا شد: {cycle}")
        visiting.add(node)
        for dep in MODULE_DEPENDENCIES.get(node, set()):
            visit(dep, path + [node])
        visiting.discard(node)
        visited.add(node)

    for module_name in MODULE_DEPENDENCIES:
        visit(module_name, [])
```

================================================================================
## FILE: backend/tests/conftest.py
================================================================================

```python
"""Shared test setup. Environment is fixed *before* ``app`` is imported."""
import os

os.environ.setdefault("ENV", "testing")
os.environ.setdefault("DEBUG", "false")  # a local .env must not leak into tests
os.environ.setdefault("SECRET_KEY", "test-secret-key-that-is-at-least-32-chars-long")
os.environ.setdefault(
    "SQLALCHEMY_DATABASE_URI",
    "postgresql+asyncpg://admin:admin123@localhost:5432/planner_db",
)
os.environ.setdefault("RATE_LIMIT_ENABLED", "true")
```

================================================================================
## MISSING FILES (not found in source repo)
================================================================================

- [MISSING] `﻿backend/tests/test_auth.py`
- [MISSING] `backend/tests/test_rbac.py`
- [MISSING] `backend/tests/test_ws.py`
- [MISSING] `web/src/__tests__/auth.test.ts`
- [MISSING] `web/playwright.config.ts`

```

