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

