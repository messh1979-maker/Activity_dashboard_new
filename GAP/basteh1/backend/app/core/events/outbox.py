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
