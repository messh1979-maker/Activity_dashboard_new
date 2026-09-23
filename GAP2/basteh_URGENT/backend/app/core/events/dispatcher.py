"""
app/core/events/dispatcher.py

Dispatcher ردیف‌های Outbox برای مصرف‌کننده‌های «بعد از commit»
(``subscribe(..., transactional=False)``) — مثل Notification/Push/Email.
handlerهای هم‌تراکنش (Audit) اینجا **اجرا نمی‌شوند** (قبلاً دوباره اجرا
می‌شدند و ردیف تکراری می‌ساختند).

طبق سند (بخش ۳.۱) باید توسط تسک دوره‌ای Celery
(``workers/tasks/outbox_dispatcher.py``) فراخوانی شود.

* ``FOR UPDATE SKIP LOCKED`` — چند Worker همزمان روی یک ردیف کار نمی‌کنند.
* هر ردیف در یک SAVEPOINT پردازش می‌شود؛ خطای یک ردیف تراکنش ردیف‌های
  دیگر را خراب نمی‌کند.
* ردیفی که مصرف‌کننده‌ی async ندارد، بلافاصله dispatched علامت می‌خورد.
* بعد از ``MAX_ATTEMPTS`` شکست، ردیف رها می‌شود (با ``last_error``) تا
  دستی بررسی شود (dead-letter).
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from sqlalchemy import select

from app.core.events.bus import DomainEvent, event_bus
from app.core.events.outbox import OutboxMessage

logger = logging.getLogger("core.events.dispatcher")

MAX_ATTEMPTS = 5


async def dispatch_pending_outbox_messages(session, batch_size: int = 100) -> int:
    """Process pending rows; returns the number successfully dispatched."""
    rows = (await session.execute(
        select(OutboxMessage)
        .where(OutboxMessage.dispatched_at.is_(None))
        .where(OutboxMessage.attempts < MAX_ATTEMPTS)
        .order_by(OutboxMessage.id)
        .limit(batch_size)
        .with_for_update(skip_locked=True)
    )).scalars().all()

    processed = 0
    for row in rows:
        event = DomainEvent(
            event_type=row.event_type, payload=row.payload,
            event_id=row.event_id, correlation_id=row.correlation_id,
            occurred_at=row.created_at,
        )
        handlers = event_bus.handlers_for(event.event_type, transactional=False)
        try:
            async with session.begin_nested():  # SAVEPOINT
                for handler in handlers:
                    await handler(event, session)
            row.dispatched_at = datetime.now(timezone.utc)
            row.last_error = None
            processed += 1
        except Exception as exc:  # noqa: BLE001
            row.attempts = (row.attempts or 0) + 1
            row.last_error = str(exc)[:2000]
            logger.exception("outbox dispatch failed for event_id=%s (attempt %s/%s)",
                             row.event_id, row.attempts, MAX_ATTEMPTS)

    await session.commit()
    return processed
