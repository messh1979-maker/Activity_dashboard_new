"""
app/core/events/dispatcher.py

Dispatcher برای ردیف‌های Outbox که باید به مصرف‌کننده‌های **خارج از
فرآیند** تحویل داده شوند (مثل Celery workers برای Email/Push/Export —
نه Audit، که همان‌طور که در bus.py توضیح داده شد، درون‌پروسه و هم‌تراکنش
مصرف می‌شود).

طبق ساختار پوشه‌ی سند (بخش ۳.۱)، این تابع باید توسط یک تسک دوره‌ای
Celery در ``workers/tasks/outbox_dispatcher.py`` فراخوانی شود، مثلاً
هر چند ثانیه یک‌بار:

    # app/workers/tasks/outbox_dispatcher.py
    from app.workers.celery_app import celery_app
    from app.core.events.dispatcher import dispatch_pending_outbox_messages

    @celery_app.task
    def dispatch_outbox():
        import asyncio
        asyncio.run(dispatch_pending_outbox_messages())

⚠️ این پیاده‌سازی یک **نقطه‌ی شروع حداقلی** است، نه نسخه‌ی نهایی تولید:
- تحویل واقعی به مصرف‌کننده‌های خارج از فرآیند (مثلاً صف Celery جداگانه
  به‌ازای هر نوع رویداد) هنوز باید اضافه شود؛ فعلاً فقط handlerهای
  درون‌پروسه‌ی ثبت‌شده روی همان ``event_bus`` را دوباره صدا می‌زند (برای
  مواردی که هنگام publish اصلی، به هر دلیل consumer در آن لحظه در
  حافظه نبوده — سناریوی راه‌اندازی مجدد سرویس).
- قفل توزیع‌شده (مثلاً Redis lock) برای جلوگیری از پردازش هم‌زمان یک
  ردیف توسط چند Worker اضافه نشده — برای تک-Worker فعلاً کافی است.
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
    """ردیف‌های dispatched_at IS NULL را پردازش و علامت‌گذاری می‌کند.

    ``session`` یک AsyncSession جدا از تراکنش publish اصلی است (این
    تابع در Worker جدا اجرا می‌شود). عدد ردیف‌های پردازش‌شده را برمی‌گرداند.
    """
    result = await session.execute(
        select(OutboxMessage)
        .where(OutboxMessage.dispatched_at.is_(None))
        .where(OutboxMessage.attempts < MAX_ATTEMPTS)
        .order_by(OutboxMessage.created_at)
        .limit(batch_size)
        .with_for_update(skip_locked=True)  # چند Worker هم‌زمان ایمن باشند
    )
    rows = result.scalars().all()

    processed = 0
    for row in rows:
        event = DomainEvent(
            event_type=row.event_type,
            payload=row.payload,
            event_id=row.event_id,
            correlation_id=row.correlation_id,
        )
        try:
            handlers = event_bus._handlers.get(event.event_type, [])  # noqa: SLF001
            for handler in handlers:
                await handler(event, session)
            row.dispatched_at = datetime.now(timezone.utc)
            processed += 1
        except Exception as exc:  # noqa: BLE001
            row.attempts += 1
            row.last_error = str(exc)[:2000]
            logger.exception(
                "outbox dispatch failed for event_id=%s (attempt %s/%s)",
                row.event_id, row.attempts, MAX_ATTEMPTS,
            )

    await session.commit()
    return processed
