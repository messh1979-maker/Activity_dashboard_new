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
