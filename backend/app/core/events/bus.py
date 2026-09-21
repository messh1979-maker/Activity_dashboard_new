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
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, DefaultDict
from collections import defaultdict
from uuid import UUID, uuid4

logger = logging.getLogger("core.events")

# امضای هر handler: async def handler(event: DomainEvent, session) -> None
EventHandler = Callable[["DomainEvent", Any], Awaitable[None]]


@dataclass(frozen=True)
class DomainEvent:
    """رویداد دامنه — دقیقاً مطابق سند معماری v2.0، بخش ۲.۳.

    ``event_type`` باید با کاتالوگ رویدادهای سند (بخش ۲.۴) هماهنگ باشد،
    مثل ``"auth.login.succeeded"``.
    """

    event_type: str
    payload: dict[str, Any]
    actor_id: UUID | None = None
    event_id: UUID = field(default_factory=uuid4)
    occurred_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    correlation_id: UUID | None = None


class EventBus:
    """Event Bus درون‌پروسه‌ای؛ یک نمونه‌ی Singleton (``event_bus``) در کل اپ استفاده می‌شود."""

    def __init__(self) -> None:
        self._handlers: DefaultDict[str, list[EventHandler]] = defaultdict(list)

    def subscribe(self, event_type: str, handler: EventHandler) -> None:
        """یک ماژول مصرف‌کننده، خودش را برای یک نوع رویداد ثبت می‌کند.

        هیچ‌جا از ماژول ناشر import نمی‌شود؛ فقط رشته‌ی ``event_type``
        (که در کاتالوگ رویدادهای سند مستند شده) لازم است.
        """
        self._handlers[event_type].append(handler)
        logger.debug("subscribed handler for event_type=%s", event_type)

    async def publish(self, event: DomainEvent, session: Any) -> None:
        """رویداد را هم به Outbox درج می‌کند و هم بلافاصله به مشترکین درون‌پروسه تحویل می‌دهد.

        ``session`` باید همان AsyncSession تراکنش جاری باشد تا اگر
        تراکنش اصلی Rollback شود، هیچ اثری (نه ردیف Outbox و نه نوشته‌ی
        هیچ handler‌ی که در همین session کار کرده) باقی نماند.
        """
        # وارد کردن دیرهنگام (lazy import) برای پرهیز از وابستگی حلقه‌ای
        # بین bus.py و outbox.py در زمان import ماژول.
        from app.core.events.outbox import OutboxMessage

        session.add(OutboxMessage.from_event(event))

        handlers = self._handlers.get(event.event_type, [])
        if not handlers:
            logger.debug(
                "no in-process subscriber for event_type=%s (outbox row still written)",
                event.event_type,
            )
            return

        for handler in handlers:
            try:
                await handler(event, session)
            except Exception:  # noqa: BLE001 — یک handler خراب نباید انتشار رویداد را متوقف کند
                logger.exception(
                    "event handler failed for event_type=%s (event_id=%s)",
                    event.event_type, event.event_id,
                )
                raise  # همان تراکنش است؛ اجازه بده خطا بالا برود و کل تراکنش Rollback شود


# نمونه‌ی Singleton — طبق الگوی import سند: `from app.core.events.bus import event_bus`
event_bus = EventBus()
