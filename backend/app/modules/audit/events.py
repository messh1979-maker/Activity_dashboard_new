"""
app/modules/audit/events.py

طبق سند معماری v2.0 بخش ۲.۱: «M10 و M11 هیچ ماژولی را import نمی‌کنند —
فقط رویداد مصرف می‌کنند». به همین دلیل اینجا **هیچ importی از
app.modules.auth وجود ندارد** — حتی برای خواندن اسم ثابت‌های
event_type. رشته‌های event_type مستقیم نوشته شده‌اند (همان مقادیری که
در app/modules/auth/events.py صادر شده‌اند: "auth.login.succeeded" و...)
تا وابستگی کد از audit به auth هرگز ایجاد نشود.

نحوه‌ی اتصال (طبق main.py، بخش ۱۲.۱ سند):

    from app.modules import audit
    audit.register_event_handlers(event_bus)

⚠️ TODO مهم: بدنه‌ی ``_write_login_audit_row`` و ``_write_audit_row``
پایین فقط یک placeholder امن (فقط لاگ ساختاریافته) است — چون من به
محتوای واقعی ``app/audit`` (پوشه‌ی غیراستاندارد بالای app/modules/) و
``app/modules/audit`` (که فعلاً فقط api/ دارد، نه db/) دسترسی ندارم.
وقتی این دو مسیر را برایم بفرستید، این دو تابع را به نوشتن واقعی در
``audit.login_audit_logs`` / ``audit.audit_logs`` (با زنجیره‌ی هش طبق
بخش ۱۲.۳ سند) وصل می‌کنم. تا آن زمان، این فایل دست‌کم تضمین می‌کند
هیچ رویدادی گم نمی‌شود — در لاگ ساختاریافته (structlog) ثبت می‌شود و
از طریق ردیف Outbox هم قابل بازیابی/Replay است.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger("audit.events")

# نام‌های رویداد — عمداً این‌جا هم به‌صورت رشته تکرار شده‌اند (نه import
# از auth) تا مرز ماژول حفظ شود. اگر رویداد جدیدی در auth یا ماژول دیگری
# اضافه شد که audit باید مصرف کند، فقط رشته‌اش را این‌جا اضافه کنید.
_AUTH_EVENTS_TO_LOG = (
    "auth.user.registered",
    "auth.login.succeeded",
    "auth.login.failed",
    "auth.logout",
    "auth.password.changed",
    "auth.device.registered",
    "auth.device.trusted",
)


async def _handle_auth_event(event: Any, session: Any) -> None:
    """Handler عمومی برای همه‌ی رویدادهای auth که audit باید ثبت کند.

    امضا با ``EventHandler`` در core/events/bus.py هماهنگ است:
    ``async def handler(event: DomainEvent, session) -> None``.
    """
    if event.event_type in ("auth.login.succeeded", "auth.login.failed"):
        await _write_login_audit_row(event, session)
    else:
        await _write_audit_row(event, session)


async def _write_login_audit_row(event: Any, session: Any) -> None:
    """باید در audit.login_audit_logs بنویسد (طبق بخش ۴.۸ سند).

    TODO: جایگزین کنید با نوشتن واقعی + زنجیره‌ی هش، وقتی مدل ORM
    واقعی (``LoginAuditLog`` یا هرچه اسمش هست) مشخص شود.
    """
    logger.info(
        "login_audit_log (placeholder — not yet persisted): "
        "event_type=%s actor_id=%s payload=%s",
        event.event_type, event.actor_id, event.payload,
    )


async def _write_audit_row(event: Any, session: Any) -> None:
    """باید در audit.audit_logs بنویسد (طبق بخش ۴.۸ و ۱۲.۳ سند، با زنجیره‌ی هش).

    TODO: جایگزین کنید با ``AuditService.log(...)`` واقعی (بخش ۱۲.۳ سند)
    وقتی مدل‌های ORM ماژول audit مشخص شوند.
    """
    logger.info(
        "audit_log (placeholder — not yet persisted): "
        "event_type=%s actor_id=%s payload=%s",
        event.event_type, event.actor_id, event.payload,
    )


def register_event_handlers(bus) -> None:
    """طبق قرارداد main.py (بخش ۱۲.۱ سند): ``m.register_event_handlers(event_bus)``."""
    for event_type in _AUTH_EVENTS_TO_LOG:
        bus.subscribe(event_type, _handle_auth_event)
    logger.debug("audit module subscribed to %d event types", len(_AUTH_EVENTS_TO_LOG))
