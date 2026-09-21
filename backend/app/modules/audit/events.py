"""
app/modules/audit/events.py  (نسخه‌ی به‌روز — جایگزین نسخه‌ی placeholder قبلی)

حالا واقعاً در audit.audit_logs / audit.login_audit_logs می‌نویسد،
نه فقط لاگ ساختاریافته. طبق سند بخش ۲.۱، همچنان **هیچ importی از
app.modules.auth یا app.modules.rbac وجود ندارد** — فقط رشته‌های
event_type مستقیم نوشته شده‌اند.
"""

from __future__ import annotations

import logging
from typing import Any

from app.modules.audit.services.audit_service import AuditService

logger = logging.getLogger("audit.events")

_LOGIN_EVENT_TYPES = ("auth.login.succeeded", "auth.login.failed")

# سایر رویدادهایی که audit باید ثبت کند (رشته، نه import، تا مرز ماژول حفظ شود)
_GENERIC_AUDIT_EVENT_TYPES = (
    "auth.user.registered",
    "auth.logout",
    "auth.password.changed",
    "auth.device.registered",
    "auth.device.trusted",
    "rbac.role.assigned",
    "rbac.role.revoked",
)

_ALL_SUBSCRIBED_EVENTS = _LOGIN_EVENT_TYPES + _GENERIC_AUDIT_EVENT_TYPES


async def _handle_login_event(event: Any, session: Any) -> None:
    audit = AuditService(session)
    payload = event.payload or {}
    await audit.log_login(
        success=(event.event_type == "auth.login.succeeded"),
        auth_method="local",  # TODO: از payload بگیرید وقتی SSO/LDAP هم رویداد لاگین منتشر کند
        user_id=event.actor_id,
        username=payload.get("identifier"),
        mfa_used=payload.get("mfa_used"),
        failure_reason=payload.get("reason"),
    )


async def _handle_generic_event(event: Any, session: Any) -> None:
    audit = AuditService(session)
    payload = event.payload or {}
    # rbac.role.assigned خودش target_user_id را در payload دارد؛ برای بقیه actor_id همان کاربر است.
    user_id = payload.get("target_user_id", event.actor_id) if event.event_type.startswith("rbac.") else event.actor_id
    await audit.log(
        action=event.event_type,
        user_id=user_id,
        result="success",
        details=payload,
    )


def register_event_handlers(bus) -> None:
    """طبق قرارداد main.py: ``m.register_event_handlers(event_bus)``."""
    for event_type in _LOGIN_EVENT_TYPES:
        bus.subscribe(event_type, _handle_login_event)
    for event_type in _GENERIC_AUDIT_EVENT_TYPES:
        bus.subscribe(event_type, _handle_generic_event)
    logger.debug("audit module subscribed to %d event types", len(_ALL_SUBSCRIBED_EVENTS))
