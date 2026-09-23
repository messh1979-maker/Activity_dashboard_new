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
