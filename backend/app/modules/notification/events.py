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