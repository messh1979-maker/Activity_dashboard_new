"""
app/modules/rbac/events.py  (نسخه‌ی به‌روز — جایگزین نسخه‌ی rbac_patch.zip)

علاوه بر ثابت‌های event_type قبلی، حالا rbac به رویداد خودش
(``rbac.role.assigned``) مشترک می‌شود تا کش Permission کاربر را فوراً
باطل کند — دقیقاً طبق بخش ۱۲.۴ سند: «رویداد rbac.role.assigned کش آن
کاربر را فوراً باطل می‌کند». این خودِ ماژول است که به رویداد خودش گوش
می‌دهد (self-subscription) — نقض مرز ماژول نیست، چون هیچ importی از
ماژول دیگر لازم نشد.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger("rbac.events")

RBAC_ROLE_ASSIGNED = "rbac.role.assigned"
RBAC_ROLE_REVOKED = "rbac.role.revoked"
RBAC_ACCESS_DENIED = "rbac.denied"


async def _invalidate_permission_cache(event: Any, session: Any) -> None:
    from app.modules.rbac.services.permission_service import PermissionService

    payload = event.payload or {}
    target_user_id = payload.get("target_user_id")
    if not target_user_id:
        return

    try:
        from app.modules.rbac.api.deps_internal import get_redis_client_sync  # type: ignore
        redis_client = get_redis_client_sync()
    except ImportError:
        redis_client = None
        logger.debug(
            "no redis client wiring found (app.modules.rbac.api.deps_internal) — "
            "cache invalidation skipped; the 60s TTL will still expire it naturally"
        )

    service = PermissionService(session, redis_client)
    await service.invalidate(target_user_id)


def register_event_handlers(bus) -> None:
    """طبق قرارداد main.py: ``m.register_event_handlers(event_bus)``."""
    bus.subscribe(RBAC_ROLE_ASSIGNED, _invalidate_permission_cache)
    bus.subscribe(RBAC_ROLE_REVOKED, _invalidate_permission_cache)
    logger.debug("rbac module subscribed to its own role-change events for cache invalidation")
