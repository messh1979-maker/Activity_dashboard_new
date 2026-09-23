"""
app/modules/rbac/services/permission_service.py

``effective_permissions(user_id)`` طبق بخش ۱۲.۴ سند: «نتیجه در Redis با
TTL ۶۰ ثانیه کش می‌شود». ابطال کش با رویداد ``rbac.role.assigned``
(که ``RoleAssignmentService`` در rbac_patch.zip قبلاً منتشر می‌کند)
در ``app/modules/rbac/events.py`` انجام می‌شود — نه اینجا.

⚠️ فرض: مسیر Redis client شما را نمی‌دانم، پس این کلاس یک شیء
async سازگار با ``redis.asyncio.Redis`` (متدهای get/setex/delete)
می‌گیرد. اگر wrapper اختصاصی دارید (مثل ``app.core.cache.get_redis()``)،
همان را در dependency تزریق کنید — امضای PermissionService عوض
نمی‌شود.
"""

from __future__ import annotations

import json
from typing import Any
from uuid import UUID

CACHE_TTL_SECONDS = 60
_CACHE_KEY_PREFIX = "rbac:perms:"


def cache_key(user_id: UUID) -> str:
    return f"{_CACHE_KEY_PREFIX}{user_id}"


class PermissionService:
    def __init__(self, session: Any, redis_client: Any | None = None) -> None:
        self.session = session
        self.redis = redis_client

    async def effective_permissions(self, user_id: UUID) -> set[str]:
        if self.redis is not None:
            cached = await self._get_cached(user_id)
            if cached is not None:
                return cached

        perms = await self._load_from_db(user_id)

        if self.redis is not None:
            await self._set_cached(user_id, perms)

        return perms

    async def invalidate(self, user_id: UUID) -> None:
        """توسط subscriber رویداد rbac.role.assigned/revoked صدا زده می‌شود."""
        if self.redis is None:
            return
        try:
            await self.redis.delete(cache_key(user_id))
        except Exception:  # noqa: BLE001 — خرابی کش نباید عملیات اصلی را بشکند
            import logging
            logging.getLogger("rbac.permissions").exception(
                "failed to invalidate permission cache for user_id=%s", user_id
            )

    # ── داخلی ──────────────────────────────────────────────
    async def _load_from_db(self, user_id: UUID) -> set[str]:
        from sqlalchemy import text

        # طبق schema بخش ۴.۳: user_roles → role_permissions → permissions
        # نقش‌های منقضی‌شده (expires_at گذشته) حساب نمی‌شوند.
        result = await self.session.execute(
            text(
                """
                SELECT DISTINCT p.code
                FROM rbac.user_roles ur
                JOIN rbac.role_permissions rp ON rp.role_id = ur.role_id
                JOIN rbac.permissions p ON p.id = rp.permission_id
                WHERE ur.user_id = :user_id
                  AND (ur.expires_at IS NULL OR ur.expires_at > now())
                """
            ),
            {"user_id": str(user_id)},
        )
        return {row[0] for row in result.fetchall()}

    async def _get_cached(self, user_id: UUID) -> set[str] | None:
        try:
            raw = await self.redis.get(cache_key(user_id))
        except Exception:  # noqa: BLE001 — کش در دسترس نبود؛ برو سراغ DB
            return None
        if raw is None:
            return None
        try:
            return set(json.loads(raw))
        except (TypeError, ValueError):
            return None

    async def _set_cached(self, user_id: UUID, perms: set[str]) -> None:
        try:
            await self.redis.setex(cache_key(user_id), CACHE_TTL_SECONDS, json.dumps(sorted(perms)))
        except Exception:  # noqa: BLE001 — نوشتن کش شکست خورد؛ درخواست جاری هنوز درست جواب می‌گیرد
            import logging
            logging.getLogger("rbac.permissions").exception(
                "failed to cache permissions for user_id=%s", user_id
            )
