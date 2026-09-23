"""RBAC internal dependency — real ``get_permission_service``.

This file is what ``app/modules/rbac/api/deps.py`` tries to import; without
it ``require_permission`` defers to a stub that raises NotImplementedError.
PermissionService reads straight from the ``rbac`` schema (raw SQL) and
optionally caches in Redis (falls back to DB when Redis is absent).
"""
from __future__ import annotations

from fastapi import Depends

from app.core.dependencies import get_session_dep
from app.modules.rbac.services.permission_service import PermissionService


async def get_permission_service(
    session=Depends(get_session_dep),
) -> PermissionService:
    """Build PermissionService (no Redis in this deployment → DB-backed)."""
    return PermissionService(session=session, redis_client=None)


__all__ = ["get_permission_service"]