"""Auth module dependencies (composition root for admin user management).

Wires the real ``get_current_user`` from core so the RBAC ``require_permission``
guard resolves, and builds ``AdminUserService`` with the live session repo.
"""
from __future__ import annotations

from fastapi import Depends

from app.core.dependencies import get_current_user, get_user_repository
from app.modules.auth.admin_ports import AdminCreateUserRequest


async def get_admin_user_service(
    user_repo=Depends(get_user_repository),
):
    """Build AdminUserService with the real repo (auth.users ORM)."""
    from app.modules.auth.services.admin_user_service import AdminUserService

    return AdminUserService(user_repo=user_repo)


__all__ = ["get_current_user", "get_admin_user_service", "AdminCreateUserRequest"]