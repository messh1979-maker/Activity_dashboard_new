"""
app/modules/auth/api/admin_routes.py

Endpointهای «تعریف/مدیریت کاربر» در تنظیمات — طبق الگوی RBAC middleware
سند (بخش ۱۲.۴: ``require_permission``). این فایل جدید است (کنار
``routes.py`` موجودتان)، تا با روترهای فعلی auth تداخل نکند — کافی
است در ``app/modules/auth/__init__.py`` هر دو روتر را include کنید:

    from app.modules.auth.api.routes import router as auth_router
    from app.modules.auth.api.admin_routes import router as admin_users_router
    router = APIRouter()
    router.include_router(auth_router)
    router.include_router(admin_users_router)

(یا هرطور که routes.py فعلی‌تان را می‌سازید — فقط این router هم باید
مثل بقیه به app اصلی mount شود.)

⚠️ فرض: ``require_permission`` در ``app.modules.rbac.api.deps`` است
(دقیقاً مسیر بخش ۱۲.۴ سند). ``get_current_user`` و ``get_uow``/``get_user_repo``
هم باید از dependency injection موجود پروژه‌ی شما بیایند — اسم دقیق
را با محتوای واقعی ``app/core/db/session.py`` و ``app/modules/auth/api/deps.py``
(اگر دارید) تطبیق دهید.
"""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, Query

from app.modules.auth.admin_ports import (
    AdminCreateUserRequest,
    AdminUpdateUserRequest,
    AdminUserListResponse,
    BulkLoginModeRequest,
    BulkResult,
)
from app.modules.auth.services.admin_user_service import AdminUserService

try:
    from app.modules.rbac.api.deps import require_permission
except ImportError:  # pragma: no cover — تا وقتی deps.py واقعی RBAC مشخص شود
    def require_permission(*codes: str, mode: str = "all"):  # type: ignore[no-redef]
        async def _dep():
            raise NotImplementedError(
                "require_permission در app.modules.rbac.api.deps پیدا نشد — "
                "این endpointها بدون آن نباید در production فعال شوند."
            )
        return _dep

try:
    # اگر app/modules/auth/api/deps.py از قبل چیزی مشابه دارد، از همان استفاده کنید
    from app.modules.auth.api.deps import get_admin_user_service
except ImportError:  # pragma: no cover — fallback حداقلی تا وقتی deps.py واقعی وصل شود
    def get_admin_user_service():  # type: ignore[no-redef]
        """TODO: جایگزین کنید با دیپندنسی واقعی که AdminUserService را با
        session/UnitOfWork واقعی درخواست جاری می‌سازد — مثلاً:

            async def get_admin_user_service(uow: UnitOfWork = Depends(get_uow)):
                return AdminUserService(uow.users)
        """
        raise NotImplementedError(
            "get_admin_user_service هنوز به session/UnitOfWork واقعی وصل نشده — "
            "app/modules/auth/api/deps.py را تکمیل کنید."
        )

router = APIRouter(prefix="/admin/users", tags=["admin-users"])


@router.get("", response_model=AdminUserListResponse)
async def list_users(
    search: str | None = Query(default=None, max_length=100),
    is_active: bool | None = Query(default=None),
    limit: int = Query(default=50, le=200),
    offset: int = Query(default=0, ge=0),
    _user=Depends(require_permission("user.read")),
    service: AdminUserService = Depends(get_admin_user_service),
):
    items, total = await service.list_users(
        search=search, is_active=is_active, limit=limit, offset=offset
    )
    return AdminUserListResponse(items=items, total=total, limit=limit, offset=offset)


@router.post("", status_code=201)
async def create_user(
    payload: AdminCreateUserRequest,
    user=Depends(require_permission("user.create")),
    service: AdminUserService = Depends(get_admin_user_service),
):
    return await service.create_user(user, payload)


@router.patch("/{user_id}")
async def update_user(
    user_id: UUID,
    payload: AdminUpdateUserRequest,
    user=Depends(require_permission("user.manage")),
    service: AdminUserService = Depends(get_admin_user_service),
):
    return await service.update_user(user, user_id, payload)


@router.post("/bulk-login-mode", response_model=BulkResult)
async def bulk_change_login_mode(
    payload: BulkLoginModeRequest,
    user=Depends(require_permission("user.bulk_login_mode")),
    service: AdminUserService = Depends(get_admin_user_service),
):
    """طبق سند بخش ۱۲.۶ — تغییر sso_enabled برای گروهی از کاربران؛ نتیجه‌ی جزئی مجاز است."""
    result = await service.bulk_change_login_mode(user, payload)
    return result
