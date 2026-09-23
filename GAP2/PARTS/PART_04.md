# PART 4/12 of GAP PACK

## FILE: bastehA_auth_rbac_audit/backend/app/modules/auth/services/admin_user_service.py
## SIZE: 13461 bytes
==========================================================================================

```python
"""
app/modules/auth/services/admin_user_service.py

بخش «تعریف/مدیریت کاربر» در تنظیمات ادمین — طبق سند بخش ۵.۲/۵.۳ فقط
ثبت‌نام خودِ کاربر (`/auth/register`) و اعطای نقش تعریف شده بود؛ این
سرویس آن حلقه‌ی گم‌شده (ساخت/فهرست/ویرایش/غیرفعال‌سازی کاربر توسط
ادمین) را اضافه می‌کند — به‌علاوه پیاده‌سازی واقعی «تغییر انبوه حالت
ورود» طبق نمونه‌کد بخش ۱۲.۶ سند (که تا الان فقط نمونه‌کد بود).

هم‌خانواده با AuthService و RoleAssignmentService: همان الگوی
تزریق `user_repo`، همان `pwd_context`، و همان‌طور که در auth_service.py
اصلاح شد، رویدادها از طریق ``event_bus`` منتشر می‌شوند — نه با
import مستقیم از audit.
"""

from __future__ import annotations

import hashlib
from datetime import datetime
from typing import Any
from uuid import UUID

from fastapi import status
from passlib.context import CryptContext

from app.core.errors import APIError
from app.core.events.bus import DomainEvent, event_bus
from app.modules.auth.admin_ports import (
    AdminCreateUserRequest,
    AdminUpdateUserRequest,
    AdminUserListItem,
    BulkFailure,
    BulkLoginModeRequest,
    BulkResult,
)

pwd_context = CryptContext(schemes=["argon2"], argon2__time_cost=3, deprecated="auto")

# ── رویدادهای جدید مربوط به این فایل (به auth/events.py هم اضافه کنید
#    اگر می‌خواهید همه‌ی رویدادهای auth یک‌جا باشند — اینجا محلی نگه
#    داشته شده تا وابسته به merge شدن آن فایل نباشد)
AUTH_USER_CREATED_BY_ADMIN = "auth.user.created_by_admin"
AUTH_USER_UPDATED = "auth.user.updated"
AUTH_USER_DEACTIVATED = "auth.user.deactivated"
AUTH_USER_LOGIN_MODE_CHANGED = "auth.user.login_mode.changed"


def _validate_national_id(national_id: str) -> bool:
    """کپی هدفمند از AuthService._validate_national_id — تا این فایل مستقل
    از merge شدن auth_service.py کار کند. اگر ترجیح می‌دهید یک‌جا باشد،
    هر دو را به app/modules/auth/validators.py منتقل کنید."""
    national_id = national_id.strip()
    if not national_id.isdigit() or len(national_id) != 10:
        return False
    digits = [int(d) for d in national_id]
    weights = [10, 9, 8, 7, 6, 5, 4, 3, 2]
    weighted_sum = sum(d * w for d, w in zip(digits[:9], weights))
    remainder = weighted_sum % 11
    expected_check = remainder if remainder < 2 else 11 - remainder
    return digits[9] == expected_check


class AdminUserService:
    def __init__(self, user_repo: Any, role_assignment_service: Any | None = None) -> None:
        self.user_repo = user_repo
        # اختیاری: اگر می‌خواهید create_user بلافاصله نقش اولیه هم بدهد،
        # همان RoleAssignmentService که در rbac_patch.zip ساختیم را تزریق کنید.
        self.role_assignment_service = role_assignment_service

    @staticmethod
    def _actor_id(actor: Any) -> Any:
        """accept str (from get_current_user) or an object with .id"""
        return actor.id if not isinstance(actor, str) else actor

    # ── ایجاد ──────────────────────────────────────────────
    async def create_user(self, actor: Any, request: AdminCreateUserRequest) -> dict:
        if not _validate_national_id(request.national_id):
            raise APIError(
                error_code="INVALID_NATIONAL_ID",
                message="فرمت کد ملی صحیح نیست.",
                status_code=status.HTTP_400_BAD_REQUEST,
            )
        if await self.user_repo.get_by_username(request.username):
            raise APIError(
                error_code="USERNAME_EXISTS",
                message="این نام کاربری قبلاً استفاده شده است.",
                status_code=status.HTTP_409_CONFLICT,
            )
        if await self.user_repo.get_by_national_id(request.national_id):
            raise APIError(
                error_code="USER_EXISTS",
                message="کاربری با این کد ملی قبلاً ثبت شده است.",
                status_code=status.HTTP_409_CONFLICT,
            )

        from app.modules.auth.db.models import Users
        from app.modules.auth.db.repositories import national_id_hash

        nid_enc, nid_nonce = self._encrypt_national_id(request.national_id)
        user = Users(
            username=request.username,
            national_id_enc=nid_enc,
            national_id_nonce=nid_nonce,
            national_id_hash=national_id_hash(request.national_id),
            national_id_last4=request.national_id[-4:],
            password_hash=pwd_context.hash(request.initial_password),
            display_name=request.display_name,
            auth_mode="local",
            is_active=True,
            must_change_password=True,  # ادمین رمز موقت گذاشته؛ کاربر باید عوضش کند
        )
        await self.user_repo.add(user)
        await self.user_repo.commit()

        if request.role_id is not None and self.role_assignment_service is not None:
            await self.role_assignment_service.assign_role(actor, user.id, request.role_id)

        await self._publish(
            AUTH_USER_CREATED_BY_ADMIN,
            actor_id=self._actor_id(actor),
            payload={
                "target_user_id": str(user.id),
                "username": user.username,
                "role_id": request.role_id,
                "dangerous": True,
            },
        )
        return {"status": "success", "user_id": str(user.id)}

    # ── فهرست ──────────────────────────────────────────────
    async def list_users(
        self, *, search: str | None = None, is_active: bool | None = None,
        limit: int = 50, offset: int = 0,
    ) -> tuple[list[AdminUserListItem], int]:
        from sqlalchemy import func, or_, select

        from app.modules.auth.db.models import Users

        limit = min(limit, 200)  # سقف امن — از اسکن کامل جدول بدون صفحه‌بندی جلوگیری می‌کند
        query = select(Users)
        count_query = select(func.count()).select_from(Users)

        if search:
            like = f"%{search}%"
            cond = or_(Users.username.ilike(like), Users.display_name.ilike(like))
            query = query.where(cond)
            count_query = count_query.where(cond)
        if is_active is not None:
            query = query.where(Users.is_active == is_active)
            count_query = count_query.where(Users.is_active == is_active)

        total = (await self.user_repo.session.execute(count_query)).scalar_one()
        result = await self.user_repo.session.execute(
            query.order_by(Users.username).limit(limit).offset(offset)
        )
        users = result.scalars().all()

        items = [
            AdminUserListItem(
                id=u.id,
                username=u.username,
                display_name=u.display_name,
                national_id_masked=f"*****{u.national_id_last4}" if u.national_id_last4 else "******",
                is_active=u.is_active,
                auth_mode=u.auth_mode or "local",
                mfa_enabled=bool(u.mfa_enabled),
                last_login_at=u.last_login_at.isoformat() if u.last_login_at else None,
            )
            for u in users
        ]
        return items, total

    # ── ویرایش ─────────────────────────────────────────────
    async def update_user(self, actor: Any, user_id: UUID, request: AdminUpdateUserRequest) -> dict:
        user = await self.user_repo.get(user_id)
        if not user:
            raise APIError(
                error_code="USER_NOT_FOUND", message="کاربر یافت نشد.",
                status_code=status.HTTP_404_NOT_FOUND,
            )

        old_value: dict[str, Any] = {}
        new_value: dict[str, Any] = {}

        if request.display_name is not None and request.display_name != user.display_name:
            old_value["display_name"] = user.display_name
            user.display_name = request.display_name
            new_value["display_name"] = request.display_name

        if request.is_active is not None and request.is_active != user.is_active:
            if user_id == self._actor_id(actor) and request.is_active is False:
                raise APIError(
                    error_code="CANNOT_DEACTIVATE_SELF",
                    message="نمی‌توانید حساب خودتان را غیرفعال کنید.",
                    status_code=status.HTTP_400_BAD_REQUEST,
                )
            old_value["is_active"] = user.is_active
            user.is_active = request.is_active
            new_value["is_active"] = request.is_active
            if request.is_active is False:
                user.token_version += 1  # غیرفعال‌سازی یعنی همه‌ی نشست‌ها هم باطل شوند

        if request.must_change_password is not None:
            old_value["must_change_password"] = user.must_change_password
            user.must_change_password = request.must_change_password
            new_value["must_change_password"] = request.must_change_password

        await self.user_repo.commit()

        if new_value:
            event_type = AUTH_USER_DEACTIVATED if new_value.get("is_active") is False else AUTH_USER_UPDATED
            await self._publish(
                event_type,
                actor_id=self._actor_id(actor),
                payload={
                    "target_user_id": str(user_id),
                    "old_value": old_value,
                    "new_value": new_value,
                },
            )

        return {"status": "updated", "user_id": str(user_id)}

    # ── تغییر انبوه حالت ورود (طبق نمونه‌کد سند، بخش ۱۲.۶) ──
    async def bulk_change_login_mode(self, actor: Any, payload: BulkLoginModeRequest) -> BulkResult:
        if len(payload.user_ids) > 500:
            raise APIError(
                error_code="TOO_MANY_USERS",
                message="حداکثر ۵۰۰ کاربر در هر عملیات.",
                status_code=status.HTTP_400_BAD_REQUEST,
            )

        updated: list[UUID] = []
        failed: list[BulkFailure] = []

        for uid in payload.user_ids:
            target = await self.user_repo.get(uid)
            if target is None:
                failed.append(BulkFailure(user_id=uid, code="NOT_FOUND"))
                continue
            if target.id == self._actor_id(actor):
                failed.append(BulkFailure(user_id=uid, code="CANNOT_MODIFY_SELF"))
                continue
            # کاربر SSO بدون رمز محلی نباید بدون تنظیم رمز به حالت local برود
            if payload.sso_enabled is False and target.password_hash is None:
                failed.append(BulkFailure(user_id=uid, code="NO_LOCAL_PASSWORD"))
                continue

            old = {"sso_enabled": getattr(target, "sso_enabled", None), "auth_mode": target.auth_mode}
            target.sso_enabled = payload.sso_enabled
            target.auth_mode = "sso" if payload.sso_enabled else "local"
            if payload.revoke_sessions:
                target.token_version += 1

            await self._publish(
                AUTH_USER_LOGIN_MODE_CHANGED,
                actor_id=self._actor_id(actor),
                payload={
                    "target_user_id": str(uid),
                    "old_value": old,
                    "new_value": {"sso_enabled": payload.sso_enabled},
                },
            )
            updated.append(uid)

        await self.user_repo.commit()
        return BulkResult(updated=updated, failed=failed)

    # ── کمکی ───────────────────────────────────────────────
    def _encrypt_national_id(self, national_id: str) -> tuple[bytes, bytes]:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        import secrets
        from app.core.config import settings

        nonce = secrets.token_bytes(12)
        kdf_key = hashlib.sha256(settings.SECRET_KEY.encode()).digest()
        aesgcm = AESGCM(kdf_key)
        return aesgcm.encrypt(nonce, national_id.encode(), None), nonce

    async def _publish(self, event_type: str, *, actor_id: UUID, payload: dict) -> None:
        event = DomainEvent(event_type=event_type, actor_id=actor_id, payload=payload)
        try:
            await event_bus.publish(event, self.user_repo.session)
            await self.user_repo.commit()
        except Exception:
            import logging
            logging.getLogger("auth.admin_users").exception(
                "failed to publish event_type=%s", event_type
            )
```

==========================================================================================
## FILE: bastehA_auth_rbac_audit/backend/app/modules/rbac/api/deps.py
## SIZE: 4328 bytes
==========================================================================================

```python
"""
app/modules/rbac/api/deps.py

``require_permission`` — دقیقاً طبق شبه‌کد بخش ۱۲.۴ سند، با همان
تفاوت آگاهانه‌ای که در همه‌ی پچ‌های قبلی اعمال شد: به‌جای
``await audit.log(...)`` مستقیم (که در نمونه‌کد سند هست ولی نقشه‌ی
وابستگی ماژول‌ها بخش ۲.۱ را نقض می‌کند)، رویداد ``rbac.denied`` از
طریق ``event_bus`` منتشر می‌شود.

⚠️ فرض‌ها (چون به app/core/db/session.py و app/modules/auth/api/deps.py
واقعی شما دسترسی ندارم):
  - ``get_current_user`` در ``app.modules.auth.api.deps`` است
  - یک دیپندنسی ``get_permission_service`` باید PermissionService را
    با session + redis واقعی بسازد — اینجا فقط fallback گذاشته شده
"""

from __future__ import annotations

from fastapi import Depends, Request

from app.core.events.bus import DomainEvent, event_bus
from app.modules.rbac.services.permission_service import PermissionService

try:
    from app.core.errors import PermissionDeniedError
except ImportError:  # pragma: no cover
    from app.modules.rbac.services.role_assignment_service import PermissionDeniedError

try:
    from app.modules.auth.api.deps import get_current_user
except ImportError:  # pragma: no cover
    async def get_current_user():  # type: ignore[no-redef]
        raise NotImplementedError(
            "get_current_user در app.modules.auth.api.deps پیدا نشد."
        )

try:
    from app.modules.rbac.api.deps_internal import get_permission_service  # type: ignore
except ImportError:  # pragma: no cover
    async def get_permission_service():  # type: ignore[no-redef]
        """TODO: جایگزین کنید با چیزی مثل:

            async def get_permission_service(
                uow: UnitOfWork = Depends(get_uow),
                redis=Depends(get_redis),
            ) -> PermissionService:
                return PermissionService(uow.session, redis)
        """
        raise NotImplementedError(
            "get_permission_service هنوز به session/Redis واقعی وصل نشده."
        )


def require_permission(*codes: str, mode: str = "all"):
    """کنترل دسترسی سطح عملیات (لایه ۱). برای سطح رکورد از PolicyEngine
    جدا استفاده کنید (طبق نمونه‌ی بخش ۱۲.۴: هر دو لایه با هم، نه یکی)."""

    async def _dep(
        request: Request,
        user=Depends(get_current_user),
        permission_service: PermissionService = Depends(get_permission_service),
    ):
        user_id = user if isinstance(user, str) else str(user.id)
        perms = await permission_service.effective_permissions(user_id)
        ok = all(c in perms for c in codes) if mode == "all" else any(c in perms for c in codes)
        if not ok:
            await _publish_denied(user_id, codes, request.url.path)
            raise PermissionDeniedError("ACCESS_DENIED", required=codes, path=request.url.path)
        return user

    return _dep


async def _publish_denied(user_id, codes: tuple[str, ...], path: str) -> None:
    """رویداد rbac.denied را منتشر می‌کند — audit (اگر مشترک باشد) بدون
    وابستگی کدی rbac به audit، آن را ثبت می‌کند. اگر session این‌جا در
    دسترس نیست (چون require_permission قبل از ساخته‌شدن UoW کامل اجرا
    می‌شود)، فقط لاگ ساختاریافته می‌زنیم — بهتر از انفجار کل درخواست
    به خاطر شکست ثبت رویداد.
    """
    import logging
    logger = logging.getLogger("rbac.denied")
    logger.warning("permission denied: user_id=%s required=%s path=%s", user_id, codes, path)
    # TODO: اگر session/UoW این‌جا در دسترس است، به‌جای فقط لاگ، از
    # event_bus.publish(..., session) استفاده کنید تا audit هم ثبتش کند:
    #
    #   event = DomainEvent(event_type="rbac.denied", actor_id=user_id,
    #                        payload={"required": list(codes), "path": path})
    #   await event_bus.publish(event, session)
    #   await session.commit()
```

==========================================================================================
## FILE: bastehA_auth_rbac_audit/backend/app/modules/rbac/api/deps_internal.py
## SIZE: 832 bytes
==========================================================================================

```python
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
```

==========================================================================================
## FILE: bastehA_auth_rbac_audit/backend/app/modules/rbac/api/routes.py
## SIZE: 6429 bytes
==========================================================================================

```python
"""
RBAC Module API Routes
Architecture Reference: Sections 7.1, 7.3, 7.4, 11.1
Endpoints: /api/v1/rbac
"""

from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Body, Path
from fastapi.responses import JSONResponse

from app.core.dependencies import (
    get_db_session, get_current_user, get_rbac_service
)
from app.core.errors import APIError, NotFoundError
from app.core.database import async_session_context
from app.modules.rbac.ports import (
    PermissionCreate, PermissionUpdate, RoleCreate, RoleUpdate,
    UserRoleAssignment, AssignRoleRequest, RevokeRoleRequest,
    RBACDecision
)
from app.modules.rbac.services.rbac_service import RBACService
from app.modules.rbac.db.Models import Permissions, Roles, RolePermissions, UserRoles


router = APIRouter(prefix="/rbac", tags=["RBAC"])


@router.post("/permissions", response_model=dict)
async def create_permission(
    request: PermissionCreate,
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Create a new permission."""
    async with db_session() as session:
        try:
            service = RBACService(session)
            permission = await service.create_permission(request)
            return {"status": "permission_created", "permission_code": permission.code}
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.get("/permissions", response_model=dict)
async def list_permissions(
    module: Optional[str] = Query(None),
    action: Optional[str] = Query(None),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """List permissions, optionally filtered."""
    async with db_session() as session:
        try:
            service = RBACService(session)
            permissions = await service.list_permissions(
                module=module, action=action, viewer_id=user_id
            )
            return {
                "status": "success",
                "data": {"permissions": permissions}
            }
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.post("/roles", response_model=dict)
async def create_role(
    request: RoleCreate,
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Create a new role."""
    async with db_session() as session:
        try:
            service = RBACService(session)
            role = await service.create_role(request)
            return {"status": "role_created", "role_code": role.code}
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.get("/roles", response_model=dict)
async def list_roles(
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """List all roles."""
    async with db_session() as session:
        try:
            service = RBACService(session)
            roles = await service.list_roles(viewer_id=user_id)
            return {
                "status": "success",
                "data": {"roles": roles}
            }
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.post("/assign", response_model=dict)
async def assign_role(
    request: AssignRoleRequest,
    user_id: UUID = Depends(get_current_user),
    actor_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Assign a role to a user."""
    async with db_session() as session:
        try:
            service = RBACService(session)
            target = request.target_user_id or user_id
            payload = request.model_dump(exclude={"target_user_id"})
            result = await service.assign_role(
                actor_id=actor_id, target_user_id=target, **payload
            )
            return {"status": "role_assigned", "result": result}
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.post("/revoke", response_model=dict)
async def revoke_role(
    request: RevokeRoleRequest,
    user_id: UUID = Depends(get_current_user),
    actor_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Revoke a role from a user."""
    async with db_session() as session:
        try:
            service = RBACService(session)
            target = request.target_user_id or user_id
            payload = request.model_dump(exclude={"target_user_id"})
            result = await service.revoke_role(
                actor_id=actor_id, target_user_id=target, **payload
            )
            return {"status": "role_revoked", "result": result}
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.get("/user/{user_id}/roles", response_model=dict)
async def get_user_roles(
    user_id: UUID = Path(...),
    viewer_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Get roles for a specific user."""
    async with db_session() as session:
        try:
            service = RBACService(session)
            roles = await service.get_user_roles(user_id, viewer_id)
            return {
                "status": "success",
                "data": {"roles": roles}
            }
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )
```

==========================================================================================
## FILE: bastehA_auth_rbac_audit/backend/app/modules/rbac/db/Models.py
## SIZE: 6099 bytes
==========================================================================================

```python
import uuid
from uuid import UUID
from datetime import datetime
from sqlalchemy import func

from sqlalchemy import (
    Column, Integer, String, Boolean, DateTime,
    ForeignKey, Table, UniqueConstraint, Index, Text, JSON
)
from sqlalchemy.orm import relationship

from app.core.db.base import AuditMixin, BaseModel


# --- Permissions Table ---

class Permissions(BaseModel, AuditMixin):
    """System permissions defining what actions are allowed."""
    
    __tablename__ = "permissions"
    __table_args__ = (
        UniqueConstraint("code", name="uq_permission_code"),
        Index("ix_permissions_module_action", "module", "action"),
    )
    
    # Primary key inherited
    code = Column(String(100), nullable=False, unique=True)
    # Format: "module.action" e.g., "goal.create", "group.manage"
    
    module = Column(String(40), nullable=False)
    # Module name e.g., "goal", "group", "user", "rbac"
    
    action = Column(String(40), nullable=False)
    # Action name e.g., "create", "read", "update", "delete", "manage"
    
    title_fa = Column(String(120), nullable=False)
    # Persian title for UI display
    
    is_dangerous = Column(
        Boolean,
        nullable=False,
        default=False,
        comment="Requires secondary confirmation"
    )
    
    # Relationships
    # role_permissions = relationship("RolePermissions", back_populates="permission")
    # user_actions = relationship("UserActions", back_populates="permission")


# --- Roles Table ---

class Roles(BaseModel, AuditMixin):
    """System roles with hierarchical levels."""
    
    __tablename__ = "roles"
    __table_args__ = (
        UniqueConstraint("code", name="uq_role_code"),
        Index("ix_roles_level", "level"),
    )
    
    # Primary key inherited
    code = Column(String(32), nullable=False, unique=True)
    # e.g., "super_admin", "admin", "manager", "user", "viewer"
    
    title_fa = Column(String(64), nullable=False)
    # Persian title for UI display
    
    level = Column(
        Integer,
        nullable=False,
        server_default="1",
        comment="Hierarchy level (1=lowest, 10=highest). Used for privilege escalation prevention."
    )
    
    is_system = Column(
        Boolean,
        nullable=False,
        default=True,
        comment="System role (cannot be deleted, only modified)"
    )
    
    description = Column(Text, nullable=True)
    
    # Relationships
    # role_permissions = relationship("RolePermissions", back_populates="role")
    # user_roles = relationship("UserRoles", back_populates="role")


# --- Role-Permission Junction Table ---

class RolePermissions(BaseModel, AuditMixin):
    """Junction table for role-permission many-to-many relationship."""
    
    __tablename__ = "role_permissions"
    __table_args__ = (
        UniqueConstraint("role_id", "permission_id", name="uq_role_permission"),
    )
    
    # Primary key inherited
    role_id = Column(
        Integer,
        ForeignKey("roles.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    permission_id = Column(
        Integer,
        ForeignKey("permissions.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    
    # Composite primary key (role_id, permission_id)
    
    # Relationships
    # role = relationship("Roles", back_populates="role_permissions")
    # permission = relationship("Permissions", back_populates="role_permissions")


# --- User-Role Junction Table ---

class UserRoles(BaseModel, AuditMixin):
    """Junction table for user-role many-to-many relationship with scoping."""
    
    __tablename__ = "user_roles"
    __table_args__ = (
        UniqueConstraint(
            "user_id", "role_id", "scope_type", "scope_id",
            name="uq_user_role"
        ),
        Index("ix_user_roles_user", "user_id"),
        Index("ix_user_roles_scope", "scope_type", "scope_id"),
    )
    
    # Primary key components
    user_id = Column(
        String(36),  # UUID as string
        ForeignKey("auth.users.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    role_id = Column(
        Integer,
        ForeignKey("roles.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    scope_type = Column(
        String(16),
        nullable=False,
        default="global",
        comment="global | group"
    )
    scope_id = Column(
        String(36),
        nullable=True,
        comment="group_id when scope_type=group, otherwise NULL"
    )
    
    # Additional fields
    granted_by = Column(String(36), nullable=True)  # UUID of who granted
    granted_at = Column(DateTime(timezone=True), server_default=func.now())
    expires_at = Column(DateTime(timezone=True), nullable=True)
    source = Column(
        String(16),
        nullable=False,
        default="manual",
        comment="manual | ldap_group"
    )
    
    # Relationships
    # user = relationship("Users", foreign_keys=[user_id])
    # role = relationship("Roles", back_populates="user_roles")


# --- LDAP Group Sync ---

class LDAPGroupSync(BaseModel, AuditMixin):
    """LDAP group synchronization tracking."""
    
    __tablename__ = "ldap_group_sync"
    __table_args__ = (
        UniqueConstraint("ldap_dn", name="uq_ldap_group_dn"),
    )
    
    # Primary key inherited
    ldap_dn = Column(String(512), nullable=False)
    # Distinguished Name from Active Directory
    
    sync_status = Column(
        String(16),
        nullable=False,
        default="pending",
        comment="pending | success | failed"
    )
    sync_last_run = Column(DateTime(timezone=True), nullable=True)
    synced_group_ids = Column(Text, nullable=True)  # JSON array of group IDs
    error_message = Column(Text, nullable=True)


# Export all
__all__ = [
    "Permissions", "Roles", "RolePermissions", "UserRoles",
    "LDAPGroupSync"
]
```

==========================================================================================
## FILE: bastehA_auth_rbac_audit/backend/app/modules/rbac/events.py
## SIZE: 2064 bytes
==========================================================================================

```python
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
```

==========================================================================================
## FILE: bastehA_auth_rbac_audit/backend/app/modules/rbac/ports.py
## SIZE: 3236 bytes
==========================================================================================

```python
from typing import Protocol, Optional, List, Tuple
from uuid import UUID
from datetime import datetime
from pydantic import BaseModel, Field


# --- Permission Protocol ---

class PermissionReadModel(Protocol):
    """Read model for permissions visible to other modules."""
    code: str  # e.g., "goal.create", "group.manage"
    module: str
    action: str
    title_fa: str
    is_dangerous: bool


# --- Role Protocol ---

class RoleReadModel(Protocol):
    """Read model for roles visible to other modules."""
    id: int
    code: str  # e.g., "super_admin", "admin", "manager", "user", "viewer"
    title_fa: str
    level: int  # for privilege escalation prevention
    is_system: bool


# --- User Role Assignment ---

class UserRoleAssignment(BaseModel):
    """User role assignment schema."""
    user_id: UUID
    role_id: int
    scope_type: str = "global"  # global | group
    scope_id: Optional[UUID] = None  # group_id for scoped roles
    source: str = "manual"  # manual | ldap_group
    granted_at: datetime = Field(default_factory=datetime.utcnow)
    expires_at: Optional[datetime] = None


# --- Role Schemas ---

class PermissionCreate(BaseModel):
    """Create permission request."""
    code: str = Field(..., min_length=1, max_length=100)
    module: str = Field(..., min_length=1, max_length=40)
    action: str = Field(..., min_length=1, max_length=40)
    title_fa: str = Field(..., min_length=1, max_length=120)
    is_dangerous: bool = False


class PermissionUpdate(BaseModel):
    """Update permission request."""
    title_fa: Optional[str] = Field(None, min_length=1, max_length=120)
    is_dangerous: Optional[bool] = Field(None)


class RoleCreate(BaseModel):
    """Create role request."""
    code: str = Field(..., min_length=1, max_length=32, unique=True)
    title_fa: str = Field(..., min_length=1, max_length=64)
    level: int = Field(default=1, ge=1, le=10)
    is_system: bool = True
    description: Optional[str] = Field(None, max_length=255)


class RoleUpdate(BaseModel):
    """Update role request."""
    title_fa: Optional[str] = Field(None, min_length=1, max_length=64)
    level: Optional[int] = Field(None, ge=1, le=10)
    is_system: Optional[bool] = Field(None)


# --- User Role Assignment Schemas ---

class AssignRoleRequest(BaseModel):
    """Assign role to user."""
    role_id: int
    scope_type: str = "global"
    scope_id: Optional[UUID] = None
    target_user_id: Optional[UUID] = None  # defaults to self when omitted


class RevokeRoleRequest(BaseModel):
    """Revoke role from user."""
    role_id: int
    scope_type: str = "global"
    target_user_id: Optional[UUID] = None  # defaults to self when omitted


# --- RBAC Decision ---

class RBACDecision(BaseModel):
    """RBAC authorization decision."""
    allowed: bool
    reason: Optional[str] = None
    redaction: Optional[str] = None  # for privacy-aware responses


# Export all
__all__ = [
    "PermissionReadModel", "RoleReadModel",
    "UserRoleAssignment", "PermissionCreate", "PermissionUpdate",
    "RoleCreate", "RoleUpdate", "AssignRoleRequest", "RevokeRoleRequest",
    "RBACDecision"
]
```

==========================================================================================
## FILE: bastehA_auth_rbac_audit/backend/app/modules/rbac/services/rbac_service.py
## SIZE: 8590 bytes
==========================================================================================

```python
"""RBAC service — raw SQL against the real DDL (schema ``rbac``).

Architecture Reference: Sections 2, 7.1, 7.4.
The ORM models drifted from the migration DDL (missing schema, extra
columns, wrong PK types), so this service uses schema-qualified SQL,
the same proven pattern as the reporting dashboard endpoints.
"""
from typing import List, Optional
from types import SimpleNamespace
from uuid import UUID

from sqlalchemy import text

from app.core.errors import APIError


class RBACService:
    """Service layer for RBAC module operations."""

    def __init__(self, session):
        self.session = session

    # --- Permissions ---

    async def create_permission(self, request) -> SimpleNamespace:
        """Create a new permission."""
        row = (await self.session.execute(text("""
            INSERT INTO rbac.permissions (code, module, action, title_fa, is_dangerous)
            VALUES (:code, :module, :action, :title_fa, :dangerous)
            ON CONFLICT (code) DO NOTHING
            RETURNING id, code, module, action, title_fa, is_dangerous
        """), {
            "code": request.code, "module": request.module,
            "action": request.action, "title_fa": request.title_fa,
            "dangerous": bool(request.is_dangerous),
        })).mappings().first()
        if row is None:
            raise APIError(error_code="PERMISSION_EXISTS",
                           message="این دسترسی قبلاً ثبت شده است.", status_code=409)
        await self.session.commit()
        return SimpleNamespace(**dict(row))

    async def list_permissions(self, module: Optional[str] = None,
                               action: Optional[str] = None,
                               viewer_id: Optional[UUID] = None) -> List[dict]:
        """List permissions, optionally filtered."""
        conds, params = [], {}
        if module:
            conds.append("module = :module"); params["module"] = module
        if action:
            conds.append("action = :action"); params["action"] = action
        where = ("WHERE " + " AND ".join(conds)) if conds else ""
        rows = (await self.session.execute(text(f"""
            SELECT id, code, module, action, title_fa, is_dangerous
              FROM rbac.permissions {where} ORDER BY module, action
        """), params)).mappings().all()
        return [dict(r) for r in rows]

    # --- Roles ---

    async def create_role(self, request) -> SimpleNamespace:
        """Create a new role."""
        row = (await self.session.execute(text("""
            INSERT INTO rbac.roles (code, title_fa, level, is_system, description)
            VALUES (:code, :title_fa, :level, :is_system, :description)
            ON CONFLICT (code) DO NOTHING
            RETURNING id, code, title_fa, level, is_system, description
        """), {
            "code": request.code, "title_fa": request.title_fa,
            "level": request.level, "is_system": bool(request.is_system),
            "description": request.description,
        })).mappings().first()
        if row is None:
            raise APIError(error_code="ROLE_EXISTS",
                           message="این نقش قبلاً ثبت شده است.", status_code=409)
        await self.session.commit()
        return SimpleNamespace(**dict(row))

    async def list_roles(self, viewer_id: Optional[UUID] = None) -> List[dict]:
        """List all roles."""
        rows = (await self.session.execute(text("""
            SELECT id, code, title_fa, level, is_system, description
              FROM rbac.roles ORDER BY level DESC, code
        """))).mappings().all()
        return [dict(r) for r in rows]

    # --- Assignments (with anti-escalation guards per ADR/7.4) ---

    async def _max_level(self, user_id: UUID) -> int:
        row = (await self.session.execute(text("""
            SELECT COALESCE(MAX(r.level), 0) AS m
              FROM rbac.user_roles ur JOIN rbac.roles r ON r.id = ur.role_id
             WHERE ur.user_id = :uid
               AND (ur.expires_at IS NULL OR ur.expires_at > now())
        """), {"uid": str(user_id)})).mappings().first()
        return int(row["m"] if row else 0)

    async def assign_role(self, actor_id: UUID, target_user_id: UUID,
                          role_id: int, scope_type: str = "global",
                          scope_id: Optional[UUID] = None, **_) -> dict:
        """Assign a role to a user (guards: no self-assign, no equal/higher)."""
        if str(target_user_id) == str(actor_id):
            raise APIError(error_code="CANNOT_SELF_ASSIGN",
                           message="نمی‌توان به خود نقش داد.", status_code=403)
        role = (await self.session.execute(text(
            "SELECT id, code, level FROM rbac.roles WHERE id = :rid"),
            {"rid": role_id})).mappings().first()
        if role is None:
            raise APIError(error_code="ROLE_NOT_FOUND",
                           message="نقش یافت نشد.", status_code=404)
        actor_max = await self._max_level(actor_id)
        # Bootstrap: a user with no roles yet may assign only level-1 roles.
        if actor_max > 0 and int(role["level"]) >= actor_max:
            raise APIError(error_code="CANNOT_GRANT_EQUAL_OR_HIGHER_ROLE",
                           message="نمی‌توان نقش هم‌سطح یا بالاتر از خود اعطا کرد.",
                           status_code=403)
        if scope_type == "group" and scope_id is not None:
            mgr = (await self.session.execute(text("""
                SELECT 1 FROM groups.group_members
                 WHERE group_id = :gid AND user_id = :uid AND is_manager
            """), {"gid": str(scope_id), "uid": str(actor_id)})).first()
            if mgr is None:
                raise APIError(error_code="NOT_GROUP_MANAGER",
                               message="مدیر این گروه نیستید.", status_code=403)
        await self.session.execute(text("""
            INSERT INTO rbac.user_roles (user_id, role_id, scope_type, scope_id, granted_by, source)
            VALUES (:uid, :rid, :scope, :sid, :by, 'manual')
            ON CONFLICT DO NOTHING
        """), {
            "uid": str(target_user_id), "rid": role_id, "scope": scope_type,
            "sid": str(scope_id) if scope_id else None, "by": str(actor_id),
        })
        await self.session.commit()
        return {"role_id": role_id, "role_code": role["code"],
                "target_user_id": str(target_user_id)}

    async def revoke_role(self, actor_id: UUID, target_user_id: UUID,
                          role_id: int, scope_type: str = "global", **_) -> dict:
        """Revoke a role from a user."""
        await self.session.execute(text("""
            DELETE FROM rbac.user_roles
             WHERE user_id = :uid AND role_id = :rid AND scope_type = :scope
        """), {"uid": str(target_user_id), "rid": role_id, "scope": scope_type})
        await self.session.commit()
        return {"role_id": role_id, "target_user_id": str(target_user_id)}

    async def get_user_roles(self, user_id: UUID,
                             viewer_id: Optional[UUID] = None) -> List[dict]:
        """Get roles for a specific user."""
        rows = (await self.session.execute(text("""
            SELECT r.id, r.code, r.title_fa, r.level,
                   ur.scope_type, ur.scope_id::text AS scope_id,
                   ur.granted_at, ur.expires_at, ur.source
              FROM rbac.user_roles ur JOIN rbac.roles r ON r.id = ur.role_id
             WHERE ur.user_id = :uid
               AND (ur.expires_at IS NULL OR ur.expires_at > now())
             ORDER BY r.level DESC
        """), {"uid": str(user_id)})).mappings().all()
        out = []
        for r in rows:
            d = dict(r)
            for k in ("granted_at", "expires_at"):
                if d.get(k) is not None:
                    d[k] = d[k].isoformat()
            out.append(d)
        return out

    async def effective_permissions(self, user_id: UUID) -> List[str]:
        """Flat permission codes for a user (used by the policy engine)."""
        rows = (await self.session.execute(text("""
            SELECT DISTINCT p.code
              FROM rbac.user_roles ur
              JOIN rbac.role_permissions rp ON rp.role_id = ur.role_id
              JOIN rbac.permissions p ON p.id = rp.permission_id
             WHERE ur.user_id = :uid
               AND (ur.expires_at IS NULL OR ur.expires_at > now())
        """), {"uid": str(user_id)})).mappings().all()
        return [r["code"] for r in rows]
```

==========================================================================================
## FILE: bastehA_auth_rbac_audit/backend/app/modules/rbac/services/role_assignment_service.py
## SIZE: 6535 bytes
==========================================================================================

```python
"""
app/modules/rbac/services/role_assignment_service.py

پیاده‌سازی «جلوگیری از Privilege Escalation» — دقیقاً سه قاعده‌ی
بخش ۷.۴ سند معماری v2.0:

  ۱) نمی‌توان نقشی بالاتر یا هم‌سطح خودِ actor به کسی اعطا کرد.
  ۲) نمی‌توان به خود نقش داد (self-assignment).
  ۳) نقش دامنه‌دار (scope_type='group') فقط توسط مدیر همان گروه قابل‌اعطاست.

طبق سند: «هر سه بررسی لازم است. حذف بند اول یعنی هر Manager می‌تواند
خود را Super Admin کند — کلاسیک‌ترین Privilege Escalation.»

⚠️ تفاوت عمدی با نمونه‌کد خودِ سند (بخش ۷.۴):
نمونه‌کد سند این‌طور می‌نویسد:

    await audit.log("rbac.role.assigned", target=target_user_id, dangerous=True)

که یعنی import مستقیم از ماژول audit — همان اشکالی که در
auth_service.py پیدا و اصلاح شد (نقض نقشه‌ی وابستگی بخش ۲.۱: هیچ
فلشی از RBAC به Audit وجود ندارد). این‌جا به‌جایش از همان
``event_bus`` که برای auth ساختیم استفاده می‌شود — audit (و هر
مصرف‌کننده‌ی دیگری، مثل کش Permission در بخش ۱۲.۴) بدون این‌که RBAC
به آن‌ها import اضافه کند، مطلع می‌شوند.

⚠️ فرض‌های این فایل (چون به سرویس/ریپازیتوری واقعی RBAC شما دسترسی
ندارم) — با Protocol مشخص شده‌اند تا مشخص باشد دقیقاً چه چیزی باید
به این کلاس تزریق شود:
  - ``rbac_repo.max_role_level(user_id) -> int``
  - ``rbac_repo.get_role(role_id) -> RoleLike`` (با فیلد ``level``)
  - ``rbac_repo.grant(target_user_id, role_id, scope, granted_by) -> None``
  - ``groups_repo.is_manager(user_id, group_id) -> bool``

اگر اسم متدهای واقعی شما فرق دارد، فقط همین چهار خط فراخوانی را در
``assign_role`` پایین تطبیق دهید — منطق سه‌قاعده‌ای دست‌نخورده می‌ماند.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol
from uuid import UUID

from app.core.events.bus import DomainEvent, event_bus
from app.modules.rbac import events as rbac_events

try:
    from app.core.errors import PermissionDeniedError
except ImportError:  # pragma: no cover — fallback اگر این کلاس هنوز در core.errors نیست
    class PermissionDeniedError(Exception):
        def __init__(self, code: str, **details: Any) -> None:
            self.code = code
            self.details = details
            super().__init__(code)


@dataclass(frozen=True)
class RoleScope:
    """معادل ``scope`` در شبه‌کد سند: ``scope.type`` و ``scope.id``."""

    type: str = "global"  # "global" | "group"
    id: UUID | None = None


class RoleLike(Protocol):
    level: int


class RbacRepo(Protocol):
    async def max_role_level(self, user_id: UUID) -> int: ...
    async def get_role(self, role_id: int) -> RoleLike: ...
    async def grant(
        self, target_user_id: UUID, role_id: int, scope: RoleScope | None, granted_by: UUID
    ) -> None: ...


class GroupsRepo(Protocol):
    async def is_manager(self, user_id: UUID, group_id: UUID) -> bool: ...


class RoleAssignmentService:
    """سرویس اختصاصی اعطای نقش با اجرای اجباری هر سه قاعده‌ی ضد Privilege Escalation.

    این را می‌توانید مستقیماً به‌جای منطق فعلی endpoint اعطای نقش‌تان
    صدا بزنید، یا متد ``assign_role`` را به کلاس RBAC service موجودتان
    منتقل کنید — منطق مستقل از نحوه‌ی ساختاردهی فایل‌هاست.
    """

    def __init__(self, session: Any, rbac_repo: RbacRepo, groups_repo: GroupsRepo) -> None:
        self.session = session
        self.rbac_repo = rbac_repo
        self.groups_repo = groups_repo

    async def assign_role(
        self,
        actor: Any,
        target_user_id: UUID,
        role_id: int,
        scope: RoleScope | None = None,
    ) -> None:
        actor_max = await self.rbac_repo.max_role_level(actor.id)
        target_role = await self.rbac_repo.get_role(role_id)

        # ── قاعده ۱: نمی‌توان نقشی بالاتر یا هم‌سطح خود اعطا کرد
        if target_role.level >= actor_max:
            raise PermissionDeniedError(
                "CANNOT_GRANT_EQUAL_OR_HIGHER_ROLE",
                actor_max_level=actor_max,
                target_role_level=target_role.level,
            )

        # ── قاعده ۲: نمی‌توان به خود نقش داد
        if target_user_id == actor.id:
            raise PermissionDeniedError("CANNOT_SELF_ASSIGN")

        # ── قاعده ۳: نقش دامنه‌دار فقط توسط مدیر همان دامنه (گروه)
        if scope is not None and scope.type == "group":
            if scope.id is None:
                raise PermissionDeniedError("SCOPE_GROUP_REQUIRES_ID")
            if not await self.groups_repo.is_manager(actor.id, scope.id):
                raise PermissionDeniedError("NOT_GROUP_MANAGER")

        await self.rbac_repo.grant(target_user_id, role_id, scope, granted_by=actor.id)

        # به‌جای `await audit.log(...)` مستقیم (که در نمونه‌کد سند هست
        # ولی نقشه‌ی وابستگی ماژول‌ها را نقض می‌کند)، رویداد منتشر می‌شود.
        # Audit (اگر مشترک باشد) و کش Permission (بخش ۱۲.۴ سند) هر دو
        # بدون وابستگی کدی RBAC به آن‌ها، این را دریافت می‌کنند.
        event = DomainEvent(
            event_type=rbac_events.RBAC_ROLE_ASSIGNED,
            actor_id=actor.id,
            payload={
                "target_user_id": str(target_user_id),
                "role_id": role_id,
                "role_level": target_role.level,
                "scope_type": scope.type if scope else "global",
                "scope_id": str(scope.id) if scope and scope.id else None,
                "dangerous": True,
            },
        )
        await event_bus.publish(event, self.session)
```

==========================================================================================
## FILE: bastehB_ws_chat_notif_files/backend/app/modules/chat/api/routes.py
## SIZE: 6760 bytes
==========================================================================================

```python
"""
Chat Module API Routes
Architecture Reference: Sections 8.1, 8.2, 8.3
Endpoints: /api/v1/chat
"""

from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends, Query, Body, Path
from fastapi.responses import JSONResponse

from app.core.dependencies import (
    get_db_session, get_current_user, get_chat_service
)
from app.core.errors import APIError, NotFoundError, PrivacyHiddenError
from app.core.database import async_session_context
from app.modules.chat.ports import (
    RoomCreate, RoomUpdate, MessageCreate, MessageResponse,
    MemberCreate, ChatExport
)
from app.modules.chat.services.chat_service import ChatService
from app.modules.chat.db.Models import Rooms, RoomMembers, Messages


router = APIRouter(prefix="/chat", tags=["Chat"])


@router.post("/rooms", response_model=dict)
async def create_room(
    request: RoomCreate,
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Create a new chat room."""
    async with db_session() as session:
        try:
            service = ChatService(session)
            room = await service.create_room(
                title=request.title,
                linked_type=request.linked_type,
                linked_id=request.linked_id,
                owner_id=user_id
            )
            return {"status": "room_created", "room_id": str(room.id)}
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.get("/rooms", response_model=dict)
async def list_rooms(
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """List chat rooms."""
    async with db_session() as session:
        try:
            service = ChatService(session)
            rooms = await service.list_rooms(user_id)
            return {
                "status": "success",
                "data": {"rooms": rooms}
            }
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.get("/rooms/{room_id}", response_model=dict)
async def get_room(
    room_id: UUID = Path(...),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Get a single chat room."""
    async with db_session() as session:
        try:
            service = ChatService(session)
            room = await service.get_room(room_id, user_id)
            
            if not room:
                return JSONResponse(
                    status_code=404,
                    content={"error": "ROOM_NOT_FOUND", "message": "اتاق یافت نشد.", "success": False}
                )
            
            return {
                "status": "success",
                "data": room
            }
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.post("/rooms/{room_id}/members", response_model=dict)
async def add_room_member(
    room_id: UUID = Path(...),
    user_id: UUID = Body(...),
    role: str = Body("member"),
    user_adding_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Add member to chat room."""
    async with db_session() as session:
        try:
            service = ChatService(session)
            result = await service.add_member(room_id, user_id, role, user_adding_id)
            return {"status": "member_added", "result": result}
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.post("/{room_id}/messages", response_model=dict)
async def send_message(
    room_id: UUID = Path(...),
    request: MessageCreate = Body(...),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Send a chat message."""
    async with db_session() as session:
        try:
            service = ChatService(session)
            message = await service.send_message(room_id, request.body, user_id)
            return {
                "status": "message_sent",
                "message_id": str(message.id),
                "message": {
                    "id": str(message.id),
                    "room_id": str(message.room_id),
                    "sender_id": str(message.sender_id),
                    "body": message.body,
                    "created_at": message.created_at.isoformat(),
                    "message_type": message.message_type,
                }
            }
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.get("/{room_id}/messages", response_model=dict)
async def get_messages(
    room_id: UUID = Path(...),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Get chat messages."""
    async with db_session() as session:
        try:
            service = ChatService(session)
            messages = await service.get_messages(room_id, user_id)
            return {
                "status": "success",
                "data": {"messages": messages}
            }
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.post("/rooms/{room_id}/archive", response_model=dict)
async def archive_room(
    room_id: UUID = Path(...),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Archive a chat room."""
    async with db_session() as session:
        try:
            service = ChatService(session)
            result = await service.archive_room(room_id, user_id)
            return {"status": "room_archived", "result": result}
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )
```

==========================================================================================
## FILE: bastehB_ws_chat_notif_files/backend/app/modules/chat/db/Models.py
## SIZE: 4722 bytes
==========================================================================================

```python
import uuid
from uuid import UUID
from datetime import datetime
from sqlalchemy import func

from sqlalchemy import (
    Column, String, Integer, Boolean, DateTime,
    ForeignKey, Text, JSON, Index, UniqueConstraint, Table
)
from sqlalchemy.orm import relationship

from app.core.db.base import AuditMixin, BaseModel


# --- Rooms Table ---

class Rooms(BaseModel, AuditMixin):
    """Chat room entity."""
    
    __tablename__ = "rooms"
    __table_args__ = (
        Index("ix_rooms_linked", "linked_type", "linked_id"),
        Index("ix_rooms_owner", "owner_id"),
    )
    
    # Primary key inherited
    title = Column(String(160), nullable=False)
    description = Column(Text, nullable=True)
    
    # Linkage to other entities
    linked_type = Column(
        String(32),
        nullable=True,
        comment="task | meeting | goal | null (free room)"
    )
    linked_id = Column(String(36), nullable=True, index=True)
    
    # Ownership
    owner_id = Column(
        String(36),
        ForeignKey("auth.users.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    
    # Privacy & Archive
    is_archived = Column(Boolean, nullable=False, default=False)
    archived_at = Column(DateTime(timezone=True), nullable=True)
    archive_object_key = Column(String(512), nullable=True)  # S3 path
    retention_days = Column(
        Integer,
        nullable=False,
        default=365,
        comment="Message retention in days"
    )
    
    # Timestamps inherited
    # created_at, updated_at, deleted_at, version, created_by, updated_by
    
    # Relationships
    # members = relationship("RoomMembers", back_populates="room")
    # messages = relationship("Messages", back_populates="room", cascade="all, delete-orphan")


# --- Room Members ---

class RoomMembers(BaseModel, AuditMixin):
    """Room membership."""
    
    __tablename__ = "room_members"
    __table_args__ = (
        UniqueConstraint("room_id", "user_id", name="uq_room_member"),
        Index("ix_room_members_room", "room_id"),
    )
    
    # Primary key components
    room_id = Column(
        String(36),
        ForeignKey("rooms.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    user_id = Column(
        String(36),
        ForeignKey("auth.users.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    
    # Member role
    role = Column(
        String(16),
        nullable=False,
        default="member",
        comment="owner | moderator | member | readonly"
    )
    
    # Status
    is_muted = Column(Boolean, nullable=False, default=False)
    muted_until = Column(DateTime(timezone=True), nullable=True)
    left_at = Column(DateTime(timezone=True), nullable=True)
    
    # Timestamps inherited
    # created_at inherited from AuditMixin


# --- Messages Table ---

class Messages(BaseModel, AuditMixin):
    """Chat message entity."""
    
    __tablename__ = "messages"
    __table_args__ = (
        Index("ix_messages_room", "room_id", "created_at"),
        Index("ix_messages_sender", "sender_id"),
        Index("ix_messages_search", "search_vector"),
    )
    
    # Primary key inherited
    room_id = Column(
        String(36),
        ForeignKey("rooms.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    sender_id = Column(
        String(36),
        ForeignKey("auth.users.id", ondelete="SET NULL"),
        nullable=True,
        index=True
    )
    
    # Message content
    body = Column(Text, nullable=False)
    body_html = Column(Text, nullable=True)  # Sanitized HTML
    reply_to_id = Column(String(36), nullable=True)
    
    # Message type
    message_type = Column(
        String(16),
        nullable=False,
        server_default="text",
        comment="text | file | system"
    )
    
    # Edit tracking
    is_edited = Column(Boolean, nullable=False, default=False)
    edited_at = Column(DateTime(timezone=True), nullable=True)
    edit_history = Column(JSON, nullable=True, default={})
    
    # Search vector (PostgreSQL)
    search_vector = Column(
        Text,
        nullable=True,
        comment="GIN index for full-text search"
    )
    
    # Timestamps inherited from AuditMixin
    
    # Relationships
    # room = relationship("Rooms", back_populates="messages")
    # sender = relationship("Users", foreign_keys=[sender_id])
    # reply_to = relationship("Messages", remote_messages.id, remote_side=[id])


# --- Export all ---
__all__ = ["Rooms", "RoomMembers", "Messages"]
```

==========================================================================================
## FILE: bastehB_ws_chat_notif_files/backend/app/modules/chat/ports.py
## SIZE: 2367 bytes
==========================================================================================

```python
from typing import Protocol, Optional, List, Tuple, Dict, Any
from uuid import UUID
from datetime import datetime
from pydantic import BaseModel, Field


# --- Chat Room Protocols ---

class RoomReadModel(Protocol):
    """Read model for chat rooms visible to other modules."""
    id: UUID
    title: str
    owner_id: UUID
    is_archived: bool
    member_count: int
    privacy_level: str  # from groups module


# --- Chat Message Protocols ---

class MessageReadModel(Protocol):
    """Read model for chat messages."""
    id: UUID
    room_id: UUID
    sender_id: UUID
    body: str
    sender_name: str
    created_at: datetime
    message_type: str  # 'text' | 'file' | 'system'
    is_edited: bool
    edited_at: Optional[datetime]


# --- Chat Schemas ---

class RoomCreate(BaseModel):
    """Create room request."""
    title: str = Field(..., min_length=1, max_length=160)
    linked_type: Optional[str] = Field(
        None,
        pattern="^(task|meeting|goal|null)$"
    )
    linked_id: Optional[UUID] = Field(None, description="ID of linked entity")


class RoomUpdate(BaseModel):
    """Update room request."""
    title: Optional[str] = Field(None, min_length=1, max_length=160)
    is_archived: Optional[bool] = Field(None)


class MessageCreate(BaseModel):
    """Create message request."""
    room_id: UUID = Field(...)
    body: str = Field(..., min_length=1, max_length=4000)
    reply_to: Optional[UUID] = Field(None, description="Message ID to reply to")


class MessageResponse(BaseModel):
    """Message response."""
    id: UUID
    room_id: UUID
    sender_id: UUID
    body: str
    sender_name: str
    created_at: datetime
    message_type: str
    is_edited: bool
    edit_history: List[dict] = Field(default_factory=list)


# --- Room Membership ---

class MemberCreate(BaseModel):
    """Add member to room."""
    user_id: UUID
    role: str = "member"  # 'member' | 'moderator' | 'owner'


# --- Export ---

class ChatExport(BaseModel):
    """Chat export format."""
    room_id: UUID
    room_title: str
    messages: List[MessageResponse]
    exported_at: datetime


# Export all
__all__ = [
    "RoomReadModel", "MessageReadModel", "RoomCreate", "RoomUpdate",
    "MessageCreate", "MessageResponse", "MemberCreate", "ChatExport"
]
```

==========================================================================================
## FILE: bastehB_ws_chat_notif_files/backend/app/modules/chat/services/chat_service.py
## SIZE: 8609 bytes
==========================================================================================

```python
"""Chat service — raw SQL against the real DDL (schema ``chat``).

Architecture Reference: Sections 8.1, 8.2, 8.3.
"""
from typing import Optional, List
from types import SimpleNamespace
from uuid import UUID
from datetime import datetime

from sqlalchemy import text

from app.core.errors import APIError, NotFoundError


def _iso(v):
    return v.isoformat() if isinstance(v, datetime) else v


class ChatService:
    """Service layer for Chat module operations (real DDL)."""

    def __init__(self, session):
        self.session = session

    async def _member_of(self, room_id: UUID, user_id: UUID) -> bool:
        row = (await self.session.execute(text("""
            SELECT 1 FROM chat.room_members
             WHERE room_id = :rid AND user_id = :uid AND left_at IS NULL
        """), {"rid": str(room_id), "uid": str(user_id)})).first()
        return row is not None

    async def create_room(self, title: str, linked_type: Optional[str],
                          linked_id: Optional[UUID], owner_id: UUID) -> SimpleNamespace:
        """Create a new chat room."""
        row = (await self.session.execute(text("""
            INSERT INTO chat.rooms (title, linked_type, linked_id, owner_id,
                                    is_archived, retention_days)
            VALUES (:title, :ltype, :lid, :owner, FALSE, 30)
            RETURNING id, title, owner_id, is_archived
        """), {"title": title, "ltype": linked_type,
               "lid": str(linked_id) if linked_id else None,
               "owner": str(owner_id)})).mappings().first()
        # Add room creator as an owner member
        await self.session.execute(text("""
            INSERT INTO chat.room_members (room_id, user_id, role)
            VALUES (:rid, :uid, 'owner')
            ON CONFLICT DO NOTHING
        """), {"rid": row["id"], "uid": str(owner_id)})
        await self.session.commit()
        return SimpleNamespace(id=row["id"], title=row["title"],
                               owner_id=row["owner_id"], is_archived=row["is_archived"])

    async def list_rooms(self, user_id: UUID) -> List[dict]:
        """List rooms user is member of."""
        rows = (await self.session.execute(text("""
            SELECT r.id, r.title, r.is_archived, r.owner_id, r.linked_type, r.linked_id,
                   (SELECT count(*) FROM chat.room_members m
                     WHERE m.room_id = r.id AND m.left_at IS NULL) AS member_count
              FROM chat.rooms r
              JOIN chat.room_members m ON m.room_id = r.id
             WHERE m.user_id = :uid AND m.left_at IS NULL
               AND r.is_archived = FALSE
             ORDER BY r.created_at DESC
        """), {"uid": str(user_id)})).mappings().all()
        return [{
            "id": str(r["id"]),
            "title": r["title"],
            "is_archived": r["is_archived"],
            "member_count": int(r["member_count"]),
            "owner_id": str(r["owner_id"]),
            "linked_type": r["linked_type"],
            "linked_id": str(r["linked_id"]) if r["linked_id"] else None,
        } for r in rows]

    async def get_room(self, room_id: UUID, user_id: UUID) -> Optional[dict]:
        """Get room with membership check."""
        row = (await self.session.execute(text("""
            SELECT id, title, owner_id, is_archived, linked_type, linked_id,
                   retention_days, created_at
              FROM chat.rooms WHERE id = :rid
        """), {"rid": str(room_id)})).mappings().first()
        if not row:
            return None
        if not await self._member_of(room_id, user_id):
            return None
        cnt = (await self.session.execute(text("""
            SELECT count(*) AS n FROM chat.room_members
             WHERE room_id = :rid AND left_at IS NULL
        """), {"rid": str(room_id)})).mappings().first()
        return {
            "id": str(row["id"]),
            "title": row["title"],
            "description": None,
            "is_archived": row["is_archived"],
            "member_count": int(cnt["n"]),
            "owner_id": str(row["owner_id"]),
            "linked_type": row["linked_type"],
            "linked_id": str(row["linked_id"]) if row["linked_id"] else None,
        }

    async def add_member(self, room_id: UUID, user_id: UUID, role: str,
                         added_by: UUID) -> dict:
        """Add member to room."""
        room = (await self.session.execute(text(
            "SELECT 1 FROM chat.rooms WHERE id = :rid"),
            {"rid": str(room_id)})).first()
        if not room:
            raise APIError(error_code="ROOM_NOT_FOUND",
                           message="اتاق یافت نشد.", status_code=404)
        await self.session.execute(text("""
            INSERT INTO chat.room_members (room_id, user_id, role, joined_at)
            VALUES (:rid, :uid, :role, now())
            ON CONFLICT (room_id, user_id)
            DO UPDATE SET left_at = NULL, role = EXCLUDED.role
        """), {"rid": str(room_id), "uid": str(user_id), "role": role})
        await self.session.commit()
        return {"status": "added", "room_id": str(room_id), "user_id": str(user_id)}

    async def send_message(self, room_id: UUID, body: str,
                           sender_id: UUID) -> SimpleNamespace:
        """Send a chat message."""
        room = (await self.session.execute(text("""
            SELECT is_archived, owner_id FROM chat.rooms WHERE id = :rid
        """), {"rid": str(room_id)})).mappings().first()
        if not room:
            raise APIError(error_code="ROOM_NOT_FOUND",
                           message="اتاق یافت نشد.", status_code=404)
        if room["is_archived"] and str(room["owner_id"]) != str(sender_id):
            raise APIError(error_code="ROOM_ARCHIVED",
                           message="اتاق آرشیو شده است.", status_code=403)
        if not await self._member_of(room_id, sender_id):
            raise APIError(error_code="NOT_MEMBER",
                           message="شما عضو این اتاق نیستید.", status_code=403)
        if len(body) > 4000:
            raise APIError(error_code="MESSAGE_TOO_LONG",
                           message="متن پیام بیش از حد مجاز است.", status_code=400)
        row = (await self.session.execute(text("""
            INSERT INTO chat.messages (room_id, sender_id, body, message_type, is_edited)
            VALUES (:rid, :uid, :body, 'text', FALSE)
            RETURNING id, room_id, sender_id, body, created_at, message_type, is_edited
        """), {"rid": str(room_id), "uid": str(sender_id), "body": body})).mappings().first()
        await self.session.commit()
        return SimpleNamespace(**dict(row))

    async def get_messages(self, room_id: UUID, viewer_id: UUID) -> List[dict]:
        """Get messages for a room."""
        if not await self._member_of(room_id, viewer_id):
            return []
        rows = (await self.session.execute(text("""
            SELECT id, room_id, sender_id, body, message_type, is_edited,
                   is_edited AS edited, created_at
              FROM chat.messages
             WHERE room_id = :rid AND deleted_at IS NULL
             ORDER BY created_at ASC
             LIMIT 200
        """), {"rid": str(room_id)})).mappings().all()
        return [{
            "id": str(m["id"]),
            "room_id": str(m["room_id"]),
            "sender_id": str(m["sender_id"]),
            "body": m["body"],
            "sender_name": "user",
            "created_at": _iso(m["created_at"]),
            "message_type": m["message_type"],
            "is_edited": m["is_edited"],
        } for m in rows]

    async def archive_room(self, room_id: UUID, archived_by: UUID) -> dict:
        """Archive a chat room."""
        room = (await self.session.execute(text("""
            SELECT owner_id FROM chat.rooms WHERE id = :rid
        """), {"rid": str(room_id)})).mappings().first()
        if not room:
            raise APIError(error_code="ROOM_NOT_FOUND",
                           message="اتاق یافت نشد.", status_code=404)
        if str(room["owner_id"]) != str(archived_by):
            raise APIError(error_code="PERMISSION_DENIED",
                           message="شما اجازه آرشیو این اتاق را ندارید.", status_code=403)
        await self.session.execute(text("""
            UPDATE chat.rooms SET is_archived = TRUE, archived_at = now()
             WHERE id = :rid
        """), {"rid": str(room_id)})
        await self.session.commit()
        return {"status": "archived"}
```

==========================================================================================
