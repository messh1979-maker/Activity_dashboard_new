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
