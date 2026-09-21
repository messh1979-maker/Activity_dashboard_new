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
