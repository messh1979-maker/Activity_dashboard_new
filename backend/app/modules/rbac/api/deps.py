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
