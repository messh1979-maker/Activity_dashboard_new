"""
app/modules/ssoldap/services/sso_login_service.py

پیاده‌سازی سمت "LDAP Bind" جریان بخش ۱.۳ سند (نه شاخه‌ی Kerberos/SPNEGO
که به Keytab واقعی نیاز دارد). مراحل، دقیقاً مطابق دیاگرام توالی سند:

  ۱) LdapService.authenticate() → اطلاعات کاربر از AD
  ۲) جست‌وجوی کاربر محلی بر اساس national_id_hash (طبق سند: «نگاشت بر
     objectGUID و کد ملی، نه sAMAccountName»)
  ۳) اگر پیدا نشد و auto_provision=true → کاربر جدید با auth_mode='sso'
  ۴) اگر sso_enabled=false → 403 SSO_DISABLED_FOR_USER
  ۵) نگاشت memberOf → roles (از طریق RoleAssignmentService، تا همان
     محافظت‌های ضد Privilege Escalation این‌جا هم اعمال شود — نه یک
     مسیر جانبی که RBAC را دور می‌زند)
  ۶) صدور توکن (از AuthService._generate_tokens تزریق‌شده — بدون تکرار
     منطق JWT/Session)
  ۷) انتشار auth.login.succeeded/failed روی event_bus — همان چیزی که
     AuditService (در audit_module_patch.zip) از قبل مشترکش است، پس
     login_audit_logs بدون کد اضافه پر می‌شود.

⚠️ این فایل به AuthService و RoleAssignmentService تزریق‌شده نیاز
دارد — یعنی composition خودتان (deps.py) باید هر سه را با هم بسازد.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from fastapi import status

from app.core.errors import APIError
from app.core.events.bus import DomainEvent, event_bus
from app.modules.ssoldap.services.ldap_service import (
    LdapAuthError,
    LdapService,
    LdapUserInfo,
    map_groups_to_roles,
)


class SsoLoginService:
    def __init__(
        self,
        settings: Any,
        user_repo: Any,
        ldap_service: LdapService,
        auth_service: Any,               # برای _generate_tokens (بدون تکرار منطق JWT)
        role_assignment_service: Any | None = None,  # برای نگاشت گروه→نقش با محافظت escalation
    ) -> None:
        self.settings = settings
        self.user_repo = user_repo
        self.ldap_service = ldap_service
        self.auth_service = auth_service
        self.role_assignment_service = role_assignment_service

    async def login(self, username: str, password: str) -> dict:
        try:
            ldap_info = await self.ldap_service.authenticate(username, password)
        except LdapAuthError as exc:
            await self._publish_login_event(success=False, username=username, reason=exc.code)
            raise APIError(
                error_code=exc.code, message=exc.message,
                status_code=status.HTTP_401_UNAUTHORIZED,
            ) from exc

        user = await self._find_or_provision_user(ldap_info)

        if not user.sso_enabled:
            await self._publish_login_event(
                success=False, username=username, reason="sso_disabled", user_id=user.id
            )
            raise APIError(
                error_code="SSO_DISABLED_FOR_USER",
                message="ورود از طریق SSO برای این کاربر فعال نیست.",
                status_code=status.HTTP_403_FORBIDDEN,
            )
        if not user.is_active:
            await self._publish_login_event(
                success=False, username=username, reason="account_inactive", user_id=user.id
            )
            raise APIError(
                error_code="ACCESS_DENIED", message="حساب کاربری فعال نیست.",
                status_code=status.HTTP_403_FORBIDDEN,
            )

        await self._sync_roles_from_ldap_groups(user, ldap_info)

        tokens = await self.auth_service._generate_tokens(user)  # noqa: SLF001 — reuse عمدی
        await self._publish_login_event(success=True, username=username, user_id=user.id)
        return tokens

    async def _find_or_provision_user(self, ldap_info: LdapUserInfo):
        from app.modules.auth.db.models import Users
        from app.modules.auth.db.repositories import national_id_hash

        user = None
        if ldap_info.national_id:
            user = await self.user_repo.get_by_national_id(ldap_info.national_id)

        if user is None:
            if not getattr(self.settings, "LDAP_AUTO_PROVISION", False):
                raise APIError(
                    error_code="USER_NOT_PROVISIONED",
                    message="این کاربر در سامانه ثبت نشده و Auto-Provision غیرفعال است.",
                    status_code=status.HTTP_403_FORBIDDEN,
                )
            if not ldap_info.national_id:
                raise APIError(
                    error_code="LDAP_MISSING_NATIONAL_ID",
                    message="Attribute کد ملی در AD برای این کاربر تنظیم نشده.",
                    status_code=status.HTTP_403_FORBIDDEN,
                )
            user = Users(
                username=ldap_info.sam_account_name,
                national_id_enc=b"",  # TODO: با همان AESGCM موجود در AuthService رمزنگاری شود
                national_id_nonce=b"",
                national_id_hash=national_id_hash(ldap_info.national_id),
                national_id_last4=ldap_info.national_id[-4:],
                display_name=ldap_info.display_name,
                auth_mode="sso",
                sso_enabled=True,
                is_active=True,
                ldap_dn=ldap_info.dn,
                ldap_object_guid=ldap_info.object_guid,
                ldap_sam_account=ldap_info.sam_account_name,
            )
            await self.user_repo.add(user)
            await self.user_repo.commit()
        else:
            # کاربر از قبل بود — DN/GUID را به‌روز نگه‌دار (ممکن است در AD جابه‌جا شده باشد)
            user.ldap_dn = ldap_info.dn
            user.ldap_object_guid = ldap_info.object_guid
            await self.user_repo.commit()

        return user

    async def _sync_roles_from_ldap_groups(self, user, ldap_info: LdapUserInfo) -> None:
        group_role_map = getattr(self.settings, "LDAP_GROUP_ROLE_MAP", {}) or {}
        if not group_role_map or self.role_assignment_service is None:
            return
        role_codes = map_groups_to_roles(ldap_info.member_of, group_role_map)
        # TODO: role_codes (رشته) باید به role_id (عدد) نگاشت شوند — طبق جدول
        # roles واقعی شما. اینجا عمداً پیاده نشده چون به schema واقعی RBAC
        # نیاز دارد که ندیده‌ام؛ نقطه‌ی اتصال درست همین‌جاست.

    async def _publish_login_event(
        self, *, success: bool, username: str, reason: str | None = None,
        user_id: UUID | None = None,
    ) -> None:
        event_type = "auth.login.succeeded" if success else "auth.login.failed"
        payload = {"identifier": username, "auth_method": "ldap"}
        if reason:
            payload["reason"] = reason
        event = DomainEvent(event_type=event_type, actor_id=user_id, payload=payload)
        try:
            await event_bus.publish(event, self.user_repo.session)
            await self.user_repo.commit()
        except Exception:
            import logging
            logging.getLogger("ssoldap").exception("failed to publish %s", event_type)
