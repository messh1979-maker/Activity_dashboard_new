# PART 8/12 of GAP PACK

## FILE: bastehC_domain/backend/app/modules/ssoldap/api/routes.py
## SIZE: 4028 bytes
==========================================================================================

```python
#!/usr/bin/env python3
"""
app/modules/ssoldap/api/routes.py

دو endpoint سند (بخش ۵.۲):
  - POST /auth/sso/ldap-login   → کامل
  - GET  /auth/sso/negotiate    → SIP-challenge SPNEGO (Kerberos؛ پاسخ
    به تلاش دوم کلاینت با ``Authorization: Negotiate`` فقط وقتی امکان‌پذیر
    است که gssapi + Keytab واقعی پیکربندی شده باشند — خارج از این محیط)
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, Header, Response
from pydantic import BaseModel

from app.core.config import settings
from app.modules.ssoldap.services.sso_login_service import SsoLoginService

try:
    from app.modules.ssoldap.api.deps import get_sso_login_service
except ImportError:  # pragma: no cover
    def get_sso_login_service():  # type: ignore[no-redef]
        raise NotImplementedError(
            "get_sso_login_service هنوز به LdapService/AuthService/session واقعی "
            "وصل نشده — app/modules/ssoldap/api/deps.py را تکمیل کنید."
        )

router = APIRouter(prefix="/auth/sso", tags=["sso-ldap"])


class LdapLoginRequest(BaseModel):
    username: str
    password: str


@router.get("/status")
async def sso_status():
    """SSO/LDAP deployment status for the settings UI (no secrets exposed)."""
    import importlib.util

    return {
        "status": "ok",
        "enabled": settings.ENABLE_SSO,
        "ldap3_installed": importlib.util.find_spec("ldap3") is not None,
        "ldap_server_uri": settings.LDAP_SERVER_URI,
        "ldap_base_dn": settings.LDAP_BASE_DN,
        "ldap_auto_provision": settings.LDAP_AUTO_PROVISION,
        "kerberos_available": bool(settings.LDAP_KERBEROS_ENABLED and settings.LDAP_KERBEROS_KEYTAB),
        "group_role_map_enabled": bool(settings.LDAP_GROUP_ROLE_MAP),
        "negotiate": "/api/v1/auth/sso/negotiate",
        "ldap_login": "/api/v1/auth/sso/ldap-login",
    }


@router.post("/ldap-login")
async def ldap_login(
    payload: LdapLoginRequest,
    service: SsoLoginService = Depends(get_sso_login_service),
):
    return await service.login(payload.username, payload.password)


def _kerberos_available() -> bool:
    """True only when a real Keytab/SPN is configured for this deployment."""
    return bool(settings.LDAP_KERBEROS_ENABLED and settings.LDAP_KERBEROS_KEYTAB)


@router.get("/negotiate")
async def negotiate(
    response: Response,
    authorization: Optional[str] = Header(default=None),
):
    """SPNEGO/Kerberos challenge (arch 1.3, 5.2).

    Step 1 (no ``Authorization`` header): respond 401 + ``WWW-Authenticate:
    Negotiate`` so the client requests a service ticket from the KDC.

    Step 2 (header present): the real exchange needs ``gssapi`` +
    ``accept_sec_context(keytab)``.  Until a Keytab is provisioned the
    endpoint degrades to 501 so callers can fall back to LDAP bind.
    """
    details = {
        "service_principal": settings.LDAP_SERVER_URI,
        "kerberos_available": _kerberos_available(),
        "fallback": "POST /api/v1/auth/sso/ldap-login",
    }

    if authorization:
        scheme, _, _ = authorization.partition(" ")
        if scheme.lower() == "negotiate" and not _kerberos_available():
            response.status_code = 501
            return {
                "error": {
                    "code": "KERBEROS_NOT_CONFIGURED",
                    "message": "Kerberos/SPNEGO برای این دیتابیس فعال نشده است (Keytab/SPN موجود نیست). "
                               "از LDAP bind استفاده کنید.",
                    "details": details,
                }
            }

    response.headers["WWW-Authenticate"] = "Negotiate"
    response.status_code = 401
    return {
        "error": {
            "code": "SPNEGO_CHALLENGE",
            "message": "چالش Kerberos: هدر Authorization: Negotiate را ارسال کنید.",
            "details": details,
        }
    }
```

==========================================================================================
## FILE: bastehC_domain/backend/app/modules/ssoldap/services/ldap_service.py
## SIZE: 8945 bytes
==========================================================================================

```python
"""
app/modules/ssoldap/services/ldap_service.py

این ماژول (M12) قبلاً فقط یک ``api/`` خالی بود — نه db، نه services.
طبق سند:
  - بخش ۲.۵: SSO/LDAP جزو فاز ۱ (پیش‌نیاز همه‌چیز) است.
  - بخش ۱۴ (جدول ریسک): «SSO با Kerberos در محیط واقعی AD کار نکند» →
    ریسک بالا → **«Fallback به LDAP Bind از روز اول»**.

پس اول ``LDAP Bind`` (نام‌کاربری+رمز مستقیم به AD) ساخته می‌شود —
چون بدون Keytab/KDC واقعی هم قابل‌ساخت و تا حدی قابل‌تست است. Kerberos/
SPNEGO کامل (``gssapi``) نیاز به محیط AD واقعی برای تست دارد و باید
جدا (به‌عنوان Spike دوروزه، طبق توصیه‌ی خودِ سند) پیگیری شود —
``app/modules/ssoldap/api/negotiate.py`` در همین پچ فقط یک اسکلت
401 برمی‌گرداند، نه پیاده‌سازی کامل SPNEGO.

⚠️ وابستگی‌ها: `pip list` شما نشان داد ``ldap3`` نصب نیست. برای همین
import آن اینجا **تنبل (lazy)** است — تا وقتی کسی واقعاً وارد کردن
LDAP نزند، بقیه‌ی اپ (که به این ماژول نیازی ندارد) از کار نمی‌افتد.
نصب لازم:

    pip install ldap3

⚠️ تنظیمات لازم (باید به ``app/core/config.py`` اضافه شوند — چون به
محتوای فایل شما دسترسی ندارم، فقط اسم‌هایی که این فایل انتظار دارد
را مستند می‌کنم):

    LDAP_SERVER_URI        # مثل "ldaps://ad.corp.local:636"
    LDAP_BASE_DN           # مثل "DC=corp,DC=local"
    LDAP_BIND_DN           # اکانت سرویس فقط-خواندنی برای search
    LDAP_BIND_PASSWORD     # طبق سند باید AES-256-GCM رمزنگاری‌شده در Vault/DB
                            # باشد؛ اگر از env var/Secret Manager می‌آید همین کافی است
    LDAP_USER_SEARCH_FILTER = "(sAMAccountName={username})"
    LDAP_ATTR_OBJECT_GUID = "objectGUID"
    LDAP_ATTR_NATIONAL_ID  # نام Attribute سفارشی AD شما برای کد ملی — باید با تیم AD هماهنگ شود
    LDAP_ATTR_DISPLAY_NAME = "displayName"
    LDAP_ATTR_MEMBEROF = "memberOf"
    LDAP_GROUP_ROLE_MAP: dict[str, str]  # DN گروه AD → کد نقش داخلی، مثل:
        # {"CN=Managers,OU=Groups,DC=corp,DC=local": "manager"}
    LDAP_AUTO_PROVISION: bool = True
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


class LdapAuthError(Exception):
    """احراز هویت LDAP شکست خورد (رمز غلط، کاربر یافت نشد، سرور در دسترس نیست)."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(f"{code}: {message}")


@dataclass(frozen=True)
class LdapUserInfo:
    """نتیجه‌ی موفق احراز هویت + جست‌وجوی LDAP — چیزی که SsoLoginService مصرف می‌کند."""

    dn: str
    object_guid: str
    sam_account_name: str
    display_name: str
    national_id: str | None
    member_of: list[str] = field(default_factory=list)


def escape_ldap_filter_value(value: str) -> str:
    """طبق سند (بخش امنیت، ردیف A03 Injection): ``escape_filter_chars`` برای LDAP.

    این تابع pure و بدون وابستگی به ldap3 است تا بدون نصب ldap3 هم قابل‌تست
    باشد (ldap3.utils.conv.escape_filter_chars هم دقیقاً همین RFC 4515 را
    پیاده می‌کند — اگر ldap3 نصب بود می‌توانید مستقیم از آن استفاده کنید).
    """
    replacements = {
        "\\": r"\5c",
        "*": r"\2a",
        "(": r"\28",
        ")": r"\29",
        "\x00": r"\00",
    }
    return "".join(replacements.get(ch, ch) for ch in value)


def map_groups_to_roles(member_of: list[str], group_role_map: dict[str, str]) -> list[str]:
    """نگاشت DN گروه‌های AD به کدهای نقش داخلی — طبق سند بخش ۱.۳: «نگاشت memberOf → roles».

    مقایسه‌ی DN بدون حساسیت به بزرگی/کوچکی حروف و فاصله‌های اضافه انجام
    می‌شود، چون AD معمولاً DN را با فرمت‌بندی متفاوت (فاصله بعد از کاما)
    برمی‌گرداند.
    """
    normalized_map = {_normalize_dn(dn): role for dn, role in group_role_map.items()}
    roles = []
    for dn in member_of:
        role = normalized_map.get(_normalize_dn(dn))
        if role and role not in roles:
            roles.append(role)
    return roles


def _normalize_dn(dn: str) -> str:
    return re.sub(r",\s*", ",", dn.strip().lower())


class LdapService:
    """Bind مستقیم کاربر به AD (نه Kerberos) — endpoint: ``POST /auth/sso/ldap-login``."""

    def __init__(self, settings: Any) -> None:
        self.settings = settings

    async def authenticate(self, username: str, password: str) -> LdapUserInfo:
        """کاربر را مستقیماً به AD bind می‌کند و اطلاعاتش را برمی‌گرداند.

        دو مرحله (طبق الگوی رایج AD bind، چون sAMAccountName به‌تنهایی DN
        نیست): (۱) با اکانت سرویس bind و DN کاربر را search می‌کند،
        (۲) با DN واقعی و رمز کاربر دوباره bind می‌کند تا رمز واقعاً
        تأیید شود.
        """
        try:
            import ldap3
            from ldap3 import ALL, Connection, Server
            from ldap3.core.exceptions import LDAPBindError, LDAPException
        except ImportError as exc:  # pragma: no cover
            raise LdapAuthError(
                "LDAP_NOT_CONFIGURED",
                "پکیج ldap3 نصب نیست — `pip install ldap3` را اجرا کنید.",
            ) from exc

        if not username or not password:
            raise LdapAuthError("INVALID_CREDENTIALS", "نام کاربری/رمز خالی است.")

        safe_username = escape_ldap_filter_value(username)
        search_filter = self.settings.LDAP_USER_SEARCH_FILTER.format(username=safe_username)

        server = Server(self.settings.LDAP_SERVER_URI, get_info=ALL, use_ssl=True)

        # مرحله ۱: bind با اکانت سرویس (فقط خواندنی) + search برای پیدا کردن DN کاربر
        try:
            service_conn = Connection(
                server, user=self.settings.LDAP_BIND_DN,
                password=self.settings.LDAP_BIND_PASSWORD, auto_bind=True,
            )
        except LDAPException as exc:
            raise LdapAuthError("LDAP_UNAVAILABLE", "اتصال به AD ممکن نشد.") from exc

        attrs = [
            self.settings.LDAP_ATTR_OBJECT_GUID,
            self.settings.LDAP_ATTR_DISPLAY_NAME,
            self.settings.LDAP_ATTR_MEMBEROF,
        ]
        national_id_attr = getattr(self.settings, "LDAP_ATTR_NATIONAL_ID", None)
        if national_id_attr:
            attrs.append(national_id_attr)

        service_conn.search(
            search_base=self.settings.LDAP_BASE_DN,
            search_filter=search_filter,
            attributes=attrs,
        )
        if not service_conn.entries:
            service_conn.unbind()
            raise LdapAuthError("USER_NOT_FOUND", "کاربر در AD یافت نشد.")

        entry = service_conn.entries[0]
        user_dn = entry.entry_dn
        service_conn.unbind()

        # مرحله ۲: bind واقعی با DN کاربر + رمزی که کاربر فرستاده — این
        # مرحله است که واقعاً رمز را تأیید می‌کند.
        try:
            user_conn = Connection(server, user=user_dn, password=password, auto_bind=True)
            user_conn.unbind()
        except LDAPBindError as exc:
            raise LdapAuthError("INVALID_CREDENTIALS", "نام کاربری یا رمز عبور اشتباه است.") from exc

        member_of = list(entry[self.settings.LDAP_ATTR_MEMBEROF].values) \
            if self.settings.LDAP_ATTR_MEMBEROF in entry else []
        national_id = None
        if national_id_attr and national_id_attr in entry:
            values = entry[national_id_attr].values
            national_id = values[0] if values else None

        return LdapUserInfo(
            dn=user_dn,
            object_guid=str(entry[self.settings.LDAP_ATTR_OBJECT_GUID].value),
            sam_account_name=username,
            display_name=str(entry[self.settings.LDAP_ATTR_DISPLAY_NAME].value),
            national_id=national_id,
            member_of=member_of,
        )
```

==========================================================================================
## FILE: bastehC_domain/backend/app/modules/ssoldap/services/sso_login_service.py
## SIZE: 7571 bytes
==========================================================================================

```python
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
```

==========================================================================================
## FILE: bastehD_migrations_config/backend/.env.example
## SIZE: 1787 bytes
==========================================================================================

```bash
ENV=development            # development | testing | production
DEBUG=False
SQL_ECHO=False             # log every SQL statement (very noisy)
# At least 32 characters. Generate with:
#   .\.venv\Scripts\python.exe -c "import secrets; print(secrets.token_urlsafe(32))"
SECRET_KEY=change-me-to-a-random-string-at-least-32-chars-long
POSTGRES_SERVER=localhost
POSTGRES_PORT=5432
POSTGRES_USER=admin
POSTGRES_PASSWORD=admin123
POSTGRES_DB=planner_db
# App reads SQLALCHEMY_DATABASE_URI first, DATABASE_URL as fallback.
SQLALCHEMY_DATABASE_URI=postgresql+asyncpg://admin:admin123@localhost:5432/planner_db
REDIS_HOST=localhost
REDIS_PORT=6379
HOST=0.0.0.0
PORT=8000
# Must be JSON array syntax (comma-separated string fails to parse).
CORS_ORIGINS=["http://localhost:3000","http://localhost:8080"]
ENABLE_MFA=True
ENABLE_SSO=True
ENABLE_AUDIT_LOGGING=True
RATE_LIMIT_DEFAULT=100/minute
RATE_LIMIT_AUTH=10/minute
MAX_UPLOAD_SIZE=52428800

# ---- Added in architecture-v2 infrastructure pass -------------------------
# Separate keys per purpose (section 4.9 / ADR-06). REQUIRED when ENV=production.
#   DATA_ENCRYPTION_KEY: python -c "import os,base64;print(base64.b64encode(os.urandom(32)).decode())"
#   NATIONAL_ID_PEPPER : python -c "import secrets;print(secrets.token_urlsafe(48))"
DATA_ENCRYPTION_KEY=
NATIONAL_ID_PEPPER=
# HS256 by default; for RS256 set ALGORITHM=RS256 plus both PEM keys.
ALGORITHM=HS256
# JSON arrays. '*' is rejected in production.
ALLOWED_HOSTS=["*"]
ALLOWED_ORIGINS=[]         # WebSocket Origin allow-list; empty = CORS_ORIGINS
TRUSTED_PROXIES=[]         # only these peers may set X-Forwarded-For
IP_ALLOW_LIST=[]
IP_DENY_LIST=[]
MAX_BODY_SIZE=1048576
RATE_LIMIT_ENABLED=True
ALLOW_SELF_REGISTRATION=False
DEVICE_BINDING_MODE=observe  # off | observe | enforce
```

==========================================================================================
## FILE: bastehD_migrations_config/backend/alembic/env.py
## SIZE: 3020 bytes
==========================================================================================

```python
import os
import sys
from alembic import context
from sqlalchemy import engine_from_config, pool

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# Ensure `backend/` (project root for `app.*`) is on sys.path when
# alembic runs from D:\Projects\Activity_dashboard\backend.
_BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)


def _load_dotenv(path):
    """Minimal .env loader (avoids a python-dotenv dependency)."""
    if not os.path.isfile(path):
        return
    with open(path, encoding="utf-8") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key, value = key.strip(), value.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = value


_load_dotenv(os.path.join(_BACKEND_DIR, ".env"))

# Alembic runs in sync mode, but the app .env uses the async driver
# (postgresql+asyncpg://...). Convert it to the sync psycopg2 driver,
# which is what requirements.txt ships (psycopg2-binary).
_db_url = os.environ.get(
    "SQLALCHEMY_DATABASE_URI",
    config.get_main_option("sqlalchemy.url"),
)
if _db_url and "+asyncpg" in _db_url:
    _db_url = _db_url.replace("+asyncpg", "+psycopg2")
if _db_url:
    config.set_main_option("sqlalchemy.url", _db_url)

try:
    from app.core.db.base import Base  # noqa: E402

    target_metadata = Base.metadata
except Exception:
    from sqlalchemy import MetaData  # noqa: E402

    target_metadata = MetaData()

def run_migrations_offline():
    """Run migrations in 'offline' mode.
    
    This configures the context with just a URL
    and gives us the ability to emit SQL script without
    needing a DBAPI.
    """
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()

def run_migrations_online():
    """Run migrations in 'online' mode.
    
    In this mode we need to connect to the database and run migrations
    against a live connection.
    """
    connectable = engine_from_config(
        config.get_section(config.config_ini_section),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection, 
            target_metadata=target_metadata
        )

        with context.begin_transaction():
            context.run_migrations()

if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
```

==========================================================================================
## FILE: bastehD_migrations_config/backend/alembic/head.py
## SIZE: 1057 bytes
==========================================================================================

```python
from datetime import datetime
from alembic import context
from sqlalchemy import engine_from_config, pool, MetaData, Table, Column, String, DateTime
import os

# Add models here so they are registered before head generates
import sys
sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)) + '/../../../../..')

from backend.app.core.db.base import Base

# Get target metadata from Base
target_metadata = Base.metadata

# Get URL from config
config = context.config
url = config.get_main_option("sqlalchemy.url")

engine = engine_from_config(
    config.get_section(config.config_ini_section),
    prefix="sqlalchemy.",
    poolclass=pool.NullPool,
)

# Run a simple query to check connection
with engine.connect() as connection:
    connection.execute("SELECT 1")

# Set the revision to the latest base
opts = {}
if context.is_offline_mode():
    opts['input_file'] = 'offline.sql'
else:
    # Set head to the latest migration
    opts['sqlalchemy.url'] = url

# Set target_metadata
target_metadata.bind = engine
```

==========================================================================================
## FILE: bastehD_migrations_config/backend/alembic/versions/0001_initial.py
## SIZE: 1639 bytes
==========================================================================================

```python
"""Initial schema: 13 module SQL files in FK-safe order.

Applied manually on 2026-09-19 with several PG-validity fixes
(inline INDEX -> CREATE INDEX, expression PKs -> partial unique indexes,
missing CREATE SCHEMA, partitioned PK including partition key).
`alembic stamp head` was used on the dev database; fresh databases can run
`alembic upgrade head` to execute everything below.
"""
import os

from alembic import op

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None

SCHEMAS = [
    "auth", "rbac", "groups", "planning", "calendar", "chat", "files",
    "inbox", "notification", "reporting", "sharing", "ssoldap", "audit",
]

# FK-safe order: auth first (referenced everywhere), chat before files
# (chat creates files.uploads), audit last.
SQL_FILES = [
    "auth_schema.sql",
    "rbac_schema.sql",
    "groups_schema.sql",
    "planning_schema.sql",
    "calendar_schema.sql",
    "chat_schema.sql",
    "files_schema.sql",
    "inbox_schema.sql",
    "notification_schema.sql",
    "reporting_schema.sql",
    "sharing_schema.sql",
    "ssoldap_schema.sql",
    "audit_schema.sql",
]


def _sql_dir():
    return os.path.dirname(os.path.realpath(__file__))


def upgrade():
    for schema in SCHEMAS:
        op.execute(f"CREATE SCHEMA IF NOT EXISTS {schema}")
    for name in SQL_FILES:
        path = os.path.join(_sql_dir(), name)
        with open(path, encoding="utf-8") as fh:
            op.execute(fh.read())


def downgrade():
    for schema in reversed(SCHEMAS):
        op.execute(f"DROP SCHEMA IF EXISTS {schema} CASCADE")
```

==========================================================================================
## FILE: bastehD_migrations_config/backend/alembic/versions/0002_core_outbox.py
## SIZE: 1821 bytes
==========================================================================================

```python
"""create core.outbox_messages

Architecture v2.0, section 2.3 (transactional outbox).

The ORM model lives in app/core/events/outbox.py; this migration brings
the physical table in line with that model so domain-event publishing
(e.g. on login) does not fail with "relation core.outbox_messages does
not exist".
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0002_core_outbox"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("CREATE SCHEMA IF NOT EXISTS core")

    op.create_table(
        "outbox_messages",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("event_id", postgresql.UUID(as_uuid=True), nullable=False, unique=True),
        sa.Column("event_type", sa.String(length=100), nullable=False),
        sa.Column("payload", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("correlation_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("dispatched_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("attempts", sa.SmallInteger(), server_default="0", nullable=False),
        sa.Column("last_error", sa.Text(), nullable=True),
        schema="core",
    )

    op.create_index(
        "ix_outbox_pending",
        "outbox_messages",
        ["created_at"],
        schema="core",
        postgresql_where=sa.text("dispatched_at IS NULL"),
    )


def downgrade() -> None:
    op.drop_index("ix_outbox_pending", table_name="outbox_messages", schema="core")
    op.drop_table("outbox_messages", schema="core")
```

==========================================================================================
## FILE: bastehD_migrations_config/backend/alembic.ini
## SIZE: 704 bytes
==========================================================================================

```ini
[alembic]
script_location = alembic
prepend_sys_path = .
version_path_separator = os
sqlalchemy.url = postgresql+psycopg2://admin:admin123@localhost:5432/planner_db

[post_write_hooks]

[loggers]
keys = root,sqlalchemy,alembic

[handlers]
keys = console

[formatters]
keys = generic

[logger_root]
level = WARN
handlers = console
qualname =

[logger_sqlalchemy]
level = WARN
handlers =
qualname = sqlalchemy.engine

[logger_alembic]
level = INFO
handlers =
qualname = alembic

[handler_console]
class = StreamHandler
args = (sys.stderr,)
level = NOTSET
formatter = generic

[formatter_generic]
format = %(levelname)-5.5s [%(name)s] %(message)s
datefmt = %H:%M:%S
```

==========================================================================================
## FILE: bastehD_migrations_config/backend/pytest.ini
## SIZE: 271 bytes
==========================================================================================

```ini
[pytest]
asyncio_mode = auto
asyncio_default_fixture_loop_scope = function
testpaths = tests
markers =
    integration: needs a reachable PostgreSQL (SQLALCHEMY_DATABASE_URI)
filterwarnings =
    ignore::DeprecationWarning:passlib.*
    ignore::DeprecationWarning:jose.*
```

==========================================================================================
## FILE: bastehD_migrations_config/backend/requirements.txt
## SIZE: 324 bytes
==========================================================================================

```text
fastapi==0.115.6
uvicorn[standard]==0.30.1
sqlalchemy[asyncio]==2.0.30
asyncpg==0.29.0
alembic==1.13.0
psycopg2-binary==2.9.9
redis==5.0.1
python-jose[cryptography]==3.3.0
PyJWT==2.8.0
structlog==24.4.0
passlib[bcrypt]==1.7.4
argon2-cffi==23.1.0
python-multipart==0.0.6
pydantic==2.9.2
pydantic-settings==2.0.0
```

==========================================================================================
## FILE: bastehE_frontend/web/package.json
## SIZE: 958 bytes
==========================================================================================

```json
{
  "name": "planner-web",
  "private": true,
  "version": "1.0.0",
  "type": "module",
  "scripts": {
    "dev": "vite",
    "build": "vite build",
    "preview": "vite preview"
  },
  "dependencies": {
    "@fingerprintjs/fingerprintjs": "^5.2.0",
    "@tanstack/react-query": "^5.60.0",
    "axios": "^1.7.7",
    "crypto-js": "^4.2.0",
    "date-fns": "^3.6.0",
    "react": "^18.3.0",
    "react-dom": "^18.3.0",
    "react-redux": "^9.1.2",
    "react-router-dom": "^7.18.4",
    "recoil": "^0.7.7",
    "zustand": "^5.0.15"
  },
  "devDependencies": {
    "@axe-core/react": "^4.6.0",
    "@types/react": "^18.3.12",
    "@types/react-dom": "^18.3.0",
    "@vitejs/plugin-react": "^4.3.1",
    "autoprefixer": "^10.4.20",
    "daisyui": "^4.12.14",
    "postcss": "^8.4.49",
    "tailwindcss": "^3.4.14",
    "typescript": "^5.6.2",
    "vite": "^8.3.0"
  },
  "allowScripts": {
    "esbuild@0.21.5": true
  }
}
```

==========================================================================================
## FILE: bastehE_frontend/web/src/api/client.ts
## SIZE: 7775 bytes
==========================================================================================

```typescript
import axios, { AxiosInstance, AxiosRequestConfig, CanceledError } from 'axios'
import { getFingerprint, getMacAddress, isDeviceInitialized, generateDeviceHeaders } from '../security/deviceHeaders'
import { secureStorage } from '../security/fingerprint'
import type { AxiosRequestConfig as AxiosConfig } from 'axios'

// Base API URL
const API_BASE_URL = import.meta.env.VITE_API_BASE || 'https://api.corp.local/api/v1'

// Request interface to include device headers
interface RequestConfig extends AxiosConfig {
  skipAuth?: boolean
  skipDeviceHeaders?: boolean
}

/** API client instance */
let api: AxiosInstance | null = null

/** Initialize API client with auth interceptors */
export function initApiClient(): AxiosInstance {
  if (api) return api
  
  api = axios.create({
    baseURL: API_BASE_URL,
    timeout: 30_000,
    withCredentials: true, // For cookie-based refresh tokens
    headers: {
      'Accept': 'application/json',
      'Content-Type': 'application/json',
    },
  })
  
  // Attach device headers to every request
  api.interceptors.request.use(
    async (config: RequestConfig) => {
      // Check if device identity is initialized
      if (!isDeviceInitialized() && !config.skipAuth) {
        // If not initialized and not skipping auth, we need to handle this
        // In practice, this would happen after login
        console.debug('Device identity not initialized - adding minimal headers')
      }
      
      // Generate device authentication headers if not skipped
      if (!config.skipDeviceHeaders && !config.skipAuth) {
        const headers = generateDeviceHeaders(
          config.method?.toUpperCase() || 'GET',
          config.url || '',
          config.data
        )
        
        // Merge headers with existing ones
        config.headers = {
          ...config.headers,
          ...headers,
          // Remove X-Device-MAC for web clients (would be set for desktop)
          ...(getMacAddress() ? { 'X-Device-MAC': getMacAddress() } : {}),
        }
      }
      
      // Add auth token if available
      const token = secureStorage.get('access_token')
      if (token && !config.headers?.Authorization) {
        config.headers.Authorization = `Bearer ${token}`
      }
      
      // Add request ID if not present
      if (!config.headers?.['X-Request-ID']) {
        config.headers['X-Request-ID'] = crypto.randomUUID()
      }
      
      return config
    },
    (error) => {
      return Promise.reject(error)
    }
  )
  
  // Handle token refresh on 401
  // Single-flight: concurrent 401s share one refresh call so the rotated
  // refresh token is not consumed twice (second use => 401 REVOKED).
  let refreshPromise: Promise<{ access: string; refresh: string }> | null = null

  function doRefresh(): Promise<{ access: string; refresh: string }> {
    if (!refreshPromise) {
      const refreshToken = secureStorage.get('refresh_token')
      if (!refreshToken) {
        return Promise.reject(new Error('no refresh token'))
      }
      refreshPromise = (async () => {
        try {
          const response = await api!.post('/auth/refresh', {
            refresh_token: refreshToken
          })
          const data = response.data
          // Update tokens
          secureStorage.set('access_token', data.tokens.access_token)
          secureStorage.set('refresh_token', data.tokens.refresh_token)
          return { access: data.tokens.access_token, refresh: data.tokens.refresh_token }
        } finally {
          refreshPromise = null
        }
      })()
    }
    return refreshPromise
  }

  api.interceptors.response.use(
    (response) => response,
    async (error) => {
      const originalRequest = error.config as RequestConfig & { _retry?: boolean }
      const failedUrl = String(originalRequest?.url || '')
      const isAuthCall = failedUrl.includes('/auth/refresh') || failedUrl.includes('/auth/login')

      // If 401 and not already retried (never retry the auth calls themselves)
      if (error.response?.status === 401 && !originalRequest._retry && !isAuthCall) {
        originalRequest._retry = true
        
        try {
          // Try to refresh token (single-flight across concurrent 401s)
          const { access } = await doRefresh()
          
          // Retry original request with new token.
          // NOTE: axios already serialized originalRequest.data to a JSON
          // string on the first attempt; re-dispatching would stringify it
          // AGAIN (422 dict_type on the server). Bypass re-transform.
          originalRequest.headers.Authorization = `Bearer ${access}`
          
          // Also regenerate device headers
          const headers = generateDeviceHeaders(
            originalRequest.method?.toUpperCase() || 'GET',
            originalRequest.url || '',
            originalRequest.data
          )
          originalRequest.headers = {
            ...originalRequest.headers,
            ...headers,
          }
          
          return api({
            ...originalRequest,
            transformRequest: [(data) => data],
          })
        } catch (refreshError) {
          // Refresh failed - clear tokens and notify the app shell
          // (client.ts cannot import the auth store: authProvider imports this
          // module, so we signal via a DOM event instead of a direct call).
          secureStorage.remove('access_token')
          secureStorage.remove('refresh_token')
          sessionStorage.removeItem('user')
          if (typeof window !== 'undefined') {
            window.dispatchEvent(new CustomEvent('auth:expired'))
          }

          // Navigate to login
          // In real app: navigate('/login')
          return Promise.reject(refreshError)
        }
      }

      // No refresh token stored: nothing to recover with. Notify shell too.
      if (error.response?.status === 401 && !isAuthCall) {
        if (typeof window !== 'undefined') {
          window.dispatchEvent(new CustomEvent('auth:expired'))
        }
      }
      
      return Promise.reject(error)
    }
  )
  
  return api
}

/** Get the API client instance */
export function getApi(): AxiosInstance {
  if (!api) {
    return initApiClient()
  }
  return api
}

/** Simple API helper functions */
export const apiRef = {
  get: <T>(url: string, config?: RequestConfig) => 
    getApi().get<T, T>(url, config),
  
  post: <T, D = any>(url: string, data?: D, config?: RequestConfig) => 
    getApi().post<T, T>(url, data, config),
  
  put: <T, D = any>(url: string, data?: D, config?: RequestConfig) => 
    getApi().put<T, T>(url, data, config),
  
  delete: <T>(url: string, config?: RequestConfig) => 
    getApi().delete<T, T>(url, config),
  
  patch: <T, D = any>(url: string, data?: D, config?: RequestConfig) => 
    getApi().patch<T, T>(url, data, config),
  
  // File upload with progress
  upload: <T>(url: string, file: File, onProgress?: (progress: number) => void) => {
    const formData = new FormData()
    formData.append('file', file)
    
    return getApi().post<T, any>(url, formData, {
      onUploadProgress: (progressEvent) => {
        if (onProgress && progressEvent.total) {
          const progress = Math.round((progressEvent.loaded * 100) / progressEvent.total)
          onProgress(progress)
        }
      }
    })
  },
  
  // Download file
  download: (url: string) => {
    return getApi().get(url, {
      responseType: 'blob',
      headers: {
        'X-Requested-With': ' XMLHttpRequest'
      }
    })
  },
}

export default apiRef
```

==========================================================================================
## FILE: bastehE_frontend/web/src/App.tsx
## SIZE: 15955 bytes
==========================================================================================

```tsx
import React, { useEffect, useMemo, useState } from 'react'
import {
  BrowserRouter,
  Routes,
  Route,
  Navigate,
  Link,
  useLocation,
  useNavigate,
} from 'react-router-dom'
import { useAuth } from './security/authProvider'
import DashboardPage from './features/DashboardPage'
import ChatPage from './features/ChatPage'
import InboxPage from './features/InboxPage'
import GroupsPage from './features/GroupsPage'
import ReportsPage from './features/ReportsPage'
import SettingsPage from './features/SettingsPage'

/* ---------------- Icons (inline SVG, no emoji) ---------------- */

function Icon({ d, className = 'h-5 w-5' }: { d: string; className?: string }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.8}
      strokeLinecap="round" strokeLinejoin="round" className={className} aria-hidden>
      <path d={d} />
    </svg>
  )
}

const PATHS = {
  grid: 'M3 3h7v7H3zM14 3h7v7h-7zM3 14h7v7H3zM14 14h7v7h-7z',
  chat: 'M21 11.5a8.38 8.38 0 0 1-.9 3.8 8.5 8.5 0 0 1-7.6 4.7 8.38 8.38 0 0 1-3.8-.9L3 21l1.9-5.7a8.38 8.38 0 0 1-.9-3.8 8.5 8.5 0 0 1 4.7-7.6 8.38 8.38 0 0 1 3.8-.9h.5a8.48 8.48 0 0 1 8 8v.5z',
  inbox: 'M22 12h-6l-2 3h-4l-2-3H2M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z',
  users: 'M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2M9 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM23 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75',
  chart: 'M18 20V10M12 20V4M6 20v-6',
  cog: 'M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6zM19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 1 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 1 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z',
  logout: 'M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9',
  target: 'M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20zM12 18a6 6 0 1 0 0-12 6 6 0 0 0 0 12zM12 14a2 2 0 1 0 0-4 2 2 0 0 0 0 4z',
  lock: 'M5 11h14a2 2 0 0 1 2 2v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-7a2 2 0 0 1 2-2zM7 11V7a5 5 0 0 1 10 0v4',
  user: 'M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2M12 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8z',
  check: 'M20 6 9 17l-5-5',
}

/* ---------------- Login ---------------- */

function LoginPage() {
  const { login, isLoading } = useAuth()
  const [identifier, setIdentifier] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)

  const onSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError(null)
    try {
      await login({ identifier, password })
    } catch {
      setError('ورود ناموفق بود. مشخصات را بررسی کنید.')
    }
  }

  const features = useMemo(
    () => [
      { d: PATHS.target, t: 'اهداف و وظایف', s: 'تعریف، پیگیری پیشرفت و مدیریت مهلت‌ها' },
      { d: PATHS.users, t: 'گروه‌ها و حریم خصوصی', s: 'کار تیمی با کنترل دقیق دسترسی' },
      { d: PATHS.chart, t: 'گزارش و داشبورد', s: 'نمای زنده از عملکرد شما و تیم' },
    ],
    [],
  )

  return (
    <div className="flex min-h-screen bg-slate-100">
      {/* Brand panel */}
      <div className="relative hidden w-[44%] overflow-hidden bg-slate-900 lg:block">
        <div className="absolute inset-0 bg-gradient-to-bl from-brand-700 via-slate-900 to-slate-950" />
        <div
          className="absolute inset-0 opacity-[0.15]"
          style={{
            backgroundImage:
              'radial-gradient(circle at 25% 25%, #fff 1.5px, transparent 1.5px)',
            backgroundSize: '28px 28px',
          }}
        />
        <div className="absolute -left-24 -top-24 h-96 w-96 rounded-full bg-brand-500/30 blur-3xl" />
        <div className="absolute -bottom-32 -right-16 h-[28rem] w-[28rem] rounded-full bg-indigo-500/20 blur-3xl" />
        <div className="relative flex h-full flex-col justify-between p-12 text-white">
          <div className="animate-fade-up flex items-center gap-3">
            <div className="flex h-12 w-12 items-center justify-center rounded-2xl bg-white/15 text-white backdrop-blur">
              <Icon d={PATHS.target} className="h-7 w-7" />
            </div>
            <div>
              <p className="text-lg font-bold leading-6">سامانه مدیریت اهداف</p>
              <p className="text-xs text-slate-300">نسخه سازمانی</p>
            </div>
          </div>
          <div className="space-y-6">
            <h2 className="animate-fade-up stagger-1 text-3xl font-bold leading-[2.6rem]">
              مدیریت اهداف، برنامه‌ریزی و همکاری تیمی
            </h2>
            <p className="animate-fade-up stagger-2 max-w-md text-sm leading-7 text-slate-300">
              همه اهداف، وظایف، گفتگوها و پیگیری‌ها — یکجا، امن و یکپارچه.
            </p>
            <ul className="space-y-4 pt-2">
              {features.map((f, i) => (
                <li
                  key={f.t}
                  className={`animate-fade-up stagger-${i + 3} flex items-start gap-3`}
                >
                  <span className="mt-0.5 flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-white/10 text-brand-200">
                    <Icon d={f.d} className="h-5 w-5" />
                  </span>
                  <span>
                    <span className="block text-sm font-medium">{f.t}</span>
                    <span className="block text-xs text-slate-400">{f.s}</span>
                  </span>
                </li>
              ))}
            </ul>
          </div>
          <p className="text-[11px] text-slate-500">امنیت چندلایه · احراز هویت دو عاملی · ثبت وقایع</p>
        </div>
      </div>

      {/* Form panel */}
      <div className="flex flex-1 items-center justify-center p-6">
        <form
          onSubmit={onSubmit}
          className="animate-fade-up w-full max-w-md rounded-3xl bg-white p-8 shadow-pop sm:p-10"
        >
          <div className="mb-8 text-center lg:hidden">
            <div className="mx-auto mb-3 flex h-12 w-12 items-center justify-center rounded-2xl bg-gradient-to-l from-brand-600 to-brand-500 text-white">
              <Icon d={PATHS.target} className="h-7 w-7" />
            </div>
            <p className="font-bold">سامانه مدیریت اهداف</p>
          </div>
          <h1 className="text-2xl font-bold">ورود به سامانه</h1>
          <p className="mb-6 mt-1 text-sm text-slate-500">برای ادامه وارد حساب کاربری خود شوید</p>

          <label className="label" htmlFor="login-id">
            نام کاربری یا کد ملی
          </label>
          <div className="relative mb-4">
            <span className="pointer-events-none absolute right-3.5 top-1/2 -translate-y-1/2 text-slate-400">
              <Icon d={PATHS.user} className="h-5 w-5" />
            </span>
            <input
              id="login-id"
              className="input pr-11"
              placeholder="مثلاً ali.rezaei"
              value={identifier}
              onChange={(e) => setIdentifier(e.target.value)}
              autoComplete="username"
            />
          </div>

          <label className="label" htmlFor="login-pw">
            گذرواژه
          </label>
          <div className="relative mb-2">
            <span className="pointer-events-none absolute right-3.5 top-1/2 -translate-y-1/2 text-slate-400">
              <Icon d={PATHS.lock} className="h-5 w-5" />
            </span>
            <input
              id="login-pw"
              className="input pr-11"
              placeholder="گذرواژه خود را وارد کنید"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="current-password"
            />
          </div>

          {error && (
            <p className="animate-fade-in mb-2 rounded-xl bg-red-50 px-4 py-2.5 text-xs text-red-600">
              {error}
            </p>
          )}

          <button type="submit" disabled={isLoading} className="btn-primary mt-4 w-full py-3">
            {isLoading ? (
              <>
                <span className="h-4 w-4 animate-spin rounded-full border-2 border-white/40 border-t-white" />
                در حال ورود…
              </>
            ) : (
              'ورود'
            )}
          </button>
          <p className="mt-5 text-center text-[11px] leading-5 text-slate-400">
            حساب پیش‌فرض مدیر: admin / admin123
          </p>
        </form>
      </div>
    </div>
  )
}

/* ---------------- Shell ---------------- */

const NAV = [
  { to: '/dashboard', label: 'داشبورد', icon: PATHS.grid },
  { to: '/chat', label: 'گفتگوها', icon: PATHS.chat },
  { to: '/inbox', label: 'صندوق ورودی', icon: PATHS.inbox },
  { to: '/groups', label: 'گروه‌ها', icon: PATHS.users },
  { to: '/reports', label: 'گزارش‌ها', icon: PATHS.chart },
  { to: '/settings', label: 'تنظیمات', icon: PATHS.cog },
]

function Sidebar({ onNav }: { onNav?: () => void }) {
  const { user, logout } = useAuth()
  const { pathname } = useLocation()
  const navigate = useNavigate()

  const doLogout = async () => {
    await logout()
    navigate('/login', { replace: true })
    onNav?.()
  }

  return (
    <div className="flex h-full flex-col bg-slate-900 text-white">
      <div className="flex items-center gap-3 px-5 pb-6 pt-6">
        <div className="flex h-11 w-11 items-center justify-center rounded-2xl bg-gradient-to-l from-brand-500 to-indigo-500 shadow-lg shadow-brand-900/40">
          <Icon d={PATHS.target} className="h-6 w-6" />
        </div>
        <div className="min-w-0">
          <p className="truncate text-sm font-bold">سامانه مدیریت اهداف</p>
          <p className="text-[11px] text-slate-400">نسخه سازمانی</p>
        </div>
      </div>
      <nav className="flex-1 space-y-1 overflow-y-auto px-3">
        {NAV.map((n) => {
          const active = pathname === n.to || (n.to === '/dashboard' && pathname === '/')
          return (
            <Link
              key={n.to}
              to={n.to}
              onClick={onNav}
              className={`navlink ${active ? 'navlink-active' : ''}`}
            >
              <Icon d={n.icon} />
              <span>{n.label}</span>
            </Link>
          )
        })}
      </nav>
      <div className="border-t border-white/10 p-4">
        <div className="mb-3 flex items-center gap-3 rounded-xl bg-white/5 p-3">
          <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-gradient-to-l from-brand-400 to-indigo-400 text-sm font-bold">
            {(user?.display_name || user?.username || '?').slice(0, 1)}
          </div>
          <div className="min-w-0 flex-1">
            <p className="truncate text-sm font-medium">
              {user?.display_name || user?.username}
            </p>
            <p className="truncate text-[11px] text-slate-400" dir="ltr">
              {user?.national_id_masked}
            </p>
          </div>
        </div>
        <button onClick={() => void doLogout()} className="navlink w-full text-red-300 hover:text-red-200">
          <Icon d={PATHS.logout} />
          <span>خروج از حساب</span>
        </button>
      </div>
    </div>
  )
}

function Topbar({ onMenu }: { onMenu: () => void }) {
  const today = useMemo(
    () =>
      new Intl.DateTimeFormat('fa-IR', {
        weekday: 'long',
        day: 'numeric',
        month: 'long',
      }).format(new Date()),
    [],
  )
  return (
    <header className="sticky top-0 z-10 border-b border-slate-200/70 bg-white/80 backdrop-blur">
      <div className="flex items-center gap-3 px-4 py-3 sm:px-6">
        <button onClick={onMenu} className="btn-ghost p-2 lg:hidden" aria-label="menu">
          <svg viewBox="0 0 24 24" className="h-6 w-6" fill="none" stroke="currentColor"
            strokeWidth={2} strokeLinecap="round">
            <path d="M4 6h16M4 12h16M4 18h16" />
          </svg>
        </button>
        <div className="min-w-0 flex-1">
          <p className="truncate text-sm font-bold text-slate-800">سامانه مدیریت اهداف</p>
          <p className="text-[11px] text-slate-400">{today}</p>
        </div>
        <span className="badge bg-emerald-50 text-emerald-700">
          <span className="ml-1.5 h-2 w-2 rounded-full bg-emerald-500" />
          متصل
        </span>
      </div>
    </header>
  )
}

function Shell() {
  const [open, setOpen] = useState(false)
  return (
    <div className="flex min-h-screen bg-slate-100">
      <aside className="sticky top-0 hidden h-screen w-72 shrink-0 lg:block">
        <Sidebar />
      </aside>
      {open && (
        <div className="fixed inset-0 z-20 lg:hidden">
          <div className="animate-fade-in absolute inset-0 bg-slate-900/50" onClick={() => setOpen(false)} />
          <aside className="animate-fade-in absolute bottom-0 right-0 top-0 w-72">
            <Sidebar onNav={() => setOpen(false)} />
          </aside>
        </div>
      )}
      <div className="flex min-w-0 flex-1 flex-col">
        <Topbar onMenu={() => setOpen(true)} />
        <main className="flex-1">
          <Routes>
            <Route path="/dashboard" element={<DashboardPage />} />
            <Route path="/chat" element={<ChatPage />} />
            <Route path="/inbox" element={<InboxPage />} />
            <Route path="/groups" element={<GroupsPage />} />
            <Route path="/reports" element={<ReportsPage />} />
            <Route path="/settings" element={<SettingsPage />} />
            <Route path="/" element={<Navigate to="/dashboard" replace />} />
            <Route path="*" element={<Navigate to="/dashboard" replace />} />
          </Routes>
        </main>
      </div>
    </div>
  )
}

/* ---------------- App ---------------- */

function App() {
  const { isAuthenticated, isLoading, init } = useAuth()

  useEffect(() => {
    void init()
  }, [init])

  // When the API layer reports an unrecoverable 401 (refresh failed or no
  // refresh token), drop the persisted "authenticated" flag so the user is
  // sent back to the login page instead of a dead dashboard.
  useEffect(() => {
    const onExpired = () => {
      useAuth.getState().forceLogout()
    }
    window.addEventListener('auth:expired', onExpired)
    return () => window.removeEventListener('auth:expired', onExpired)
  }, [])

  if (isLoading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-slate-100">
        <div className="flex flex-col items-center gap-4">
          <div className="h-12 w-12 animate-spin rounded-full border-[3px] border-brand-200 border-t-brand-600" />
          <p className="text-sm text-slate-500">در حال بارگذاری…</p>
        </div>
      </div>
    )
  }

  return (
    <BrowserRouter>
      <Routes>
        {isAuthenticated ? (
          <Route path="/*" element={<Shell />} />
        ) : (
          <>
            <Route path="/login" element={<LoginPage />} />
            <Route path="*" element={<Navigate to="/login" replace />} />
          </>
        )}
      </Routes>
    </BrowserRouter>
  )
}

export default App
```

==========================================================================================
## FILE: bastehE_frontend/web/src/AuthLayout.tsx
## SIZE: 10764 bytes
==========================================================================================

```tsx
import React from 'react'
import { Routes, Route, Navigate } from 'react-router-dom'
import { useAuth } from '../security/authProvider'
import { useNavigate } from 'react-router-dom'

/** Authentication layout - shows login/register pages */
export const AuthLayout: React.FC = () => {
  const { isLoading, login, init } = useAuth()
  const navigate = useNavigate()
  
  useEffect(() => {
    init()
  }, [init])
  
  if (isLoading) {
    return (
      <div className="rtl min-h-screen flex items-center justify-center bg-gray-100 dark:bg-gray-900">
        <div className="text-center">
          <div className="spinner spinner-sm" />
          <p className="mt-4 text-gray-600 dark:text-gray-300">
            ورود در حال انجام است...
          </p>
        </div>
      </div>
    )
  }
  
  // If already authenticated, redirect to dashboard
  if (!isLoading) {
    const user = localStorage.getItem('user') 
      ? JSON.parse(localStorage.getItem('user') as string)
      : null
    
    if (user) {
      return <Navigate to="/dashboard" replace /> 
    }
  }
  
  return (
    <div className="rtl min-h-screen bg-gray-100 dark:bg-gray-900">
      <div className="max-w-md mx-auto p-6">
        <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-6">
          ورود به سامانه
        </h2>
        
        <Routes>
          <Route path="/login" element={<LoginPage />} />
          <Route path="/mfa-challenge" element={<MfaChallengePage />} />
          <Route path="/register" element={<RegisterPage />} />
          <Route path="/" element={<Navigate to="/login" replace />} />
        </Routes>
      </div>
    </div>
  )
}

/** Login page */
const LoginPage: React.FC = () => {
  const [credentials, setCredentials] = React.useState({
    identifier: '',
    password: '',
    rememberMe: false
  })
  const [error, setError] = React.useState<string | null>(null)
  const { login } = useAuth()
  const navigate = useNavigate()
  
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError(null)
    
    try {
      await login(credentials as any)
      navigate('/dashboard')
    } catch (err: any) {
      setError(err.message || 'ورود ناموفق')
    }
  }
  
  return (
    <div className="space-y-4">
      <form onSubmit={handleSubmit} className="space-y-2">
        <div>
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">
            شماره ملی / نام کاربری
          </label>
          <input
            className="mt-1 block w-full rounded-md border-gray-300 shadow-sm dark:bg-gray-700 dark:text-white"
            type="text"
            placeholder="0012345678 یا نام کاربری"
            required
            {...credentials.identifier ? {} : 'autoFocus'}
            onChange={(e) => 
              setCredentials({ ...credentials, identifier: e.target.value })}
          />
        </div>
        
        <div>
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">
            رمز عبور
          </label>
          <input
            className="mt-1 block w-full rounded-md border-gray-300 shadow-sm dark:bg-gray-700 dark:text-white"
            type="password"
            required
            placeholder="••••••••"
            {...credentials.password ? {} : ''}
            onChange={(e) => 
              setCredentials({ ...credentials, password: e.target.value })}
          />
        </div>
        
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <input
              type="checkbox"
              checked={credentials.rememberMe}
              onChange={(e) => 
                setCredentials({ ...credentials, rememberMe: e.target.checked })}
              className="rounded border-gray-300 w-4 h-4 dark:border-gray-600"
            />
            <span className="text-sm text-gray-600 dark:text-gray-300">
              مرا به خاطر بسپار
            </span>
          </div>
          
          <button
            type="submit"
            className="px-4 py-2 rounded-md bg-gray-900 text-white font-medium hover:bg-gray-800 dark:hover:bg-gray-600 transition-colors"
          >
            ورود
          </button>
        </div>
      </form>
      
      {error && (
        <div className="bg-red-100 dark:bg-red-900 text-red-800 dark:text-red-200 rounded px-3 py-2 text-sm mt-4">
          {error}
        </div>
      )}
      
      <p className="text-center text-sm text-gray-500 dark:text-gray-400">
        یا با حساب_company وارد شوید
      </p>
    </div>
  )
}

/** MFA challenge page */
const MfaChallengePage: React.FC = () => {
  const [code, setCode] = React.useState('')
  const { verifyMFA } = useAuth()
  const navigate = useNavigate()
  const { mfaMethod } = useAuth()
  
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    
    try {
      await verifyMFA(code)
      navigate('/dashboard')
    } catch (err: any) {
      setCode('') // Clear on error
      alert(err.message || 'کد MFA نامعتبر است')
    }
  }
  
  if (!mfaMethod) {
    return <p className="text-center text-gray-600">خطا: مfa چالش باز نیست</p>
  }
  
  return (
    <div className="rtl max-w-md mx-auto p-6">
      <h3 className="text-xl font-bold text-gray-900 dark:text-white mb-6">
        اعتبارسنجی امنیتی
      </h3>
      <p className="text-gray-600 dark:text-gray-300 mb-8">
        برای ادامه ورود، کد MFA خود را وارد کنید.<br />
        {mfaMethod === 'totp' && (
          <p className="text-sm">
            می‌توانید از اپلیکیشن Authenticator (Google Authenticator, Authy و...) استفاده کنید
          </p>
        )}
      </p>
      
      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">
            کد MFA
          </label>
          <input
            value={code}
            onChange={(e) => setCode(e.target.value)}
            type="text"
            maxLength="6"
            className="mt-1 block w-full rounded-md border-gray-300 shadow-sm dark:bg-gray-700 dark:text-white"
            placeholder="123456"
            required
          />
        </div>
        
        <button
          type="submit"
          className="w-full py-2 rounded-md bg-primary text-white font-medium hover:bg-secondary dark:hover:bg-primary-transition"
        >
          تأیید کد
        </button>
      </form>
    </div>
  )
}

/** Register page */
const RegisterPage: React.FC = () => {
  const [credentials, setCredentials] = React.useState({
    nationalId: '',
    username: '',
    password: '',
    displayName: ''
  })
  const [error, setError] = React.useState<string | null>(null)
  const { register } = useAuth()
  const navigate = useNavigate()
  
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError(null)
    
    try {
      await register(credentials as any)
      navigate('/dashboard')
    } catch (err: any) {
      setError(err.message || 'ثبت‌نام ناموفق')
    }
  }
  
  return (
    <div className="rtl max-w-md mx-auto p-6">
      <h3 className="text-xl font-bold text-gray-900 dark:text-white mb-6">
        ثبت‌نام جدید
      </h3>
      
      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">
            کد ملی
          </label>
          <input
            value={credentials.nationalId}
            onChange={(e) => 
              setCredentials({ ...credentials, nationalId: e.target.value })}
            type="text"
            placeholder="0012345678"
            maxLength="10"
            className="mt-1 block w-full rounded-md border-gray-300 shadow-sm dark:bg-gray-700 dark:text-white"
            required
          />
          <p className="text-xs text-gray-500">
            فرمت: ۱۰ رقم با عدد کنترلی
          </p>
        </div>
        
        <div>
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">
            نام کاربری
          </label>
          <input
            value={credentials.username}
            onChange={(e) => 
              setCredentials({ ...credentials, username: e.target.value })}
            type="text"
            placeholder="username"
            className="mt-1 block w-full rounded-md border-gray-300 shadow-sm dark:bg-gray-700 dark:text-white"
            required
          />
        </div>
        
        <div>
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">
            نام نمایشی
          </label>
          <input
            value={credentials.displayName}
            onChange={(e) => 
              setCredentials({ ...credentials, displayName: e.target.value })}
            type="text"
            placeholder="علی رضایی"
            className="mt-1 block w-full rounded-md border-gray-300 shadow-sm dark:bg-gray-700 dark:text-white"
            required
          />
        </div>
        
        <div>
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">
            رمز عبور
          </label>
          <input
            value={credentials.password}
            onChange={(e) => 
              setCredentials({ ...credentials, password: e.target.value })}
            type="password"
            placeholder="••••••••"
            className="mt-1 block w-full rounded-md border-gray-300 shadow-sm dark:bg-gray-700 dark:text-white"
            required
          />
        </div>
        
        <button
          type="submit"
          className="w-full py-2 rounded-md bg-primary text-white font-medium hover:bg-secondary dark:hover:bg-primary-transition"
        >
          ثبت‌نام
        </button>
      </form>
      
      {error && (
        <div className="bg-red-100 dark:bg-red-900 text-red-800 dark:text-red-200 rounded px-3 py-2 text-sm mt-2">
          {error}
        </div>
      )}
    </div>
  )
}

export default AuthLayout
```

==========================================================================================
## FILE: bastehE_frontend/web/src/components/sidebar.tsx
## SIZE: 3761 bytes
==========================================================================================

```tsx
import React from 'react'
import { Link } from 'react-router-dom'
import { useAuth } from '../security/authProvider'
import { usePermissionCache } from '../hooks/usePermissionCache'

/** Sidebar navigation for the dashboard */
export const Sidebar: React.FC<{ user?: User }> = ({ user }) => {
  const { isAuthenticated } = useAuth()
  const { hasPermission } = usePermissionCache()
  const navigate = useNavigate()

  // Navigation items with permissions
  const navItems = [
    { key: 'dashboard', label: 'داشبورد', icon: 'Layout', requiredPerm: undefined },
    { key: 'goals', label: 'اهداف', icon: 'TrendingUp', requiredPerm: 'goal.view' },
    { key: 'calendar', label: 'تقویم', icon: 'Calendar', requiredPerm: 'calendar.view' },
    { key: 'inbox', label: 'کارتابل', icon: 'MessageSquare', requiredPerm: 'inbox.view' },
    { key: 'chat', label: 'چت', icon: 'MessageCircle', requiredPerm: 'chat.view' },
    { key: 'reports', label: 'گزارش‌ها', icon: 'BarChart3', requiredPerm: 'report.view' },
    { key: 'widgets', label: 'ویجت‌ها', icon: 'Widgets', requiredPerm: 'widgets.manage' },
    { key: 'group-manager', label: 'مدیریت گروه', icon: 'Users', requiredPerm: 'group.manage' },
    { key: 'profile', label: 'پروفایل', icon: 'User', requiredPerm: undefined },
    { key: 'settings', label: 'تنظیمات', icon: 'Settings', requiredPerm: 'settings.manage' },
  ]

  return (
    <nav className="rtl bg-white dark:bg-gray-900 h-screen w-64 shadow-lg border2 border-gray-200 dark:border-gray-700 flex-shrink-0">
      <div className="p-4 border-b border-gray-200 dark:border-gray-700">
        <h2 className="text-lg font-bold text-gray-900 dark:text-white">
          {user?.display_name || 'کاربر'}
        </h2>
        <p className="text-sm text-gray-500 dark:text-gray-400">
          {user?.username || ''}
        </p>
      </div>
      
      <ul className="mt-4 space-y-1 max-h-screen overflow-y-auto">
        {navItems.map((item) => {
          const isVisible = !item.requiredPerm || hasPermission(item.requiredPerm)
          
          if (!isVisible) return null
          
          const isActive = item.key === 'dashboard' // Simplified active check
          
          return (
            <li key={item.key} className={`transition-colors duration-200 ${
              isActive 
                ? 'bg-gray-100 dark:bg-gray-800' 
                : 'hover:bg-gray-50 dark:hover:bg-gray-800'}
              rounded-md px-3 py-2 flex items-center gap-3`}
            >
              <Link
                to={`/${item.key}`}
                className="flex items-center gap-2 text-sm text-gray-700 dark:text-gray-300 hover:text-primary transition-colors"
                onClick={() => navigate(`/${item.key}`)}
              >
                <svg className="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" d={item.icon} />
                </svg>
                <span>{item.label}</span>
              </Link>
            </li>
          )
        })}
      </ul>
      
      <div className="mt-6 p-3 border-t border-gray-200 dark:border-gray-700">
        <button
          onClick={() => {
            // Logout
            useAuth.getState().logout()
            navigate('/login')
          }
          className="w-full py-2 rounded-md bg-red-100 text-red-800 text-sm font-medium hover:bg-red-200 dark:bg-red-900 dark:hover:bg-red-200 transition-colors"
        >
          خروج
        </button>
      </div>
    </nav>
  )
}

/** User type import */
import type { User } from '../types'
```

==========================================================================================
