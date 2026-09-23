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
