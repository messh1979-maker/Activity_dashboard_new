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
