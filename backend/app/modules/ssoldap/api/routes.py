"""
app/modules/ssoldap/api/routes.py

دو endpoint سند (بخش ۵.۲):
  - POST /auth/sso/ldap-login   → کامل (این پچ)
  - GET  /auth/sso/negotiate    → فقط اسکلت 401 (Kerberos/SPNEGO کامل
    نیاز به Keytab و محیط AD واقعی برای پیاده‌سازی/تست دارد — طبق
    توصیه‌ی خودِ سند در جدول ریسک، این باید یک Spike جدا باشد)
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Response
from pydantic import BaseModel

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


@router.post("/ldap-login")
async def ldap_login(
    payload: LdapLoginRequest,
    service: SsoLoginService = Depends(get_sso_login_service),
):
    return await service.login(payload.username, payload.password)


@router.get("/negotiate")
async def negotiate(response: Response):
    """اسکلت — بدنه‌ی واقعی SPNEGO/gssapi هنوز پیاده نشده (نیاز به Keytab واقعی).

    طبق دیاگرام سند، این endpoint باید همیشه با 401 و هدر
    ``WWW-Authenticate: Negotiate`` پاسخ دهد تا کلاینت تیکت Kerberos
    بگیرد و در تلاش بعدی با ``Authorization: Negotiate <SPNEGO>``
    برگردد. آن مسیر (``gssapi.accept_sec_context``) TODO است.
    """
    response.headers["WWW-Authenticate"] = "Negotiate"
    response.status_code = 401
    return {
        "error": {
            "code": "NOT_IMPLEMENTED",
            "message": "Kerberos/SPNEGO SSO هنوز پیاده نشده. از /auth/sso/ldap-login استفاده کنید.",
        }
    }
