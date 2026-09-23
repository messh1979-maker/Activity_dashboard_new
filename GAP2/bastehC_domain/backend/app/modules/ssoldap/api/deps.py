"""app/modules/ssoldap/api/deps.py

Composition root for the SSO/LDAP module (this file was the missing
piece that made ``POST /auth/sso/ldap-login`` raise NotImplementedError).

Builds SsoLoginService from the real AuthService / UserRepository /
LdapService, mirroring app/core/dependencies.get_auth_service.
"""

from __future__ import annotations

from fastapi import Depends

from app.core.dependencies import (
    get_session_dep,
    get_user_repository,
    get_auth_service,
)
from app.modules.ssoldap.services.ldap_service import LdapService
from app.modules.ssoldap.services.sso_login_service import SsoLoginService
from app.core.config import settings


def get_ldap_service() -> LdapService:
    """Build LdapService bound to app settings (ldap3 imported lazily)."""
    return LdapService(settings)


def get_sso_login_service(
    session=Depends(get_session_dep),
    user_repo=Depends(get_user_repository),
    ldap_service: LdapService = Depends(get_ldap_service),
    auth_service=Depends(get_auth_service),
) -> SsoLoginService:
    """Compose SsoLoginService for the ldap-login endpoint."""
    return SsoLoginService(
        settings=settings,
        user_repo=user_repo,
        ldap_service=ldap_service,
        auth_service=auth_service,
        role_assignment_service=None,  # wired when LDAP_GROUP_ROLE_MAP is enabled
    )