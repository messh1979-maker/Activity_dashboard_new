"""
tests/ssoldap/test_sso_login_service.py

اجرا:
    cd backend && pytest tests/ssoldap/ -v
"""

from __future__ import annotations

import asyncio
import functools
from uuid import uuid4

import pytest

from app.core.errors import APIError
from app.modules.ssoldap.services.ldap_service import (
    LdapAuthError,
    LdapUserInfo,
    escape_ldap_filter_value,
    map_groups_to_roles,
)
from app.modules.ssoldap.services.sso_login_service import SsoLoginService


def run_async(fn):
    @functools.wraps(fn)
    def wrapper(*a, **k):
        return asyncio.run(fn(*a, **k))
    return wrapper


# ── توابع خالص (بدون وابستگی به ldap3/شبکه) ──────────────────

def test_escape_blocks_ldap_filter_injection():
    malicious = "admin)(|(uid=*"
    escaped = escape_ldap_filter_value(malicious)
    assert "(" not in escaped.replace(r"\28", "")
    assert ")" not in escaped.replace(r"\29", "")
    assert r"\28" in escaped and r"\29" in escaped and r"\2a" in escaped


def test_map_groups_to_roles_is_case_and_space_insensitive():
    group_map = {
        "CN=Managers,OU=Groups,DC=corp,DC=local": "manager",
        "CN=Admins, OU=Groups,DC=corp,DC=local": "admin",
    }
    member_of = [
        "cn=managers, ou=groups,dc=corp,dc=local",
        "CN=SomeOtherGroup,OU=Groups,DC=corp,DC=local",
    ]
    assert map_groups_to_roles(member_of, group_map) == ["manager"]


def test_map_groups_to_roles_no_duplicates():
    group_map = {"CN=A,DC=x": "role_a"}
    member_of = ["CN=A,DC=x", "cn=a,dc=x"]
    assert map_groups_to_roles(member_of, group_map) == ["role_a"]


# ── SsoLoginService (با LdapService/AuthService/UserRepo فیک) ─

class FakeUser:
    def __init__(self, **kw):
        self.id = uuid4()
        self.sso_enabled = kw.get("sso_enabled", True)
        self.is_active = kw.get("is_active", True)
        self.ldap_dn = None
        self.ldap_object_guid = None


class FakeSession:
    def __init__(self):
        self.added = []

    def add(self, obj):
        self.added.append(obj)


class FakeUserRepo:
    def __init__(self, user=None):
        self._user = user
        self.session = FakeSession()
        self.commits = 0

    async def get_by_national_id(self, nid):
        return self._user

    async def add(self, user):
        self._user = user

    async def commit(self):
        self.commits += 1


class FakeLdapService:
    def __init__(self, info=None, error=None):
        self._info = info
        self._error = error

    async def authenticate(self, username, password):
        if self._error:
            raise self._error
        return self._info


class FakeAuthService:
    async def _generate_tokens(self, user):
        return {"access_token": "fake", "user": {"id": str(user.id)}}


class FakeSettings:
    LDAP_AUTO_PROVISION = False
    LDAP_GROUP_ROLE_MAP: dict = {}


SAMPLE_LDAP_INFO = LdapUserInfo(
    dn="CN=Ali Rezaei,OU=Users,DC=corp,DC=local",
    object_guid="11111111-1111-1111-1111-111111111111",
    sam_account_name="ali",
    display_name="Ali Rezaei",
    national_id="0499370899",
    member_of=[],
)


@run_async
async def test_ldap_bind_failure_propagates_as_api_error():
    service = SsoLoginService(
        FakeSettings(), FakeUserRepo(),
        FakeLdapService(error=LdapAuthError("INVALID_CREDENTIALS", "bad")),
        FakeAuthService(),
    )
    with pytest.raises(APIError) as exc_info:
        await service.login("ali", "wrongpass")
    assert exc_info.value.error_code == "INVALID_CREDENTIALS"


@run_async
async def test_unprovisioned_user_rejected_when_auto_provision_off():
    service = SsoLoginService(
        FakeSettings(), FakeUserRepo(user=None),
        FakeLdapService(info=SAMPLE_LDAP_INFO), FakeAuthService(),
    )
    with pytest.raises(APIError) as exc_info:
        await service.login("ali", "pw")
    assert exc_info.value.error_code == "USER_NOT_PROVISIONED"


@run_async
async def test_sso_disabled_for_user_is_rejected():
    existing = FakeUser(sso_enabled=False)
    service = SsoLoginService(
        FakeSettings(), FakeUserRepo(user=existing),
        FakeLdapService(info=SAMPLE_LDAP_INFO), FakeAuthService(),
    )
    with pytest.raises(APIError) as exc_info:
        await service.login("ali", "pw")
    assert exc_info.value.error_code == "SSO_DISABLED_FOR_USER"


@run_async
async def test_inactive_account_is_rejected():
    existing = FakeUser(sso_enabled=True, is_active=False)
    service = SsoLoginService(
        FakeSettings(), FakeUserRepo(user=existing),
        FakeLdapService(info=SAMPLE_LDAP_INFO), FakeAuthService(),
    )
    with pytest.raises(APIError) as exc_info:
        await service.login("ali", "pw")
    assert exc_info.value.error_code == "ACCESS_DENIED"


@run_async
async def test_successful_login_returns_tokens():
    existing = FakeUser(sso_enabled=True, is_active=True)
    service = SsoLoginService(
        FakeSettings(), FakeUserRepo(user=existing),
        FakeLdapService(info=SAMPLE_LDAP_INFO), FakeAuthService(),
    )
    tokens = await service.login("ali", "pw")
    assert tokens["access_token"] == "fake"
