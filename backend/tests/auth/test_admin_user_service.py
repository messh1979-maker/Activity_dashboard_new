"""
tests/auth/test_admin_user_service.py

تست‌های واحد برای AdminUserService — بدون DB واقعی (Fake repo)، هم‌خانواده
با tests/rbac/test_role_assignment_escalation.py (همان الگوی run_async).

اجرا:
    cd backend && pytest tests/auth/test_admin_user_service.py -v
"""

from __future__ import annotations

import asyncio
import functools
from uuid import uuid4

import pytest

from app.core.errors import APIError
from app.modules.auth.admin_ports import (
    AdminCreateUserRequest,
    AdminUpdateUserRequest,
    BulkLoginModeRequest,
)
from app.modules.auth.services.admin_user_service import AdminUserService


def run_async(fn):
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        return asyncio.run(fn(*args, **kwargs))
    return wrapper


class FakeActor:
    def __init__(self, id):
        self.id = id


class FakeUser:
    def __init__(self, id, username, password_hash="hashed:x", auth_mode="local",
                 sso_enabled=False, token_version=0, is_active=True,
                 national_id_last4="1234", display_name="Test",
                 mfa_enabled=False, last_login_at=None):
        self.id = id
        self.username = username
        self.password_hash = password_hash
        self.auth_mode = auth_mode
        self.sso_enabled = sso_enabled
        self.token_version = token_version
        self.is_active = is_active
        self.national_id_last4 = national_id_last4
        self.display_name = display_name
        self.mfa_enabled = mfa_enabled
        self.last_login_at = last_login_at
        self.must_change_password = False


class FakeSession:
    def __init__(self):
        self.added = []

    def add(self, obj):
        self.added.append(obj)


class FakeUserRepo:
    def __init__(self, users=None):
        self._users = {u.id: u for u in (users or [])}
        self.session = FakeSession()
        self.commits = 0

    async def get(self, uid):
        return self._users.get(uid)

    async def get_by_username(self, username):
        return next((u for u in self._users.values() if u.username == username), None)

    async def get_by_national_id(self, nid):
        return None

    async def add(self, user):
        self._users[user.id] = user

    async def commit(self):
        self.commits += 1


# کد ملی معتبر (چک‌سام درست) صرفاً برای تست
VALID_NATIONAL_ID = "0499370899"


@run_async
async def test_create_user_rejects_invalid_national_id():
    admin_id = uuid4()
    repo = FakeUserRepo([FakeUser(id=admin_id, username="admin")])
    svc = AdminUserService(repo)

    with pytest.raises(APIError) as exc_info:
        await svc.create_user(FakeActor(admin_id), AdminCreateUserRequest(
            username="newguy", national_id="1234567890",
            display_name="New Guy", initial_password="longpassword123",
        ))
    assert exc_info.value.error_code == "INVALID_NATIONAL_ID"


@run_async
async def test_create_user_rejects_duplicate_username():
    admin_id = uuid4()
    repo = FakeUserRepo([FakeUser(id=admin_id, username="admin")])
    svc = AdminUserService(repo)
    actor = FakeActor(admin_id)

    await svc.create_user(actor, AdminCreateUserRequest(
        username="newguy", national_id=VALID_NATIONAL_ID,
        display_name="New Guy", initial_password="longpassword123",
    ))

    with pytest.raises(APIError) as exc_info:
        await svc.create_user(actor, AdminCreateUserRequest(
            username="newguy", national_id=VALID_NATIONAL_ID,
            display_name="Someone Else", initial_password="anotherpassword123",
        ))
    assert exc_info.value.error_code == "USERNAME_EXISTS"


@run_async
async def test_cannot_deactivate_self():
    admin_id = uuid4()
    repo = FakeUserRepo([FakeUser(id=admin_id, username="admin")])
    svc = AdminUserService(repo)

    with pytest.raises(APIError) as exc_info:
        await svc.update_user(FakeActor(admin_id), admin_id, AdminUpdateUserRequest(is_active=False))
    assert exc_info.value.error_code == "CANNOT_DEACTIVATE_SELF"


@run_async
async def test_deactivate_other_user_revokes_sessions():
    admin_id, target_id = uuid4(), uuid4()
    target = FakeUser(id=target_id, username="bob")
    repo = FakeUserRepo([FakeUser(id=admin_id, username="admin"), target])
    svc = AdminUserService(repo)

    await svc.update_user(FakeActor(admin_id), target_id, AdminUpdateUserRequest(is_active=False))

    assert target.is_active is False
    assert target.token_version == 1  # نشست‌ها باطل شدند


@run_async
async def test_bulk_login_mode_all_three_failure_kinds_plus_success():
    admin = FakeUser(id=uuid4(), username="admin", auth_mode="local")
    normal_user = FakeUser(id=uuid4(), username="ali", auth_mode="sso")  # هم رمز محلی دارد هم sso
    sso_only_user = FakeUser(id=uuid4(), username="sara", password_hash=None, auth_mode="sso")
    missing_id = uuid4()

    repo = FakeUserRepo([admin, normal_user, sso_only_user])
    svc = AdminUserService(repo)
    actor = FakeActor(admin.id)

    # خاموش‌کردن sso (اجبار به local) برای همه — sso_only_user باید رد شود
    request = BulkLoginModeRequest(
        user_ids=[normal_user.id, sso_only_user.id, missing_id, admin.id],
        sso_enabled=False, revoke_sessions=True,
    )
    result = await svc.bulk_change_login_mode(actor, request)

    assert normal_user.id in result.updated
    assert normal_user.auth_mode == "local"
    assert normal_user.token_version == 1

    failure_codes = {f.code for f in result.failed}
    assert failure_codes == {"NOT_FOUND", "CANNOT_MODIFY_SELF", "NO_LOCAL_PASSWORD"}
    assert sso_only_user.auth_mode == "sso"  # دست‌نخورده ماند


@run_async
async def test_bulk_login_mode_rejects_more_than_500():
    admin = FakeUser(id=uuid4(), username="admin")
    repo = FakeUserRepo([admin])
    svc = AdminUserService(repo)

    class OversizedRequest:
        user_ids = [uuid4() for _ in range(501)]
        sso_enabled = True
        revoke_sessions = False

    with pytest.raises(APIError) as exc_info:
        await svc.bulk_change_login_mode(FakeActor(admin.id), OversizedRequest())
    assert exc_info.value.error_code == "TOO_MANY_USERS"
