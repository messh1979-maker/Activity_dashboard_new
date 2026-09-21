"""
tests/rbac/test_permission_service.py

اجرا:
    cd backend && pytest tests/rbac/test_permission_service.py -v
"""

from __future__ import annotations

import asyncio
import functools
from uuid import uuid4

from app.modules.rbac.services.permission_service import PermissionService


def run_async(fn):
    @functools.wraps(fn)
    def wrapper(*a, **k):
        return asyncio.run(fn(*a, **k))
    return wrapper


class FakeRedis:
    def __init__(self):
        self.store: dict[str, str] = {}
        self.setex_calls = 0
        self.delete_calls = 0

    async def get(self, key):
        return self.store.get(key)

    async def setex(self, key, ttl, value):
        self.setex_calls += 1
        self.store[key] = value

    async def delete(self, key):
        self.delete_calls += 1
        self.store.pop(key, None)


class BrokenRedis(FakeRedis):
    async def get(self, key):
        raise ConnectionError("redis down")


class FakeResult:
    def __init__(self, rows):
        self._rows = rows

    def fetchall(self):
        return self._rows


class FakeSession:
    def __init__(self, rows):
        self._rows = rows
        self.db_query_count = 0

    async def execute(self, *a, **k):
        self.db_query_count += 1
        return FakeResult(self._rows)


@run_async
async def test_second_call_hits_cache_not_db():
    user_id = uuid4()
    redis = FakeRedis()
    session = FakeSession(rows=[("goal.create",), ("goal.read",)])
    service = PermissionService(session, redis)

    first = await service.effective_permissions(user_id)
    second = await service.effective_permissions(user_id)

    assert first == second == {"goal.create", "goal.read"}
    assert session.db_query_count == 1  # دومین بار از کش آمد، نه DB
    assert redis.setex_calls == 1


@run_async
async def test_invalidate_forces_db_requery():
    user_id = uuid4()
    redis = FakeRedis()
    session = FakeSession(rows=[("goal.create",)])
    service = PermissionService(session, redis)

    await service.effective_permissions(user_id)
    await service.invalidate(user_id)
    await service.effective_permissions(user_id)

    assert session.db_query_count == 2
    assert redis.delete_calls == 1


@run_async
async def test_redis_outage_falls_back_to_db_without_crashing():
    user_id = uuid4()
    session = FakeSession(rows=[("x.y",)])
    service = PermissionService(session, BrokenRedis())

    perms = await service.effective_permissions(user_id)

    assert perms == {"x.y"}


@run_async
async def test_no_redis_configured_still_works():
    """اگر Redis تزریق نشود (None)، سرویس باید بدون کش درست کار کند."""
    user_id = uuid4()
    session = FakeSession(rows=[("a.b",), ("c.d",)])
    service = PermissionService(session, redis_client=None)

    perms = await service.effective_permissions(user_id)

    assert perms == {"a.b", "c.d"}
    assert session.db_query_count == 1
