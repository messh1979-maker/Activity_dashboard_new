"""Async Redis utilities (architecture 1.1 / ADR-05).

Provides a small async ``RedisBroker`` used for cross-worker WebSocket
pub/sub and cache.  When Redis is unreachable (dev machines, testing) the
broker transparently degrades to an in-process fan-out so the app keeps
working in a single process - mirroring the rate-limiter fallback policy.
"""

from __future__ import annotations

import asyncio
import logging
import os
from typing import Any, AsyncIterator, Awaitable, Callable, Optional

from app.core.config import settings

logger = logging.getLogger("core.redis")

_missing = object()


def _redis_disabled() -> bool:
    return os.getenv("REDIS_DISABLED", "").lower() in ("1", "true", "yes")


class RedisBroker:
    """Thin async pub/sub + kv facade with in-memory fallback.

    ``publish`` / ``subscribe`` are safe to call from multiple tasks.
    Subscribers receive string payloads via an async iterator.
    """

    def __init__(self) -> None:
        self._pool: Any = None
        self._fallback = _InMemoryFanout()
        self._disabled = _redis_disabled()

    # --- connection management ---

    async def connect(self) -> None:
        if self._disabled:
            logger.info("redis disabled via REDIS_DISABLED; using in-memory pub/sub")
            return
        try:
            import redis.asyncio as aioredis

            self._pool = aioredis.from_url(
                settings.redis_url,
                socket_connect_timeout=1.0,
                socket_timeout=1.0,
                encoding="utf-8",
                decode_responses=True,
            )
            await self._pool.ping()
            logger.info("connected to redis at %s", settings.redis_url)
        except Exception as exc:
            logger.warning("redis unavailable (%s); using in-memory pub/sub", exc)
            self._pool = None

    async def close(self) -> None:
        if self._pool is not None:
            try:
                await self._pool.aclose()
            except Exception:  # pragma: no cover - cleanup only
                pass
            self._pool = None

    @property
    def available(self) -> bool:
        return self._pool is not None

    @property
    def client(self) -> Any:
        """Low-level redis client (rate limiter/cache); None when unavailable."""
        return self._pool

    # --- kv (for WS rate limiting / caching) ---

    async def incr_expire(self, key: str, ttl: int) -> int:
        """Atomic INCR + EXPIRE via redis when available (in-memory fallback)."""
        if self._pool is not None:
            try:
                pipe = self._pool.pipeline()
                pipe.incr(key)
                pipe.expire(key, ttl)
                count, _ = await pipe.execute()
                return count
            except Exception as exc:
                logger.warning("redis incr failed (%s); falling back to memory", exc)
                self._pool = None
        return self._fallback.incr_expire(key, ttl)

    # --- pub/sub ---

    async def publish(self, channel: str, message: str) -> None:
        if self._pool is not None:
            try:
                await self._pool.publish(channel, message)
                return
            except Exception as exc:
                logger.warning("redis publish failed (%s); falling back to memory", exc)
                self._pool = None
        await self._fallback.publish(channel, message)

    async def subscribe(self, channel: str) -> AsyncIterator[str]:
        """Yield message strings from a Redis pub/sub (or in-memory) channel."""
        iterator: AsyncIterator[str] | None = None
        if self._pool is not None:
            try:
                pubsub = self._pool.pubsub()
                await pubsub.subscribe(channel)
                iterator = _RedisStreamAdapter(pubsub)
            except Exception as exc:
                logger.warning("redis subscribe failed (%s); falling back to memory", exc)
                self._pool = None
        if iterator is None:
            iterator = self._fallback.subscribe(channel)
        async for message in iterator:
            yield message


class _RedisStreamAdapter:
    """Adapts aioredis pubsub messages into a plain async iterator of str."""

    def __init__(self, pubsub):
        self._pubsub = pubsub

    async def __aiter__(self):
        while True:
            msg = await self._pubsub.get_message(
                ignore_subscribe_messages=True, timeout=30.0
            )
            if msg is None:
                continue
            data = msg.get("data")
            if isinstance(data, bytes):
                data = data.decode("utf-8", errors="replace")
            if isinstance(data, str):
                yield data


class _InMemoryFanout:
    """Process-local topic fan-out (pub/sub parity when Redis is absent)."""

    def __init__(self) -> None:
        self._topics: dict[str, set[asyncio.Queue]] = {}
        self._lock = asyncio.Lock()

    async def publish(self, channel: str, message: str) -> None:
        async with self._lock:
            qs = list(self._topics.get(channel, ()))
        for q in qs:
            q.put_nowait(message)

    async def subscribe(self, channel: str) -> AsyncIterator[str]:
        q: asyncio.Queue = asyncio.Queue(maxsize=512)
        async with self._lock:
            self._topics.setdefault(channel, set()).add(q)
        try:
            while True:
                yield await q.get()
        finally:
            async with self._lock:
                s = self._topics.get(channel)
                if s is not None:
                    s.discard(q)
                    if not s:
                        self._topics.pop(channel, None)

    async def incr_expire(self, key: str, ttl: int) -> int:
        """Tiny TTL counter in memory (Redis parity for tests)."""
        async with self._lock:
            now = asyncio.get_running_loop().time()
            bucket = int(now)
            if getattr(self, "_rk", None) != key or getattr(self, "_rt", None) != bucket:
                self._rk, self._rt, self._rc = key, bucket, 0
            self._rc += 1
            return self._rc


_broker: Optional[RedisBroker] = None


def get_redis_broker() -> RedisBroker:
    """Return the process-wide broker (created lazily, safe for single proc)."""
    global _broker
    if _broker is None:
        _broker = RedisBroker()
    return _broker


async def redis_cache_get(key: str) -> Optional[str]:
    """Get a cached string (None on miss or when Redis is down)."""
    broker = get_redis_broker()
    if broker.client is not None:
        try:
            return await broker.client.get(key)
        except Exception:
            return None
    return None


async def redis_cache_set(key: str, value: str, ttl: int) -> None:
    """Best-effort cache write."""
    broker = get_redis_broker()
    if broker.client is not None:
        try:
            await broker.client.set(key, value, ex=ttl)
        except Exception:
            pass