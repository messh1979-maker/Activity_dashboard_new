"""L7 rate limiting (architecture 1.1 / 11).

* Limits come from settings (``RATE_LIMIT_DEFAULT`` / ``RATE_LIMIT_AUTH``) -
  the old middleware ignored them and hard-coded 100.
* Backend: Redis when reachable (shared by all workers), otherwise a bounded
  in-process sliding window. The in-memory backend evicts idle keys, so it can
  no longer grow without bound.
* Keyed by client IP + bucket (auth endpoints have their own, stricter bucket)
  - not by path, which let an attacker multiply their quota by rotating URLs.
"""
from __future__ import annotations

import logging
import time
from collections import deque
from typing import Optional, Protocol

from starlette.types import ASGIApp, Receive, Scope, Send

from app.core.config import settings
from app.core.middleware._http import client_ip, send_error

logger = logging.getLogger("core.rate_limit")

_PERIODS = {"second": 1, "minute": 60, "hour": 3600, "day": 86400}
_AUTH_PREFIXES = (
    "/api/v1/auth/login", "/api/v1/auth/register", "/api/v1/auth/refresh",
    "/api/v1/auth/password", "/api/v1/auth/mfa", "/api/v1/auth/sso",
)


def parse_limit(spec: str) -> tuple[int, int]:
    """``"100/minute"`` -> (100, 60)."""
    try:
        count, period = spec.strip().split("/")
        return int(count), _PERIODS[period.strip().lower()]
    except (ValueError, KeyError):
        raise ValueError(f"invalid rate limit spec: {spec!r} (expected N/second|minute|hour|day)")


class Limiter(Protocol):
    async def hit(self, key: str, limit: int, window: int) -> tuple[bool, int]:
        """Register a hit. Returns (allowed, retry_after_seconds)."""


class MemoryLimiter:
    def __init__(self, max_keys: int = 50_000) -> None:
        self._hits: dict[str, deque[float]] = {}
        self._max_keys = max_keys
        self._last_sweep = time.monotonic()

    async def hit(self, key: str, limit: int, window: int) -> tuple[bool, int]:
        now = time.monotonic()
        self._sweep(now, window)
        q = self._hits.setdefault(key, deque())
        while q and now - q[0] >= window:
            q.popleft()
        if len(q) >= limit:
            return False, max(1, int(window - (now - q[0])) + 1)
        q.append(now)
        return True, 0

    def _sweep(self, now: float, window: int) -> None:
        if now - self._last_sweep < 30 and len(self._hits) < self._max_keys:
            return
        self._last_sweep = now
        for k in [k for k, q in self._hits.items() if not q or now - q[-1] >= max(window, 60)]:
            del self._hits[k]
        if len(self._hits) >= self._max_keys:  # hard cap: drop oldest half
            for k in list(self._hits)[: self._max_keys // 2]:
                del self._hits[k]


class RedisLimiter:
    """Fixed-window counter shared across workers; falls back on any error."""

    def __init__(self, url: str, fallback: Limiter) -> None:
        import redis.asyncio as aioredis

        self._redis = aioredis.from_url(url, socket_connect_timeout=0.5, socket_timeout=0.5)
        self._fallback = fallback

    async def hit(self, key: str, limit: int, window: int) -> tuple[bool, int]:
        try:
            bucket = int(time.time()) // window
            rkey = f"rl:{key}:{bucket}"
            pipe = self._redis.pipeline()
            pipe.incr(rkey)
            pipe.expire(rkey, window + 1)
            count, _ = await pipe.execute()
            if count > limit:
                return False, window - (int(time.time()) % window) or 1
            return True, 0
        except Exception as exc:  # Redis down must not take the API down
            logger.warning("redis rate limiter unavailable (%s); using in-memory", exc)
            return await self._fallback.hit(key, limit, window)


def build_limiter() -> Limiter:
    memory = MemoryLimiter()
    if settings.ENV == "testing":
        return memory
    try:
        return RedisLimiter(settings.redis_url, memory)
    except Exception:  # redis package missing / bad URL
        return memory


class RateLimitMiddleware:
    def __init__(self, app: ASGIApp, limiter: Optional[Limiter] = None,
                 default: Optional[str] = None, auth: Optional[str] = None) -> None:
        self.app = app
        self.limiter = limiter or build_limiter()
        self.default = parse_limit(default or settings.RATE_LIMIT_DEFAULT)
        self.auth = parse_limit(auth or settings.RATE_LIMIT_AUTH)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if (scope["type"] != "http" or not settings.RATE_LIMIT_ENABLED
                or scope["method"] == "OPTIONS"):
            await self.app(scope, receive, send)
            return
        path = scope.get("path", "")
        if path in ("/health", "/ready"):
            await self.app(scope, receive, send)
            return
        bucket, (limit, window) = (("auth", self.auth) if path.startswith(_AUTH_PREFIXES)
                                   else ("default", self.default))
        allowed, retry_after = await self.limiter.hit(
            f"{bucket}:{client_ip(scope)}", limit, window)
        if not allowed:
            await send_error(
                scope, receive, send, status=429, code="RATE_LIMIT_EXCEEDED",
                message="درخواست‌های بیش از حد ارسال شده است. لطفاً کمی بعد تلاش کنید.",
                headers={"Retry-After": str(retry_after)})
            return
        await self.app(scope, receive, send)
