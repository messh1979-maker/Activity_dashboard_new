"""Middleware chain (architecture 3.1 ``core/middleware/``).

Order, outermost first:

    RequestID -> SecurityHeaders -> CORS -> TrustedHost -> IPFilter
      -> RateLimit -> BodyGuard -> AuditContext -> application

CORS sits outside the filters so that 403/413/429 answers still carry CORS
headers (otherwise browsers report them as opaque network errors).
"""
from __future__ import annotations

from fastapi import FastAPI
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app.core.config import settings
from app.core.middleware.audit_context import AuditContextMiddleware
from app.core.middleware.body_guard import BodyGuardMiddleware
from app.core.middleware.ip_filter import IPFilterMiddleware
from app.core.middleware.rate_limit import RateLimitMiddleware
from app.core.middleware.request_id import RequestIDMiddleware
from app.core.middleware.security_headers import SecurityHeadersMiddleware


def register_middlewares(app: FastAPI) -> None:
    """Register the whole chain once. (``add_middleware``: last added = outermost.)"""
    app.add_middleware(AuditContextMiddleware)
    app.add_middleware(BodyGuardMiddleware)
    app.add_middleware(RateLimitMiddleware)
    app.add_middleware(IPFilterMiddleware, allow_ips=settings.IP_ALLOW_LIST,
                       deny_ips=settings.IP_DENY_LIST)
    if settings.ALLOWED_HOSTS:
        app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.ALLOWED_HOSTS)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-Request-ID",
                       "X-Correlation-ID", "Idempotency-Key", "If-Match",
                       "X-Device-Fingerprint", "X-Device-MAC", "X-Device-Nonce",
                       "X-Device-Timestamp", "X-Device-Signature",
                       "X-Device-MAC-Source", "X-Requested-With"],
        expose_headers=["X-Request-ID", "ETag", "Retry-After"],
    )
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(RequestIDMiddleware)


__all__ = [
    "register_middlewares", "RequestIDMiddleware", "SecurityHeadersMiddleware",
    "IPFilterMiddleware", "RateLimitMiddleware", "BodyGuardMiddleware",
    "AuditContextMiddleware",
]
