"""Security headers on every HTTP response (architecture 11 / 1.5)."""
from __future__ import annotations

from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.config import settings

# Pure JSON API: nothing may be loaded or framed from an API response.
_API_CSP = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
# Swagger UI / ReDoc need inline scripts and a CDN (non-production only).
_DOCS_CSP = (
    "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "img-src 'self' data: https://fastapi.tiangolo.com; frame-ancestors 'none'"
)
_DOCS_PATHS = ("/docs", "/redoc")


class SecurityHeadersMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        path = scope.get("path", "")
        is_docs = (not settings.is_production) and path.startswith(_DOCS_PATHS)

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                h = MutableHeaders(scope=message)
                h["X-Content-Type-Options"] = "nosniff"
                h["X-Frame-Options"] = "DENY"
                h["Referrer-Policy"] = "strict-origin-when-cross-origin"
                h["Cross-Origin-Resource-Policy"] = "same-site"
                h["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
                h["Content-Security-Policy"] = _DOCS_CSP if is_docs else _API_CSP
                if not is_docs:
                    h.setdefault("Cache-Control", "no-store")  # tokens/PII in bodies
                if settings.is_production:
                    h["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
            await send(message)

        await self.app(scope, receive, send_wrapper)
