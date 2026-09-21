"""Error types and exception handlers (architecture 5.1: uniform error format).

Body shape (unchanged, so existing clients keep working)::

    {"error": "<CODE>", "message": "<fa text>", "success": false, "request_id": "..."}
"""
from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import ValidationError
from starlette import status
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.config import settings
from app.core.context import get_context

logger = logging.getLogger(__name__)


class APIError(Exception):
    """Base class for API errors."""

    def __init__(
        self,
        error_code: str,
        message: str,
        status_code: int = status.HTTP_400_BAD_REQUEST,
        details: Optional[Dict] = None,
        headers: Optional[Dict[str, str]] = None,
    ):
        super().__init__(message)
        self.error_code = error_code
        self.message = message
        self.status_code = status_code
        self.details = details or {}
        self.headers = headers

    def to_dict(self) -> Dict[str, Any]:
        return {
            "error": self.error_code,
            "message": self.message,
            "success": False,
            "request_id": get_context().request_id,
            **self.details,
        }


class ValidationErrorAPI(APIError):
    def __init__(self, details: dict | None = None, message: str = "داده‌های ورودی نامعتبر هستند."):
        super().__init__("VALIDATION_ERROR", message,
                         status.HTTP_422_UNPROCESSABLE_ENTITY, details)


class AuthenticationError(APIError):
    def __init__(self, message: str = "احراز هویت ناموفق بود.", error_code: str = "AUTHENTICATION_ERROR"):
        super().__init__(error_code, message, status.HTTP_401_UNAUTHORIZED,
                         headers={"WWW-Authenticate": "Bearer"})


class AuthorizationError(APIError):
    def __init__(self, message: str = "شما دسترسی لازم را ندارید.", details: dict | None = None):
        super().__init__("AUTHORIZATION_ERROR", message, status.HTTP_403_FORBIDDEN, details)


class PermissionDeniedError(APIError):
    """RBAC denial (architecture 7.4 / 12.4). ``code`` is the machine reason,
    e.g. ``CANNOT_GRANT_EQUAL_OR_HIGHER_ROLE`` or ``CANNOT_SELF_ASSIGN``."""

    def __init__(self, code: str = "PERMISSION_DENIED", message: str | None = None, **details: Any):
        self.code = code
        super().__init__(code, message or "شما دسترسی لازم را ندارید.",
                         status.HTTP_403_FORBIDDEN, details or None)


class NotFoundError(APIError):
    """404 - also used instead of 403 when existence must not leak (5.1)."""

    def __init__(self, resource: str = "منبع"):
        super().__init__("NOT_FOUND", f"{resource} یافت نشد.", status.HTTP_404_NOT_FOUND)


class ConflictError(APIError):
    def __init__(self, message: str = "تعارض در منبع."):
        super().__init__("CONFLICT_ERROR", message, status.HTTP_409_CONFLICT)


class RateLimitError(APIError):
    def __init__(self, retry_after: int = 60):
        super().__init__(
            "RATE_LIMIT_EXCEEDED",
            "درخواست‌های بیش از حد ارسال شده است. لطفاً کمی بعد تلاش کنید.",
            status.HTTP_429_TOO_MANY_REQUESTS,
            {"retry_after": retry_after},
            headers={"Retry-After": str(retry_after)},
        )


class MFARequiredError(APIError):
    def __init__(self, method: str = "totp"):
        super().__init__("MFA_REQUIRED", f"احراز هویت دو مرحله‌ای لازم است ({method}).",
                         status.HTTP_401_UNAUTHORIZED)


class DeviceNotTrustedError(APIError):
    def __init__(self):
        super().__init__("DEVICE_NOT_TRUSTED",
                         "ورود از این دستگاه مجاز نیست. با مدیر سیستم تماس بگیرید.",
                         status.HTTP_403_FORBIDDEN)


class PrivacyHiddenError(APIError):
    """Hidden by privacy settings; 404 so existence does not leak."""

    def __init__(self):
        super().__init__("PRIVACY_HIDDEN", "این داده به دلیل تنظیمات حریم خصوصی قابل نمایش نیست.",
                         status.HTTP_404_NOT_FOUND)


# ── Handlers ────────────────────────────────────────────────────────────

def _body(code: str, message: Any, **extra: Any) -> dict:
    return {"error": code, "message": message, "success": False,
            "request_id": get_context().request_id, **extra}


def _simplify_errors(exc: RequestValidationError | ValidationError) -> list[str]:
    out = []
    for err in exc.errors():
        loc = " -> ".join(str(x) for x in err.get("loc", []) if x != "body")
        out.append(f"{loc}: {err.get('msg', 'خطا')}" if loc else str(err.get("msg", "خطا")))
    return out


async def validation_exception_handler(request: Request, exc: RequestValidationError | ValidationError):
    details = _simplify_errors(exc)
    logger.warning("Validation error on %s %s: %s", request.method, request.url.path, details)
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content=_body("VALIDATION_ERROR", "داده‌های ورودی نامعتبر هستند.", details=details),
    )


async def api_error_handler(request: Request, exc: APIError):
    logger.warning("API error on %s %s: %s - %s", request.method, request.url.path,
                   exc.error_code, exc.message)
    return JSONResponse(status_code=exc.status_code, content=exc.to_dict(), headers=exc.headers)


async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    """Also catches Starlette's own 404/405 (FastAPI's HTTPException subclasses it)."""
    detail = exc.detail if isinstance(exc.detail, str) else "خطا"
    code = {401: "AUTHENTICATION_ERROR", 403: "AUTHORIZATION_ERROR", 404: "NOT_FOUND",
            405: "METHOD_NOT_ALLOWED"}.get(exc.status_code, "HTTP_ERROR")
    if exc.status_code >= 500:
        logger.error("HTTP %s on %s %s: %s", exc.status_code, request.method, request.url.path, detail)
    return JSONResponse(status_code=exc.status_code, content=_body(code, detail),
                        headers=getattr(exc, "headers", None))


async def general_exception_handler(request: Request, exc: Exception):
    """Unexpected error: log with stack trace, never leak internals in production."""
    logger.exception("Unexpected error on %s %s", request.method, request.url.path)
    message = str(exc) if (settings.DEBUG and not settings.is_production) else "خطای داخلی سرور"
    return JSONResponse(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                        content=_body("INTERNAL_SERVER_ERROR", message))


def register_exception_handlers(app: FastAPI) -> None:
    app.add_exception_handler(RequestValidationError, validation_exception_handler)
    app.add_exception_handler(ValidationError, validation_exception_handler)
    app.add_exception_handler(APIError, api_error_handler)
    app.add_exception_handler(StarletteHTTPException, http_exception_handler)
    app.add_exception_handler(Exception, general_exception_handler)
