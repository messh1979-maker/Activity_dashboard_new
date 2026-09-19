import traceback
import logging
from typing import Any, Dict, Optional
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from starlette import status
from pydantic import ValidationError

from app.core.config import settings

logger = logging.getLogger(__name__)


class APIError(Exception):
    """Base class for API errors."""
    
    def __init__(
        self, 
        error_code: str, 
        message: str, 
        status_code: int = status.HTTP_400_BAD_REQUEST,
        details: Optional[Dict] = None
    ):
        self.error_code = error_code
        self.message = message
        self.status_code = status_code
        self.details = details or {}
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "error": self.error_code,
            "message": self.message,
            "success": False,
            **self.details
        }


# Specific error classes
class ValidationErrorAPI(APIError):
    """Pydantic validation error."""
    def __init__(self, details: dict):
        super().__init__(
            error_code="VALIDATION_ERROR",
            message="داده‌های ورودی نامعتبر هستند.",
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            details=details
        )


class AuthenticationError(APIError):
    """Authentication failed."""
    def __init__(self, message: str = "احراز هویت_FAILED."):
        super().__init__(
            error_code="AUTHENTICATION_ERROR",
            message=message,
            status_code=status.HTTP_401_UNAUTHORIZED
        )


class AuthorizationError(APIError):
    """Authorization denied."""
    def __init__(self, message: str = "شما دسترسی لازم را ندارید."):
        super().__init__(
            error_code="AUTHORIZATION_ERROR",
            message=message,
            status_code=status.HTTP_403_FORBIDDEN
        )


class NotFoundError(APIError):
    """Resource not found (404 vs 403 distinction)."""
    def __init__(self, resource: str = "منبع"):
        super().__init__(
            error_code="NOT_FOUND",
            message=f"{resource} یافت نشد.",
            status_code=status.HTTP_404_NOT_FOUND
        )


class ConflictError(APIError):
    """Resource conflict."""
    def __init__(self, message: str = "Resource conflict."):
        super().__init__(
            error_code="CONFLICT_ERROR",
            message=message,
            status_code=status.HTTP_409_CONFLICT
        )


class RateLimitError(APIError):
    """Rate limit exceeded."""
    def __init__(self, retry_after: int = 60):
        super().__init__(
            error_code="RATE_LIMIT_EXCEEDED",
            message="چندین درخواست بیش از حد ارسال کردید. لطفاً منتظر بمانید.",
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            details={"retry_after": retry_after}
        )


class MFARequiredError(APIError):
    """MFA verification required."""
    def __init__(self, method: str = "totp"):
        super().__init__(
            error_code="MFA_REQUIRED",
            message=f"احراز هویت دو عاملی لازم است ({method}).",
            status_code=status.HTTP_401_UNAUTHORIZED
        )


class DeviceNotTrustedError(APIError):
    """Device not trusted."""
    def __init__(self):
        super().__init__(
            error_code="DEVICE_NOT_TRUSTED",
            message="این دستگاه confiance نیست. با مدیر سیستم تماس بگیرید.",
            status_code=status.HTTP_403_FORBIDDEN
        )


class PrivacyHiddenError(APIError):
    """Data hidden due to privacy settings."""
    def __init__(self):
        super().__init__(
            error_code="PRIVACY_HIDDEN",
            message="این داده به دلیل تنظیمات حریم خصوصیvisibility پنهان است.",
            status_code=status.HTTP_404_NOT_FOUND  # 404 to avoid leaking existence
        )


# Exception handlers


async def validation_exception_handler(request: Request, exc: ValidationError):
    """Handle Pydantic validation errors."""
    errors = exc.errors()
    # Simplify error messages for Persian users
    simplified = []
    for error in errors:
        loc = " -> ".join(str(x) for x in error.get("loc", []))
        msg = error.get("msg", "خطا")
        simplified.append(f"{loc}: {msg}")
    
    logger.warning(
        f"Validation error on {request.method} {request.url}: {simplified}"
    )
    
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "error": "VALIDATION_ERROR",
            "message": "داده‌های ورودی نامعتبر هستند.",
            "details": simplified,
            "success": False
        }
    )


async def api_error_handler(request: Request, exc: APIError):
    """Handle custom API errors."""
    logger.warning(
        f"API error on {request.method} {request.url}: "
        f"{exc.error_code} - {exc.message}"
    )
    
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": exc.error_code,
            "message": exc.message,
            "success": False,
            **exc.details
        }
    )


async def http_exception_handler(request: Request, exc: HTTPException):
    """Handle FastAPI HTTP exceptions."""
    logger.error(
        f"HTTP error on {request.method} {request.url}: "
        f"{exc.status_code} - {exc.detail}"
    )
    
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": "HTTP_ERROR",
            "message": exc.detail,
            "success": False
        }
    )


async def general_exception_handler(request: Request, exc: Exception):
    """Handle unexpected errors - log and return generic error."""
    # In production, mask the details
    error_detail = str(exc) if settings.DEBUG else "خطای داخلی سرور"
    
    logger.exception(
        f"Unexpected error on {request.method} {request.url}: {exc}"
    )
    
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": "INTERNAL_SERVER_ERROR",
            "message": error_detail,
            "success": False,
            "request_id": getattr(getattr(request, "state", None),
                                "request_id", "unknown")
        }
    )


# Register all handlers
def register_exception_handlers(app: FastAPI):
    """Register all exception handlers with the FastAPI app."""
    app.add_exception_handler(ValidationError, validation_exception_handler)
    app.add_exception_handler(APIError, api_error_handler)
    app.add_exception_handler(HTTPException, http_exception_handler)
    app.add_exception_handler(Exception, general_exception_handler)