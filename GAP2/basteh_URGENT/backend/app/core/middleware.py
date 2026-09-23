import time
import uuid
from typing import Optional, Dict, Any, Callable
from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
import structlog

from app.core.config import settings
from app.core.errors import APIError


# Context variable for request context
# In a real implementation, this would use contextvars
_request_context: Optional[Dict[str, Any]] = None


class RequestContext:
    """Holds request-level context data."""
    
    def __init__(self):
        self.request_id: str = str(uuid.uuid4())
        self.user_id: Optional[str] = None
        self.user_ip: Optional[str] = None
        self.mac_address: Optional[str] = None
        self.device_fingerprint: Optional[str] = None
        self.session_id: Optional[str] = None
        self.correlation_id: Optional[str] = None
        self.geo_location: Optional[Dict] = None
        self.start_time: Optional[float] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "request_id": self.request_id,
            "user_id": self.user_id,
            "user_ip": self.user_ip,
            "mac_address": self.mac_address,
            "device_fingerprint": self.device_fingerprint,
            "session_id": self.session_id,
            "correlation_id": self.correlation_id,
        }


def set_request_context(ctx: RequestContext):
    """Set the current request context (for within-request use)."""
    global _request_context
    _request_context = ctx.to_dict()


def get_request_context() -> Optional[Dict[str, Any]]:
    """Get the current request context."""
    return _request_context


# --- Middleware Chain ---

class RequestIDMiddleware(BaseHTTPMiddleware):
    """Add unique Request-ID to every request."""
    
    async def dispatch(self, request: Request, call_next):
        request_id = str(uuid.uuid4())
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to every response."""
    
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        
        # Content Security Policy
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        
        # CSP - lock down
        csp = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://apis.google.com; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: https:; "
            "connect-src 'self' wss://; "
            "font-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "object-src 'none'"
        )
        response.headers["Content-Security-Policy"] = csp
        
        # HSTS (only in production with HTTPS)
        if settings.ENV == "production":
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        
        return response


class IPFilterMiddleware(BaseHTTPMiddleware):
    """IP allow/deny list filtering."""
    
    def __init__(self, app, allow_ips: list = None, deny_ips: list = None):
        super().__init__(app)
        self.allow_ips = allow_ips or []
        self.deny_ips = deny_ips or []
    
    async def dispatch(self, request: Request, call_next):
        client_ip = request.client.host if request.client else "unknown"
        
        # Check deny list first
        if self.deny_ips and client_ip in self.deny_ips:
            return JSONErrorResponse(
                error="IP_ADDRESS_DENIED",
                message="Your IP address has been denied access."
            ), 403
        
        # Check allow list (if specified)
        if self.allow_ips and client_ip not in self.allow_ips:
            return JSONErrorResponse(
                error="IP_ADDRESS_NOT_ALLOWED",
                message="Your IP address is not allowed to access this API."
            ), 403
        
        return await call_next(request)


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Simple rate limiting middleware using in-memory store."""
    
    def __init__(self, app, limit: str = "100/minute", key_func: Callable = None):
        super().__init__(app)
        self.limit = limit
        self.key_func = key_func or self._default_key_func
        self._counters: Dict[str, list] = {}
    
    def _default_key_func(self, request: Request) -> str:
        """Default key function based on IP + endpoint."""
        ip = request.client.host if request.client else "unknown"
        path = request.url.path
        return f"{ip}:{path}"
    
    async def dispatch(self, request: Request, call_next):
        key = self.key_func(request)
        now = time.time()
        
        # Initialize counter if needed
        if key not in self._counters:
            self._counters[key] = []
        
        # Clean old entries
        self._counters[key] = [t for t in self._counters[key] if now - t < 60]
        
        # Check limit
        if len(self._counters[key]) >= 100:  # Simplified - real impl uses Redis
            return JSONErrorResponse(
                error="RATE_LIMIT_EXCEEDED",
                message="Too many requests. Please try again later."
            ), 429
        
        # Add current request
        self._counters[key].append(now)
        
        return await call_next(request)


class JSONErrorResponse:
    """Helper to create consistent JSON error responses."""
    
    def __init__(self, error: str, message: str, status_code: int = 400):
        self.error = error
        self.message = message
        self.status_code = status_code
    
    def __call__(self):
        return JSONResponse(
            status_code=self.status_code,
            content={
                "error": self.error,
                "message": self.message,
                "success": False
            }
        )


# Register middlewares function
def register_middlewares(app: Any) -> None:
    """Register all middleware chains in the correct order."""
    # CORS - first
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    # Trusted host
    if settings.ALLOWED_HOSTS:
        app.add_middleware(
            TrustedHostMiddleware,
            allowed_hosts=settings.ALLOWED_HOSTS
        )
    
    # Security headers
    app.add_middleware(SecurityHeadersMiddleware)
    
    # Request ID
    app.add_middleware(RequestIDMiddleware)
    
    # Rate limiting
    app.add_middleware(
        RateLimitMiddleware,
        limit=settings.RATE_LIMIT_DEFAULT,
    )


# Export middleware classes
__all__ = [
    "RequestIDMiddleware", "SecurityHeadersMiddleware", 
    "IPFilterMiddleware", "RateLimitMiddleware",
    "RequestContext", "set_request_context", "get_request_context",
    "register_middlewares"
]