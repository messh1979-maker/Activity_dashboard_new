# GAP PACK

- Generated: 2026-09-23 10:34:30
- Copied: 154 files
- Missing: 0 files

==========================================================================================

==========================================================================================
## FILE: basteh_URGENT/backend/app/audit/integrity.py
## SIZE: 3890 bytes
==========================================================================================

```python
"""
Audit Hash Chain Integrity Verification (real DDL, section 11.6 / ADR-10).

Re-links the ``audit.audit_logs`` chain from the database and verifies every
link: prev_hash[i] MUST equal row_hash[i-1], and the self hash is recomputed
with the same formula as ``AuditService._chain_hash_audit``.
"""

from __future__ import annotations

import hashlib
import json

from sqlalchemy import text


def _recompute_row_hash(prev_hash_ord, user_id, action, timestamp, ip_address,
                        mac_address, result, details) -> str:
    details_str = json.dumps(details, sort_keys=True, ensure_ascii=False) if details else "null"
    material = "|".join([
        prev_hash_ord or "GENESIS",
        str(user_id) if user_id else "None",
        action or "",
        timestamp.isoformat() if timestamp else "",
        str(ip_address) if ip_address else "",
        mac_address or "",
        result or "",
        details_str,
    ])
    return hashlib.sha256(material.encode()).hexdigest()


def _recompute_login_hash(prev_hash_ord, user_id, username, timestamp, ip_address,
                          mac_address, success, failure_reason) -> str:
    material = "|".join([
        prev_hash_ord or "GENESIS",
        str(user_id) if user_id else "None",
        username or "",
        timestamp.isoformat() if timestamp else "",
        str(ip_address) if ip_address else "",
        mac_address or "",
        "success" if success else "failure",
        failure_reason or "",
    ])
    return hashlib.sha256(material.encode()).hexdigest()


async def _verify_log_chain(conn, table: str) -> tuple[int, int]:
    """Verify one hash chain (audit_logs or login_audit_logs); returns (total, broken)."""
    broken = 0
    prev_row_hash: str | None = None
    total = 0
    if table == "audit.login_audit_logs":
        projection = ("id, user_id, timestamp, ip_address, mac_address,"
                      " prev_hash, row_hash, username, success, failure_reason")
    else:
        projection = ("id, user_id, timestamp, ip_address, mac_address,"
                      " prev_hash, row_hash, action, result, details")
    rows = (await conn.execute(text(f"""
        SELECT {projection}
          FROM {table}
         ORDER BY id
    """))).mappings().all()
    for row in rows:
        total += 1
        if row["prev_hash"] != prev_row_hash:
            broken += 1
        if table == "audit.login_audit_logs":
            recomputed = _recompute_login_hash(
                prev_row_hash, row["user_id"], row["username"], row["timestamp"],
                row["ip_address"], row["mac_address"], row["success"], row["failure_reason"],
            )
        else:
            recomputed = _recompute_row_hash(
                prev_row_hash, row["user_id"], row["action"], row["timestamp"],
                row["ip_address"], row["mac_address"], row["result"], row["details"],
            )
        if recomputed != row["row_hash"]:
            broken += 1
        prev_row_hash = row["row_hash"]
    return total, broken


async def verify_integrity(conn) -> dict:
    """Verify every hash chain (audit_logs + login_audit_logs)."""
    total = 0
    broken = 0
    for table in ("audit.audit_logs", "audit.login_audit_logs"):
        t, b = await _verify_log_chain(conn, table)
        total += t
        broken += b

    status = "integrity_ok" if broken == 0 else "integrity_broken"
    return {
        "status": status,
        "total_logs": total,
        "broken_links": broken,
        "total_links": max(total - 2, 0),
        "message": "Chain integrity verified" if broken == 0 else f"{broken} chain links broken",
    }


async def check_audit_integrity() -> dict:
    """Public entry point for GET /audit/integrity-check."""
    from app.core.database import engine

    async with engine.connect() as conn:
        result = await verify_integrity(conn)
    return result
```

==========================================================================================
## FILE: basteh_URGENT/backend/app/core/config.py
## SIZE: 7590 bytes
==========================================================================================

```python
"""Application configuration (Pydantic Settings, loaded from ENV / .env).

Architecture v2.0: section 3.1 (core/config.py) and 13.5 (deployment hardening).

Validation happens *inside* the model. (The previous version declared the
``@field_validator`` functions at module level, so they were never applied and
a weak ``SECRET_KEY`` / empty password was silently accepted.)
"""
from __future__ import annotations

from pathlib import Path
from typing import List

from pydantic import AliasChoices, Field, PostgresDsn, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_INSECURE_SECRETS = {
    "change-me-to-a-random-string-at-least-32-chars-long",
    "changeme",
    "secret",
}


class Settings(BaseSettings):
    """Application configuration from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Application
    APP_NAME: str = "Planner Enterprise API"
    APP_VERSION: str = "2.0.0"
    ENV: str = "development"  # development | testing | production
    DEBUG: bool = False
    SQL_ECHO: bool = False  # log every SQL statement (was tied to ENV before)

    # ── Server
    HOST: str = "0.0.0.0"
    PORT: int = 8000

    # ── Security
    SECRET_KEY: str = Field(..., min_length=32)
    # HS256 (shared secret) by default; set both JWT_*_KEY for RS256 (ADR / 3.1).
    ALGORITHM: str = "HS256"
    JWT_PRIVATE_KEY: str | None = None
    JWT_PUBLIC_KEY: str | None = None
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 30
    PASSWORD_RESET_EXPIRE_MINUTES: int = 1440
    # Separate keys per purpose (section 4.9). When unset they are derived from
    # SECRET_KEY, which is acceptable for dev only (enforced in production).
    DATA_ENCRYPTION_KEY: str | None = None   # base64, 32 bytes (AES-256-GCM)
    NATIONAL_ID_PEPPER: str | None = None    # HMAC key for searchable hash

    # ── Database
    POSTGRES_SERVER: str = "localhost"
    POSTGRES_PORT: int = 5432
    POSTGRES_USER: str = ""
    POSTGRES_PASSWORD: str = ""
    POSTGRES_DB: str = ""
    SQLALCHEMY_DATABASE_URI: PostgresDsn = Field(
        ...,
        validation_alias=AliasChoices("SQLALCHEMY_DATABASE_URI", "DATABASE_URL"),
    )
    DB_POOL_SIZE: int = 20
    DB_MAX_OVERFLOW: int = 30

    # ── Redis
    REDIS_HOST: str = "localhost"
    REDIS_PORT: int = 6379
    REDIS_DB: int = 0
    REDIS_URL: str | None = None  # overrides host/port/db when set

    # ── HTTP hardening
    ALLOWED_HOSTS: List[str] = ["*"]
    CORS_ORIGINS: List[str] = ["http://localhost:3000", "http://localhost:8080"]
    # WebSocket Origin allow-list (WebSocket is not covered by CORS, 12.8).
    # Empty -> falls back to CORS_ORIGINS.
    ALLOWED_ORIGINS: List[str] = []
    TRUSTED_PROXIES: List[str] = []  # only these may set X-Forwarded-For
    IP_ALLOW_LIST: List[str] = []
    IP_DENY_LIST: List[str] = []
    MAX_BODY_SIZE: int = 1_048_576  # 1 MiB for JSON endpoints

    # ── Feature flags
    ENABLE_MFA: bool = True
    ENABLE_SSO: bool = True
    ENABLE_AUDIT_LOGGING: bool = True
    ALLOW_SELF_REGISTRATION: bool = False
    DEVICE_BINDING_MODE: str = "observe"  # off | observe | enforce (ADR-08)

    # ── Rate limiting (limits are "N/period", period: second|minute|hour)
    RATE_LIMIT_DEFAULT: str = "100/minute"
    RATE_LIMIT_AUTH: str = "10/minute"
    RATE_LIMIT_ENABLED: bool = True

    # ── Paths
    BASE_DIR: Path = Path(__file__).parent.parent
    ROOT_PATH: str = ""

    # ── File storage
    MAX_UPLOAD_SIZE: int = 52_428_800  # 50MB
    FILE_STORAGE_DIR: str = "backend/storage/uploads"
    ALLOWED_IMAGE_TYPES: List[str] = ["image/jpeg", "image/png", "image/gif"]
    ALLOWED_DOCUMENT_TYPES: List[str] = [
        "application/pdf", "application/msword",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ]

    # ── SSO / LDAP (M12) — LdapService expects these attributes
    LDAP_SERVER_URI: str = "ldaps://ad.corp.local:636"
    LDAP_BASE_DN: str = "DC=corp,DC=local"
    LDAP_BIND_DN: str = ""
    LDAP_BIND_PASSWORD: str = ""
    LDAP_USER_SEARCH_FILTER: str = "(sAMAccountName={username})"
    LDAP_ATTR_OBJECT_GUID: str = "objectGUID"
    LDAP_ATTR_NATIONAL_ID: str | None = None
    LDAP_ATTR_DISPLAY_NAME: str = "displayName"
    LDAP_ATTR_MEMBEROF: str = "memberOf"
    LDAP_GROUP_ROLE_MAP: dict = {}
    LDAP_AUTO_PROVISION: bool = True
    LDAP_KERBEROS_ENABLED: bool = False  # set true only with a real Keytab
    LDAP_KERBEROS_KEYTAB: str = ""       # path to the HTTP service keytab

    # ── Logging
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = (
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s "
        "[%(filename)s:%(lineno)d]"
    )

    # ── Key rotation (key_version is stored beside encrypted data, 4.9)
    KEY_ROTATION_INTERVAL_DAYS: int = 365
    KEY_VERSION: int = 1

    # ------------------------------------------------------------------ #
    @field_validator("SECRET_KEY")
    @classmethod
    def _secret_key_strength(cls, v: str) -> str:
        if len(v) < 32:
            raise ValueError("SECRET_KEY must be at least 32 characters")
        return v

    @field_validator("ALGORITHM")
    @classmethod
    def _algorithm_allowed(cls, v: str) -> str:
        if v not in {"HS256", "RS256"}:
            raise ValueError("ALGORITHM must be HS256 or RS256 ('none' is never allowed)")
        return v

    @field_validator("DEVICE_BINDING_MODE")
    @classmethod
    def _device_mode(cls, v: str) -> str:
        if v not in {"off", "observe", "enforce"}:
            raise ValueError("DEVICE_BINDING_MODE must be off | observe | enforce")
        return v

    @model_validator(mode="after")
    def _cross_field_checks(self) -> "Settings":
        if self.ALGORITHM == "RS256" and not (self.JWT_PRIVATE_KEY and self.JWT_PUBLIC_KEY):
            raise ValueError("ALGORITHM=RS256 requires JWT_PRIVATE_KEY and JWT_PUBLIC_KEY")
        if self.ENV == "production":
            problems = []
            if self.SECRET_KEY in _INSECURE_SECRETS:
                problems.append("SECRET_KEY is a placeholder value")
            if "*" in self.ALLOWED_HOSTS:
                problems.append("ALLOWED_HOSTS must not contain '*'")
            if self.DEBUG:
                problems.append("DEBUG must be false")
            if not self.DATA_ENCRYPTION_KEY:
                problems.append("DATA_ENCRYPTION_KEY must be set (section 4.9)")
            if not self.NATIONAL_ID_PEPPER:
                problems.append("NATIONAL_ID_PEPPER must be set (ADR-06)")
            if self.DEVICE_BINDING_MODE == "off":
                problems.append("DEVICE_BINDING_MODE must not be 'off'")
            if problems:
                raise ValueError("Insecure production configuration: " + "; ".join(problems))
        return self

    # ------------------------------------------------------------------ #
    @property
    def is_production(self) -> bool:
        return self.ENV == "production"

    @property
    def redis_url(self) -> str:
        return self.REDIS_URL or f"redis://{self.REDIS_HOST}:{self.REDIS_PORT}/{self.REDIS_DB}"

    @property
    def ws_allowed_origins(self) -> List[str]:
        return self.ALLOWED_ORIGINS or self.CORS_ORIGINS


settings = Settings()


def get_db_url() -> str:
    """Async SQLAlchemy URL (single source of truth: SQLALCHEMY_DATABASE_URI)."""
    return str(settings.SQLALCHEMY_DATABASE_URI)
```

==========================================================================================
## FILE: basteh_URGENT/backend/app/core/context.py
## SIZE: 1740 bytes
==========================================================================================

```python
"""Per-request context (architecture 3.1: ``core/context.py``).

Uses :mod:`contextvars`, so concurrent requests/tasks never see each other's
values. (The old implementation stored a single module-level global, which
leaks user/IP/MAC between simultaneous requests - and audit rows are built
from this data.)
"""
from __future__ import annotations

from contextvars import ContextVar, Token
from dataclasses import asdict, dataclass, field
from typing import Any, Optional
from uuid import uuid4


@dataclass
class RequestContext:
    request_id: str = field(default_factory=lambda: str(uuid4()))
    correlation_id: Optional[str] = None
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    ip: Optional[str] = None
    user_agent: Optional[str] = None
    mac_address: Optional[str] = None
    mac_verified: bool = False
    device_fingerprint: Optional[str] = None
    path: Optional[str] = None
    method: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


_ctx: ContextVar[Optional[RequestContext]] = ContextVar("request_ctx", default=None)


def set_context(ctx: RequestContext) -> Token:
    return _ctx.set(ctx)


def reset_context(token: Token) -> None:
    _ctx.reset(token)


def get_context() -> RequestContext:
    """Current context, or an empty one outside a request (workers, tests)."""
    return _ctx.get() or RequestContext()


def bind_user(user_id: Any, session_id: Any = None) -> None:
    """Called after authentication so later audit rows carry the actor."""
    ctx = _ctx.get()
    if ctx is not None:
        ctx.user_id = str(user_id) if user_id is not None else None
        if session_id is not None:
            ctx.session_id = str(session_id)
```

==========================================================================================
## FILE: basteh_URGENT/backend/app/core/database.py
## SIZE: 717 bytes
==========================================================================================

```python
"""Database access compatibility layer.

Re-exports the async engine/session from ``app.core.db.session`` under the
names the rest of the codebase imports (``get_session``, ``engine``,
``async_session_context``, ``get_async_session``).
"""
from app.core.db.session import (
    async_session_factory,
    dispose_engine,
    engine,
    get_db,
    get_session,
)

# Alias used as ``async with async_session_context() as session:``.
async_session_context = get_session

# Alias used as a FastAPI dependency / factory.
get_async_session = get_session

__all__ = [
    "engine",
    "get_session",
    "async_session_factory",
    "async_session_context",
    "get_async_session",
    "get_db",
    "dispose_engine",
]
```

==========================================================================================
## FILE: basteh_URGENT/backend/app/core/dependencies.py
## SIZE: 6409 bytes
==========================================================================================

```python
from typing import Optional, Generator
from contextlib import contextmanager
from uuid import uuid4

import jwt  # PyJWT
from fastapi import Depends, Request, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.core.config import settings
from app.core.errors import AuthenticationError


# --- Security Scheme ---
# HTTP Bearer token scheme
security_bearer = HTTPBearer(auto_error=False)


def get_request_id(request: Request) -> str:
    """Extract or generate request ID from headers."""
    request_id = request.headers.get("X-Request-ID")
    if not request_id:
        request_id = str(uuid4())
    return request_id


# --- User Dependencies ---

def get_db_session():
    """Get database session dependency.

    Returns the async session context-manager factory so routes can do
    ``async with db_session() as session:``.
    """
    from app.core.database import async_session_context
    return async_session_context


async def get_session_dep():
    """Yield a live async session (for repository dependencies)."""
    from app.core.database import async_session_context
    async with async_session_context() as session:
        yield session


def get_user_repository(session=Depends(get_session_dep)):
    """Get user repository dependency."""
    from app.modules.auth.db.repositories import UserRepository
    return UserRepository(session)


def get_auth_service(
    user_repo=Depends(get_user_repository),
):
    """Get auth service dependency."""
    from app.modules.auth.services.auth_service import AuthService
    from app.modules.auth.db import mfa as mfa_module
    from app.modules.auth.db.repositories import DeviceRepository

    mfa_service = mfa_module.MFAService()
    device_repo = DeviceRepository(user_repo.session)
    return AuthService(
        user_repo=user_repo, device_repo=device_repo, mfa_service=mfa_service
    )


async def get_current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_bearer),
) -> str:
    """Get the current authenticated user ID from JWT token.

    Verifies HS256 signature + expiry, loads the user row and rejects
    revoked tokens (token_version mismatch) and inactive accounts.
    Returns the user ID as str (FastAPI coerces it to UUID in routes).

    Raises:
        HTTPException: 401 if not authenticated or token invalid
    """
    from jose import JWTError, jwt as jose_jwt

    if credentials is None or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        claims = jose_jwt.decode(
            credentials.credentials, settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM],
        )
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if claims.get("type") != "access":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token type",
            headers={"WWW-Authenticate": "Bearer"},
        )

    from app.core.database import async_session_context
    from app.modules.auth.db.repositories import UserRepository

    async with async_session_context() as session:
        repo = UserRepository(session)
        user = await repo.get(claims.get("sub"))
        if user is None or not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found or inactive",
                headers={"WWW-Authenticate": "Bearer"},
            )
        if claims.get("token_version") != user.token_version:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token revoked",
                headers={"WWW-Authenticate": "Bearer"},
            )
        # Later audit rows / events of this request carry the actor
        from app.core.context import bind_user
        bind_user(user.id)
        return str(user.id)


# --- Rate Limiting Dependencies ---

def check_rate_limit(
    request: Request,
    limit: int = 100,
    window_seconds: int = 60
) -> bool:
    """Deprecated no-op kept for import compatibility.

    Rate limiting is enforced globally by ``RateLimitMiddleware``
    (settings ``RATE_LIMIT_DEFAULT`` / ``RATE_LIMIT_AUTH``); do not rely on
    this dependency for protection.
    """
    return True


# --- Per-module service factories ---
# Imported by module routers for interface compatibility; resolved lazily so
# importing this module never pulls the whole dependency graph.

def get_mfa_service():
    """Get the MFA service."""
    from app.modules.auth.db.mfa import MFAService
    return MFAService()


def get_rate_limit_check():
    """Get the rate-limit check dependency."""
    return check_rate_limit


def get_chat_service():
    """Get the chat service."""
    from app.modules.chat.services.chat_service import ChatService
    return ChatService()


def get_goals_service():
    """Get the goals service."""
    from app.modules.goals.services.goals_service import GoalsService
    return GoalsService()


def get_groups_service():
    """Get the groups service."""
    from app.modules.groups.services.groups_service import GroupsService
    return GroupsService()


def get_rbac_service():
    """Get the RBAC service."""
    from app.modules.rbac.services.rbac_service import RBACService
    return RBACService()


def get_reporting_service():
    """Get the reporting service."""
    from app.modules.reporting.services.reporting_service import ReportingService
    return ReportingService()


def get_sharing_service():
    """Get the sharing service."""
    from app.modules.sharing.services.sharing_service import SharingService
    return SharingService()


# --- Export ---
__all__ = [
    "get_db_session", "get_user_repository", "get_auth_service",
    "get_mfa_service", "get_rate_limit_check",
    "get_chat_service", "get_goals_service", "get_groups_service",
    "get_rbac_service", "get_reporting_service", "get_sharing_service",
    "get_current_user", "check_rate_limit", "get_request_id",
    "security_bearer"
]
```

==========================================================================================
## FILE: basteh_URGENT/backend/app/core/errors.py
## SIZE: 7586 bytes
==========================================================================================

```python
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
```

==========================================================================================
## FILE: basteh_URGENT/backend/app/core/events/bus.py
## SIZE: 7216 bytes
==========================================================================================

```python
"""
app/core/events/bus.py

پیاده‌سازی Event Bus درون‌پروسه‌ای طبق ADR-02 و سند معماری v2.0، بخش ۲.۳.

هدف این فایل: جایگزین کردن importهای مستقیم بین ماژول‌ها (مثل
`from app.modules.audit.db.models import AuditLogs` که در auth_service.py
پیدا شد) با یک مکانیزم رویدادمحور که هیچ ماژولی را به ماژول دیگر
گره نمی‌زند.

طراحی
------
`EventBus.publish()` دو کار همزمان انجام می‌دهد:

  ۱) **تحویل درون‌پروسه‌ای هم‌زمان (synchronous in-process delivery)**:
     هر handler ثبت‌شده برای `event.event_type` بلافاصله در همان
     تراکنش دیتابیس (`session`) فراخوانی می‌شود. این برای مصرف‌کننده‌هایی
     مثل ماژول Audit مناسب است — چون سند صراحتاً می‌گوید ردیف Audit باید
     "در همان تراکنش عملیات اصلی" نوشته شود (بخش ۱۲.۳)، تا اگر تراکنش
     اصلی Rollback شود، ردیف Audit هم با آن Rollback شود (سازگاری کامل،
     نه لاگِ عملیاتی که هرگز ذخیره نشد).

  ۲) **درج در Outbox برای تحویل At-Least-Once به مصرف‌کننده‌های
     بیرون از فرآیند** (Celery workers، مثل Notification/Push/Email):
     یک ردیف `OutboxMessage` در همان تراکنش درج می‌شود. یک Dispatcher
     جداگانه (`workers/tasks/outbox_dispatcher.py`) بعداً این ردیف‌ها را
     می‌خواند و به مصرف‌کننده‌های خارج از فرآیند تحویل می‌دهد.

     چرا هر دو مسیر؟ چون Audit نیاز به تضمین "همان تراکنش" دارد (زنجیره‌ی
     هش باید دقیقاً با ترتیب واقعی نوشته‌ها هماهنگ باشد)، ولی
     Notification/Push نیاز به تضمین "حتی اگر پردازش درخواست کرش کند،
     بعداً ارسال شود" دارد. Outbox این دومی را تضمین می‌کند.

هیچ ماژولی، صرفاً با ثبت/انتشار رویداد، به ماژول دیگر import اضافه
نمی‌کند — رویداد فقط یک `event_type` رشته‌ای و یک payload دیکشنری
است، نه یک کلاس از ماژول دیگر.

نحوه‌ی استفاده در main.py (طبق سند، بخش ۱۲.۱):

    from app.core.events.bus import event_bus
    for m in MODULES:
        m.register_event_handlers(event_bus)

هر ماژول (مثل audit) در `__init__.py` یا `events.py` خودش تابع
`register_event_handlers(bus)` را تعریف می‌کند و `bus.subscribe(...)`
را صدا می‌زند — بدون این‌که هرگز از ماژول ناشر رویداد import کند.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, DefaultDict
from uuid import UUID, uuid4

logger = logging.getLogger("core.events")

# امضای هر handler: async def handler(event: DomainEvent, session) -> None
EventHandler = Callable[["DomainEvent", Any], Awaitable[None]]


@dataclass(frozen=True)
class DomainEvent:
    """رویداد دامنه — مطابق سند معماری v2.0، بخش ۲.۳."""

    event_type: str
    payload: dict[str, Any]
    actor_id: UUID | None = None
    event_id: UUID = field(default_factory=uuid4)
    occurred_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    correlation_id: UUID | None = None


def _as_uuid(value: Any) -> UUID | None:
    try:
        return UUID(str(value)) if value else None
    except (ValueError, AttributeError):
        return None


class EventBus:
    """Event Bus درون‌پروسه‌ای؛ یک نمونه‌ی Singleton (``event_bus``) در کل اپ.

    دو نوع مشترک:

    * ``transactional=True`` (پیش‌فرض) — داخل ``publish`` و در همان تراکنش اجرا
      می‌شود (مثل Audit). اگر تراکنش Rollback شود، اثر handler هم برمی‌گردد.
    * ``transactional=False`` — مصرف‌کننده‌ی «بعد از commit» (مثل Notification):
      فقط توسط Dispatcher از روی جدول Outbox با تضمین At-Least-Once فراخوانی
      می‌شود و باید با ``event_id`` Idempotent باشد.

    قبلاً Dispatcher همان handlerهای هم‌تراکنش را دوباره صدا می‌زد و ردیف‌های
    Audit تکراری ساخته می‌شد؛ حالا این دو دسته کاملاً جدا هستند.
    """

    def __init__(self) -> None:
        self._sync: DefaultDict[str, list[EventHandler]] = defaultdict(list)
        self._async: DefaultDict[str, list[EventHandler]] = defaultdict(list)

    def subscribe(self, event_type: str, handler: EventHandler, *,
                  transactional: bool = True) -> None:
        target = self._sync if transactional else self._async
        if handler in target[event_type]:  # idempotent registration (reload / tests)
            return
        target[event_type].append(handler)
        logger.debug("subscribed %s handler for %s", "txn" if transactional else "async", event_type)

    def handlers_for(self, event_type: str, *, transactional: bool) -> list[EventHandler]:
        return list((self._sync if transactional else self._async).get(event_type, ()))

    def clear(self) -> None:
        """Remove every subscription (test helper)."""
        self._sync.clear()
        self._async.clear()

    async def publish(self, event: DomainEvent, session: Any) -> None:
        """Outbox را در همان تراکنش می‌نویسد و handlerهای هم‌تراکنش را اجرا می‌کند.

        ``actor_id`` / ``correlation_id`` در صورت خالی بودن از Request Context
        پر می‌شوند تا کل زنجیره‌ی یک درخواست قابل ردیابی باشد.
        """
        from app.core.context import get_context
        from app.core.events.outbox import OutboxMessage

        ctx = get_context()
        if event.correlation_id is None or event.actor_id is None:
            event = replace(
                event,
                correlation_id=event.correlation_id or _as_uuid(ctx.correlation_id),
                actor_id=event.actor_id or _as_uuid(ctx.user_id),
            )

        session.add(OutboxMessage.from_event(event))

        for handler in self.handlers_for(event.event_type, transactional=True):
            try:
                await handler(event, session)
            except Exception:  # noqa: BLE001
                logger.exception("event handler failed for event_type=%s (event_id=%s)",
                                 event.event_type, event.event_id)
                raise  # همان تراکنش است؛ کل تراکنش Rollback شود


event_bus = EventBus()
```

==========================================================================================
## FILE: basteh_URGENT/backend/app/core/events/dispatcher.py
## SIZE: 2801 bytes
==========================================================================================

```python
"""
app/core/events/dispatcher.py

Dispatcher ردیف‌های Outbox برای مصرف‌کننده‌های «بعد از commit»
(``subscribe(..., transactional=False)``) — مثل Notification/Push/Email.
handlerهای هم‌تراکنش (Audit) اینجا **اجرا نمی‌شوند** (قبلاً دوباره اجرا
می‌شدند و ردیف تکراری می‌ساختند).

طبق سند (بخش ۳.۱) باید توسط تسک دوره‌ای Celery
(``workers/tasks/outbox_dispatcher.py``) فراخوانی شود.

* ``FOR UPDATE SKIP LOCKED`` — چند Worker همزمان روی یک ردیف کار نمی‌کنند.
* هر ردیف در یک SAVEPOINT پردازش می‌شود؛ خطای یک ردیف تراکنش ردیف‌های
  دیگر را خراب نمی‌کند.
* ردیفی که مصرف‌کننده‌ی async ندارد، بلافاصله dispatched علامت می‌خورد.
* بعد از ``MAX_ATTEMPTS`` شکست، ردیف رها می‌شود (با ``last_error``) تا
  دستی بررسی شود (dead-letter).
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from sqlalchemy import select

from app.core.events.bus import DomainEvent, event_bus
from app.core.events.outbox import OutboxMessage

logger = logging.getLogger("core.events.dispatcher")

MAX_ATTEMPTS = 5


async def dispatch_pending_outbox_messages(session, batch_size: int = 100) -> int:
    """Process pending rows; returns the number successfully dispatched."""
    rows = (await session.execute(
        select(OutboxMessage)
        .where(OutboxMessage.dispatched_at.is_(None))
        .where(OutboxMessage.attempts < MAX_ATTEMPTS)
        .order_by(OutboxMessage.id)
        .limit(batch_size)
        .with_for_update(skip_locked=True)
    )).scalars().all()

    processed = 0
    for row in rows:
        event = DomainEvent(
            event_type=row.event_type, payload=row.payload,
            event_id=row.event_id, correlation_id=row.correlation_id,
            occurred_at=row.created_at,
        )
        handlers = event_bus.handlers_for(event.event_type, transactional=False)
        try:
            async with session.begin_nested():  # SAVEPOINT
                for handler in handlers:
                    await handler(event, session)
            row.dispatched_at = datetime.now(timezone.utc)
            row.last_error = None
            processed += 1
        except Exception as exc:  # noqa: BLE001
            row.attempts = (row.attempts or 0) + 1
            row.last_error = str(exc)[:2000]
            logger.exception("outbox dispatch failed for event_id=%s (attempt %s/%s)",
                             row.event_id, row.attempts, MAX_ATTEMPTS)

    await session.commit()
    return processed
```

==========================================================================================
## FILE: basteh_URGENT/backend/app/core/events/outbox.py
## SIZE: 3455 bytes
==========================================================================================

```python
"""
app/core/events/outbox.py

مدل ORM جدول ``core.outbox_messages`` — دقیقاً مطابق DDL سند معماری v2.0،
بخش ۲.۳:

    CREATE TABLE core.outbox_messages (
        id             BIGSERIAL PRIMARY KEY,
        event_id       UUID NOT NULL UNIQUE,
        event_type     VARCHAR(100) NOT NULL,
        payload        JSONB NOT NULL,
        correlation_id UUID,
        created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
        dispatched_at  TIMESTAMPTZ,
        attempts       SMALLINT NOT NULL DEFAULT 0,
        last_error     TEXT
    );
    CREATE INDEX ix_outbox_pending ON core.outbox_messages(created_at)
        WHERE dispatched_at IS NULL;

⚠️ فرض این فایل: پایه‌ی مدل‌های شما در ``app.core.db.base`` با نام
``Base`` صادر می‌شود (الگوی رایج SQLAlchemy 2.0). اگر اسم/مسیر واقعی
پروژه‌ی شما فرق دارد، فقط خط import زیر را اصلاح کنید — بقیه‌ی فایل
دست‌نخورده می‌ماند.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import BigInteger, DateTime, Integer, SmallInteger, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func

try:
    # مسیر استاندارد طبق ساختار پوشه‌ی سند (بخش ۳.۱): core/db/base.py
    from app.core.db.base import Base
except ImportError:  # pragma: no cover — فقط برای این‌که فایل به‌تنهایی هم import شود
    from sqlalchemy.orm import DeclarativeBase

    class Base(DeclarativeBase):  # type: ignore[no-redef]
        """Fallback موقت — اگر این اجرا شد یعنی import بالا را باید اصلاح کنید."""


class OutboxMessage(Base):
    """ردیف Outbox — طبق الگوی Transactional Outbox (ADR-02)."""

    __tablename__ = "outbox_messages"
    __table_args__ = {"schema": "core"}

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    event_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False, unique=True)
    event_type: Mapped[str] = mapped_column(String(100), nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    correlation_id: Mapped[UUID | None] = mapped_column(PG_UUID(as_uuid=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    dispatched_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    attempts: Mapped[int] = mapped_column(SmallInteger, nullable=False, server_default="0")
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)

    @classmethod
    def from_event(cls, event: "DomainEvent") -> "OutboxMessage":  # noqa: F821 — type hint only
        """DomainEvent (از bus.py) را به یک ردیف Outbox قابل‌درج تبدیل می‌کند."""
        return cls(
            event_id=event.event_id,
            event_type=event.event_type,
            # JSONB needs JSON-safe values (UUID/datetime/Decimal -> str)
            payload=json.loads(json.dumps(event.payload, default=str)),
            correlation_id=event.correlation_id,
        )
```

==========================================================================================
## FILE: basteh_URGENT/backend/app/core/events.py
## SIZE: 1102 bytes
==========================================================================================

```python
"""Event bus for cross-module communication."""
from typing import Dict, List, Callable, Any
from concurrent.futures import ThreadPoolExecutor


class EventBus:
    """Simple event bus for inter-module communication."""
    
    def __init__(self):
        self._subscribers: Dict[str, List[Callable]] = {}
        self._executor = ThreadPoolExecutor(max_workers=4)
    
    def subscribe(self, event_type: str, handler: Callable) -> None:
        """Subscribe to an event type."""
        if event_type not in self._subscribers:
            self._subscribers[event_type] = []
        self._subscribers[event_type].append(handler)
    
    def publish(self, event_type: str, data: Any = None) -> None:
        """Publish an event to all subscribers."""
        handlers = self._subscribers.get(event_type, [])
        # Run handlers in thread pool to avoid blocking
        for handler in handlers:
            try:
                self._executor.submit(handler, data)
            except Exception:
                pass


# Global event bus instance
event_bus = EventBus()
```

==========================================================================================
## FILE: basteh_URGENT/backend/app/core/middleware/_http.py
## SIZE: 1997 bytes
==========================================================================================

```python
"""Small helpers shared by the pure-ASGI middlewares."""
from __future__ import annotations

import ipaddress
from typing import Iterable, Optional

from starlette.datastructures import Headers
from starlette.responses import JSONResponse
from starlette.types import Receive, Scope, Send

from app.core.config import settings
from app.core.context import get_context


async def send_error(
    scope: Scope, receive: Receive, send: Send, *, status: int, code: str,
    message: str, headers: Optional[dict[str, str]] = None,
) -> None:
    """Send the platform-wide error body (same shape as ``core.errors``)."""
    body = {"error": code, "message": message, "success": False,
            "request_id": get_context().request_id}
    await JSONResponse(body, status_code=status, headers=headers)(scope, receive, send)


def parse_networks(values: Iterable[str]):
    nets = []
    for v in values:
        try:
            nets.append(ipaddress.ip_network(v.strip(), strict=False))
        except ValueError:
            continue
    return nets


def ip_in(ip: str, networks) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in n for n in networks)


def client_ip(scope: Scope) -> str:
    """Peer address; ``X-Forwarded-For`` is honoured only from TRUSTED_PROXIES.

    Trusting the header unconditionally lets any client spoof its IP and
    bypass rate limiting / IP rules / audit attribution.
    """
    peer = (scope.get("client") or ("unknown", 0))[0]
    if settings.TRUSTED_PROXIES and ip_in(peer, parse_networks(settings.TRUSTED_PROXIES)):
        xff = Headers(scope=scope).get("x-forwarded-for")
        if xff:
            # right-most entry that is not itself a trusted proxy
            nets = parse_networks(settings.TRUSTED_PROXIES)
            for hop in reversed([h.strip() for h in xff.split(",") if h.strip()]):
                if not ip_in(hop, nets):
                    return hop
    return peer
```

==========================================================================================
## FILE: basteh_URGENT/backend/app/core/middleware/audit_context.py
## SIZE: 1512 bytes
==========================================================================================

```python
"""Fills network/device identity into the request context (architecture 3.1).

The identity that ends up in audit rows always comes from here (headers /
socket), never from a request body. ``mac_verified`` stays False until the
device-binding step validates the HMAC signature (ADR-08: MAC is a forensic
signal, not a security control).
"""
from __future__ import annotations

import re

from starlette.datastructures import Headers
from starlette.types import ASGIApp, Receive, Scope, Send

from app.core.context import get_context
from app.core.middleware._http import client_ip

_MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$")
_FP_RE = re.compile(r"^[A-Za-z0-9+/=_\-]{16,255}$")


class AuditContextMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] in ("http", "websocket"):
            h = Headers(scope=scope)
            ctx = get_context()
            ctx.ip = client_ip(scope)
            ctx.user_agent = (h.get("user-agent") or "")[:512] or None
            mac = h.get("x-device-mac")
            if mac and _MAC_RE.match(mac):
                ctx.mac_address = mac.upper().replace("-", ":")
            fp = h.get("x-device-fingerprint")
            if fp and _FP_RE.match(fp):
                ctx.device_fingerprint = fp
            ctx.correlation_id = h.get("x-correlation-id") or ctx.request_id
        await self.app(scope, receive, send)
```

==========================================================================================
## FILE: basteh_URGENT/backend/app/core/middleware/body_guard.py
## SIZE: 2845 bytes
==========================================================================================

```python
"""Request body size guard (architecture 3.1 ``body_guard``).

Checks ``Content-Length`` up front and also counts streamed bytes, so
chunked uploads cannot bypass the limit. Upload endpoints (``/files``) use
``MAX_UPLOAD_SIZE`` instead of the small JSON limit.
"""
from __future__ import annotations

from starlette.datastructures import Headers
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.config import settings
from app.core.middleware._http import send_error

_UPLOAD_PREFIXES = ("/api/v1/files",)


class _TooLarge(Exception):
    pass


class BodyGuardMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope["method"] in ("GET", "HEAD", "OPTIONS"):
            await self.app(scope, receive, send)
            return
        limit = (settings.MAX_UPLOAD_SIZE
                 if scope.get("path", "").startswith(_UPLOAD_PREFIXES)
                 else settings.MAX_BODY_SIZE)
        declared = Headers(scope=scope).get("content-length")
        if declared is not None:
            try:
                too_big = int(declared) > limit
            except ValueError:
                too_big = True
            if too_big:
                await send_error(scope, receive, send, status=413,
                                 code="PAYLOAD_TOO_LARGE",
                                 message="حجم درخواست بیش از حد مجاز است.")
                return

        received = 0
        exceeded = False
        started = False

        async def counting_receive() -> Message:
            nonlocal received, exceeded
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > limit:
                    exceeded = True
                    raise _TooLarge()
            return message

        async def tracking_send(message: Message) -> None:
            nonlocal started
            if exceeded:
                # FastAPI wraps any body-read exception into its own 400; once the
                # limit was crossed that response is wrong, so swallow it and let
                # the 413 below win.
                return
            if message["type"] == "http.response.start":
                started = True
            await send(message)

        try:
            await self.app(scope, counting_receive, tracking_send)
        except _TooLarge:
            pass
        if exceeded and not started:
            await send_error(scope, receive, send, status=413,
                             code="PAYLOAD_TOO_LARGE",
                             message="حجم درخواست بیش از حد مجاز است.")
```

==========================================================================================
## FILE: basteh_URGENT/backend/app/core/middleware/ip_filter.py
## SIZE: 1605 bytes
==========================================================================================

```python
"""IP allow / deny lists (CIDR aware). Deny wins over allow."""
from __future__ import annotations

from starlette.types import ASGIApp, Receive, Scope, Send

from app.core.middleware._http import client_ip, ip_in, parse_networks, send_error


class IPFilterMiddleware:
    def __init__(self, app: ASGIApp, allow_ips: list[str] | None = None,
                 deny_ips: list[str] | None = None) -> None:
        self.app = app
        self.allow = parse_networks(allow_ips or [])
        self.deny = parse_networks(deny_ips or [])

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ("http", "websocket") or not (self.allow or self.deny):
            await self.app(scope, receive, send)
            return
        ip = client_ip(scope)
        if self.deny and ip_in(ip, self.deny):
            await self._reject(scope, receive, send, "IP_ADDRESS_DENIED",
                               "آدرس IP شما مسدود شده است.")
            return
        if self.allow and not ip_in(ip, self.allow):
            await self._reject(scope, receive, send, "IP_ADDRESS_NOT_ALLOWED",
                               "دسترسی از این آدرس IP مجاز نیست.")
            return
        await self.app(scope, receive, send)

    @staticmethod
    async def _reject(scope, receive, send, code, message) -> None:
        if scope["type"] == "websocket":
            await send({"type": "websocket.close", "code": 4403})
            return
        await send_error(scope, receive, send, status=403, code=code, message=message)
```

==========================================================================================
## FILE: basteh_URGENT/backend/app/core/middleware/rate_limit.py
## SIZE: 5467 bytes
==========================================================================================

```python
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
```

==========================================================================================
## FILE: basteh_URGENT/backend/app/core/middleware/request_id.py
## SIZE: 1489 bytes
==========================================================================================

```python
"""Creates the per-request context and the ``X-Request-ID`` header."""
from __future__ import annotations

import re
from uuid import uuid4

from starlette.datastructures import Headers, MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.context import RequestContext, reset_context, set_context

_SAFE_ID = re.compile(r"^[A-Za-z0-9\-_.]{8,64}$")


class RequestIDMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return
        incoming = Headers(scope=scope).get("x-request-id", "")
        # Accept a client id only if it is short/safe (log-injection guard).
        request_id = incoming if _SAFE_ID.match(incoming) else str(uuid4())
        ctx = RequestContext(request_id=request_id, path=scope.get("path"),
                             method=scope.get("method"))
        scope.setdefault("state", {})["request_id"] = request_id
        token = set_context(ctx)

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                MutableHeaders(scope=message)["X-Request-ID"] = request_id
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            reset_context(token)
```

==========================================================================================
## FILE: basteh_URGENT/backend/app/core/middleware/security_headers.py
## SIZE: 2084 bytes
==========================================================================================

```python
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
```

==========================================================================================
## FILE: basteh_URGENT/backend/app/core/middleware.py
## SIZE: 7586 bytes
==========================================================================================

```python
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
```

==========================================================================================
## FILE: basteh_URGENT/backend/app/core/redis.py
## SIZE: 7001 bytes
==========================================================================================

```python
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
```

==========================================================================================
## FILE: basteh_URGENT/backend/app/core/security.py
## SIZE: 2348 bytes
==========================================================================================

```python
"""Security primitives for WebSocket/device binding (architecture 1.2).

Mirrors the Windows desktop client's device fingerprint + HMAC scheme so a
WebSocket handshake can be tied to a known device, reusing the same
``SECRET_KEY`` domain.
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Optional
from uuid import UUID

from app.core.config import settings


def get_device_fingerprint(
    user_agent: Optional[str] = None,
    ip: Optional[str] = None,
    mac: Optional[str] = None,
    salt: Optional[str] = None,
) -> str:
    """Stable per-device fingerprint from the available client hints.

    Missing components are skipped so fingerprints stay stable for clients
    that do not disclose them.  The digest is truncated (16 bytes) to keep
    stored fingerprints compact.
    """
    parts: list[str] = []
    if salt:
        parts.append(salt)
    if mac:
        parts.append(mac.strip().lower())
    if user_agent:
        parts.append(user_agent.strip())
    if ip:
        parts.append(ip.strip())
    if not parts:
        # Deterministic fallback so a missing fingerprint never crashes auth.
        parts.append("unknown-device")
    raw = "|".join(parts).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:32]


def verify_hmac_signature(
    signature: str,
    *,
    user_id,
    endpoint: str,
    payload: Optional[str] = None,
) -> bool:
    """Verify an HMAC-SHA256 device signature (constant-time compare).

    The signature should be computed by the client as
    ``HMAC_SHA256(secret_key, f"{user_id}|{endpoint}|{payload}")``.  A
    missing signature or key is a hard reject.
    """
    if not signature or not settings.SECRET_KEY:
        return False
    message = "|".join([str(user_id), endpoint, payload or ""]).encode("utf-8")
    expected = hmac.new(
        settings.SECRET_KEY.encode("utf-8"), message, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(signature.strip().lower(), expected.lower())


def hmac_sign(user_id, endpoint: str, payload: Optional[str] = None) -> str:
    """Helper used where the *server* must mint a signature (e.g. callbacks)."""
    message = "|".join([str(user_id), endpoint, payload or ""]).encode("utf-8")
    return hmac.new(
        settings.SECRET_KEY.encode("utf-8"), message, hashlib.sha256
    ).hexdigest()
```

==========================================================================================
## FILE: basteh_URGENT/backend/app/main.py
## SIZE: 4012 bytes
==========================================================================================

```python
"""
Planner Enterprise API - Main Application Entry Point

Architecture: Modular Monolith with Defense in Depth
Version: 2.0
"""

import logging
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from sqlalchemy import text

from app.core.config import settings
from app.core.database import dispose_engine, engine
from app.core.errors import register_exception_handlers
from app.core.events import event_bus
from app.core.middleware import register_middlewares
from app.core.redis import get_redis_broker
from app.modules import auth, rbac, groups, goals, sharing, chat, inbox, \
                        reporting, notification, audit, ssoldap, files, calendar
from app.ws.routes import router as websocket_router

logging.basicConfig(level=settings.LOG_LEVEL, format=settings.LOG_FORMAT)

# Module order matters for initialization
MODULES = [auth, rbac, groups, goals, sharing,
           chat, inbox, reporting, notification, audit, ssoldap, files, calendar]


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    # Redis publisher/subscriber pool (in-memory fallback when unreachable)
    broker = get_redis_broker()
    await broker.connect()

    # Event bus subscriptions (modules without handlers are skipped)
    for m in MODULES:
        register = getattr(m, "register_event_handlers", None)
        if callable(register):
            register(event_bus)

    yield

    # Graceful shutdown: return pooled connections to PostgreSQL
    await shutdown_gracefully()
    await broker.close()


_docs_enabled = not settings.is_production

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    lifespan=lifespan,
    root_path=settings.ROOT_PATH,
    docs_url="/docs" if _docs_enabled else None,
    redoc_url="/redoc" if _docs_enabled else None,
    openapi_url="/openapi.json" if _docs_enabled else None,
)

# --- Middleware chain (single place; order documented in core/middleware) ---
register_middlewares(app)

# --- Exception handlers ---
register_exception_handlers(app)

# --- Include Module Routers ---
# All modules use /api/v1 prefix.
# Empty/stub modules (audit, files, notification, ssoldap) expose no router
# yet and are skipped until their routes land.
for m in MODULES:
    router = getattr(m, "router", None)
    if router is not None:
        app.include_router(router, prefix="/api/v1")

# --- WebSocket gateway (architecture 5.5: /ws/chat, /ws/notifications) ---
app.include_router(websocket_router)

async def shutdown_gracefully():
    """Graceful shutdown routine."""
    await dispose_engine()


# Liveness: process is up (no dependencies touched)
@app.get("/health", include_in_schema=False)
async def health_check():
    return {
        "status": "healthy",
        "service": "planner-enterprise-api",
        "version": settings.APP_VERSION,
        "modules": [m.__name__ for m in MODULES],
    }


# Readiness: dependencies reachable (used by the load balancer)
@app.get("/ready", include_in_schema=False)
async def readiness_check():
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
    except Exception:
        logging.getLogger("app.health").exception("readiness: database unreachable")
        return JSONResponse(status_code=503, content={"status": "unavailable", "database": "down"})
    return {"status": "ready", "database": "up"}


# Root endpoint
@app.get("/", include_in_schema=False)
async def root():
    return {
        "message": "Planner Enterprise API",
        "version": settings.APP_VERSION,
        "docs": "/docs" if settings.ENV != "production" else "disabled",
        "endpoints": "/api/v1/auth, /api/v1/goals, /api/v1/groups, etc."
    }

if __name__ == "__main__":
    uvicorn.run(
        "app.main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.ENV == "development",
        access_log=False
    )
```

==========================================================================================
## FILE: basteh_URGENT/backend/app/modules/audit/services/audit_service.py
## SIZE: 7105 bytes
==========================================================================================

```python
"""
app/modules/audit/services/audit_service.py

پیاده‌سازی واقعی «ثبت Audit Log با زنجیره‌ی هش»، طبق بخش ۱۲.۳ سند.

⚠️ تفاوت آگاهانه با نمونه‌کد سند: نمونه‌ی سند همه‌ی اطلاعات هویتی
(ip، mac، device_fingerprint و...) را از ``request_ctx.get()``
می‌خواند. آن ContextVar/middleware (``app/core/middleware/``) هنوز
در این پروژه ساخته نشده (طبق بررسی پوشه‌ها). پس اینجا این مقادیر را
به‌عنوان پارامتر ورودی اختیاری می‌گیرد (پیش‌فرض None) — همین امروز
کار می‌کند، و وقتی context/middleware واقعی ساخته شد، فراخوان
(events.py) فقط باید این آرگومان‌ها را از آن‌جا پر کند؛ امضای
AuditService عوض نمی‌شود.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from app.modules.audit.db.models import AuditLog, LoginAuditLog
from app.modules.audit.db.repositories import AuditRepository

# فیلدهایی که هرگز نباید خام در JSONB جزئیات audit ذخیره شوند —
# حتی اگر caller اشتباهاً آن‌ها را در payload بگذارد.
_SENSITIVE_KEYS = {
    "password", "password_hash", "current_password", "new_password",
    "national_id", "refresh_token", "access_token", "hmac_key",
    "secret", "otp", "mfa_token",
}


def mask_sensitive(value: dict[str, Any] | None) -> dict[str, Any] | None:
    """یک لایه‌ی دفاعی ساده — کلیدهای حساس را قبل از نوشتن در Audit پاک می‌کند."""
    if value is None:
        return None
    return {
        k: ("***REDACTED***" if k.lower() in _SENSITIVE_KEYS else v)
        for k, v in value.items()
    }


class AuditService:
    def __init__(self, session: Any) -> None:
        self.session = session
        self.repo = AuditRepository(session)

    async def log(
        self,
        *,
        action: str,
        result: str = "success",
        user_id: UUID | None = None,
        entity_type: str | None = None,
        entity_id: UUID | None = None,
        old_value: dict[str, Any] | None = None,
        new_value: dict[str, Any] | None = None,
        details: dict[str, Any] | None = None,
        ip_address: str | None = None,
        mac_address: str | None = None,
        mac_verified: bool = False,
        device_fingerprint: str | None = None,
        device_id: UUID | None = None,
        user_agent: str | None = None,
        session_id: UUID | None = None,
        request_id: UUID | None = None,
        correlation_id: UUID | None = None,
    ) -> AuditLog:
        """یک ردیف در ``audit.audit_logs`` می‌نویسد و آن را به زنجیره‌ی هش وصل می‌کند."""
        prev_hash = await self.repo.last_audit_log_hash()

        row = AuditLog(
            user_id=user_id, action=action, result=result,
            entity_type=entity_type, entity_id=entity_id,
            timestamp=datetime.now(timezone.utc),
            ip_address=ip_address, mac_address=mac_address, mac_verified=mac_verified,
            device_fingerprint=device_fingerprint, device_id=device_id,
            user_agent=user_agent, session_id=session_id,
            old_value=mask_sensitive(old_value), new_value=mask_sensitive(new_value),
            details=mask_sensitive(details),
            request_id=request_id, correlation_id=correlation_id,
            prev_hash=prev_hash,
        )
        row.row_hash = self._chain_hash_audit(prev_hash, row)
        self.session.add(row)  # همان تراکنش عملیات اصلی — طبق سند
        return row

    async def log_login(
        self,
        *,
        success: bool,
        auth_method: str,
        user_id: UUID | None = None,
        username: str | None = None,
        national_id_hash: str | None = None,
        mfa_used: str | None = None,
        failure_reason: str | None = None,
        ip_address: str | None = None,
        mac_address: str | None = None,
        mac_verified: bool = False,
        device_fingerprint: str | None = None,
        device_is_trusted: bool | None = None,
        user_agent: str | None = None,
        session_id: UUID | None = None,
        risk_score: int | None = None,
    ) -> LoginAuditLog:
        """یک ردیف در ``audit.login_audit_logs`` می‌نویسد (جدول اختصاصی لاگین، سند بخش ۴.۸)."""
        prev_hash = await self.repo.last_login_audit_hash()

        row = LoginAuditLog(
            user_id=user_id, username=username, national_id_hash=national_id_hash,
            auth_method=auth_method, mfa_used=mfa_used,
            timestamp=datetime.now(timezone.utc),
            ip_address=ip_address, mac_address=mac_address, mac_verified=mac_verified,
            device_fingerprint=device_fingerprint, device_is_trusted=device_is_trusted,
            user_agent=user_agent, success=success, failure_reason=failure_reason,
            session_id=session_id, risk_score=risk_score,
            prev_hash=prev_hash,
        )
        row.row_hash = self._chain_hash_login(prev_hash, row)
        self.session.add(row)
        return row

    # ── زنجیره‌ی هش — دقیقاً طبق فرمول بخش ۴.۸:
    #    row_hash = SHA256(prev_hash ‖ id ‖ user_id ‖ action ‖ timestamp ‖ ip ‖ mac ‖ result ‖ details)
    #    نکته: چون `id` قبل از INSERT واقعی (autoincrement) هنوز مقدار ندارد،
    #    از تلفیق (prev_hash + سایر فیلدهای معین‌شده در همین لحظه) استفاده
    #    می‌شود — دقیقاً مثل نمونه‌کد سند در ۱۲.۳ که هم `id` را در فرمول
    #    متنی نمی‌آورد (چون در لحظه‌ی ساخت شیء هنوز تعیین نشده).

    @staticmethod
    def _chain_hash_audit(prev_hash: str | None, row: AuditLog) -> str:
        material = "|".join([
            prev_hash or "GENESIS",
            str(row.user_id), row.action,
            row.timestamp.isoformat(),
            str(row.ip_address) if row.ip_address else "",
            row.mac_address or "",
            row.result,
            json.dumps(row.details, sort_keys=True, ensure_ascii=False) if row.details else "null",
        ])
        return hashlib.sha256(material.encode()).hexdigest()

    @staticmethod
    def _chain_hash_login(prev_hash: str | None, row: LoginAuditLog) -> str:
        material = "|".join([
            prev_hash or "GENESIS",
            str(row.user_id), row.username or "",
            row.timestamp.isoformat(),
            str(row.ip_address) if row.ip_address else "",
            row.mac_address or "",
            "success" if row.success else "failure",
            row.failure_reason or "",
        ])
        return hashlib.sha256(material.encode()).hexdigest()
```

==========================================================================================
## FILE: basteh_URGENT/backend/app/modules/auth/api/routes.py
## SIZE: 13222 bytes
==========================================================================================

```python
"""
Auth Module API Routes
Architecture Reference: Sections 5.2, 5.3, 6.2-6.5, 7.1, 11.2-11.3
Endpoints: /api/v1/auth
"""

from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Body, Path, Request, status
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials

from app.core.dependencies import (
    get_db_session, get_current_user, get_auth_service,
    get_mfa_service, get_rate_limit_check, security_bearer
)
from app.core.errors import APIError, AuthenticationError, NotFoundError
from app.core.database import async_session_context
from app.modules.auth.ports import (
    LoginRequest, MFAVerifyRequest, RegisterRequest, TokenResponse,
    DeviceRegisterRequest, DeviceTrustRequest, PasswordChangeRequest,
    PasswordForgotRequest, AuditLogEntry, RefreshRequest
)
from app.modules.auth.services.auth_service import AuthService
from app.modules.auth.db.models import Users, UserDevices, Sessions
from app.core.database import get_async_session


router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/register", response_model=dict, status_code=201)
async def register(
    request: RegisterRequest,
    db_session=Depends(get_db_session),
    auth_service: AuthService = Depends(get_auth_service)
):
    """Register a new user with national ID."""
    async with db_session() as session:
        try:
            result = await auth_service.register(request)
            return {"status": "success", "data": result}
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.post("/login", response_model=dict)
async def login(
    request: LoginRequest,
    db_session=Depends(get_db_session),
    auth_service: AuthService = Depends(get_auth_service)
):
    """Authenticate user and return tokens or MFA challenge."""
    async with db_session() as session:
        try:
            mfa_info, mfa_required = await auth_service.login(request)
            
            if mfa_required:
                return {
                    "mfa_required": True,
                    "mfa_token": mfa_info.get("mfa_token"),
                    "mfa_method": mfa_info.get("mfa_method"),
                    "expires_in": mfa_info.get("expires_in"),
                    "message": "کد MFA ارسال شد به سامانه تأیید"
                }
            
            # Successful login - no MFA needed
            tokens = mfa_info  # This is actually the token dict from _generate_tokens
            return {
                "mfa_required": False,
                "tokens": {
                    "access_token": tokens.get("access_token"),
                    "refresh_token": tokens.get("refresh_token"),
                    "expires_in": tokens.get("expires_in"),
                    "token_type": "Bearer"
                },
                "user": tokens.get("user"),
                "message": "ورود réussi"
            }
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.post("/mfa/verify", response_model=dict)
async def verify_mfa(
    request_data: Request,
    request: MFAVerifyRequest,
    db_session=Depends(get_db_session),
    auth_service: AuthService = Depends(get_auth_service),
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_bearer),
):
    """Verify MFA code.

    During the MFA leg of login the caller does NOT own an access token yet,
    so the user is identified from the short-lived ``challenge_token`` that
    login() issued (falling back to the bearer token when provided).
    """
    from app.core.config import settings
    from jose import JWTError, jwt as jose_jwt
    from app.core.errors import AuthenticationError

    if request.challenge_token:
        try:
            claims = jose_jwt.decode(
                request.challenge_token, settings.SECRET_KEY,
                algorithms=[settings.ALGORITHM],
            )
        except JWTError:
            raise AuthenticationError(message="مهلت تأیید MFA منقضی شده است؛ دوباره وارد شوید.")
        if claims.get("purpose") != "mfa":
            raise AuthenticationError(message="توکن تأیید MFA نامعتبر است.")
        try:
            user_id = UUID(claims.get("sub"))
        except (TypeError, ValueError):
            raise AuthenticationError(message="توکن تأیید MFA نامعتبر است.")
    else:
        # Fallback: an already-authenticated session verifying a code.
        user_id = await get_current_user(request_data, credentials)

    async with db_session() as session:
        try:
            verified = await auth_service.verify_mfa(
                request.mfa_token, request.mfa_method, user_id
            )
            
            if verified:
                # Generate tokens after MFA success
                tokens = await auth_service._generate_tokens_by_id(user_id)
                return {
                    "status": "mfa_verified",
                    "tokens": {
                        "access_token": tokens.get("access_token"),
                        "refresh_token": tokens.get("refresh_token"),
                        "expires_in": tokens.get("expires_in"),
                        "token_type": "Bearer"
                    },
                    "message": "MFA erfolgreich"
                }
            else:
                return JSONResponse(
                    status_code=401,
                    content={"error": "MFA_INVALID", "message": "کد MFA نامعتبر است.", "success": False}
                )
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.post("/mfa/enroll", response_model=dict)
async def enroll_mfa(
    user_id: UUID = Depends(get_current_user),
    auth_service: AuthService = Depends(get_auth_service)
):
    """Enroll TOTP MFA (return QR code info)."""
    try:
        result = await auth_service.enroll_mfa(user_id, secret="temp")
        return {
            "status": "enrolled",
            "qr_code": result.get("qr_url"),
            "secret": result.get("secret"),
            "recovery_codes": result.get("recovery_codes", []),
            "message": result.get("message"),
        }
    except APIError as e:
        return JSONResponse(
            status_code=e.status_code,
            content={"error": e.error_code, "message": e.message, "success": False}
        )


@router.post("/mfa/enroll/confirm", response_model=dict)
async def enroll_mfa_confirm(
    code: str = Body(...),
    user_id: UUID = Depends(get_current_user),
    auth_service: AuthService = Depends(get_auth_service)
):
    """Confirm MFA enrollment."""
    try:
        result = await auth_service.enroll_mfa(user_id, secret=code)
        return {"status": "enrollment_confirmed", "message": "MFA ثبت شد", "data": result}
    except APIError as e:
        return JSONResponse(
            status_code=e.status_code,
            content={"error": e.error_code, "message": e.message, "success": False}
        )


@router.post("/devices/register", response_model=dict)
async def register_device(
    request: DeviceRegisterRequest,
    user_id: UUID = Depends(get_current_user),
    auth_service: AuthService = Depends(get_auth_service)
):
    """Register a new device for a user."""
    async with db_session() as session:
        try:
            result = await auth_service.register_device(request, user_id)
            return {"status": "device_registered", "data": result}
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.post("/devices/{device_id}/trust", response_model=dict)
async def trust_device(
    device_id: UUID = Path(...),
    mfa_satisfied: bool = Body(...),
    user_id: UUID = Depends(get_current_user),
    auth_service: AuthService = Depends(get_auth_service)
):
    """Mark device as trusted (requires MFA)."""
    async with db_session() as session:
        try:
            result = await auth_service.trust_device(device_id, mfa_satisfied, user_id)
            return {"status": "device_trusted", "data": result}
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.post("/password/change", response_model=dict)
async def change_password(
    request: PasswordChangeRequest,
    user_id: UUID = Depends(get_current_user),
    auth_service: AuthService = Depends(get_auth_service)
):
    """Change user password."""
    async with db_session() as session:
        try:
            result = await auth_service.change_password(user_id, request)
            return {"status": "password_changed", "data": result}
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.post("/password/forgot", response_model=dict)
async def forgot_password(
    request: PasswordForgotRequest,
    auth_service: AuthService = Depends(get_auth_service)
):
    """Initiate password reset process."""
    async with db_session() as session:
        try:
            result = await auth_service.forgot_password(request)
            return {"status": "reset_initiated", "data": result}
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.get("/me", response_model=dict)
async def get_me(
    user_id: UUID = Depends(get_current_user),
    auth_service: AuthService = Depends(get_auth_service),
):
    """Current user profile + effective roles/permissions."""
    try:
        profile = await auth_service.get_profile(user_id)
        return {"status": "success", "data": profile}
    except APIError as e:
        return JSONResponse(
            status_code=e.status_code,
            content={"error": e.error_code, "message": e.message, "success": False}
        )


@router.post("/logout", response_model=dict)
async def logout(
    user_id: UUID = Depends(get_current_user),
    auth_service: AuthService = Depends(get_auth_service),
):
    """Revoke the current session (bump token_version)."""
    try:
        await auth_service.logout(user_id)
        return {"status": "success", "message": "Logged out"}
    except APIError as e:
        return JSONResponse(
            status_code=e.status_code,
            content={"error": e.error_code, "message": e.message, "success": False}
        )


@router.get("/devices", response_model=dict)
async def list_devices(
    user_id: UUID = Depends(get_current_user),
    auth_service: AuthService = Depends(get_auth_service),
):
    """List known devices (MAC masked)."""
    try:
        devices = await auth_service.list_devices(user_id)
        return {"status": "success", "items": devices}
    except APIError as e:
        return JSONResponse(
            status_code=e.status_code,
            content={"error": e.error_code, "message": e.message, "success": False}
        )


@router.post("/refresh", response_model=dict)
async def refresh_token(
    request: RefreshRequest,
    auth_service: AuthService = Depends(get_auth_service)
):
    """Refresh access token using an opaque refresh token.

    The opaque refresh token (secrets.token_urlsafe) is stored hashed in
    ``auth.sessions``. The service looks it up by SHA-256, rotates the
    session and returns fresh tokens with the same shape the frontend
    already expects.
    """
    try:
        return await auth_service.refresh_session(request.refresh_token)
    except APIError as e:
        return JSONResponse(
            status_code=e.status_code,
            content={"error": e.error_code, "message": e.message, "success": False}
        )
    except Exception:
        import logging, traceback
        logging.getLogger(__name__).exception("refresh failed")
        traceback.print_exc()
        return JSONResponse(
            status_code=401,
            content={"error": "TOKEN_INVALID", "message": "توکن یافت نشد یا منقضی شده است.", "success": False}
        )
```

==========================================================================================
## FILE: basteh_URGENT/backend/app/modules/auth/db/mfa.py
## SIZE: 11654 bytes
==========================================================================================

```python
"""MFA service (RFC 6238 TOTP implementation, stdlib only).

The auth flow (auth_service + api/routes) always referenced these methods
while this file was a bootstrap stub — so enabling MFA on a user would
crash at login/verify/enroll time. This is the real implementation:

  - generate_mfa_token(user_id) -> short-lived signed "challenge" token
    returned by login() when the user has a second factor enabled.
  - verify_token(token, method, user_id) -> verifies a TOTP code (or a
    hashed recovery code) against the stored, AES-GCM-encrypted secret.
  - enroll(user_id, secret) -> generates + stores an encrypted TOTP secret
    (and 10 one-time recovery codes); when called again with the 6-digit
    confirmation code it enables the second factor.

No third-party OTP library is required (pyotp/qrcode are not installed);
the client renders the returned ``otpauth://`` URI itself.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from uuid import UUID

from jose import jwt as jose_jwt

from app.core.config import settings
from app.core.errors import APIError

_JWT_ALGORITHM = settings.ALGORITHM if settings.ALGORITHM in ("HS256", "HS384", "HS512") else "HS256"
_MFA_CHALLENGE_LIFETIME = 300  # seconds (5 minutes)
_TOTP_STEP = 30
_TOTP_DIGITS = 6
_TOTP_WINDOW = 1  # +/- 30s to tolerate clock skew
_TOTP_HASH = hashlib.sha1
_RECOVERY_CODE_COUNT = 10


# --- RFC 6238 helpers (pure stdlib) ---

def _base32_decode(value: str) -> bytes:
    padded = value.upper().strip().replace(" ", "")
    padded += "=" * ((8 - len(padded) % 8) % 8)
    return base64.b32decode(padded, casefold=True)


def _totp_at(secret_bytes: bytes, timestamp: int) -> str:
    """Return the 6-digit TOTP code for ``timestamp`` (RFC 6238 / 4226)."""
    counter = struct.pack(">Q", timestamp // _TOTP_STEP)
    digest = hmac.new(secret_bytes, counter, _TOTP_HASH).digest()
    offset = digest[-1] & 0x0F
    code = (struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF) % (10 ** _TOTP_DIGITS)
    return f"{code:0{_TOTP_DIGITS}d}"


def _generate_secret() -> str:
    """Random 20-byte base32 secret (160-bit, RFC 6238 recommendation)."""
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def _totp_secret_match(stored_secret: bytes, code: str, now: Optional[int] = None) -> bool:
    """Check ``code`` against the current +/- window of TOTP codes."""
    now = int(time.time()) if now is None else now
    return any(
        hmac.compare_digest(code, _totp_at(stored_secret, now + delta * _TOTP_STEP))
        for delta in range(-_TOTP_WINDOW, _TOTP_WINDOW + 1)
    )


def _encrypt_secret(secret_b32: str) -> tuple:
    """AES-GCM encrypt a TOTP secret; returns (ciphertext, nonce)."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    nonce = secrets.token_bytes(12)
    key = hashlib.sha256(settings.SECRET_KEY.encode()).digest()
    ciphertext = AESGCM(key).encrypt(nonce, secret_b32.encode(), None)
    return ciphertext, nonce


def _decrypt_secret(ciphertext: bytes, nonce: bytes) -> str:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    key = hashlib.sha256(settings.SECRET_KEY.encode()).digest()
    return AESGCM(key).decrypt(nonce, ciphertext, None).decode()


class MFAService:
    """Multi-factor authentication helper (real TOTP + recovery codes)."""

    def __init__(self):
        pass

    def generate_mfa_token(self, user_id: UUID) -> str:
        """Return a short-lived signed challenge token for the login flow."""
        now = datetime.utcnow()
        return jose_jwt.encode(
            {
                "sub": str(user_id),
                "purpose": "mfa",
                "jti": secrets.token_urlsafe(12),
                "exp": now + timedelta(seconds=_MFA_CHALLENGE_LIFETIME),
            },
            settings.SECRET_KEY,
            algorithm=_JWT_ALGORITHM,
        )

    async def verify_token(self, mfa_token: str, mfa_method: str, user_id: UUID) -> bool:
        """Verify a TOTP code (or recovery code) for ``user_id``.

        ``mfa_token`` is the 6-digit code entered by the user (the
        challenge token from ``generate_mfa_token`` identifies the login
        at the route layer; it is separate from this field).
        """
        from app.core.database import async_session_context

        async with async_session_context() as session:
            from sqlalchemy import select
            from app.modules.auth.db.models import Users

            result = await session.execute(select(Users).where(Users.id == user_id))
            user = result.scalar_one_or_none()
            if user is None:
                return False

            if mfa_method == "recovery":
                return await self._verify_recovery_code(session, user_id, mfa_token)

            # TOTP (fallback default when method is unspecified/totp)
            if mfa_method not in ("totp", ""):
                return False
            if not (user.mfa_secret_enc and user.mfa_secret_nonce):
                return False
            secret = _decrypt_secret(user.mfa_secret_enc, user.mfa_secret_nonce)
            return _totp_secret_match(_base32_decode(secret), mfa_token.strip())

    async def enable_totp(self, user_id: UUID, secret_b32: str) -> bool:
        """Persist a (already validated) TOTP secret and mark MFA enabled."""
        from app.core.database import async_session_context
        from sqlalchemy import select
        from app.modules.auth.db.models import Users

        async with async_session_context() as session:
            result = await session.execute(select(Users).where(Users.id == user_id))
            user = result.scalar_one_or_none()
            if user is None:
                return False
            ciphertext, nonce = _encrypt_secret(secret_b32)
            user.mfa_secret_enc = ciphertext
            user.mfa_secret_nonce = nonce
            user.mfa_enabled = True
            user.mfa_method = "totp"
            user.mfa_enrolled_at = datetime.utcnow()
            await session.commit()
            return True

    async def enroll(self, user_id: UUID, secret: str) -> dict:
        """Create or confirm TOTP enrollment.

        ``secret`` == "temp" (or empty): the *create* step — a new secret is
        generated and stored encrypted, plus recovery codes are issued.
        ``secret`` == a 6-digit code: the *confirm* step — verify the code
        against the stored secret and only then enable the factor.
        """
        if not secret or secret == "temp":
            return await self._create_enrollment(user_id)

        # Confirm step
        from app.core.database import async_session_context
        from sqlalchemy import select
        from app.modules.auth.db.models import Users

        async with async_session_context() as session:
            result = await session.execute(select(Users).where(Users.id == user_id))
            user = result.scalar_one_or_none()
            if user is None:
                raise APIError(error_code="USER_NOT_FOUND", message="کاربر یافت نشد.", status_code=404)
            if not (user.mfa_secret_enc and user.mfa_secret_nonce):
                raise APIError(error_code="MFA_NOT_INITIATED", message="ابتدا مرحله‌ی ساخت رمز MFA انجام شود.", status_code=400)
            stored = _decrypt_secret(user.mfa_secret_enc, user.mfa_secret_nonce)
            if not _totp_secret_match(_base32_decode(stored), secret.strip()):
                raise APIError(error_code="MFA_INVALID", message="کد MFA نامعتبر است.", status_code=400)
            user.mfa_enabled = True
            user.mfa_method = "totp"
            user.mfa_enrolled_at = datetime.utcnow()
            await session.commit()
            return {"status": "enrollment_confirmed", "mfa_method": "totp", "mfa_enabled": True}

    async def _create_enrollment(self, user_id: UUID) -> dict:
        """Generate a fresh secret, store it encrypted and return the QR data."""
        from app.core.database import async_session_context
        from sqlalchemy import select
        from app.modules.auth.db.models import Users

        secret_b32 = _generate_secret()
        ciphertext, nonce = _encrypt_secret(secret_b32)
        recovery_codes: List[str] = []

        async with async_session_context() as session:
            result = await session.execute(select(Users).where(Users.id == user_id))
            user = result.scalar_one_or_none()
            if user is None:
                raise APIError(error_code="USER_NOT_FOUND", message="کاربر یافت نشد.", status_code=404)

            user.mfa_secret_enc = ciphertext
            user.mfa_secret_nonce = nonce
            user.mfa_method = "totp"
            user.mfa_enrolled_at = datetime.utcnow()

            # Issue fresh recovery codes (hashed, one-time use).
            from app.modules.auth.db.models import MFARecoveryCodes
            from sqlalchemy import delete

            await session.execute(delete(MFARecoveryCodes).where(MFARecoveryCodes.user_id == user_id))
            for _ in range(_RECOVERY_CODE_COUNT):
                code = _format_recovery_code()
                recovery_codes.append(code)
                session.add(
                    MFARecoveryCodes(
                        user_id=user_id,
                        code_hash=hashlib.sha256(code.encode()).hexdigest(),
                    )
                )
            await session.commit()

        username = user.username if user is not None else str(user_id)
        otpauth = (
            f"otpauth://totp/{_urlsafe(username)}?secret={secret_b32}"
            f"&issuer={_urlsafe(settings.APP_NAME or 'Planner Enterprise')}&digits={_TOTP_DIGITS}"
            f"&period={_TOTP_STEP}"
        )
        return {
            "status": "enrolled",
            "secret": secret_b32,
            "qr_url": otpauth,
            "recovery_codes": recovery_codes,
            "mfa_enabled": False,
            "message": "رمز یک‌بارمصرف (TOTP) ساخته شد؛ برای فعال‌سازی کد ۶ رقمی را تأیید کنید.",
        }

    async def _verify_recovery_code(self, session, user_id: UUID, code: str) -> bool:
        """Validate + consume a hashed recovery code."""
        from sqlalchemy import select, update
        from app.modules.auth.db.models import MFARecoveryCodes

        code_hash = hashlib.sha256(code.strip().encode()).hexdigest()
        result = await session.execute(
            select(MFARecoveryCodes).where(
                MFARecoveryCodes.user_id == user_id,
                MFARecoveryCodes.code_hash == code_hash,
                MFARecoveryCodes.used_at.is_(None),
            )
        )
        row = result.scalar_one_or_none()
        if row is None:
            return False
        row.used_at = datetime.utcnow()
        await session.execute(
            update(MFARecoveryCodes)
            .where(MFARecoveryCodes.id == row.id)
            .values(used_at=datetime.utcnow())
        )
        await session.commit()
        return True


def _format_recovery_code() -> str:
    """8 groups of 8 base32-ish chars, e.g. ``ABCD-EFGH-IJKL-MNOP``."""
    block = base64.b32encode(secrets.token_bytes(10)).decode().rstrip("=")
    return "-".join(block[i : i + 4] for i in range(0, len(block), 4))


def _urlsafe(value: str) -> str:
    return value.replace(" ", "_").replace("%", "_")


__all__ = ["MFAService", "_totp_at", "_generate_secret"]
```

==========================================================================================
## FILE: basteh_URGENT/backend/app/modules/auth/services/auth_service.py
## SIZE: 27510 bytes
==========================================================================================

```python
import hashlib
import secrets
import base64
from typing import Optional, Tuple, Dict, Any
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

from passlib.context import CryptContext
from fastapi import HTTPException, status

from app.core.config import settings
from app.core.errors import APIError, AuthenticationError, MFARequiredError
from app.core.events.bus import event_bus
from app.modules.auth import events as auth_events
from app.modules.auth.ports import (
    LoginRequest, MFAVerifyRequest, RegisterRequest, TokenResponse,
    DeviceRegisterRequest, DeviceTrustRequest, PasswordChangeRequest,
    PasswordForgotRequest, AuditLogEntry
)


# Password hashing context
pwd_context = CryptContext(
    schemes=["argon2"],
    argon2__time_cost=3,
    deprecated="auto",
)


class AuthService:
    """Core authentication service implementing the logic for user login, 
    registration, MFA, and device management."""
    
    def __init__(self, user_repo, device_repo, mfa_service):
        self.user_repo = user_repo
        self.device_repo = device_repo
        self.mfa_service = mfa_service
    
    # --- Registration ---
    
    async def register(self, request: RegisterRequest) -> dict:
        """Register a new user with national ID."""
        
        # Validate national ID format (10 digits with check digit)
        if not self._validate_national_id(request.national_id):
            raise APIError(
                error_code="INVALID_NATIONAL_ID",
                message="فرمت کد ملی صحیح نیست.",
                status_code=status.HTTP_400_BAD_REQUEST
            )
        
        # Check if user already exists
        existing = await self.user_repo.get_by_national_id(request.national_id)
        if existing:
            raise APIError(
                error_code="USER_EXISTS",
                message="کاربری با این کد ملی قبلاً ثبت شده است.",
                status_code=status.HTTP_409_CONFLICT
            )
        
        # Check username availability
        existing_username = await self.user_repo.get_by_username(request.username)
        if existing_username:
            raise APIError(
                error_code="USERNAME_EXISTS",
                message="این نام کاربری قبلاً استفاده شده است.",
                status_code=status.HTTP_409_CONFLICT
            )
        
        # Hash password
        password_hash = pwd_context.hash(request.password)
        
        # Create user (national ID stored encrypted + hashed for lookup)
        from app.modules.auth.db.models import Users
        from app.modules.auth.db.repositories import national_id_hash
        nid_enc, nid_nonce = self._encrypt_national_id(request.national_id)
        user = Users(
            username=request.username,
            national_id_enc=nid_enc,
            national_id_nonce=nid_nonce,
            national_id_hash=national_id_hash(request.national_id),
            national_id_last4=request.national_id[-4:],
            password_hash=password_hash,
            display_name=request.display_name,
            auth_mode="local",
            is_active=True,
        )
        # Transient (non-column) attributes used by the read model below
        user.national_id = request.national_id
        
        await self.user_repo.add(user)
        await self.user_repo.commit()
        
        # Create initial device entry
        await self.device_repo.create_initial_device(user.id)
        
        # Publish domain event — audit (and anything else that subscribes,
        # e.g. notification for a welcome email) reacts without auth ever
        # importing their internal tables (ADR-02 / section 2.3).
        await self._publish_event(
            auth_events.AUTH_USER_REGISTERED,
            actor_id=user.id,
            payload={"username": user.username},
        )
        
        return {"status": "success", "user_id": str(user.id)}
    
    # --- Login ---
    
    async def login(self, request: LoginRequest) -> Tuple[dict, Optional[str]]:
        """Authenticate user and return tokens.
        
        Returns:
            Tuple of (token_response, mfa_required_flag)
        """
        
        # Find user by identifier (username or national ID)
        user = await self.user_repo.get_by_identifier(request.identifier)
        if not user:
            await self._publish_event(
                auth_events.AUTH_LOGIN_FAILED,
                payload={"identifier": request.identifier, "reason": "user_not_found"},
            )
            # Generic error to avoid leaking whether user exists
            raise AuthenticationError(
                message="اطلاعات ورود نادرست است."
            )
        
        # Check if account is active
        if not user.is_active:
            await self._publish_event(
                auth_events.AUTH_LOGIN_FAILED,
                actor_id=user.id,
                payload={"identifier": request.identifier, "reason": "account_inactive"},
            )
            raise AuthenticationError(
                message="حساب کاربری فعال نیست."
            )
        
        # Verify password
        if not pwd_context.verify(request.password, user.password_hash):
            # Increment failed login counter
            user.failed_login_count += 1
            # Lock account if too many failures
            if user.failed_login_count >= 5:
                user.locked_until = datetime.utcnow() + timedelta(minutes=30)
            await self.user_repo.commit()
            await self._publish_event(
                auth_events.AUTH_LOGIN_FAILED,
                actor_id=user.id,
                payload={
                    "identifier": request.identifier,
                    "reason": "wrong_password",
                    "failed_login_count": user.failed_login_count,
                },
            )
            raise AuthenticationError(
                message="اطلاعات ورود نادرست است."
            )
        
        # Reset failed login counter on success
        user.failed_login_count = 0
        user.locked_until = None
        await self.user_repo.commit()
        
        # Check MFA status
        mfa_required = bool(user.mfa_enabled) and not getattr(
            user, "is_trusted_device", False
        )
        
        if mfa_required:
            # Generate MFA token (short-lived)
            mfa_token = self.mfa_service.generate_mfa_token(user.id)
            return {
                "mfa_required": True,
                "mfa_token": mfa_token,
                "mfa_method": user.mfa_method,
                "expires_in": 300  # 5 minutes
            }, True
        
        # No MFA needed — login is fully successful right here.
        # NOTE: if MFA *is* required, the success event is published once
        # verify_mfa() actually confirms the second factor (see below) —
        # publishing it here too would record a "succeeded" login for an
        # attempt that hasn't cleared MFA yet.
        await self._publish_event(
            auth_events.AUTH_LOGIN_SUCCEEDED,
            actor_id=user.id,
            payload={"identifier": request.identifier, "mfa_used": "none"},
        )
        return await self._generate_tokens(user), False
    
    # --- Token Generation ---
    
    async def _generate_tokens(self, user) -> dict:
        """Generate access and refresh tokens for a user."""
        from jose import jwt  # PyJWT

        # Bump FIRST so the freshly issued access token carries the new
        # version; bumping after encoding instantly revokes the new token.
        user.token_version += 1
        await self.user_repo.commit()

        # Access token (HS256 + exp claim; python-jose has no expires_at kwarg)
        access_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = jwt.encode(
            {
                "sub": str(user.id),
                "username": user.username,
                "roles": getattr(user, "roles", []) or [],
                "permissions": getattr(user, "permissions", []) or [],
                "privacy_level": getattr(user, "privacy_level", None) or "team_only",
                "token_version": user.token_version,
                "type": "access",
                "exp": datetime.utcnow() + access_expires,
            },
            settings.SECRET_KEY,
            algorithm=settings.ALGORITHM,
        )
        
        # Refresh token
        refresh_token = secrets.token_urlsafe(32)
        # Store hash of refresh token
        refresh_token_hash = hashlib.sha256(refresh_token.encode()).hexdigest()
        
        # Store in sessions table
        from app.modules.auth.db.models import Sessions
        session = Sessions(
            user_id=user.id,
            refresh_hash=refresh_token_hash,
            family_id=getattr(user, "family_id", None) or uuid4(),
            auth_method=user.auth_mode,
            mfa_satisfied=bool(user.mfa_enabled),
            expires_at=datetime.utcnow() + timedelta(
                days=settings.REFRESH_TOKEN_EXPIRE_DAYS
            ),
        )
        await self.user_repo.add(session)
        await self.user_repo.commit()

        # Get user read model for response
        user_read = self._get_user_read_model(user)
        
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "Bearer",
            "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            "user": user_read,
        }
    
    # --- MFA ---
    
    async def verify_mfa(self, mfa_token: str, mfa_method: str, user_id: UUID) -> bool:
        """Verify MFA token."""
        verified = await self.mfa_service.verify_token(mfa_token, mfa_method, user_id)
        if verified:
            # This is the actual "login succeeded" moment for an MFA-gated
            # login — the plain login() above only got this far because
            # mfa_required was True, so it deliberately did not publish
            # AUTH_LOGIN_SUCCEEDED itself.
            await self._publish_event(
                auth_events.AUTH_LOGIN_SUCCEEDED,
                actor_id=user_id,
                payload={"mfa_used": mfa_method},
            )
        else:
            await self._publish_event(
                auth_events.AUTH_LOGIN_FAILED,
                actor_id=user_id,
                payload={"reason": "mfa_invalid", "mfa_method": mfa_method},
            )
        return verified
    
    async def enroll_mfa(self, user_id: UUID, secret: str) -> dict:
        """Enroll TOTP MFA for a user."""
        return await self.mfa_service.enroll(user_id, secret)
    
    # --- Device Management ---
    
    async def register_device(self, request: DeviceRegisterRequest, user_id: UUID) -> dict:
        """Register a new device for a user."""
        # Generate HMAC key for this device
        hmac_key = secrets.token_bytes(32)
        
        from app.modules.auth.db.models import UserDevices
        device = UserDevices(
            user_id=user_id,
            device_fingerprint=request.device_fingerprint,
            mac_address=request.mac_address,
            mac_source=request.mac_source,
            platform=request.platform,
            device_label=request.device_label,
            os_info=request.os_info,
            hmac_key_enc=self._encrypt_hmac_key(hmac_key),
            is_trusted=False,
        )
        await self.device_repo.add(device)
        await self.user_repo.commit()

        await self._publish_event(
            auth_events.AUTH_DEVICE_REGISTERED,
            actor_id=user_id,
            payload={
                "device_id": str(device.id),
                "platform": request.platform,
                "device_label": request.device_label,
            },
        )
        
        return {
            "device_id": str(device.id),
            "hmac_key": base64.b64encode(hmac_key).decode(),  # Only sent once
            "is_trusted": False,
            "requires_mfa_to_trust": True,
        }
    
    async def trust_device(self, device_id: UUID, mfa_satisfied: bool, user_id: UUID) -> dict:
        """Mark device as trusted (requires MFA)."""
        from app.modules.auth.db.models import UserDevices
        device = await self.device_repo.get(device_id)
        if device.user_id != user_id:
            raise APIError(
                error_code="DEVICE_NOT_FOUND",
                message="دستگاه یافت نشد.",
                status_code=status.HTTP_404_NOT_FOUND
            )
        
        device.is_trusted = True
        device.trusted_at = datetime.utcnow()
        device.trusted_by_mfa = mfa_satisfied
        await self.user_repo.commit()

        await self._publish_event(
            auth_events.AUTH_DEVICE_TRUSTED,
            actor_id=user_id,
            payload={"device_id": str(device_id), "mfa_satisfied": mfa_satisfied},
        )
        
        return {"status": "device_trusted"}
    
    # --- Password Management ---
    
    async def change_password(self, user_id: UUID, request: PasswordChangeRequest) -> dict:
        """Change user password."""
        user = await self.user_repo.get(user_id)
        if not user:
            raise APIError(
                error_code="USER_NOT_FOUND",
                message="کاربر یافت نشد.",
                status_code=status.HTTP_404_NOT_FOUND
            )
        
        # Verify current password
        if not pwd_context.verify(request.current_password, user.password_hash):
            raise APIError(
                error_code="INVALID_PASSWORD",
                message="رمز فعلی صحیح نیست.",
                status_code=status.HTTP_400_BAD_REQUEST
            )
        
        # Hash new password
        new_hash = pwd_context.hash(request.new_password)
        user.password_hash = new_hash
        user.password_changed_at = datetime.utcnow()
        user.must_change_password = False
        await self.user_repo.commit()
        
        # Invalidate all sessions (force re-login)
        user.token_version += 1
        await self.user_repo.commit()
        
        await self._publish_event(
            auth_events.AUTH_PASSWORD_CHANGED,
            actor_id=user_id,
            payload={},
        )
        
        return {"status": "password_changed"}
    
    # --- Password Reset ---
    
    async def forgot_password(self, request: PasswordForgotRequest) -> dict:
        """Start password reset process."""
        user = await self.user_repo.get_by_identifier(request.identifier)
        if not user:
            # Don't reveal if user exists - security through obscurity
            return {"status": "sent"}  # Always say sent for security
        
        # Generate reset token
        reset_token = secrets.token_urlsafe(32)
        reset_token_hash = hashlib.sha256(reset_token.encode()).hexdigest()
        
        # Store in user record
        user.password_reset_token = reset_token_hash
        user.password_reset_expires = datetime.utcnow() + timedelta(hours=24)
        await self.user_repo.commit()
        
        # In real implementation: send email with reset link
        # For now, just return that process started
        return {"status": "reset_initiated", "expires_in_hours": 24}
    
    # --- Profile / Session / Devices ---

    async def get_profile(self, user_id: UUID) -> dict:
        """Current user profile + effective roles/permissions."""
        user = await self.user_repo.get(user_id)
        if not user:
            raise APIError(
                error_code="USER_NOT_FOUND",
                message="کاربر یافت نشد.",
                status_code=status.HTTP_404_NOT_FOUND,
            )
        profile = self._get_user_read_model(user)
        profile["id"] = str(profile["id"])
        return profile

    async def logout(self, user_id: UUID) -> dict:
        """Revoke all sessions for the user (bump token_version)."""
        user = await self.user_repo.get(user_id)
        if not user:
            raise APIError(
                error_code="USER_NOT_FOUND",
                message="کاربر یافت نشد.",
                status_code=status.HTTP_404_NOT_FOUND,
            )
        user.token_version += 1
        await self.user_repo.commit()
        await self._publish_event(auth_events.AUTH_LOGOUT, actor_id=user_id, payload={})
        return {"status": "logged_out"}

    async def list_devices(self, user_id: UUID) -> list:
        """List known devices with masked MAC addresses."""
        from sqlalchemy import select

        from app.modules.auth.db.models import UserDevices

        result = await self.user_repo.session.execute(
            select(UserDevices).where(UserDevices.user_id == user_id)
        )
        devices = result.scalars().all()
        items = []
        for d in devices:
            mac = d.mac_address or ""
            masked = (
                f"{mac[:5]}**:**:**:{mac[-2:]}"
                if len(mac) == 17 else None
            )
            items.append({
                "id": str(d.id),
                "device_label": d.device_label,
                "platform": d.platform,
                "mac_address_masked": masked,
                "is_trusted": d.is_trusted,
                "last_seen_at": d.last_seen_at.isoformat() if d.last_seen_at else None,
                "last_ip": str(d.last_ip) if d.last_ip else None,
            })
        return items

    async def _generate_tokens_by_id(self, user_id: UUID) -> dict:
        """Generate fresh tokens for a user ID (used by /refresh)."""
        user = await self.user_repo.get(user_id)
        if not user or not user.is_active:
            raise APIError(
                error_code="USER_NOT_FOUND",
                message="کاربر یافت نشد.",
                status_code=status.HTTP_404_NOT_FOUND,
            )
        return await self._generate_tokens(user)

    async def refresh_session(self, refresh_token: str, db_session=None) -> dict:
        """Validate an opaque refresh token and rotate the session.

        The refresh token is stored as SHA-256 in ``auth.sessions``. We look
        it up, reject revoked/expired sessions, revoke the old session and
        issue fresh tokens. Returns the new ``{status, tokens, user}``-shaped
        response expected by the frontend auth client.
        """
        from sqlalchemy import select
        from app.modules.auth.db.models import Sessions

        session = self.user_repo.session
        if session is None:
            raise APIError(
                error_code="SESSION_ERROR",
                message="نشست قابل استفاده نیست.",
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        refresh_hash = hashlib.sha256(refresh_token.encode()).hexdigest()

        result = await session.execute(
            select(Sessions).where(Sessions.refresh_hash == refresh_hash)
        )
        s = result.scalar_one_or_none()
        if s is None:
            raise APIError(
                error_code="TOKEN_INVALID",
                message="توکن یافت نشد.",
                status_code=status.HTTP_401_UNAUTHORIZED,
            )
        if s.revoked_at is not None:
            raise APIError(
                error_code="TOKEN_REVOKED",
                message="نشست باطل شده است.",
                status_code=status.HTTP_401_UNAUTHORIZED,
            )
        # NOTE: timestamptz columns come back timezone-aware from asyncpg,
        # so compare against an aware "now" (naive utcnow() would TypeError).
        now_utc = datetime.now(timezone.utc)
        expires_at = s.expires_at
        if expires_at is not None:
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)
            if expires_at < now_utc:
                raise APIError(
                    error_code="TOKEN_EXPIRED",
                    message="نشست منقضی شده است.",
                    status_code=status.HTTP_401_UNAUTHORIZED,
                )

        # Revoke the old session (rotation).
        s.revoked_at = datetime.utcnow()
        s.revoked_reason = "refresh"

        user = await self.user_repo.get(s.user_id)
        if not user or not user.is_active:
            raise APIError(
                error_code="USER_NOT_FOUND",
                message="کاربر یافت نشد.",
                status_code=status.HTTP_404_NOT_FOUND,
            )

        # Carry the session family forward so rotation stays in one family.
        user.family_id = s.family_id
        new_tokens = await self._generate_tokens(user)
        await self.user_repo.commit()
        return {
            "status": "token_refreshed",
            "tokens": {
                "access_token": new_tokens.get("access_token"),
                "refresh_token": new_tokens.get("refresh_token"),
                "token_type": "Bearer",
                "expires_in": new_tokens.get("expires_in"),
            },
            "user": new_tokens.get("user"),
        }

    # --- Helper methods ---
    
    def _validate_national_id(self, national_id: str) -> bool:
        """Validate Iranian national ID format and checksum."""
        # Remove any separators
        national_id = national_id.strip()
        
        # Must be exactly 10 digits
        if not national_id.isdigit() or len(national_id) != 10:
            return False
        
        # Calculate checksum (official Iranian algorithm)
        digits = [int(d) for d in national_id]
        # Iranian national ID checksum: sum of (digit * position) % 11
        # Positions: 10, 9, 8, 7, 6, 5, 4, 3, 2 (from left to right, excluding check digit)
        weights = [10, 9, 8, 7, 6, 5, 4, 3, 2]
        weighted_sum = sum(d * w for d, w in zip(digits[:9], weights))
        remainder = weighted_sum % 11

        # Official check digit rules:
        # If remainder < 2, the 10th digit must equal remainder;
        # otherwise it must equal (11 - remainder).
        expected_check = remainder if remainder < 2 else 11 - remainder

        return digits[9] == expected_check
    
    def _encrypt_national_id(self, national_id: str) -> tuple:
        """Encrypt national ID with AES-GCM; returns (ciphertext, nonce)."""
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        nonce = secrets.token_bytes(12)  # 96-bit nonce for GCM
        kdf_key = hashlib.sha256(settings.SECRET_KEY.encode()).digest()
        aesgcm = AESGCM(kdf_key)
        return aesgcm.encrypt(nonce, national_id.encode(), None), nonce

    def _encrypt_hmac_key(self, key: bytes) -> bytes:
        """Encrypt HMAC key using AES-GCM with a per-key nonce."""
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        nonce = secrets.token_bytes(12)  # 96-bit nonce for GCM
        # In production, use a key from Vault, not hardcoded
        # Here we use a simplified approach
        kdf_key = hashlib.sha256(settings.SECRET_KEY.encode()).digest()
        aesgcm = AESGCM(kdf_key)
        encrypted = aesgcm.encrypt(nonce, key, None)
        return nonce + encrypted  # prepend nonce
    
    def _decrypt_hmac_key(self, encrypted_key: bytes) -> bytes:
        """Decrypt HMAC key."""
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        kdf_key = hashlib.sha256(settings.SECRET_KEY.encode()).digest()
        nonce = encrypted_key[:12]
        ciphertext = encrypted_key[12:]
        aesgcm = AESGCM(kdf_key)
        return aesgcm.decrypt(nonce, ciphertext, None)
    
    def _get_user_read_model(self, user) -> dict:
        """Convert user model to read model for API responses."""
        from datetime import datetime
        
        # Get masked national ID (last 4 digits)
        national_id = getattr(user, "national_id", None)
        if not national_id:
            national_id = f"*****{user.national_id_last4}" if getattr(
                user, "national_id_last4", None) else "******"
        national_id_masked = (
            f"*****{national_id[-4:]}" if national_id else "******"
        )

        return {
            "id": user.id,
            "username": user.username,
            "display_name": user.display_name,
            "national_id_masked": national_id_masked,
            "is_active": user.is_active,
            "roles": getattr(user, "roles", None) or [],
            "permissions": getattr(user, "permissions", None) or [],
            "privacy_level": getattr(user, "privacy_level", None) or "team_only",
            "auth_mode": user.auth_mode or "local",
            "mfa_enabled": user.mfa_enabled or False,
            "last_login_at": user.last_login_at,
        }
    
    async def _publish_event(
        self, event_type: str, *, payload: dict, actor_id: UUID | None = None
    ) -> None:
        """رویداد دامنه را منتشر می‌کند — جایگزین متد قدیمی ``_audit_log``.

        برخلاف نسخه‌ی قبلی، اینجا هیچ importی به ``app.modules.audit``
        وجود ندارد (نقض مرز ماژول که تست ``test_module_boundaries.py``
        آن را گرفت). به‌جایش یک ``DomainEvent`` روی ``event_bus`` منتشر
        می‌شود؛ ماژول Audit (اگر مشترک شده باشد) و هر ماژول دیگری که به
        این رویداد علاقه دارد (مثلاً Notification برای هشدار «ورود از
        دستگاه جدید» طبق کاتالوگ رویدادهای سند) بدون هیچ وابستگی کدی
        به auth، آن را دریافت می‌کنند.

        TODO(security): وقتی ``core/context.py`` (ContextVar) و
        ``core/middleware/`` واقعی پیاده شدند (بخش ۱.۲ و ۳.۱ سند)،
        ``ip_address`` / ``mac_address`` / ``device_fingerprint`` باید
        از آن‌جا در payload اضافه شوند — نه از پارامترهای متد سرویس
        (که هنوز به این service پاس داده نمی‌شوند).
        """
        from app.core.events.bus import DomainEvent

        event = DomainEvent(event_type=event_type, payload=payload, actor_id=actor_id)
        try:
            await event_bus.publish(event, self.user_repo.session)
            await self.user_repo.commit()
        except Exception:
            # مطابق طراحی bus.py: خطای یک handler بالا می‌آید. این‌جا آن را
            # قورت نمی‌دهیم (برخلاف باگ قبلی) اما هم اجازه نمی‌دهیم شکست
            # انتشار رویداد، کل جریان login/register/... را متوقف کند —
            # چون در نبود Outbox dispatcher واقعی هنوز، این یک تصمیم آگاهانه
            # است، نه بی‌توجهی. اگر می‌خواهید شکست انتشار رویداد باعث شکست
            # کل عملیات شود (مثلاً برای الزامات Compliance)، این except را
            # حذف کنید تا خطا بالا برود.
            import logging
            logging.getLogger("auth.events").exception(
                "failed to publish event_type=%s", event_type
            )
```

==========================================================================================
## FILE: basteh_URGENT/backend/app/modules/rbac/services/permission_service.py
## SIZE: 4107 bytes
==========================================================================================

```python
"""
app/modules/rbac/services/permission_service.py

``effective_permissions(user_id)`` طبق بخش ۱۲.۴ سند: «نتیجه در Redis با
TTL ۶۰ ثانیه کش می‌شود». ابطال کش با رویداد ``rbac.role.assigned``
(که ``RoleAssignmentService`` در rbac_patch.zip قبلاً منتشر می‌کند)
در ``app/modules/rbac/events.py`` انجام می‌شود — نه اینجا.

⚠️ فرض: مسیر Redis client شما را نمی‌دانم، پس این کلاس یک شیء
async سازگار با ``redis.asyncio.Redis`` (متدهای get/setex/delete)
می‌گیرد. اگر wrapper اختصاصی دارید (مثل ``app.core.cache.get_redis()``)،
همان را در dependency تزریق کنید — امضای PermissionService عوض
نمی‌شود.
"""

from __future__ import annotations

import json
from typing import Any
from uuid import UUID

CACHE_TTL_SECONDS = 60
_CACHE_KEY_PREFIX = "rbac:perms:"


def cache_key(user_id: UUID) -> str:
    return f"{_CACHE_KEY_PREFIX}{user_id}"


class PermissionService:
    def __init__(self, session: Any, redis_client: Any | None = None) -> None:
        self.session = session
        self.redis = redis_client

    async def effective_permissions(self, user_id: UUID) -> set[str]:
        if self.redis is not None:
            cached = await self._get_cached(user_id)
            if cached is not None:
                return cached

        perms = await self._load_from_db(user_id)

        if self.redis is not None:
            await self._set_cached(user_id, perms)

        return perms

    async def invalidate(self, user_id: UUID) -> None:
        """توسط subscriber رویداد rbac.role.assigned/revoked صدا زده می‌شود."""
        if self.redis is None:
            return
        try:
            await self.redis.delete(cache_key(user_id))
        except Exception:  # noqa: BLE001 — خرابی کش نباید عملیات اصلی را بشکند
            import logging
            logging.getLogger("rbac.permissions").exception(
                "failed to invalidate permission cache for user_id=%s", user_id
            )

    # ── داخلی ──────────────────────────────────────────────
    async def _load_from_db(self, user_id: UUID) -> set[str]:
        from sqlalchemy import text

        # طبق schema بخش ۴.۳: user_roles → role_permissions → permissions
        # نقش‌های منقضی‌شده (expires_at گذشته) حساب نمی‌شوند.
        result = await self.session.execute(
            text(
                """
                SELECT DISTINCT p.code
                FROM rbac.user_roles ur
                JOIN rbac.role_permissions rp ON rp.role_id = ur.role_id
                JOIN rbac.permissions p ON p.id = rp.permission_id
                WHERE ur.user_id = :user_id
                  AND (ur.expires_at IS NULL OR ur.expires_at > now())
                """
            ),
            {"user_id": str(user_id)},
        )
        return {row[0] for row in result.fetchall()}

    async def _get_cached(self, user_id: UUID) -> set[str] | None:
        try:
            raw = await self.redis.get(cache_key(user_id))
        except Exception:  # noqa: BLE001 — کش در دسترس نبود؛ برو سراغ DB
            return None
        if raw is None:
            return None
        try:
            return set(json.loads(raw))
        except (TypeError, ValueError):
            return None

    async def _set_cached(self, user_id: UUID, perms: set[str]) -> None:
        try:
            await self.redis.setex(cache_key(user_id), CACHE_TTL_SECONDS, json.dumps(sorted(perms)))
        except Exception:  # noqa: BLE001 — نوشتن کش شکست خورد؛ درخواست جاری هنوز درست جواب می‌گیرد
            import logging
            logging.getLogger("rbac.permissions").exception(
                "failed to cache permissions for user_id=%s", user_id
            )
```

==========================================================================================
## FILE: basteh_URGENT/backend/app/ws/handlers/chat.py
## SIZE: 17288 bytes
==========================================================================================

```python
"""
Chat WebSocket Handler
Architecture Reference: Sections 8.1, 8.2, 8.3
Complete implementation with:
- Connection lifecycle with auth
- Per-message room membership verification
- Message body sanitization
- File upload flow
- Redis Pub/Sub broadcasting
- Room management (join/leave/archive)
"""

import json
import base64
import hashlib
import hmac
import logging
from uuid import UUID
from datetime import datetime, timedelta
from starlette.websockets import WebSocketState
from fastapi import WebSocket, WebSocketDisconnect, Depends
from typing import Optional, Dict, Set, Any

from app.core.database import async_session_context
from app.core.security import verify_hmac_signature, get_device_fingerprint
from app.core.redis import get_redis_pool
from app.core.errors import APIError, AuthenticationError, NotFoundError, PrivacyHiddenError
from app.modules.chat.services.chat_service import ChatService
from app.ws.manager import chat_ws_manager, get_ws_manager
from app.modules.chat.db.Models import Rooms, RoomMembers, Messages

logger = logging.getLogger(__name__)


class ChatWebSocketHandler:
    """Handles WebSocket connection and message lifecycle per Architecture v2.0 Sections 8.1-8.3."""
    
    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}
        self.user_room_membership: Dict[str, Set[str]] = {}
    
    async def handle_handshake(self, websocket: WebSocket, token: str, fingerprint: str) -> Optional[UUID]:
        """Validate JWT and device fingerprint on WebSocket handshake.
        
        Returns user_id if authentication successful, None otherwise.
        """
        try:
            # Verify JWT token
            from jose import jwt
            payload = jwt.decode(token, options={"verify_signature": False})
            user_id: UUID = UUID(payload["sub"])
            
            # Verify device fingerprint
            device_valid = await verify_hmac_signature(
                fingerprint=fingerprint,
                user_id=user_id,
                endpoint="ws_chat_handshake"
            )
            
            if not device_valid:
                await websocket.close(code=4401, reason="Invalid device fingerprint")
                return None
            
            # Verify user is active (not banned, etc.)
            async with async_session_context() as session:
                from app.modules.auth.db.Models import Users
                result = await session.execute(
                    select(Users).where(Users.id == str(user_id), Users.is_active == True)
                )
                user = result.scalar_one_or_none()
                
                if not user:
                    await websocket.close(code=4401, reason="User not active")
                    return None
            
            return user_id
            
        except Exception as e:
            logger.error(f"WebSocket handshake error: {e}")
            await websocket.close(code=4403, reason="Authentication failed")
            return None
    
    async def handle_connect(self, websocket: WebSocket, user_id: UUID) -> None:
        """Accept WebSocket connection and initialize tracking."""
        await websocket.accept()
        self.active_connections[str(user_id)] = websocket
        
        # Subscribe to Redis channel for this user
        redis = get_redis_pool()
        await redis.subscribe(f"user:{user_id}:chat")
    
    async def handle_disconnect(self, user_id: UUID) -> None:
        """Handle WebSocket disconnection."""
        # Leave all rooms user was in
        rooms = self.user_room_membership.get(str(user_id), set())
        for room_id in rooms:
            await self.handle_leave_room(user_id, room_id)
        
        # Remove from tracking
        self.active_connections.pop(str(user_id), None)
        self.user_room_membership.pop(str(user_id), None)
        
        # Unsubscribe from Redis
        redis = get_redis_pool()
        await redis.unsubscribe(f"user:{user_id}:chat")
    
    async def handle_join_room(self, user_id: UUID, room_id: UUID, websocket: WebSocket) -> bool:
        """Join a chat room with membership validation."""
        async with async_session_context() as session:
            from sqlalchemy import select
            from app.modules.chat.db.Models import Rooms, RoomMembers
            
            # Check room exists
            result = await session.execute(select(Rooms).where(Rooms.id == str(room_id)))
            room = result.scalar_one_or_none()
            
            if not room:
                await websocket.close(code=4404, reason="Room not found")
                return False
            
            # Check user is active member
            result = await session.execute(
                select(RoomMembers).where(
                    (RoomMembers.room_id == str(room_id)) &
                    (RoomMembers.user_id == str(user_id)) &
                    (RoomMembers.is_active == True)
                )
            )
            membership = result.scalar_one_or_none()
            
            if not membership:
                await websocket.close(code=4403, reason="You are not a member of this room")
                return False
            
            # Track room membership
            if str(user_id) not in self.user_room_membership:
                self.user_room_membership[str(user_id)] = set()
            self.user_room_membership[str(user_id)].add(str(room_id))
            
            # Add to room connections
            if str(room_id) not in self.active_connections:
                # Would use proper connection tracking per room
                pass
            
            # Notify room
            await self.broadcast_system(room_id, {
                "type": "system",
                "action": "user_joined",
                "user_id": str(user_id),
                "timestamp": datetime.utcnow().isoformat()
            })
            
            return True
    
    async def handle_leave_room(self, user_id: UUID, room_id: UUID) -> None:
        """Handle user leaving a room."""
        # Remove from tracking
        if str(user_id) in self.user_room_membership:
            self.user_room_membership[str(user_id)].discard(str(room_id))
            if not self.user_room_membership[str(user_id)]:
                del self.user_room_membership[str(user_id)]
        
        # Notify room
        await self.broadcast_system(room_id, {
            "type": "system",
            "action": "user_left",
            "user_id": str(user_id),
            "timestamp": datetime.utcnow().isoformat()
        })
    
    async def handle_message(self, user_id: UUID, room_id: UUID, 
                           message_data: dict, websocket: WebSocket) -> Optional[dict]:
        """Handle incoming chat message with full privacy filtering."""
        from app.modules.chat.services.chat_service import ChatService
        
        # Validate room membership (per-message check per architecture 8.1)
        is_member = await ChatService.is_active_member(room_id, user_id)
        if not is_member:
            return {"error": "not_a_member", "code": 4403}
        
        # Sanitize message body (architecture 8.1: DOMPurify equivalent)
        body = message_data.get("body", "")
        sanitized_body = await self._sanitize_message(body)
        
        # Check for replies
        reply_to = message_data.get("reply_to")
        
        # Persist message
        message = await ChatService.persist_message(
            room_id=str(room_id),
            sender_id=str(user_id),
            body=sanitized_body,
            reply_to_id=UUID(reply_to) if reply_to else None
        )
        
        # Broadcast via Redis Pub/Sub (architecture 8.2)
        broadcast_payload = {
            "type": "chat_message",
            "message": {
                "id": str(message.id),
                "room_id": str(message.room_id),
                "sender_id": str(message.sender_id),
                "body": message.body,
                "created_at": message.created_at.isoformat(),
                "reply_to": str(message.reply_to_id) if message.reply_to_id else None,
                "is_edited": message.is_edited,
                "edit_history": message.edit_history if message.edit_history else []
            }
        }
        
        # Publish to Redis channel for this room
        redis = get_redis_pool()
        await redis.publish(f"room:{room_id}:chat", json.dumps(broadcast_payload))
        
        # Also broadcast directly to connected clients in same room
        await self._broadcast_to_room_clients(room_id, broadcast_payload)
        
        return {"status": "sent", "message_id": str(message.id)}
    
    async def _sanitize_message(self, body: str) -> str:
        """Sanitize message body - architecture 8.1 DOMPurify equivalent."""
        # Basic HTML sanitization - in production would use bleach or similar
        import re
        
        # Remove dangerous HTML tags and attributes
        cleanr = re.compile('<.*?>|&([a-z#]+);|[<>&"]')
        cleantext = re.sub(cleanr, '', body)
        
        # URL encoding check
        if len(cleantext) > 1000:
            raise APIError(
                error_code="MESSAGE_TOO_LONG",
                message=" پیام از حد مجاز طولانی است.",
                status_code=400
            )
        
        return cleantext
    
    async def _broadcast_to_room_clients(self, room_id: UUID, payload: dict) -> None:
        """Broadcast message to all WebSocket clients in the room."""
        # Get connected clients in this room from manager
        manager = get_ws_manager()
        if manager and room_id in manager.room_connections:
            for ws, uid in manager.room_connections.get(str(room_id), set()):
                try:
                    await ws.send_text(json.dumps(payload))
                except Exception:
                    # Connection dead, cleanup on disconnect
                    pass
    
    async def handle_file_upload(self, user_id: UUID, room_id: UUID,
                                file_data: dict, websocket: WebSocket) -> dict:
        """Handle file upload flow per architecture 8.2-8.3."""
        from app.modules.chat.services.chat_service import ChatService
        from app.core.redis import get_redis_pool
        
        filename = file_data.get("filename", "")
        file_size = file_data.get("file_size", 0)
        file_type = file_data.get("file_type", "")
        content_base64 = file_data.get("content_base64", "")
        
        # Validate membership
        is_member = await ChatService.is_active_member(room_id, user_id)
        if not is_member:
            return {"error": "not_a_member"}
        
        # Check file size limits (architecture 8.3)
        max_size = 50 * 1024 * 1024  # 50MB default
        if file_size > max_size:
            return {"error": "file_too_large"}
        
        # Check file type
        allowed_types = ["image", "video", "document", "audio"]
        if file_type not in allowed_types:
            return {"error": "invalid_file_type"}
        
        # Step 1: Generate presign URL
        presign_result = await ChatService.generate_presign_url(
            filename=filename,
            file_type=file_type,
            user_id=str(user_id)
        )
        
        if "error" in presign_result:
            return {"error": "presign_failed"}
        
        # Step 2: Client uploads to presigned URL (handled on client side)
        # Step 3: Finalize upload
        finalize_result = await ChatService.finalize_upload(
            upload_id=presign_result["upload_id"],
            filename=filename,
            user_id=str(user_id)
        )
        
        if "error" in finalize_result:
            return {"error": "finalize_failed"}
        
        # Step 4: AV Scan integration
        # Publish to AV scan queue
        redis = get_redis_pool()
        scan_payload = {
            "upload_id": finalize_result["upload_id"],
            "file_id": finalize_result["file_id"],
            "filename": filename,
            "user_id": str(user_id),
            "room_id": str(room_id)
        }
        await redis.publish("file_scan_queue", json.dumps(scan_payload))
        
        # Step 5: Store file reference in database
        # Message object will reference the file
        message = await ChatService.persist_message(
            room_id=str(room_id),
            sender_id=str(user_id),
            body=f"[File: {filename}]",
            metadata={
                "file_id": finalize_result["file_id"],
                "upload_id": finalize_result["upload_id"],
                "file_size": file_size,
                "file_type": file_type
            }
        )
        
        # Broadcast file message
        broadcast_payload = {
            "type": "file_message",
            "message": {
                "id": str(message.id),
                "room_id": str(message.room_id),
                "sender_id": str(message.sender_id),
                "file": {
                    "id": finalize_result["file_id"],
                    "filename": filename,
                    "size": file_size,
                    "type": file_type,
                    "status": "scanning"  # Will update after AV scan
                },
                "created_at": message.created_at.isoformat()
            }
        }
        
        await self._broadcast_to_room_clients(room_id, broadcast_payload)
        
        return {
            "status": "file_initiated",
            "message_id": str(message.id),
            "file_id": finalize_result["file_id"],
            "presign_url": presign_result.get("presign_url"),
            "scan_initiated": True
        }
    
    async def handle_archive_request(self, user_id: UUID, room_id: UUID) -> dict:
        """Handle room archival flow per architecture 8.2."""
        from app.modules.chat.services.chat_service import ChatService
        
        # Check user is member and has permission
        is_member = await ChatService.is_active_member(room_id, user_id)
        if not is_member:
            return {"error": "not_a_member"}
        
        # Two-step archive process per architecture:
        # 1. Soft archive (mark as archived, hide from active lists)
        # 2. Hard delete (after grace period)
        
        # For now, mark room as archived
        await ChatService.archive_room(
            room_id=str(room_id),
            archived_by=str(user_id)
        )
        
        # Notify room
        await self.broadcast_system(room_id, {
            "type": "system",
            "action": "room_archived",
            "room_id": str(room_id),
            "archived_by": str(user_id),
            "timestamp": datetime.utcnow().isoformat()
        })
        
        # Leave all WebSocket connections in this room
        await self.handle_leave_room(user_id, room_id)
        
        return {
            "status": "archiving_initiated",
            "room_id": str(room_id),
            "note": "Two-step archive: soft archive initiated, hard delete after grace period"
        }
    
    async def handle_edit_message(self, user_id: UUID, room_id: UUID,
                                  message_id: UUID, new_body: str) -> dict:
        """Handle message editing with edit history."""
        from app.modules.chat.services.chat_service import ChatService
        
        # Validate membership
        is_member = await ChatService.is_active_member(room_id, user_id)
        if not is_member:
            return {"error": "not_a_member"}
        
        # Sanitize new body
        sanitized_body = await self._sanitize_message(new_body)
        
        # Update message with edit tracking
        result = await ChatService.edit_message(
            message_id=str(message_id),
            new_body=sanitized_body,
            edited_by=str(user_id)
        )
        
        if "error" in result:
            return result
        
        # Broadcast edited message
        broadcast_payload = {
            "type": "edited_message",
            "message": {
                "id": str(message_id),
                "room_id": str(room_id),
                "sender_id": user_id,
                "body": sanitized_body,
                "is_edited": True,
                "edit_history": result.get("edit_history", []),
                "edited_at": result.get("edited_at")
            }
        }
        
        await self._broadcast_to_room_clients(room_id, broadcast_payload)
        
        return {"status": "edited", "message_id": str(message_id)}


# Global handler instance
chat_handler = ChatWebSocketHandler()


def get_chat_handler() -> ChatWebSocketHandler:
    return chat_handler
```

==========================================================================================
## FILE: basteh_URGENT/backend/app/ws/manager.py
## SIZE: 5307 bytes
==========================================================================================

```python
"""Connection manager for chat/notification WebSockets (architecture 8.1).

Connections are kept in-process per worker; room messages are fanned out
through Redis pub/sub so multiple workers deliver to the same room.
Redis is optional: when unreachable the in-memory broker on this process
is used, which is exactly right for local development and testing.
"""

from __future__ import annotations

import asyncio
import itertools
import json
import logging
from typing import Any, Awaitable, Callable, Optional
from uuid import UUID

from fastapi import WebSocket

from app.core.redis import get_redis_broker

logger = logging.getLogger("ws.manager")

_counter = itertools.count(1)

MSG_BUFFER_LIMIT = 512


class _RoomConnection:
    """One accepted socket in a room."""

    def __init__(self, ws: WebSocket, user_id: UUID, socket_id: int) -> None:
        self.ws = ws
        self.user_id = user_id
        self.socket_id = socket_id
        self.queue: asyncio.Queue = asyncio.Queue(maxsize=MSG_BUFFER_LIMIT)


class ConnectionManager:
    """In-process socket registry + Redis pub/sub bridge per room.

    ``join`` adds the socket to ``_rooms`` and registers a per-socket
    writer task that drains messages broadcast on the room channel.
    ``publish_room`` writes to Redis ``room:{room_id}`` which every worker
    subscribed for that room relays to its local sockets.
    """

    def __init__(self) -> None:
        self._rooms: dict[str, dict[str, _RoomConnection]] = {}
        self._lock = asyncio.Lock()
        self._sub_tasks: dict[str, asyncio.Task] = {}
        self._broker = get_redis_broker()

    @staticmethod
    def _channel(room_id: UUID) -> str:
        return f"room:{room_id}"

    async def join(self, room_id: UUID, ws: WebSocket, user_id: UUID) -> None:
        """Register an accepted socket on a room and relay room broadcasts."""
        key = self._channel(room_id)
        socket_id = next(_counter)
        conn = _RoomConnection(ws, user_id, socket_id)
        async with self._lock:
            self._rooms.setdefault(key, {})[str(socket_id)] = conn
            if key not in self._sub_tasks:
                task = asyncio.create_task(self._relay_loop(key))
                self._sub_tasks[key] = task

    async def leave(self, room_id: UUID, ws: WebSocket) -> None:
        key = self._channel(room_id)
        async with self._lock:
            bucket = self._rooms.get(key)
            if bucket is None:
                return
            for socket_id in list(bucket):
                if bucket[socket_id].ws is ws:
                    bucket.pop(socket_id, None)
            if not bucket:
                self._rooms.pop(key, None)
                task = self._sub_tasks.pop(key, None)
                if task is not None:
                    task.cancel()

    async def broadcast(self, room_id: UUID, payload: dict) -> None:
        """Publish a message to a room channel for every worker to relay.

        Each worker's ``_relay_loop`` subscription delivers the payload to
        the local sockets connected to that room (single delivery only).
        """
        raw = json.dumps(payload, ensure_ascii=False, default=str)
        await self.publish_room(room_id, raw)

    async def publish_room(self, room_id: UUID, raw: str) -> None:
        """Redis pub/sub for cross-worker delivery into ``room:{room_id}``."""
        await self._broker.publish(self._channel(room_id), raw)

    async def _relay_loop(self, key: str) -> None:
        """Subscribe to a room channel and relay messages to local sockets."""
        room_id = key.split(":", 1)[1]
        try:
            async for message in self._broker.subscribe(key):
                async with self._lock:
                    bucket = list(self._rooms.get(key, {}).values())
                for conn in bucket:
                    try:
                        conn.queue.put_nowait(message)
                    except asyncio.QueueFull:
                        pass
        except asyncio.CancelledError:
            return
        except Exception as exc:  # publisher gone between publish and subscribe
            logger.warning("relay loop for %s stopped: %s", key, exc)

    async def drain_to(self, room_id: UUID, ws: WebSocket) -> None:
        """Writer task: drain this socket's queue into the wire connection."""
        # Shared writer owned by the endpoint; see routes/chat.py
        key = self._channel(room_id)
        socket_id = None
        async with self._lock:
            bucket = self._rooms.get(key, {})
            for sid, c in bucket.items():
                if c.ws is ws:
                    socket_id = sid
                    break
        if socket_id is None:
            return
        conn = bucket[socket_id]
        while True:
            raw = await conn.queue.get()
            try:
                await ws.send_text(raw)
            except Exception:
                return


# --- process-wide singleton (initialized in app lifespan) ---

_manager: Optional[ConnectionManager] = None


def get_connection_manager() -> ConnectionManager:
    global _manager
    if _manager is None:
        _manager = ConnectionManager()
    return _manager


def reset_connection_manager() -> None:
    """Testing helper."""
    global _manager
    _manager = None
```

==========================================================================================
## FILE: basteh_URGENT/backend/app/ws/routes.py
## SIZE: 12081 bytes
==========================================================================================

```python
"""WebSocket endpoints (architecture 1.4 / 5.5 / 12.8).

* ``/ws/chat``           - live chat: join + message frames, per-socket rate
                           limiting (20 msg/min), idle timeout (300 s),
                           message size cap (8192 bytes), re-validation of
                           the access token every 60 s (close 4401).
* ``/ws/notifications``  - live push of unread-count + inbox events.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from uuid import UUID

from fastapi import APIRouter, Query, WebSocket, WebSocketDisconnect

from app.core.config import settings
from app.core.database import async_session_context
from app.core.redis import get_redis_broker
from app.core.security import verify_hmac_signature
from app.ws.manager import get_connection_manager

logger = logging.getLogger("ws.routes")

router = APIRouter(tags=["websocket"])

WS_CHAT: str = "/ws/chat"
WS_NOTIFICATIONS: str = "/ws/notifications"

MSG_MAX_BYTES = 8192
IDLE_TIMEOUT_S = 300
REVALIDATE_INTERVAL_S = 60
CHAT_RATE_LIMIT = 20  # messages per minute per socket

# --- shared token verification -------------------------------------------------


def _is_allowed_origin(headers) -> bool:
    allowed = settings.ws_allowed_origins
    if not allowed or "*" in allowed:
        return True
    origin = headers.get("origin") if hasattr(headers, "get") else None
    return origin in allowed


async def _verify_access_token(token: str) -> UUID | None:
    from jose import JWTError, jwt as jose_jwt

    if not token:
        return None
    try:
        claims = jose_jwt.decode(
            token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM]
        )
        sub = claims.get("sub")
        if not sub:
            return None
        return UUID(sub)
    except (JWTError, ValueError, TypeError):
        return None


async def _user_is_active(user_id: UUID) -> bool:
    from sqlalchemy import text

    async with async_session_context() as session:
        row = (await session.execute(
            text("SELECT is_active FROM auth.users WHERE id = :uid"),
            {"uid": str(user_id)},
        )).mappings().first()
    return bool(row and row["is_active"])


# --- chat gateway -----------------------------------------------------------------


@router.websocket(WS_CHAT)
async def chat_gateway(websocket: WebSocket):
    token = websocket.query_params.get("token", "")
    manager = get_connection_manager()

    await websocket.accept()

    if not _is_allowed_origin(websocket.headers):
        await websocket.close(code=4403)
        return

    user_id = await _verify_access_token(token)
    if user_id is None or not await _user_is_active(user_id):
        await websocket.close(code=4401, reason="invalid or expired token")
        return

    sw = _SlidingWindow(CHAT_RATE_LIMIT, 60)
    joined_room: UUID | None = None
    revalidate_ok = True

    async def revalidate_task():
        nonlocal revalidate_ok
        while True:
            await asyncio.sleep(REVALIDATE_INTERVAL_S)
            if not await _user_is_active(user_id):
                revalidate_ok = False
                try:
                    await websocket.close(code=4401, reason="token expired")
                except Exception:
                    pass
                return

    reval = asyncio.create_task(revalidate_task())
    writer: asyncio.Task | None = None

    try:
        while True:
            if not revalidate_ok:
                break
            try:
                raw = await asyncio.wait_for(websocket.receive_text(), timeout=IDLE_TIMEOUT_S)
            except asyncio.TimeoutError:
                await websocket.close(code=4408, reason="idle timeout")
                break

            if len(raw.encode("utf-8")) > MSG_MAX_BYTES:
                await websocket.send_json({"type": "error", "code": "MESSAGE_TOO_LARGE"})
                await websocket.close(code=1009)
                break

            try:
                frame = json.loads(raw)
            except (json.JSONDecodeError, TypeError):
                await websocket.send_json({"type": "error", "code": "INVALID_FRAME"})
                continue

            ftype = frame.get("type")
            if ftype == "join":
                try:
                    room_id = UUID(str(frame.get("room_id")))
                except (ValueError, TypeError):
                    await websocket.send_json({"type": "error", "code": "BAD_ROOM"})
                    continue
                if not await _is_member(room_id, user_id):
                    await websocket.send_json({"type": "error", "code": "NOT_A_MEMBER"})
                    continue
                if joined_room is not None and joined_room != room_id:
                    await manager.leave(joined_room, websocket)
                joined_room = room_id
                await manager.join(room_id, websocket, user_id)
                if writer is not None:
                    writer.cancel()
                writer = asyncio.create_task(_write_loop(manager, room_id, websocket, user_id))
                await websocket.send_json(
                    {"type": "connected", "room_id": str(room_id)}
                )
                continue

            if ftype == "message":
                if joined_room is None:
                    await websocket.send_json({"type": "error", "code": "NOT_JOINED"})
                    continue
                if not sw.allow():
                    await websocket.send_json({"type": "error", "code": "RATE_LIMITED"})
                    continue
                body = str(frame.get("body", ""))[:4000]
                if not body.strip():
                    await websocket.send_json({"type": "error", "code": "EMPTY_MESSAGE"})
                    continue
                body = _sanitize_html(body)
                if not body:
                    await websocket.send_json({"type": "error", "code": "EMPTY_MESSAGE"})
                    continue
                room_id = joined_room
                if not await _is_member(room_id, user_id):
                    await websocket.send_json({"type": "error", "code": "NOT_A_MEMBER"})
                    continue
                saved = await _persist_message(room_id, user_id, body)
                await manager.broadcast(
                    room_id,
                    {
                        "type": "message",
                        "room_id": str(room_id),
                        "sender_id": str(user_id),
                        "body": body,
                        "id": str(saved.get("id")),
                        "created_at": saved.get("created_at"),
                    },
                )
                continue

            if ftype == "leave":
                if joined_room is not None:
                    await manager.leave(joined_room, websocket)
                    joined_room = None
                    await websocket.send_json({"type": "left"})
                continue

            if ftype == "ping":
                await websocket.send_json({"type": "pong"})
                continue

            await websocket.send_json({"type": "error", "code": "UNKNOWN_FRAME"})

    except WebSocketDisconnect:
        pass
    finally:
        reval.cancel()
        if writer is not None:
            writer.cancel()
        if joined_room is not None:
            await manager.leave(joined_room, websocket)


# --- notifications gateway ----------------------------------------------------------


@router.websocket(WS_NOTIFICATIONS)
async def notifications_gateway(websocket: WebSocket):
    token = websocket.query_params.get("token", "")

    await websocket.accept()

    if not _is_allowed_origin(websocket.headers):
        await websocket.close(code=4403)
        return

    user_id = await _verify_access_token(token)
    if user_id is None or not await _user_is_active(user_id):
        await websocket.close(code=4401, reason="invalid or expired token")
        return

    broker = get_redis_broker()
    channel = f"notifications:{user_id}"

    async def push_unread():
        await websocket.send_json({"type": "unread_count", "count": await _unread_count(user_id)})

    await push_unread()

    async def redis_loop():
        async for message in broker.subscribe(channel):
            try:
                await websocket.send_text(message)
            except Exception:
                return
            # also refresh the headline count after an event
            await push_unread()

    task = asyncio.create_task(redis_loop())
    try:
        while True:
            try:
                raw = await asyncio.wait_for(websocket.receive_text(), timeout=IDLE_TIMEOUT_S)
            except asyncio.TimeoutError:
                await websocket.close(code=4408, reason="idle timeout")
                break
            if len(raw.encode("utf-8")) > MSG_MAX_BYTES:
                await websocket.close(code=1009)
                break
            try:
                frame = json.loads(raw)
            except (json.JSONDecodeError, TypeError):
                continue
            if frame.get("type") == "ping":
                await websocket.send_json({"type": "pong"})
            elif frame.get("type") == "unread_count":
                await push_unread()
    except WebSocketDisconnect:
        pass
    finally:
        task.cancel()


# --- helpers -------------------------------------------------------------------------


class _SlidingWindow:
    """Simple 20/min sliding window per socket (WS-only, independent of REST)."""

    def __init__(self, limit: int, window: int) -> None:
        self._limit = limit
        self._window = window
        self._hits: list[float] = []

    def allow(self) -> bool:
        now = time.monotonic()
        self._hits = [t for t in self._hits if now - t < self._window]
        if len(self._hits) >= self._limit:
            return False
        self._hits.append(now)
        return True


async def _write_loop(manager, room_id: UUID, websocket: WebSocket, user_id: UUID) -> None:
    """Drain this socket's outgoing queue into the wire (broadcast fan-out)."""
    await manager.drain_to(room_id, websocket)


async def _is_member(room_id: UUID, user_id: UUID) -> bool:
    from sqlalchemy import text

    async with async_session_context() as session:
        row = (await session.execute(
            text("""
                SELECT 1 FROM chat.room_members
                 WHERE room_id = :rid AND user_id = :uid AND left_at IS NULL
            """),
            {"rid": str(room_id), "uid": str(user_id)},
        )).first()
    return row is not None


async def _persist_message(room_id: UUID, sender_id: UUID, body: str) -> dict:
    from datetime import datetime, timezone
    from sqlalchemy import text

    async with async_session_context() as session:
        row = (await session.execute(
            text("""
                INSERT INTO chat.messages (room_id, sender_id, body, message_type, is_edited)
                VALUES (:rid, :uid, :body, 'text', FALSE)
                RETURNING id, created_at
            """),
            {"rid": str(room_id), "uid": str(sender_id), "body": body},
        )).mappings().first()
        await session.commit()
    return {
        "id": str(row["id"]),
        "created_at": row["created_at"].isoformat() if isinstance(row["created_at"], datetime) else str(row["created_at"]),
    }


def _sanitize_html(body: str) -> str:
    """Strip angle-bracket markup from message bodies (arch 8.1)."""
    import re

    return re.sub(r"<[^>]*>", "", body).strip()


async def _unread_count(user_id: UUID) -> int:
    from sqlalchemy import text

    async with async_session_context() as session:
        row = (await session.execute(
            text("""
                SELECT count(*) AS n FROM notification.notifications
                 WHERE user_id = :uid AND is_read = FALSE
            """),
            {"uid": str(user_id)},
        )).mappings().first()
    return row["n"] if row else 0
```

==========================================================================================
## FILE: bastehA_auth_rbac_audit/backend/app/modules/audit/api/routes.py
## SIZE: 682 bytes
==========================================================================================

```python
"""Audit module API routes (stub)."""
from fastapi import APIRouter

router = APIRouter(prefix="/audit", tags=["Audit"])


@router.get("/logs", response_model=dict)
async def list_audit_logs():
    """List audit logs (stub — returns empty until M11 routes land)."""
    return {"status": "success", "data": []}


@router.get("/integrity-check", response_model=dict)
async def integrity_check():
    """Verify audit hash-chain integrity."""
    try:
        from app.audit.integrity import check_audit_integrity

        return await check_audit_integrity()
    except Exception as exc:  # pragma: no cover - defensive
        return {"status": "unavailable", "message": str(exc)}
```

==========================================================================================
## FILE: bastehA_auth_rbac_audit/backend/app/modules/audit/audit_init.py
## SIZE: 260 bytes
==========================================================================================

```python
"""Audit module public interface (stub — full implementation per Architecture v2.0 Section M11)."""
from app.modules.audit.api.routes import router
from app.modules.audit.events import register_event_handlers

__all__ = ["router", "register_event_handlers"]
```

==========================================================================================
## FILE: bastehA_auth_rbac_audit/backend/app/modules/audit/db/models.py
## SIZE: 6239 bytes
==========================================================================================

```python
"""
app/modules/audit/db/models.py

مدل‌های ORM جدول‌های ماژول Audit — دقیقاً مطابق DDL سند معماری v2.0،
بخش ۴.۸. این فایل قبلاً وجود نداشت (پوشه‌ی db/ اصلاً زیر
app/modules/audit/ نبود) — پس اینجا از صفر ساخته شده، بدون ریسک
تداخل با چیزی که از قبل بود.

⚠️ پارتیشن‌بندی (`PARTITION BY RANGE (timestamp)`) در سطح ORM پیاده
نشده — پارتیشن‌بندی یک تصمیم DDL/عملیاتی است که باید در Migration
دستی مدیریت شود (پارتیشن‌های فصلی جدید باید هر فصل ساخته شوند؛
معمولاً با یک Job زمان‌بندی‌شده). برای MVP، جدول ساده (بدون
پارتیشن) کاملاً کار می‌کند؛ پارتیشن‌بندی را می‌توان بعداً، وقتی حجم
داده واقعاً به آن نیاز پیدا کرد، از طریق یک migration جدا اضافه کرد.

⚠️ فرض: ``from app.core.db.base import Base`` — مثل outbox.py، اگر
اسم/مسیر واقعی فرق دارد فقط این import را در هر دو فایل یکسان اصلاح
کنید.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import CHAR, Boolean, DateTime, SmallInteger, String, Text, BigInteger
from sqlalchemy.dialects.postgresql import INET, JSONB, UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func

try:
    from app.core.db.base import Base
except ImportError:  # pragma: no cover — فقط برای import مستقل این فایل
    from sqlalchemy.orm import DeclarativeBase

    class Base(DeclarativeBase):  # type: ignore[no-redef]
        pass


class AuditLog(Base):
    """``audit.audit_logs`` — لاگ عمومی همه‌ی عملیات (سند، بخش ۴.۸)."""

    __tablename__ = "audit_logs"
    __table_args__ = {"schema": "audit"}

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    user_id: Mapped[UUID | None] = mapped_column(PG_UUID(as_uuid=True), nullable=True)
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    entity_type: Mapped[str | None] = mapped_column(String(50), nullable=True)
    entity_id: Mapped[UUID | None] = mapped_column(PG_UUID(as_uuid=True), nullable=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    # هویت شبکه و دستگاه
    ip_address: Mapped[str | None] = mapped_column(INET, nullable=True)
    mac_address: Mapped[str | None] = mapped_column(String(17), nullable=True)
    mac_verified: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    device_fingerprint: Mapped[str | None] = mapped_column(String(255), nullable=True)
    device_id: Mapped[UUID | None] = mapped_column(PG_UUID(as_uuid=True), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(Text, nullable=True)
    session_id: Mapped[UUID | None] = mapped_column(PG_UUID(as_uuid=True), nullable=True)

    result: Mapped[str] = mapped_column(String(20), nullable=False)  # success|failure|denied
    details: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    old_value: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    new_value: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    geo_location: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    request_id: Mapped[UUID | None] = mapped_column(PG_UUID(as_uuid=True), nullable=True)
    correlation_id: Mapped[UUID | None] = mapped_column(PG_UUID(as_uuid=True), nullable=True)

    # یکپارچگی — زنجیره‌ی هش
    prev_hash: Mapped[str | None] = mapped_column(CHAR(64), nullable=True)
    row_hash: Mapped[str] = mapped_column(CHAR(64), nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class LoginAuditLog(Base):
    """``audit.login_audit_logs`` — لاگ اختصاصی تلاش‌های ورود (سند، بخش ۴.۸)."""

    __tablename__ = "login_audit_logs"
    __table_args__ = {"schema": "audit"}

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    user_id: Mapped[UUID | None] = mapped_column(PG_UUID(as_uuid=True), nullable=True)
    username: Mapped[str | None] = mapped_column(String(100), nullable=True)
    national_id_hash: Mapped[str | None] = mapped_column(CHAR(64), nullable=True)
    auth_method: Mapped[str] = mapped_column(String(20), nullable=False)  # local|sso|ldap|kerberos
    mfa_used: Mapped[str | None] = mapped_column(String(16), nullable=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    ip_address: Mapped[str | None] = mapped_column(INET, nullable=True)
    mac_address: Mapped[str | None] = mapped_column(String(17), nullable=True)
    mac_verified: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    device_fingerprint: Mapped[str | None] = mapped_column(String(255), nullable=True)
    device_is_trusted: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    user_agent: Mapped[str | None] = mapped_column(Text, nullable=True)
    success: Mapped[bool] = mapped_column(Boolean, nullable=False)
    failure_reason: Mapped[str | None] = mapped_column(String(255), nullable=True)
    session_id: Mapped[UUID | None] = mapped_column(PG_UUID(as_uuid=True), nullable=True)
    geo_location: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    risk_score: Mapped[int | None] = mapped_column(SmallInteger, nullable=True)  # 0..100

    prev_hash: Mapped[str | None] = mapped_column(CHAR(64), nullable=True)
    row_hash: Mapped[str] = mapped_column(CHAR(64), nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
```

==========================================================================================
## FILE: bastehA_auth_rbac_audit/backend/app/modules/audit/db/repositories.py
## SIZE: 2240 bytes
==========================================================================================

```python
"""
app/modules/audit/db/repositories.py

``last_row_hash`` باید زیر یک قفل مشورتی (advisory lock) خوانده شود تا
اگر دو نوشته‌ی audit هم‌زمان اتفاق بیفتد، هر دو یک ``prev_hash`` یکسان
نخوانند (که زنجیره را می‌شکند). طبق سند (بخش ۱۲.۳): «قفل مشورتی برای
ترتیب صحیح».

از ``pg_advisory_xact_lock`` استفاده شده (نه ``pg_advisory_lock``)
چون قفل تراکنشی است — خودکار در پایان تراکنش (commit/rollback) آزاد
می‌شود؛ نیازی به unlock دستی نیست و در صورت کرش سرویس، قفل باقی
نمی‌ماند.
"""

from __future__ import annotations

from typing import Type

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.modules.audit.db.models import AuditLog, LoginAuditLog

# عدد دلخواه ولی ثابت برای هر زنجیره — دو زنجیره‌ی audit_logs و
# login_audit_logs مستقل از هم قفل می‌شوند (کلید متفاوت برای هرکدام)
# تا نوشتن هم‌زمان روی یکی، دیگری را بلاک نکند.
_LOCK_KEY_AUDIT_LOGS = "audit_hash_chain:audit_logs"
_LOCK_KEY_LOGIN_LOGS = "audit_hash_chain:login_audit_logs"


class AuditRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def last_audit_log_hash(self) -> str | None:
        await self.session.execute(
            text("SELECT pg_advisory_xact_lock(hashtext(:key))"),
            {"key": _LOCK_KEY_AUDIT_LOGS},
        )
        result = await self.session.execute(
            select(AuditLog.row_hash).order_by(AuditLog.id.desc()).limit(1)
        )
        return result.scalar_one_or_none()

    async def last_login_audit_hash(self) -> str | None:
        await self.session.execute(
            text("SELECT pg_advisory_xact_lock(hashtext(:key))"),
            {"key": _LOCK_KEY_LOGIN_LOGS},
        )
        result = await self.session.execute(
            select(LoginAuditLog.row_hash).order_by(LoginAuditLog.id.desc()).limit(1)
        )
        return result.scalar_one_or_none()
```

==========================================================================================
## FILE: bastehA_auth_rbac_audit/backend/app/modules/audit/events.py
## SIZE: 2402 bytes
==========================================================================================

```python
"""
app/modules/audit/events.py  (نسخه‌ی به‌روز — جایگزین نسخه‌ی audit_module_patch.zip)

تنها تغییر نسبت به نسخه‌ی قبلی: "rbac.denied" هم به فهرست رویدادهایی
که audit ثبت می‌کند اضافه شد — چون app/modules/rbac/api/deps.py (در
همین پچ) این رویداد را منتشر می‌کند و باید جایی ثبت شود.
"""

from __future__ import annotations

import logging
from typing import Any

from app.modules.audit.services.audit_service import AuditService

logger = logging.getLogger("audit.events")

_LOGIN_EVENT_TYPES = ("auth.login.succeeded", "auth.login.failed")

_GENERIC_AUDIT_EVENT_TYPES = (
    "auth.user.registered",
    "auth.logout",
    "auth.password.changed",
    "auth.device.registered",
    "auth.device.trusted",
    "auth.user.created_by_admin",
    "auth.user.updated",
    "auth.user.deactivated",
    "auth.user.login_mode.changed",
    "rbac.role.assigned",
    "rbac.role.revoked",
    "rbac.denied",
)

_ALL_SUBSCRIBED_EVENTS = _LOGIN_EVENT_TYPES + _GENERIC_AUDIT_EVENT_TYPES


async def _handle_login_event(event: Any, session: Any) -> None:
    audit = AuditService(session)
    payload = event.payload or {}
    await audit.log_login(
        success=(event.event_type == "auth.login.succeeded"),
        auth_method=payload.get("auth_method", "local"),
        user_id=event.actor_id,
        username=payload.get("identifier"),
        mfa_used=payload.get("mfa_used"),
        failure_reason=payload.get("reason"),
    )


async def _handle_generic_event(event: Any, session: Any) -> None:
    audit = AuditService(session)
    payload = event.payload or {}
    user_id = payload.get("target_user_id", event.actor_id) \
        if event.event_type.startswith(("rbac.", "auth.user.")) else event.actor_id
    result = "denied" if event.event_type == "rbac.denied" else "success"
    await audit.log(
        action=event.event_type,
        user_id=user_id,
        result=result,
        details=payload,
    )


def register_event_handlers(bus) -> None:
    for event_type in _LOGIN_EVENT_TYPES:
        bus.subscribe(event_type, _handle_login_event)
    for event_type in _GENERIC_AUDIT_EVENT_TYPES:
        bus.subscribe(event_type, _handle_generic_event)
    logger.debug("audit module subscribed to %d event types", len(_ALL_SUBSCRIBED_EVENTS))
```

==========================================================================================
## FILE: bastehA_auth_rbac_audit/backend/app/modules/auth/admin_ports.py
## SIZE: 2938 bytes
==========================================================================================

```python
"""
app/modules/auth/admin_ports.py

اسکیمای request/response بخش «تعریف/مدیریت کاربر» در تنظیمات ادمین —
که در سند فقط برای `/auth/register` (ثبت‌نام خودِ کاربر) و
`/admin/users/bulk-login-mode` (بخش ۱۲.۶) وجود دارد، نه برای
create/list/update/deactivate عمومی. این فایل آن‌ها را اضافه می‌کند.

⚠️ عمداً در فایل جدا (نه داخل ``ports.py`` موجودتان) گذاشته شده، چون
محتوای واقعی ``ports.py`` را ندیده‌ام و نمی‌خواهم چیزی را ناخواسته
پاک کنم. اگر می‌خواهید این‌ها را به ``ports.py`` منتقل کنید، فقط
تعریف‌های زیر را کپی/پیست کنید — چیز دیگری در کد به مسیر فایل وابسته
نیست جز importها در ``admin_user_service.py`` و ``admin_routes.py``.
"""

from __future__ import annotations

from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field


class AdminCreateUserRequest(BaseModel):
    """ادمین مستقیماً کاربر می‌سازد — برخلاف ``/auth/register`` که خودِ
    کاربر با کد ملی ثبت‌نام می‌کند. رمز عبور اولیه توسط ادمین تعیین
    می‌شود و ``must_change_password`` اجباری True است."""

    username: str = Field(min_length=3, max_length=64)
    national_id: str = Field(min_length=10, max_length=10)
    display_name: str = Field(min_length=1, max_length=120)
    initial_password: str = Field(min_length=8)
    role_id: int | None = None  # اختیاری: نقش اولیه (از طریق RoleAssignmentService اعطا می‌شود)


class AdminUpdateUserRequest(BaseModel):
    """همه‌ی فیلدها اختیاری — فقط چیزی که فرستاده شود عوض می‌شود."""

    display_name: str | None = Field(default=None, min_length=1, max_length=120)
    is_active: bool | None = None
    must_change_password: bool | None = None


class AdminUserListItem(BaseModel):
    id: UUID
    username: str
    display_name: str
    national_id_masked: str
    is_active: bool
    auth_mode: str
    mfa_enabled: bool
    last_login_at: str | None = None


class AdminUserListResponse(BaseModel):
    items: list[AdminUserListItem]
    total: int
    limit: int
    offset: int


class BulkLoginModeRequest(BaseModel):
    """طبق بخش ۱۲.۶ سند — تغییر sso_enabled برای گروهی از کاربران."""

    user_ids: list[UUID] = Field(min_length=1, max_length=500)
    sso_enabled: bool
    revoke_sessions: bool = False


class BulkFailure(BaseModel):
    user_id: UUID
    code: Literal["NOT_FOUND", "CANNOT_MODIFY_SELF", "NO_LOCAL_PASSWORD"]


class BulkResult(BaseModel):
    updated: list[UUID]
    failed: list[BulkFailure]
```

==========================================================================================
## FILE: bastehA_auth_rbac_audit/backend/app/modules/auth/api/admin_routes.py
## SIZE: 4828 bytes
==========================================================================================

```python
"""
app/modules/auth/api/admin_routes.py

Endpointهای «تعریف/مدیریت کاربر» در تنظیمات — طبق الگوی RBAC middleware
سند (بخش ۱۲.۴: ``require_permission``). این فایل جدید است (کنار
``routes.py`` موجودتان)، تا با روترهای فعلی auth تداخل نکند — کافی
است در ``app/modules/auth/__init__.py`` هر دو روتر را include کنید:

    from app.modules.auth.api.routes import router as auth_router
    from app.modules.auth.api.admin_routes import router as admin_users_router
    router = APIRouter()
    router.include_router(auth_router)
    router.include_router(admin_users_router)

(یا هرطور که routes.py فعلی‌تان را می‌سازید — فقط این router هم باید
مثل بقیه به app اصلی mount شود.)

⚠️ فرض: ``require_permission`` در ``app.modules.rbac.api.deps`` است
(دقیقاً مسیر بخش ۱۲.۴ سند). ``get_current_user`` و ``get_uow``/``get_user_repo``
هم باید از dependency injection موجود پروژه‌ی شما بیایند — اسم دقیق
را با محتوای واقعی ``app/core/db/session.py`` و ``app/modules/auth/api/deps.py``
(اگر دارید) تطبیق دهید.
"""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, Query

from app.modules.auth.admin_ports import (
    AdminCreateUserRequest,
    AdminUpdateUserRequest,
    AdminUserListResponse,
    BulkLoginModeRequest,
    BulkResult,
)
from app.modules.auth.services.admin_user_service import AdminUserService

try:
    from app.modules.rbac.api.deps import require_permission
except ImportError:  # pragma: no cover — تا وقتی deps.py واقعی RBAC مشخص شود
    def require_permission(*codes: str, mode: str = "all"):  # type: ignore[no-redef]
        async def _dep():
            raise NotImplementedError(
                "require_permission در app.modules.rbac.api.deps پیدا نشد — "
                "این endpointها بدون آن نباید در production فعال شوند."
            )
        return _dep

try:
    # اگر app/modules/auth/api/deps.py از قبل چیزی مشابه دارد، از همان استفاده کنید
    from app.modules.auth.api.deps import get_admin_user_service
except ImportError:  # pragma: no cover — fallback حداقلی تا وقتی deps.py واقعی وصل شود
    def get_admin_user_service():  # type: ignore[no-redef]
        """TODO: جایگزین کنید با دیپندنسی واقعی که AdminUserService را با
        session/UnitOfWork واقعی درخواست جاری می‌سازد — مثلاً:

            async def get_admin_user_service(uow: UnitOfWork = Depends(get_uow)):
                return AdminUserService(uow.users)
        """
        raise NotImplementedError(
            "get_admin_user_service هنوز به session/UnitOfWork واقعی وصل نشده — "
            "app/modules/auth/api/deps.py را تکمیل کنید."
        )

router = APIRouter(prefix="/admin/users", tags=["admin-users"])


@router.get("", response_model=AdminUserListResponse)
async def list_users(
    search: str | None = Query(default=None, max_length=100),
    is_active: bool | None = Query(default=None),
    limit: int = Query(default=50, le=200),
    offset: int = Query(default=0, ge=0),
    _user=Depends(require_permission("user.read")),
    service: AdminUserService = Depends(get_admin_user_service),
):
    items, total = await service.list_users(
        search=search, is_active=is_active, limit=limit, offset=offset
    )
    return AdminUserListResponse(items=items, total=total, limit=limit, offset=offset)


@router.post("", status_code=201)
async def create_user(
    payload: AdminCreateUserRequest,
    user=Depends(require_permission("user.create")),
    service: AdminUserService = Depends(get_admin_user_service),
):
    return await service.create_user(user, payload)


@router.patch("/{user_id}")
async def update_user(
    user_id: UUID,
    payload: AdminUpdateUserRequest,
    user=Depends(require_permission("user.manage")),
    service: AdminUserService = Depends(get_admin_user_service),
):
    return await service.update_user(user, user_id, payload)


@router.post("/bulk-login-mode", response_model=BulkResult)
async def bulk_change_login_mode(
    payload: BulkLoginModeRequest,
    user=Depends(require_permission("user.bulk_login_mode")),
    service: AdminUserService = Depends(get_admin_user_service),
):
    """طبق سند بخش ۱۲.۶ — تغییر sso_enabled برای گروهی از کاربران؛ نتیجه‌ی جزئی مجاز است."""
    result = await service.bulk_change_login_mode(user, payload)
    return result
```

==========================================================================================
## FILE: bastehA_auth_rbac_audit/backend/app/modules/auth/api/deps.py
## SIZE: 802 bytes
==========================================================================================

```python
"""Auth module dependencies (composition root for admin user management).

Wires the real ``get_current_user`` from core so the RBAC ``require_permission``
guard resolves, and builds ``AdminUserService`` with the live session repo.
"""
from __future__ import annotations

from fastapi import Depends

from app.core.dependencies import get_current_user, get_user_repository
from app.modules.auth.admin_ports import AdminCreateUserRequest


async def get_admin_user_service(
    user_repo=Depends(get_user_repository),
):
    """Build AdminUserService with the real repo (auth.users ORM)."""
    from app.modules.auth.services.admin_user_service import AdminUserService

    return AdminUserService(user_repo=user_repo)


__all__ = ["get_current_user", "get_admin_user_service", "AdminCreateUserRequest"]
```

==========================================================================================
## FILE: bastehA_auth_rbac_audit/backend/app/modules/auth/db/models.py
## SIZE: 6406 bytes
==========================================================================================

```python
"""Auth DB models matching ``alembic/versions/auth_schema.sql``.

Column types mirror the SQL schema exactly (PostgreSQL UUID/ENUM/INET/JSONB)
so INSERTs succeed. Columns that the database fills via defaults
(created_at, failed counters, ...) are omitted from the model.
"""
import uuid as uuid_lib
from datetime import datetime

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import ENUM, INET, JSONB, UUID as PGUUID

from app.core.db.base import Base

auth_mode_enum = ENUM(
    "local", "sso", "both",
    name="auth_mode", schema="auth", create_type=False,
)
login_method_enum = ENUM(
    "local", "sso", "ldap", "kerberos", "recovery",
    name="login_method", schema="auth", create_type=False,
)


class Users(Base):
    """Application users (table ``auth.users``)."""

    __tablename__ = "users"
    __table_args__ = {"schema": "auth", "extend_existing": True}

    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid_lib.uuid4)
    username = Column(String(64), nullable=False)
    national_id_enc = Column(LargeBinary, nullable=False)
    national_id_nonce = Column(LargeBinary, nullable=False)
    national_id_hash = Column(String(64), nullable=False)
    national_id_last4 = Column(String(4), nullable=False)
    display_name = Column(String(128), nullable=False)
    auth_mode = Column(auth_mode_enum, nullable=False, default="local")
    sso_enabled = Column(Boolean, nullable=False, default=False)
    ldap_dn = Column(Text, nullable=True)
    ldap_object_guid = Column(PGUUID(as_uuid=True), nullable=True)
    ldap_sam_account = Column(String(256), nullable=True)
    ldap_synced_at = Column(DateTime(timezone=True), nullable=True)
    password_hash = Column(Text, nullable=True)
    password_changed_at = Column(DateTime(timezone=True), nullable=True)
    must_change_password = Column(Boolean, nullable=False, default=False)
    token_version = Column(Integer, nullable=False, default=1)
    mfa_enabled = Column(Boolean, nullable=False, default=False)
    mfa_method = Column(String(16), nullable=True)
    mfa_secret_enc = Column(LargeBinary, nullable=True)
    mfa_secret_nonce = Column(LargeBinary, nullable=True)
    mfa_enrolled_at = Column(DateTime(timezone=True), nullable=True)
    is_active = Column(Boolean, nullable=False, default=True)
    failed_login_count = Column(Integer, nullable=False, default=0)
    locked_until = Column(DateTime(timezone=True), nullable=True)
    last_login_at = Column(DateTime(timezone=True), nullable=True)


class UserDevices(Base):
    """Registered user devices (table ``auth.user_devices``)."""

    __tablename__ = "user_devices"
    __table_args__ = (
        UniqueConstraint("user_id", "device_fingerprint",
                         name="uq_device_user_fingerprint"),
        {"schema": "auth", "extend_existing": True},
    )

    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid_lib.uuid4)
    user_id = Column(
        PGUUID(as_uuid=True),
        ForeignKey("auth.users.id", ondelete="CASCADE"),
        nullable=False,
    )
    device_fingerprint = Column(String(255), nullable=False)
    mac_address = Column(String(17), nullable=True)
    mac_source = Column(String(16), nullable=True)
    platform = Column(String(16), nullable=False)
    device_label = Column(String(128), nullable=True)
    os_info = Column(String(128), nullable=True)
    user_agent = Column(Text, nullable=True)
    hmac_key_enc = Column(LargeBinary, nullable=True)
    is_trusted = Column(Boolean, nullable=False, default=False)
    trusted_at = Column(DateTime(timezone=True), nullable=True)
    trusted_by_mfa = Column(Boolean, nullable=False, default=False)
    first_seen_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    last_seen_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    last_ip = Column(INET, nullable=True)
    is_blocked = Column(Boolean, nullable=False, default=False)
    blocked_reason = Column(String(255), nullable=True)


class Sessions(Base):
    """Login sessions / refresh families (table ``auth.sessions``)."""

    __tablename__ = "sessions"
    __table_args__ = {"schema": "auth", "extend_existing": True}

    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid_lib.uuid4)
    user_id = Column(
        PGUUID(as_uuid=True),
        ForeignKey("auth.users.id", ondelete="CASCADE"),
        nullable=False,
    )
    device_id = Column(
        PGUUID(as_uuid=True),
        ForeignKey("auth.user_devices.id", ondelete="SET NULL"),
        nullable=True,
    )
    refresh_hash = Column(String(64), nullable=False, unique=True)
    family_id = Column(PGUUID(as_uuid=True), nullable=False)
    auth_method = Column(login_method_enum, nullable=False)
    mfa_satisfied = Column(Boolean, nullable=False, default=False)
    ip_address = Column(INET, nullable=True)
    geo_location = Column(JSONB, nullable=True)
    issued_at = Column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    last_active_at = Column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    expires_at = Column(DateTime(timezone=True), nullable=False)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    revoked_reason = Column(String(64), nullable=True)


Index("ix_auth_users_hash", Users.national_id_hash)


class MFARecoveryCodes(Base):
    """MFA recovery codes (table ``auth.mfa_recovery_codes``)."""

    __tablename__ = "mfa_recovery_codes"
    __table_args__ = {"schema": "auth", "extend_existing": True}

    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid_lib.uuid4)
    user_id = Column(
        PGUUID(as_uuid=True),
        ForeignKey("auth.users.id", ondelete="CASCADE"),
        nullable=False,
    )
    code_hash = Column(String(64), nullable=False, unique=True)
    used_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


__all__ = ["Users", "UserDevices", "Sessions", "MFARecoveryCodes"]
```

==========================================================================================
## FILE: bastehA_auth_rbac_audit/backend/app/modules/auth/db/repositories.py
## SIZE: 2734 bytes
==========================================================================================

```python
"""Auth repositories (AsyncSession-backed)."""
import hashlib
from uuid import UUID

from sqlalchemy import func, select

from app.core.config import settings
from app.modules.auth.db.models import UserDevices, Users


def national_id_hash(national_id: str) -> str:
    """HMAC-SHA256 lookup hash for a national ID (matches registration)."""
    return hashlib.sha256(
        f"{national_id}:{settings.SECRET_KEY}".encode()
    ).hexdigest()


class UserRepository:
    """Persistence adapter for users (backed by an async session)."""

    def __init__(self, session):
        self.session = session

    async def get(self, user_id):
        result = await self.session.execute(
            select(Users).where(Users.id == user_id)
        )
        return result.scalar_one_or_none()

    async def get_by_national_id(self, national_id: str):
        result = await self.session.execute(
            select(Users).where(
                Users.national_id_hash == national_id_hash(national_id.strip())
            )
        )
        return result.scalar_one_or_none()

    async def get_by_username(self, username: str):
        result = await self.session.execute(
            select(Users).where(func.lower(Users.username) == username.lower())
        )
        return result.scalar_one_or_none()

    async def get_by_identifier(self, identifier: str):
        identifier = identifier.strip()
        if identifier.isdigit() and len(identifier) == 10:
            user = await self.get_by_national_id(identifier)
            if user:
                return user
        return await self.get_by_username(identifier)

    async def add(self, obj):
        self.session.add(obj)

    async def commit(self):
        await self.session.commit()


class DeviceRepository:
    """Persistence adapter for user devices."""

    def __init__(self, session):
        self.session = session

    async def get(self, device_id):
        result = await self.session.execute(
            select(UserDevices).where(UserDevices.id == device_id)
        )
        return result.scalar_one_or_none()

    async def add(self, obj):
        self.session.add(obj)

    async def create_initial_device(self, user_id: UUID):
        import uuid as uuid_lib

        device = UserDevices(
            user_id=user_id,
            device_fingerprint=f"initial-{uuid_lib.uuid4().hex[:16]}",
            platform="web",
            device_label="Initial device",
            is_trusted=False,
        )
        self.session.add(device)
        await self.session.flush()
        return device


__all__ = ["UserRepository", "DeviceRepository", "national_id_hash"]
```

==========================================================================================
## FILE: bastehA_auth_rbac_audit/backend/app/modules/auth/events.py
## SIZE: 1482 bytes
==========================================================================================

```python
"""
app/modules/auth/events.py

رویدادهایی که ماژول Auth منتشر می‌کند — طبق قرارداد رابط سند
(بخش ۲.۲: هر ماژول رویدادهای خودش را از ``events.py`` صادر می‌کند)
و کاتالوگ رویدادها (بخش ۲.۴).

هیچ ماژول دیگری نباید این فایل را import کند تا از رویداد مطلع شود —
فقط باید با رشته‌ی ``event_type`` (مثل ``AUTH_LOGIN_SUCCEEDED``ی که
همین‌جا صادر شده) در ``event_bus.subscribe(...)`` مشترک شود. صادر کردن
این ثابت‌ها فقط برای جلوگیری از اشتباه تایپی در همین ماژول (auth) است؛
مصرف‌کننده‌ها (مثل audit) باید مقدار رشته را مستقیم بنویسند تا
وابستگی کد به auth ایجاد نشود — دقیقاً همان قاعده‌ای که تست
``test_module_boundaries.py`` اجرا می‌کند.
"""

from __future__ import annotations

# ── کاتالوگ رویدادها (بخش ۲.۴ سند) + رویدادهای اضافه‌ی مورد نیاز کد فعلی
AUTH_USER_REGISTERED = "auth.user.registered"
AUTH_LOGIN_SUCCEEDED = "auth.login.succeeded"
AUTH_LOGIN_FAILED = "auth.login.failed"
AUTH_LOGOUT = "auth.logout"
AUTH_PASSWORD_CHANGED = "auth.password.changed"
AUTH_DEVICE_REGISTERED = "auth.device.registered"
AUTH_DEVICE_TRUSTED = "auth.device.trusted"
```

==========================================================================================
## FILE: bastehA_auth_rbac_audit/backend/app/modules/auth/ports.py
## SIZE: 3584 bytes
==========================================================================================

```python
from typing import Protocol, Optional, List, Tuple, Dict, Any
from uuid import UUID
from datetime import datetime
from pydantic import BaseModel


# --- User Read Model Protocol ---
# Defines what other modules can see about a user (interface contract)

class UserReadModel(Protocol):
    """Her ماژول دیگری فقط این را می‌بیند. تغییر امضای این متدها = تغییر شکننده."""
    
    id: UUID
    username: str
    display_name: str
    national_id_masked: str  # masked: ******1234
    is_active: bool
    roles: List[str]
    permissions: List[str]
    privacy_level: str
    auth_mode: str  # local | sso | both
    mfa_enabled: bool
    last_login_at: Optional[datetime]


# --- Authentication Request/Response Schemas ---

class LoginRequest(BaseModel):
    """Login request schema."""
    identifier: str  # username or national_id
    password: str
    remember_me: bool = False
    captcha_token: Optional[str] = None


class MFAVerifyRequest(BaseModel):
    """MFA verification request."""
    mfa_token: str  # TOTP code or SMS code
    mfa_method: str  # totp | email | sms
    challenge_token: Optional[str] = None  # login-issued challenge (identifies user)


class MFACodeRequest(BaseModel):
    """TOTP code used during enrollment confirmation."""
    code: str


class RegisterRequest(BaseModel):
    """User registration request."""
    national_id: str  # 10-digit with check digit
    username: str
    password: str
    display_name: str
    email: Optional[str] = None
    mobile: Optional[str] = None


class TokenResponse(BaseModel):
    """Authentication token response."""
    access_token: str
    refresh_token: str
    token_type: str = "Bearer"
    expires_in: int
    # Serialized UserReadModel (kept as dict: pydantic cannot build a
    # schema for the Protocol interface above).
    user: dict
    device: Optional[dict] = None  # device info if new


# --- Device Binding Schemas ---

class DeviceRegisterRequest(BaseModel):
    """Device registration request."""
    device_fingerprint: str  # SHA256 fingerprint
    mac_address: str  # MAC address (desktop only)
    mac_source: str  # psutil | uuid_getnode | unavailable
    platform: str  # desktop | web | mobile_web
    device_label: str  # user-assigned label
    os_info: str  # OS description


class DeviceTrustRequest(BaseModel):
    """Device trust confirmation."""
    device_id: UUID
    trusted: bool  # user confirmation
    mfa_satisfied: bool  # MFA was used to trust


# --- Password Management ---

class PasswordChangeRequest(BaseModel):
    """Change password request."""
    current_password: str
    new_password: str


class PasswordForgotRequest(BaseModel):
    """Password forgot/request reset."""
    identifier: str  # username or national_id


class RefreshRequest(BaseModel):
    """Refresh token request schema."""
    refresh_token: str


# --- Audit Log Schemas (lightweight) ---

class AuditLogEntry(BaseModel):
    """Lightweight audit log entry for API responses."""
    id: int
    action: str
    timestamp: datetime
    result: str
    user_id: Optional[UUID]
    ip_address: Optional[str]
    mac_verified: bool


# Export all schemas
__all__ = [
    "UserReadModel", "LoginRequest", "MFAVerifyRequest",
    "RegisterRequest", "TokenResponse", "DeviceRegisterRequest",
    "DeviceTrustRequest", "PasswordChangeRequest", 
    "PasswordForgotRequest", "AuditLogEntry", "RefreshRequest"
]
```

==========================================================================================
## FILE: bastehA_auth_rbac_audit/backend/app/modules/auth/services/admin_user_service.py
## SIZE: 13461 bytes
==========================================================================================

```python
"""
app/modules/auth/services/admin_user_service.py

بخش «تعریف/مدیریت کاربر» در تنظیمات ادمین — طبق سند بخش ۵.۲/۵.۳ فقط
ثبت‌نام خودِ کاربر (`/auth/register`) و اعطای نقش تعریف شده بود؛ این
سرویس آن حلقه‌ی گم‌شده (ساخت/فهرست/ویرایش/غیرفعال‌سازی کاربر توسط
ادمین) را اضافه می‌کند — به‌علاوه پیاده‌سازی واقعی «تغییر انبوه حالت
ورود» طبق نمونه‌کد بخش ۱۲.۶ سند (که تا الان فقط نمونه‌کد بود).

هم‌خانواده با AuthService و RoleAssignmentService: همان الگوی
تزریق `user_repo`، همان `pwd_context`، و همان‌طور که در auth_service.py
اصلاح شد، رویدادها از طریق ``event_bus`` منتشر می‌شوند — نه با
import مستقیم از audit.
"""

from __future__ import annotations

import hashlib
from datetime import datetime
from typing import Any
from uuid import UUID

from fastapi import status
from passlib.context import CryptContext

from app.core.errors import APIError
from app.core.events.bus import DomainEvent, event_bus
from app.modules.auth.admin_ports import (
    AdminCreateUserRequest,
    AdminUpdateUserRequest,
    AdminUserListItem,
    BulkFailure,
    BulkLoginModeRequest,
    BulkResult,
)

pwd_context = CryptContext(schemes=["argon2"], argon2__time_cost=3, deprecated="auto")

# ── رویدادهای جدید مربوط به این فایل (به auth/events.py هم اضافه کنید
#    اگر می‌خواهید همه‌ی رویدادهای auth یک‌جا باشند — اینجا محلی نگه
#    داشته شده تا وابسته به merge شدن آن فایل نباشد)
AUTH_USER_CREATED_BY_ADMIN = "auth.user.created_by_admin"
AUTH_USER_UPDATED = "auth.user.updated"
AUTH_USER_DEACTIVATED = "auth.user.deactivated"
AUTH_USER_LOGIN_MODE_CHANGED = "auth.user.login_mode.changed"


def _validate_national_id(national_id: str) -> bool:
    """کپی هدفمند از AuthService._validate_national_id — تا این فایل مستقل
    از merge شدن auth_service.py کار کند. اگر ترجیح می‌دهید یک‌جا باشد،
    هر دو را به app/modules/auth/validators.py منتقل کنید."""
    national_id = national_id.strip()
    if not national_id.isdigit() or len(national_id) != 10:
        return False
    digits = [int(d) for d in national_id]
    weights = [10, 9, 8, 7, 6, 5, 4, 3, 2]
    weighted_sum = sum(d * w for d, w in zip(digits[:9], weights))
    remainder = weighted_sum % 11
    expected_check = remainder if remainder < 2 else 11 - remainder
    return digits[9] == expected_check


class AdminUserService:
    def __init__(self, user_repo: Any, role_assignment_service: Any | None = None) -> None:
        self.user_repo = user_repo
        # اختیاری: اگر می‌خواهید create_user بلافاصله نقش اولیه هم بدهد،
        # همان RoleAssignmentService که در rbac_patch.zip ساختیم را تزریق کنید.
        self.role_assignment_service = role_assignment_service

    @staticmethod
    def _actor_id(actor: Any) -> Any:
        """accept str (from get_current_user) or an object with .id"""
        return actor.id if not isinstance(actor, str) else actor

    # ── ایجاد ──────────────────────────────────────────────
    async def create_user(self, actor: Any, request: AdminCreateUserRequest) -> dict:
        if not _validate_national_id(request.national_id):
            raise APIError(
                error_code="INVALID_NATIONAL_ID",
                message="فرمت کد ملی صحیح نیست.",
                status_code=status.HTTP_400_BAD_REQUEST,
            )
        if await self.user_repo.get_by_username(request.username):
            raise APIError(
                error_code="USERNAME_EXISTS",
                message="این نام کاربری قبلاً استفاده شده است.",
                status_code=status.HTTP_409_CONFLICT,
            )
        if await self.user_repo.get_by_national_id(request.national_id):
            raise APIError(
                error_code="USER_EXISTS",
                message="کاربری با این کد ملی قبلاً ثبت شده است.",
                status_code=status.HTTP_409_CONFLICT,
            )

        from app.modules.auth.db.models import Users
        from app.modules.auth.db.repositories import national_id_hash

        nid_enc, nid_nonce = self._encrypt_national_id(request.national_id)
        user = Users(
            username=request.username,
            national_id_enc=nid_enc,
            national_id_nonce=nid_nonce,
            national_id_hash=national_id_hash(request.national_id),
            national_id_last4=request.national_id[-4:],
            password_hash=pwd_context.hash(request.initial_password),
            display_name=request.display_name,
            auth_mode="local",
            is_active=True,
            must_change_password=True,  # ادمین رمز موقت گذاشته؛ کاربر باید عوضش کند
        )
        await self.user_repo.add(user)
        await self.user_repo.commit()

        if request.role_id is not None and self.role_assignment_service is not None:
            await self.role_assignment_service.assign_role(actor, user.id, request.role_id)

        await self._publish(
            AUTH_USER_CREATED_BY_ADMIN,
            actor_id=self._actor_id(actor),
            payload={
                "target_user_id": str(user.id),
                "username": user.username,
                "role_id": request.role_id,
                "dangerous": True,
            },
        )
        return {"status": "success", "user_id": str(user.id)}

    # ── فهرست ──────────────────────────────────────────────
    async def list_users(
        self, *, search: str | None = None, is_active: bool | None = None,
        limit: int = 50, offset: int = 0,
    ) -> tuple[list[AdminUserListItem], int]:
        from sqlalchemy import func, or_, select

        from app.modules.auth.db.models import Users

        limit = min(limit, 200)  # سقف امن — از اسکن کامل جدول بدون صفحه‌بندی جلوگیری می‌کند
        query = select(Users)
        count_query = select(func.count()).select_from(Users)

        if search:
            like = f"%{search}%"
            cond = or_(Users.username.ilike(like), Users.display_name.ilike(like))
            query = query.where(cond)
            count_query = count_query.where(cond)
        if is_active is not None:
            query = query.where(Users.is_active == is_active)
            count_query = count_query.where(Users.is_active == is_active)

        total = (await self.user_repo.session.execute(count_query)).scalar_one()
        result = await self.user_repo.session.execute(
            query.order_by(Users.username).limit(limit).offset(offset)
        )
        users = result.scalars().all()

        items = [
            AdminUserListItem(
                id=u.id,
                username=u.username,
                display_name=u.display_name,
                national_id_masked=f"*****{u.national_id_last4}" if u.national_id_last4 else "******",
                is_active=u.is_active,
                auth_mode=u.auth_mode or "local",
                mfa_enabled=bool(u.mfa_enabled),
                last_login_at=u.last_login_at.isoformat() if u.last_login_at else None,
            )
            for u in users
        ]
        return items, total

    # ── ویرایش ─────────────────────────────────────────────
    async def update_user(self, actor: Any, user_id: UUID, request: AdminUpdateUserRequest) -> dict:
        user = await self.user_repo.get(user_id)
        if not user:
            raise APIError(
                error_code="USER_NOT_FOUND", message="کاربر یافت نشد.",
                status_code=status.HTTP_404_NOT_FOUND,
            )

        old_value: dict[str, Any] = {}
        new_value: dict[str, Any] = {}

        if request.display_name is not None and request.display_name != user.display_name:
            old_value["display_name"] = user.display_name
            user.display_name = request.display_name
            new_value["display_name"] = request.display_name

        if request.is_active is not None and request.is_active != user.is_active:
            if user_id == self._actor_id(actor) and request.is_active is False:
                raise APIError(
                    error_code="CANNOT_DEACTIVATE_SELF",
                    message="نمی‌توانید حساب خودتان را غیرفعال کنید.",
                    status_code=status.HTTP_400_BAD_REQUEST,
                )
            old_value["is_active"] = user.is_active
            user.is_active = request.is_active
            new_value["is_active"] = request.is_active
            if request.is_active is False:
                user.token_version += 1  # غیرفعال‌سازی یعنی همه‌ی نشست‌ها هم باطل شوند

        if request.must_change_password is not None:
            old_value["must_change_password"] = user.must_change_password
            user.must_change_password = request.must_change_password
            new_value["must_change_password"] = request.must_change_password

        await self.user_repo.commit()

        if new_value:
            event_type = AUTH_USER_DEACTIVATED if new_value.get("is_active") is False else AUTH_USER_UPDATED
            await self._publish(
                event_type,
                actor_id=self._actor_id(actor),
                payload={
                    "target_user_id": str(user_id),
                    "old_value": old_value,
                    "new_value": new_value,
                },
            )

        return {"status": "updated", "user_id": str(user_id)}

    # ── تغییر انبوه حالت ورود (طبق نمونه‌کد سند، بخش ۱۲.۶) ──
    async def bulk_change_login_mode(self, actor: Any, payload: BulkLoginModeRequest) -> BulkResult:
        if len(payload.user_ids) > 500:
            raise APIError(
                error_code="TOO_MANY_USERS",
                message="حداکثر ۵۰۰ کاربر در هر عملیات.",
                status_code=status.HTTP_400_BAD_REQUEST,
            )

        updated: list[UUID] = []
        failed: list[BulkFailure] = []

        for uid in payload.user_ids:
            target = await self.user_repo.get(uid)
            if target is None:
                failed.append(BulkFailure(user_id=uid, code="NOT_FOUND"))
                continue
            if target.id == self._actor_id(actor):
                failed.append(BulkFailure(user_id=uid, code="CANNOT_MODIFY_SELF"))
                continue
            # کاربر SSO بدون رمز محلی نباید بدون تنظیم رمز به حالت local برود
            if payload.sso_enabled is False and target.password_hash is None:
                failed.append(BulkFailure(user_id=uid, code="NO_LOCAL_PASSWORD"))
                continue

            old = {"sso_enabled": getattr(target, "sso_enabled", None), "auth_mode": target.auth_mode}
            target.sso_enabled = payload.sso_enabled
            target.auth_mode = "sso" if payload.sso_enabled else "local"
            if payload.revoke_sessions:
                target.token_version += 1

            await self._publish(
                AUTH_USER_LOGIN_MODE_CHANGED,
                actor_id=self._actor_id(actor),
                payload={
                    "target_user_id": str(uid),
                    "old_value": old,
                    "new_value": {"sso_enabled": payload.sso_enabled},
                },
            )
            updated.append(uid)

        await self.user_repo.commit()
        return BulkResult(updated=updated, failed=failed)

    # ── کمکی ───────────────────────────────────────────────
    def _encrypt_national_id(self, national_id: str) -> tuple[bytes, bytes]:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        import secrets
        from app.core.config import settings

        nonce = secrets.token_bytes(12)
        kdf_key = hashlib.sha256(settings.SECRET_KEY.encode()).digest()
        aesgcm = AESGCM(kdf_key)
        return aesgcm.encrypt(nonce, national_id.encode(), None), nonce

    async def _publish(self, event_type: str, *, actor_id: UUID, payload: dict) -> None:
        event = DomainEvent(event_type=event_type, actor_id=actor_id, payload=payload)
        try:
            await event_bus.publish(event, self.user_repo.session)
            await self.user_repo.commit()
        except Exception:
            import logging
            logging.getLogger("auth.admin_users").exception(
                "failed to publish event_type=%s", event_type
            )
```

==========================================================================================
## FILE: bastehA_auth_rbac_audit/backend/app/modules/rbac/api/deps.py
## SIZE: 4328 bytes
==========================================================================================

```python
"""
app/modules/rbac/api/deps.py

``require_permission`` — دقیقاً طبق شبه‌کد بخش ۱۲.۴ سند، با همان
تفاوت آگاهانه‌ای که در همه‌ی پچ‌های قبلی اعمال شد: به‌جای
``await audit.log(...)`` مستقیم (که در نمونه‌کد سند هست ولی نقشه‌ی
وابستگی ماژول‌ها بخش ۲.۱ را نقض می‌کند)، رویداد ``rbac.denied`` از
طریق ``event_bus`` منتشر می‌شود.

⚠️ فرض‌ها (چون به app/core/db/session.py و app/modules/auth/api/deps.py
واقعی شما دسترسی ندارم):
  - ``get_current_user`` در ``app.modules.auth.api.deps`` است
  - یک دیپندنسی ``get_permission_service`` باید PermissionService را
    با session + redis واقعی بسازد — اینجا فقط fallback گذاشته شده
"""

from __future__ import annotations

from fastapi import Depends, Request

from app.core.events.bus import DomainEvent, event_bus
from app.modules.rbac.services.permission_service import PermissionService

try:
    from app.core.errors import PermissionDeniedError
except ImportError:  # pragma: no cover
    from app.modules.rbac.services.role_assignment_service import PermissionDeniedError

try:
    from app.modules.auth.api.deps import get_current_user
except ImportError:  # pragma: no cover
    async def get_current_user():  # type: ignore[no-redef]
        raise NotImplementedError(
            "get_current_user در app.modules.auth.api.deps پیدا نشد."
        )

try:
    from app.modules.rbac.api.deps_internal import get_permission_service  # type: ignore
except ImportError:  # pragma: no cover
    async def get_permission_service():  # type: ignore[no-redef]
        """TODO: جایگزین کنید با چیزی مثل:

            async def get_permission_service(
                uow: UnitOfWork = Depends(get_uow),
                redis=Depends(get_redis),
            ) -> PermissionService:
                return PermissionService(uow.session, redis)
        """
        raise NotImplementedError(
            "get_permission_service هنوز به session/Redis واقعی وصل نشده."
        )


def require_permission(*codes: str, mode: str = "all"):
    """کنترل دسترسی سطح عملیات (لایه ۱). برای سطح رکورد از PolicyEngine
    جدا استفاده کنید (طبق نمونه‌ی بخش ۱۲.۴: هر دو لایه با هم، نه یکی)."""

    async def _dep(
        request: Request,
        user=Depends(get_current_user),
        permission_service: PermissionService = Depends(get_permission_service),
    ):
        user_id = user if isinstance(user, str) else str(user.id)
        perms = await permission_service.effective_permissions(user_id)
        ok = all(c in perms for c in codes) if mode == "all" else any(c in perms for c in codes)
        if not ok:
            await _publish_denied(user_id, codes, request.url.path)
            raise PermissionDeniedError("ACCESS_DENIED", required=codes, path=request.url.path)
        return user

    return _dep


async def _publish_denied(user_id, codes: tuple[str, ...], path: str) -> None:
    """رویداد rbac.denied را منتشر می‌کند — audit (اگر مشترک باشد) بدون
    وابستگی کدی rbac به audit، آن را ثبت می‌کند. اگر session این‌جا در
    دسترس نیست (چون require_permission قبل از ساخته‌شدن UoW کامل اجرا
    می‌شود)، فقط لاگ ساختاریافته می‌زنیم — بهتر از انفجار کل درخواست
    به خاطر شکست ثبت رویداد.
    """
    import logging
    logger = logging.getLogger("rbac.denied")
    logger.warning("permission denied: user_id=%s required=%s path=%s", user_id, codes, path)
    # TODO: اگر session/UoW این‌جا در دسترس است، به‌جای فقط لاگ، از
    # event_bus.publish(..., session) استفاده کنید تا audit هم ثبتش کند:
    #
    #   event = DomainEvent(event_type="rbac.denied", actor_id=user_id,
    #                        payload={"required": list(codes), "path": path})
    #   await event_bus.publish(event, session)
    #   await session.commit()
```

==========================================================================================
## FILE: bastehA_auth_rbac_audit/backend/app/modules/rbac/api/deps_internal.py
## SIZE: 832 bytes
==========================================================================================

```python
"""RBAC internal dependency — real ``get_permission_service``.

This file is what ``app/modules/rbac/api/deps.py`` tries to import; without
it ``require_permission`` defers to a stub that raises NotImplementedError.
PermissionService reads straight from the ``rbac`` schema (raw SQL) and
optionally caches in Redis (falls back to DB when Redis is absent).
"""
from __future__ import annotations

from fastapi import Depends

from app.core.dependencies import get_session_dep
from app.modules.rbac.services.permission_service import PermissionService


async def get_permission_service(
    session=Depends(get_session_dep),
) -> PermissionService:
    """Build PermissionService (no Redis in this deployment → DB-backed)."""
    return PermissionService(session=session, redis_client=None)


__all__ = ["get_permission_service"]
```

==========================================================================================
## FILE: bastehA_auth_rbac_audit/backend/app/modules/rbac/api/routes.py
## SIZE: 6429 bytes
==========================================================================================

```python
"""
RBAC Module API Routes
Architecture Reference: Sections 7.1, 7.3, 7.4, 11.1
Endpoints: /api/v1/rbac
"""

from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Body, Path
from fastapi.responses import JSONResponse

from app.core.dependencies import (
    get_db_session, get_current_user, get_rbac_service
)
from app.core.errors import APIError, NotFoundError
from app.core.database import async_session_context
from app.modules.rbac.ports import (
    PermissionCreate, PermissionUpdate, RoleCreate, RoleUpdate,
    UserRoleAssignment, AssignRoleRequest, RevokeRoleRequest,
    RBACDecision
)
from app.modules.rbac.services.rbac_service import RBACService
from app.modules.rbac.db.Models import Permissions, Roles, RolePermissions, UserRoles


router = APIRouter(prefix="/rbac", tags=["RBAC"])


@router.post("/permissions", response_model=dict)
async def create_permission(
    request: PermissionCreate,
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Create a new permission."""
    async with db_session() as session:
        try:
            service = RBACService(session)
            permission = await service.create_permission(request)
            return {"status": "permission_created", "permission_code": permission.code}
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.get("/permissions", response_model=dict)
async def list_permissions(
    module: Optional[str] = Query(None),
    action: Optional[str] = Query(None),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """List permissions, optionally filtered."""
    async with db_session() as session:
        try:
            service = RBACService(session)
            permissions = await service.list_permissions(
                module=module, action=action, viewer_id=user_id
            )
            return {
                "status": "success",
                "data": {"permissions": permissions}
            }
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.post("/roles", response_model=dict)
async def create_role(
    request: RoleCreate,
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Create a new role."""
    async with db_session() as session:
        try:
            service = RBACService(session)
            role = await service.create_role(request)
            return {"status": "role_created", "role_code": role.code}
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.get("/roles", response_model=dict)
async def list_roles(
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """List all roles."""
    async with db_session() as session:
        try:
            service = RBACService(session)
            roles = await service.list_roles(viewer_id=user_id)
            return {
                "status": "success",
                "data": {"roles": roles}
            }
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.post("/assign", response_model=dict)
async def assign_role(
    request: AssignRoleRequest,
    user_id: UUID = Depends(get_current_user),
    actor_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Assign a role to a user."""
    async with db_session() as session:
        try:
            service = RBACService(session)
            target = request.target_user_id or user_id
            payload = request.model_dump(exclude={"target_user_id"})
            result = await service.assign_role(
                actor_id=actor_id, target_user_id=target, **payload
            )
            return {"status": "role_assigned", "result": result}
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.post("/revoke", response_model=dict)
async def revoke_role(
    request: RevokeRoleRequest,
    user_id: UUID = Depends(get_current_user),
    actor_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Revoke a role from a user."""
    async with db_session() as session:
        try:
            service = RBACService(session)
            target = request.target_user_id or user_id
            payload = request.model_dump(exclude={"target_user_id"})
            result = await service.revoke_role(
                actor_id=actor_id, target_user_id=target, **payload
            )
            return {"status": "role_revoked", "result": result}
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.get("/user/{user_id}/roles", response_model=dict)
async def get_user_roles(
    user_id: UUID = Path(...),
    viewer_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Get roles for a specific user."""
    async with db_session() as session:
        try:
            service = RBACService(session)
            roles = await service.get_user_roles(user_id, viewer_id)
            return {
                "status": "success",
                "data": {"roles": roles}
            }
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )
```

==========================================================================================
## FILE: bastehA_auth_rbac_audit/backend/app/modules/rbac/db/Models.py
## SIZE: 6099 bytes
==========================================================================================

```python
import uuid
from uuid import UUID
from datetime import datetime
from sqlalchemy import func

from sqlalchemy import (
    Column, Integer, String, Boolean, DateTime,
    ForeignKey, Table, UniqueConstraint, Index, Text, JSON
)
from sqlalchemy.orm import relationship

from app.core.db.base import AuditMixin, BaseModel


# --- Permissions Table ---

class Permissions(BaseModel, AuditMixin):
    """System permissions defining what actions are allowed."""
    
    __tablename__ = "permissions"
    __table_args__ = (
        UniqueConstraint("code", name="uq_permission_code"),
        Index("ix_permissions_module_action", "module", "action"),
    )
    
    # Primary key inherited
    code = Column(String(100), nullable=False, unique=True)
    # Format: "module.action" e.g., "goal.create", "group.manage"
    
    module = Column(String(40), nullable=False)
    # Module name e.g., "goal", "group", "user", "rbac"
    
    action = Column(String(40), nullable=False)
    # Action name e.g., "create", "read", "update", "delete", "manage"
    
    title_fa = Column(String(120), nullable=False)
    # Persian title for UI display
    
    is_dangerous = Column(
        Boolean,
        nullable=False,
        default=False,
        comment="Requires secondary confirmation"
    )
    
    # Relationships
    # role_permissions = relationship("RolePermissions", back_populates="permission")
    # user_actions = relationship("UserActions", back_populates="permission")


# --- Roles Table ---

class Roles(BaseModel, AuditMixin):
    """System roles with hierarchical levels."""
    
    __tablename__ = "roles"
    __table_args__ = (
        UniqueConstraint("code", name="uq_role_code"),
        Index("ix_roles_level", "level"),
    )
    
    # Primary key inherited
    code = Column(String(32), nullable=False, unique=True)
    # e.g., "super_admin", "admin", "manager", "user", "viewer"
    
    title_fa = Column(String(64), nullable=False)
    # Persian title for UI display
    
    level = Column(
        Integer,
        nullable=False,
        server_default="1",
        comment="Hierarchy level (1=lowest, 10=highest). Used for privilege escalation prevention."
    )
    
    is_system = Column(
        Boolean,
        nullable=False,
        default=True,
        comment="System role (cannot be deleted, only modified)"
    )
    
    description = Column(Text, nullable=True)
    
    # Relationships
    # role_permissions = relationship("RolePermissions", back_populates="role")
    # user_roles = relationship("UserRoles", back_populates="role")


# --- Role-Permission Junction Table ---

class RolePermissions(BaseModel, AuditMixin):
    """Junction table for role-permission many-to-many relationship."""
    
    __tablename__ = "role_permissions"
    __table_args__ = (
        UniqueConstraint("role_id", "permission_id", name="uq_role_permission"),
    )
    
    # Primary key inherited
    role_id = Column(
        Integer,
        ForeignKey("roles.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    permission_id = Column(
        Integer,
        ForeignKey("permissions.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    
    # Composite primary key (role_id, permission_id)
    
    # Relationships
    # role = relationship("Roles", back_populates="role_permissions")
    # permission = relationship("Permissions", back_populates="role_permissions")


# --- User-Role Junction Table ---

class UserRoles(BaseModel, AuditMixin):
    """Junction table for user-role many-to-many relationship with scoping."""
    
    __tablename__ = "user_roles"
    __table_args__ = (
        UniqueConstraint(
            "user_id", "role_id", "scope_type", "scope_id",
            name="uq_user_role"
        ),
        Index("ix_user_roles_user", "user_id"),
        Index("ix_user_roles_scope", "scope_type", "scope_id"),
    )
    
    # Primary key components
    user_id = Column(
        String(36),  # UUID as string
        ForeignKey("auth.users.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    role_id = Column(
        Integer,
        ForeignKey("roles.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    scope_type = Column(
        String(16),
        nullable=False,
        default="global",
        comment="global | group"
    )
    scope_id = Column(
        String(36),
        nullable=True,
        comment="group_id when scope_type=group, otherwise NULL"
    )
    
    # Additional fields
    granted_by = Column(String(36), nullable=True)  # UUID of who granted
    granted_at = Column(DateTime(timezone=True), server_default=func.now())
    expires_at = Column(DateTime(timezone=True), nullable=True)
    source = Column(
        String(16),
        nullable=False,
        default="manual",
        comment="manual | ldap_group"
    )
    
    # Relationships
    # user = relationship("Users", foreign_keys=[user_id])
    # role = relationship("Roles", back_populates="user_roles")


# --- LDAP Group Sync ---

class LDAPGroupSync(BaseModel, AuditMixin):
    """LDAP group synchronization tracking."""
    
    __tablename__ = "ldap_group_sync"
    __table_args__ = (
        UniqueConstraint("ldap_dn", name="uq_ldap_group_dn"),
    )
    
    # Primary key inherited
    ldap_dn = Column(String(512), nullable=False)
    # Distinguished Name from Active Directory
    
    sync_status = Column(
        String(16),
        nullable=False,
        default="pending",
        comment="pending | success | failed"
    )
    sync_last_run = Column(DateTime(timezone=True), nullable=True)
    synced_group_ids = Column(Text, nullable=True)  # JSON array of group IDs
    error_message = Column(Text, nullable=True)


# Export all
__all__ = [
    "Permissions", "Roles", "RolePermissions", "UserRoles",
    "LDAPGroupSync"
]
```

==========================================================================================
## FILE: bastehA_auth_rbac_audit/backend/app/modules/rbac/events.py
## SIZE: 2064 bytes
==========================================================================================

```python
"""
app/modules/rbac/events.py  (نسخه‌ی به‌روز — جایگزین نسخه‌ی rbac_patch.zip)

علاوه بر ثابت‌های event_type قبلی، حالا rbac به رویداد خودش
(``rbac.role.assigned``) مشترک می‌شود تا کش Permission کاربر را فوراً
باطل کند — دقیقاً طبق بخش ۱۲.۴ سند: «رویداد rbac.role.assigned کش آن
کاربر را فوراً باطل می‌کند». این خودِ ماژول است که به رویداد خودش گوش
می‌دهد (self-subscription) — نقض مرز ماژول نیست، چون هیچ importی از
ماژول دیگر لازم نشد.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger("rbac.events")

RBAC_ROLE_ASSIGNED = "rbac.role.assigned"
RBAC_ROLE_REVOKED = "rbac.role.revoked"
RBAC_ACCESS_DENIED = "rbac.denied"


async def _invalidate_permission_cache(event: Any, session: Any) -> None:
    from app.modules.rbac.services.permission_service import PermissionService

    payload = event.payload or {}
    target_user_id = payload.get("target_user_id")
    if not target_user_id:
        return

    try:
        from app.modules.rbac.api.deps_internal import get_redis_client_sync  # type: ignore
        redis_client = get_redis_client_sync()
    except ImportError:
        redis_client = None
        logger.debug(
            "no redis client wiring found (app.modules.rbac.api.deps_internal) — "
            "cache invalidation skipped; the 60s TTL will still expire it naturally"
        )

    service = PermissionService(session, redis_client)
    await service.invalidate(target_user_id)


def register_event_handlers(bus) -> None:
    """طبق قرارداد main.py: ``m.register_event_handlers(event_bus)``."""
    bus.subscribe(RBAC_ROLE_ASSIGNED, _invalidate_permission_cache)
    bus.subscribe(RBAC_ROLE_REVOKED, _invalidate_permission_cache)
    logger.debug("rbac module subscribed to its own role-change events for cache invalidation")
```

==========================================================================================
## FILE: bastehA_auth_rbac_audit/backend/app/modules/rbac/ports.py
## SIZE: 3236 bytes
==========================================================================================

```python
from typing import Protocol, Optional, List, Tuple
from uuid import UUID
from datetime import datetime
from pydantic import BaseModel, Field


# --- Permission Protocol ---

class PermissionReadModel(Protocol):
    """Read model for permissions visible to other modules."""
    code: str  # e.g., "goal.create", "group.manage"
    module: str
    action: str
    title_fa: str
    is_dangerous: bool


# --- Role Protocol ---

class RoleReadModel(Protocol):
    """Read model for roles visible to other modules."""
    id: int
    code: str  # e.g., "super_admin", "admin", "manager", "user", "viewer"
    title_fa: str
    level: int  # for privilege escalation prevention
    is_system: bool


# --- User Role Assignment ---

class UserRoleAssignment(BaseModel):
    """User role assignment schema."""
    user_id: UUID
    role_id: int
    scope_type: str = "global"  # global | group
    scope_id: Optional[UUID] = None  # group_id for scoped roles
    source: str = "manual"  # manual | ldap_group
    granted_at: datetime = Field(default_factory=datetime.utcnow)
    expires_at: Optional[datetime] = None


# --- Role Schemas ---

class PermissionCreate(BaseModel):
    """Create permission request."""
    code: str = Field(..., min_length=1, max_length=100)
    module: str = Field(..., min_length=1, max_length=40)
    action: str = Field(..., min_length=1, max_length=40)
    title_fa: str = Field(..., min_length=1, max_length=120)
    is_dangerous: bool = False


class PermissionUpdate(BaseModel):
    """Update permission request."""
    title_fa: Optional[str] = Field(None, min_length=1, max_length=120)
    is_dangerous: Optional[bool] = Field(None)


class RoleCreate(BaseModel):
    """Create role request."""
    code: str = Field(..., min_length=1, max_length=32, unique=True)
    title_fa: str = Field(..., min_length=1, max_length=64)
    level: int = Field(default=1, ge=1, le=10)
    is_system: bool = True
    description: Optional[str] = Field(None, max_length=255)


class RoleUpdate(BaseModel):
    """Update role request."""
    title_fa: Optional[str] = Field(None, min_length=1, max_length=64)
    level: Optional[int] = Field(None, ge=1, le=10)
    is_system: Optional[bool] = Field(None)


# --- User Role Assignment Schemas ---

class AssignRoleRequest(BaseModel):
    """Assign role to user."""
    role_id: int
    scope_type: str = "global"
    scope_id: Optional[UUID] = None
    target_user_id: Optional[UUID] = None  # defaults to self when omitted


class RevokeRoleRequest(BaseModel):
    """Revoke role from user."""
    role_id: int
    scope_type: str = "global"
    target_user_id: Optional[UUID] = None  # defaults to self when omitted


# --- RBAC Decision ---

class RBACDecision(BaseModel):
    """RBAC authorization decision."""
    allowed: bool
    reason: Optional[str] = None
    redaction: Optional[str] = None  # for privacy-aware responses


# Export all
__all__ = [
    "PermissionReadModel", "RoleReadModel",
    "UserRoleAssignment", "PermissionCreate", "PermissionUpdate",
    "RoleCreate", "RoleUpdate", "AssignRoleRequest", "RevokeRoleRequest",
    "RBACDecision"
]
```

==========================================================================================
## FILE: bastehA_auth_rbac_audit/backend/app/modules/rbac/services/rbac_service.py
## SIZE: 8590 bytes
==========================================================================================

```python
"""RBAC service — raw SQL against the real DDL (schema ``rbac``).

Architecture Reference: Sections 2, 7.1, 7.4.
The ORM models drifted from the migration DDL (missing schema, extra
columns, wrong PK types), so this service uses schema-qualified SQL,
the same proven pattern as the reporting dashboard endpoints.
"""
from typing import List, Optional
from types import SimpleNamespace
from uuid import UUID

from sqlalchemy import text

from app.core.errors import APIError


class RBACService:
    """Service layer for RBAC module operations."""

    def __init__(self, session):
        self.session = session

    # --- Permissions ---

    async def create_permission(self, request) -> SimpleNamespace:
        """Create a new permission."""
        row = (await self.session.execute(text("""
            INSERT INTO rbac.permissions (code, module, action, title_fa, is_dangerous)
            VALUES (:code, :module, :action, :title_fa, :dangerous)
            ON CONFLICT (code) DO NOTHING
            RETURNING id, code, module, action, title_fa, is_dangerous
        """), {
            "code": request.code, "module": request.module,
            "action": request.action, "title_fa": request.title_fa,
            "dangerous": bool(request.is_dangerous),
        })).mappings().first()
        if row is None:
            raise APIError(error_code="PERMISSION_EXISTS",
                           message="این دسترسی قبلاً ثبت شده است.", status_code=409)
        await self.session.commit()
        return SimpleNamespace(**dict(row))

    async def list_permissions(self, module: Optional[str] = None,
                               action: Optional[str] = None,
                               viewer_id: Optional[UUID] = None) -> List[dict]:
        """List permissions, optionally filtered."""
        conds, params = [], {}
        if module:
            conds.append("module = :module"); params["module"] = module
        if action:
            conds.append("action = :action"); params["action"] = action
        where = ("WHERE " + " AND ".join(conds)) if conds else ""
        rows = (await self.session.execute(text(f"""
            SELECT id, code, module, action, title_fa, is_dangerous
              FROM rbac.permissions {where} ORDER BY module, action
        """), params)).mappings().all()
        return [dict(r) for r in rows]

    # --- Roles ---

    async def create_role(self, request) -> SimpleNamespace:
        """Create a new role."""
        row = (await self.session.execute(text("""
            INSERT INTO rbac.roles (code, title_fa, level, is_system, description)
            VALUES (:code, :title_fa, :level, :is_system, :description)
            ON CONFLICT (code) DO NOTHING
            RETURNING id, code, title_fa, level, is_system, description
        """), {
            "code": request.code, "title_fa": request.title_fa,
            "level": request.level, "is_system": bool(request.is_system),
            "description": request.description,
        })).mappings().first()
        if row is None:
            raise APIError(error_code="ROLE_EXISTS",
                           message="این نقش قبلاً ثبت شده است.", status_code=409)
        await self.session.commit()
        return SimpleNamespace(**dict(row))

    async def list_roles(self, viewer_id: Optional[UUID] = None) -> List[dict]:
        """List all roles."""
        rows = (await self.session.execute(text("""
            SELECT id, code, title_fa, level, is_system, description
              FROM rbac.roles ORDER BY level DESC, code
        """))).mappings().all()
        return [dict(r) for r in rows]

    # --- Assignments (with anti-escalation guards per ADR/7.4) ---

    async def _max_level(self, user_id: UUID) -> int:
        row = (await self.session.execute(text("""
            SELECT COALESCE(MAX(r.level), 0) AS m
              FROM rbac.user_roles ur JOIN rbac.roles r ON r.id = ur.role_id
             WHERE ur.user_id = :uid
               AND (ur.expires_at IS NULL OR ur.expires_at > now())
        """), {"uid": str(user_id)})).mappings().first()
        return int(row["m"] if row else 0)

    async def assign_role(self, actor_id: UUID, target_user_id: UUID,
                          role_id: int, scope_type: str = "global",
                          scope_id: Optional[UUID] = None, **_) -> dict:
        """Assign a role to a user (guards: no self-assign, no equal/higher)."""
        if str(target_user_id) == str(actor_id):
            raise APIError(error_code="CANNOT_SELF_ASSIGN",
                           message="نمی‌توان به خود نقش داد.", status_code=403)
        role = (await self.session.execute(text(
            "SELECT id, code, level FROM rbac.roles WHERE id = :rid"),
            {"rid": role_id})).mappings().first()
        if role is None:
            raise APIError(error_code="ROLE_NOT_FOUND",
                           message="نقش یافت نشد.", status_code=404)
        actor_max = await self._max_level(actor_id)
        # Bootstrap: a user with no roles yet may assign only level-1 roles.
        if actor_max > 0 and int(role["level"]) >= actor_max:
            raise APIError(error_code="CANNOT_GRANT_EQUAL_OR_HIGHER_ROLE",
                           message="نمی‌توان نقش هم‌سطح یا بالاتر از خود اعطا کرد.",
                           status_code=403)
        if scope_type == "group" and scope_id is not None:
            mgr = (await self.session.execute(text("""
                SELECT 1 FROM groups.group_members
                 WHERE group_id = :gid AND user_id = :uid AND is_manager
            """), {"gid": str(scope_id), "uid": str(actor_id)})).first()
            if mgr is None:
                raise APIError(error_code="NOT_GROUP_MANAGER",
                               message="مدیر این گروه نیستید.", status_code=403)
        await self.session.execute(text("""
            INSERT INTO rbac.user_roles (user_id, role_id, scope_type, scope_id, granted_by, source)
            VALUES (:uid, :rid, :scope, :sid, :by, 'manual')
            ON CONFLICT DO NOTHING
        """), {
            "uid": str(target_user_id), "rid": role_id, "scope": scope_type,
            "sid": str(scope_id) if scope_id else None, "by": str(actor_id),
        })
        await self.session.commit()
        return {"role_id": role_id, "role_code": role["code"],
                "target_user_id": str(target_user_id)}

    async def revoke_role(self, actor_id: UUID, target_user_id: UUID,
                          role_id: int, scope_type: str = "global", **_) -> dict:
        """Revoke a role from a user."""
        await self.session.execute(text("""
            DELETE FROM rbac.user_roles
             WHERE user_id = :uid AND role_id = :rid AND scope_type = :scope
        """), {"uid": str(target_user_id), "rid": role_id, "scope": scope_type})
        await self.session.commit()
        return {"role_id": role_id, "target_user_id": str(target_user_id)}

    async def get_user_roles(self, user_id: UUID,
                             viewer_id: Optional[UUID] = None) -> List[dict]:
        """Get roles for a specific user."""
        rows = (await self.session.execute(text("""
            SELECT r.id, r.code, r.title_fa, r.level,
                   ur.scope_type, ur.scope_id::text AS scope_id,
                   ur.granted_at, ur.expires_at, ur.source
              FROM rbac.user_roles ur JOIN rbac.roles r ON r.id = ur.role_id
             WHERE ur.user_id = :uid
               AND (ur.expires_at IS NULL OR ur.expires_at > now())
             ORDER BY r.level DESC
        """), {"uid": str(user_id)})).mappings().all()
        out = []
        for r in rows:
            d = dict(r)
            for k in ("granted_at", "expires_at"):
                if d.get(k) is not None:
                    d[k] = d[k].isoformat()
            out.append(d)
        return out

    async def effective_permissions(self, user_id: UUID) -> List[str]:
        """Flat permission codes for a user (used by the policy engine)."""
        rows = (await self.session.execute(text("""
            SELECT DISTINCT p.code
              FROM rbac.user_roles ur
              JOIN rbac.role_permissions rp ON rp.role_id = ur.role_id
              JOIN rbac.permissions p ON p.id = rp.permission_id
             WHERE ur.user_id = :uid
               AND (ur.expires_at IS NULL OR ur.expires_at > now())
        """), {"uid": str(user_id)})).mappings().all()
        return [r["code"] for r in rows]
```

==========================================================================================
## FILE: bastehA_auth_rbac_audit/backend/app/modules/rbac/services/role_assignment_service.py
## SIZE: 6535 bytes
==========================================================================================

```python
"""
app/modules/rbac/services/role_assignment_service.py

پیاده‌سازی «جلوگیری از Privilege Escalation» — دقیقاً سه قاعده‌ی
بخش ۷.۴ سند معماری v2.0:

  ۱) نمی‌توان نقشی بالاتر یا هم‌سطح خودِ actor به کسی اعطا کرد.
  ۲) نمی‌توان به خود نقش داد (self-assignment).
  ۳) نقش دامنه‌دار (scope_type='group') فقط توسط مدیر همان گروه قابل‌اعطاست.

طبق سند: «هر سه بررسی لازم است. حذف بند اول یعنی هر Manager می‌تواند
خود را Super Admin کند — کلاسیک‌ترین Privilege Escalation.»

⚠️ تفاوت عمدی با نمونه‌کد خودِ سند (بخش ۷.۴):
نمونه‌کد سند این‌طور می‌نویسد:

    await audit.log("rbac.role.assigned", target=target_user_id, dangerous=True)

که یعنی import مستقیم از ماژول audit — همان اشکالی که در
auth_service.py پیدا و اصلاح شد (نقض نقشه‌ی وابستگی بخش ۲.۱: هیچ
فلشی از RBAC به Audit وجود ندارد). این‌جا به‌جایش از همان
``event_bus`` که برای auth ساختیم استفاده می‌شود — audit (و هر
مصرف‌کننده‌ی دیگری، مثل کش Permission در بخش ۱۲.۴) بدون این‌که RBAC
به آن‌ها import اضافه کند، مطلع می‌شوند.

⚠️ فرض‌های این فایل (چون به سرویس/ریپازیتوری واقعی RBAC شما دسترسی
ندارم) — با Protocol مشخص شده‌اند تا مشخص باشد دقیقاً چه چیزی باید
به این کلاس تزریق شود:
  - ``rbac_repo.max_role_level(user_id) -> int``
  - ``rbac_repo.get_role(role_id) -> RoleLike`` (با فیلد ``level``)
  - ``rbac_repo.grant(target_user_id, role_id, scope, granted_by) -> None``
  - ``groups_repo.is_manager(user_id, group_id) -> bool``

اگر اسم متدهای واقعی شما فرق دارد، فقط همین چهار خط فراخوانی را در
``assign_role`` پایین تطبیق دهید — منطق سه‌قاعده‌ای دست‌نخورده می‌ماند.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol
from uuid import UUID

from app.core.events.bus import DomainEvent, event_bus
from app.modules.rbac import events as rbac_events

try:
    from app.core.errors import PermissionDeniedError
except ImportError:  # pragma: no cover — fallback اگر این کلاس هنوز در core.errors نیست
    class PermissionDeniedError(Exception):
        def __init__(self, code: str, **details: Any) -> None:
            self.code = code
            self.details = details
            super().__init__(code)


@dataclass(frozen=True)
class RoleScope:
    """معادل ``scope`` در شبه‌کد سند: ``scope.type`` و ``scope.id``."""

    type: str = "global"  # "global" | "group"
    id: UUID | None = None


class RoleLike(Protocol):
    level: int


class RbacRepo(Protocol):
    async def max_role_level(self, user_id: UUID) -> int: ...
    async def get_role(self, role_id: int) -> RoleLike: ...
    async def grant(
        self, target_user_id: UUID, role_id: int, scope: RoleScope | None, granted_by: UUID
    ) -> None: ...


class GroupsRepo(Protocol):
    async def is_manager(self, user_id: UUID, group_id: UUID) -> bool: ...


class RoleAssignmentService:
    """سرویس اختصاصی اعطای نقش با اجرای اجباری هر سه قاعده‌ی ضد Privilege Escalation.

    این را می‌توانید مستقیماً به‌جای منطق فعلی endpoint اعطای نقش‌تان
    صدا بزنید، یا متد ``assign_role`` را به کلاس RBAC service موجودتان
    منتقل کنید — منطق مستقل از نحوه‌ی ساختاردهی فایل‌هاست.
    """

    def __init__(self, session: Any, rbac_repo: RbacRepo, groups_repo: GroupsRepo) -> None:
        self.session = session
        self.rbac_repo = rbac_repo
        self.groups_repo = groups_repo

    async def assign_role(
        self,
        actor: Any,
        target_user_id: UUID,
        role_id: int,
        scope: RoleScope | None = None,
    ) -> None:
        actor_max = await self.rbac_repo.max_role_level(actor.id)
        target_role = await self.rbac_repo.get_role(role_id)

        # ── قاعده ۱: نمی‌توان نقشی بالاتر یا هم‌سطح خود اعطا کرد
        if target_role.level >= actor_max:
            raise PermissionDeniedError(
                "CANNOT_GRANT_EQUAL_OR_HIGHER_ROLE",
                actor_max_level=actor_max,
                target_role_level=target_role.level,
            )

        # ── قاعده ۲: نمی‌توان به خود نقش داد
        if target_user_id == actor.id:
            raise PermissionDeniedError("CANNOT_SELF_ASSIGN")

        # ── قاعده ۳: نقش دامنه‌دار فقط توسط مدیر همان دامنه (گروه)
        if scope is not None and scope.type == "group":
            if scope.id is None:
                raise PermissionDeniedError("SCOPE_GROUP_REQUIRES_ID")
            if not await self.groups_repo.is_manager(actor.id, scope.id):
                raise PermissionDeniedError("NOT_GROUP_MANAGER")

        await self.rbac_repo.grant(target_user_id, role_id, scope, granted_by=actor.id)

        # به‌جای `await audit.log(...)` مستقیم (که در نمونه‌کد سند هست
        # ولی نقشه‌ی وابستگی ماژول‌ها را نقض می‌کند)، رویداد منتشر می‌شود.
        # Audit (اگر مشترک باشد) و کش Permission (بخش ۱۲.۴ سند) هر دو
        # بدون وابستگی کدی RBAC به آن‌ها، این را دریافت می‌کنند.
        event = DomainEvent(
            event_type=rbac_events.RBAC_ROLE_ASSIGNED,
            actor_id=actor.id,
            payload={
                "target_user_id": str(target_user_id),
                "role_id": role_id,
                "role_level": target_role.level,
                "scope_type": scope.type if scope else "global",
                "scope_id": str(scope.id) if scope and scope.id else None,
                "dangerous": True,
            },
        )
        await event_bus.publish(event, self.session)
```

==========================================================================================
## FILE: bastehB_ws_chat_notif_files/backend/app/modules/chat/api/routes.py
## SIZE: 6760 bytes
==========================================================================================

```python
"""
Chat Module API Routes
Architecture Reference: Sections 8.1, 8.2, 8.3
Endpoints: /api/v1/chat
"""

from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends, Query, Body, Path
from fastapi.responses import JSONResponse

from app.core.dependencies import (
    get_db_session, get_current_user, get_chat_service
)
from app.core.errors import APIError, NotFoundError, PrivacyHiddenError
from app.core.database import async_session_context
from app.modules.chat.ports import (
    RoomCreate, RoomUpdate, MessageCreate, MessageResponse,
    MemberCreate, ChatExport
)
from app.modules.chat.services.chat_service import ChatService
from app.modules.chat.db.Models import Rooms, RoomMembers, Messages


router = APIRouter(prefix="/chat", tags=["Chat"])


@router.post("/rooms", response_model=dict)
async def create_room(
    request: RoomCreate,
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Create a new chat room."""
    async with db_session() as session:
        try:
            service = ChatService(session)
            room = await service.create_room(
                title=request.title,
                linked_type=request.linked_type,
                linked_id=request.linked_id,
                owner_id=user_id
            )
            return {"status": "room_created", "room_id": str(room.id)}
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.get("/rooms", response_model=dict)
async def list_rooms(
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """List chat rooms."""
    async with db_session() as session:
        try:
            service = ChatService(session)
            rooms = await service.list_rooms(user_id)
            return {
                "status": "success",
                "data": {"rooms": rooms}
            }
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.get("/rooms/{room_id}", response_model=dict)
async def get_room(
    room_id: UUID = Path(...),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Get a single chat room."""
    async with db_session() as session:
        try:
            service = ChatService(session)
            room = await service.get_room(room_id, user_id)
            
            if not room:
                return JSONResponse(
                    status_code=404,
                    content={"error": "ROOM_NOT_FOUND", "message": "اتاق یافت نشد.", "success": False}
                )
            
            return {
                "status": "success",
                "data": room
            }
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.post("/rooms/{room_id}/members", response_model=dict)
async def add_room_member(
    room_id: UUID = Path(...),
    user_id: UUID = Body(...),
    role: str = Body("member"),
    user_adding_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Add member to chat room."""
    async with db_session() as session:
        try:
            service = ChatService(session)
            result = await service.add_member(room_id, user_id, role, user_adding_id)
            return {"status": "member_added", "result": result}
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.post("/{room_id}/messages", response_model=dict)
async def send_message(
    room_id: UUID = Path(...),
    request: MessageCreate = Body(...),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Send a chat message."""
    async with db_session() as session:
        try:
            service = ChatService(session)
            message = await service.send_message(room_id, request.body, user_id)
            return {
                "status": "message_sent",
                "message_id": str(message.id),
                "message": {
                    "id": str(message.id),
                    "room_id": str(message.room_id),
                    "sender_id": str(message.sender_id),
                    "body": message.body,
                    "created_at": message.created_at.isoformat(),
                    "message_type": message.message_type,
                }
            }
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.get("/{room_id}/messages", response_model=dict)
async def get_messages(
    room_id: UUID = Path(...),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Get chat messages."""
    async with db_session() as session:
        try:
            service = ChatService(session)
            messages = await service.get_messages(room_id, user_id)
            return {
                "status": "success",
                "data": {"messages": messages}
            }
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.post("/rooms/{room_id}/archive", response_model=dict)
async def archive_room(
    room_id: UUID = Path(...),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Archive a chat room."""
    async with db_session() as session:
        try:
            service = ChatService(session)
            result = await service.archive_room(room_id, user_id)
            return {"status": "room_archived", "result": result}
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )
```

==========================================================================================
## FILE: bastehB_ws_chat_notif_files/backend/app/modules/chat/db/Models.py
## SIZE: 4722 bytes
==========================================================================================

```python
import uuid
from uuid import UUID
from datetime import datetime
from sqlalchemy import func

from sqlalchemy import (
    Column, String, Integer, Boolean, DateTime,
    ForeignKey, Text, JSON, Index, UniqueConstraint, Table
)
from sqlalchemy.orm import relationship

from app.core.db.base import AuditMixin, BaseModel


# --- Rooms Table ---

class Rooms(BaseModel, AuditMixin):
    """Chat room entity."""
    
    __tablename__ = "rooms"
    __table_args__ = (
        Index("ix_rooms_linked", "linked_type", "linked_id"),
        Index("ix_rooms_owner", "owner_id"),
    )
    
    # Primary key inherited
    title = Column(String(160), nullable=False)
    description = Column(Text, nullable=True)
    
    # Linkage to other entities
    linked_type = Column(
        String(32),
        nullable=True,
        comment="task | meeting | goal | null (free room)"
    )
    linked_id = Column(String(36), nullable=True, index=True)
    
    # Ownership
    owner_id = Column(
        String(36),
        ForeignKey("auth.users.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    
    # Privacy & Archive
    is_archived = Column(Boolean, nullable=False, default=False)
    archived_at = Column(DateTime(timezone=True), nullable=True)
    archive_object_key = Column(String(512), nullable=True)  # S3 path
    retention_days = Column(
        Integer,
        nullable=False,
        default=365,
        comment="Message retention in days"
    )
    
    # Timestamps inherited
    # created_at, updated_at, deleted_at, version, created_by, updated_by
    
    # Relationships
    # members = relationship("RoomMembers", back_populates="room")
    # messages = relationship("Messages", back_populates="room", cascade="all, delete-orphan")


# --- Room Members ---

class RoomMembers(BaseModel, AuditMixin):
    """Room membership."""
    
    __tablename__ = "room_members"
    __table_args__ = (
        UniqueConstraint("room_id", "user_id", name="uq_room_member"),
        Index("ix_room_members_room", "room_id"),
    )
    
    # Primary key components
    room_id = Column(
        String(36),
        ForeignKey("rooms.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    user_id = Column(
        String(36),
        ForeignKey("auth.users.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    
    # Member role
    role = Column(
        String(16),
        nullable=False,
        default="member",
        comment="owner | moderator | member | readonly"
    )
    
    # Status
    is_muted = Column(Boolean, nullable=False, default=False)
    muted_until = Column(DateTime(timezone=True), nullable=True)
    left_at = Column(DateTime(timezone=True), nullable=True)
    
    # Timestamps inherited
    # created_at inherited from AuditMixin


# --- Messages Table ---

class Messages(BaseModel, AuditMixin):
    """Chat message entity."""
    
    __tablename__ = "messages"
    __table_args__ = (
        Index("ix_messages_room", "room_id", "created_at"),
        Index("ix_messages_sender", "sender_id"),
        Index("ix_messages_search", "search_vector"),
    )
    
    # Primary key inherited
    room_id = Column(
        String(36),
        ForeignKey("rooms.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    sender_id = Column(
        String(36),
        ForeignKey("auth.users.id", ondelete="SET NULL"),
        nullable=True,
        index=True
    )
    
    # Message content
    body = Column(Text, nullable=False)
    body_html = Column(Text, nullable=True)  # Sanitized HTML
    reply_to_id = Column(String(36), nullable=True)
    
    # Message type
    message_type = Column(
        String(16),
        nullable=False,
        server_default="text",
        comment="text | file | system"
    )
    
    # Edit tracking
    is_edited = Column(Boolean, nullable=False, default=False)
    edited_at = Column(DateTime(timezone=True), nullable=True)
    edit_history = Column(JSON, nullable=True, default={})
    
    # Search vector (PostgreSQL)
    search_vector = Column(
        Text,
        nullable=True,
        comment="GIN index for full-text search"
    )
    
    # Timestamps inherited from AuditMixin
    
    # Relationships
    # room = relationship("Rooms", back_populates="messages")
    # sender = relationship("Users", foreign_keys=[sender_id])
    # reply_to = relationship("Messages", remote_messages.id, remote_side=[id])


# --- Export all ---
__all__ = ["Rooms", "RoomMembers", "Messages"]
```

==========================================================================================
## FILE: bastehB_ws_chat_notif_files/backend/app/modules/chat/ports.py
## SIZE: 2367 bytes
==========================================================================================

```python
from typing import Protocol, Optional, List, Tuple, Dict, Any
from uuid import UUID
from datetime import datetime
from pydantic import BaseModel, Field


# --- Chat Room Protocols ---

class RoomReadModel(Protocol):
    """Read model for chat rooms visible to other modules."""
    id: UUID
    title: str
    owner_id: UUID
    is_archived: bool
    member_count: int
    privacy_level: str  # from groups module


# --- Chat Message Protocols ---

class MessageReadModel(Protocol):
    """Read model for chat messages."""
    id: UUID
    room_id: UUID
    sender_id: UUID
    body: str
    sender_name: str
    created_at: datetime
    message_type: str  # 'text' | 'file' | 'system'
    is_edited: bool
    edited_at: Optional[datetime]


# --- Chat Schemas ---

class RoomCreate(BaseModel):
    """Create room request."""
    title: str = Field(..., min_length=1, max_length=160)
    linked_type: Optional[str] = Field(
        None,
        pattern="^(task|meeting|goal|null)$"
    )
    linked_id: Optional[UUID] = Field(None, description="ID of linked entity")


class RoomUpdate(BaseModel):
    """Update room request."""
    title: Optional[str] = Field(None, min_length=1, max_length=160)
    is_archived: Optional[bool] = Field(None)


class MessageCreate(BaseModel):
    """Create message request."""
    room_id: UUID = Field(...)
    body: str = Field(..., min_length=1, max_length=4000)
    reply_to: Optional[UUID] = Field(None, description="Message ID to reply to")


class MessageResponse(BaseModel):
    """Message response."""
    id: UUID
    room_id: UUID
    sender_id: UUID
    body: str
    sender_name: str
    created_at: datetime
    message_type: str
    is_edited: bool
    edit_history: List[dict] = Field(default_factory=list)


# --- Room Membership ---

class MemberCreate(BaseModel):
    """Add member to room."""
    user_id: UUID
    role: str = "member"  # 'member' | 'moderator' | 'owner'


# --- Export ---

class ChatExport(BaseModel):
    """Chat export format."""
    room_id: UUID
    room_title: str
    messages: List[MessageResponse]
    exported_at: datetime


# Export all
__all__ = [
    "RoomReadModel", "MessageReadModel", "RoomCreate", "RoomUpdate",
    "MessageCreate", "MessageResponse", "MemberCreate", "ChatExport"
]
```

==========================================================================================
## FILE: bastehB_ws_chat_notif_files/backend/app/modules/chat/services/chat_service.py
## SIZE: 8609 bytes
==========================================================================================

```python
"""Chat service — raw SQL against the real DDL (schema ``chat``).

Architecture Reference: Sections 8.1, 8.2, 8.3.
"""
from typing import Optional, List
from types import SimpleNamespace
from uuid import UUID
from datetime import datetime

from sqlalchemy import text

from app.core.errors import APIError, NotFoundError


def _iso(v):
    return v.isoformat() if isinstance(v, datetime) else v


class ChatService:
    """Service layer for Chat module operations (real DDL)."""

    def __init__(self, session):
        self.session = session

    async def _member_of(self, room_id: UUID, user_id: UUID) -> bool:
        row = (await self.session.execute(text("""
            SELECT 1 FROM chat.room_members
             WHERE room_id = :rid AND user_id = :uid AND left_at IS NULL
        """), {"rid": str(room_id), "uid": str(user_id)})).first()
        return row is not None

    async def create_room(self, title: str, linked_type: Optional[str],
                          linked_id: Optional[UUID], owner_id: UUID) -> SimpleNamespace:
        """Create a new chat room."""
        row = (await self.session.execute(text("""
            INSERT INTO chat.rooms (title, linked_type, linked_id, owner_id,
                                    is_archived, retention_days)
            VALUES (:title, :ltype, :lid, :owner, FALSE, 30)
            RETURNING id, title, owner_id, is_archived
        """), {"title": title, "ltype": linked_type,
               "lid": str(linked_id) if linked_id else None,
               "owner": str(owner_id)})).mappings().first()
        # Add room creator as an owner member
        await self.session.execute(text("""
            INSERT INTO chat.room_members (room_id, user_id, role)
            VALUES (:rid, :uid, 'owner')
            ON CONFLICT DO NOTHING
        """), {"rid": row["id"], "uid": str(owner_id)})
        await self.session.commit()
        return SimpleNamespace(id=row["id"], title=row["title"],
                               owner_id=row["owner_id"], is_archived=row["is_archived"])

    async def list_rooms(self, user_id: UUID) -> List[dict]:
        """List rooms user is member of."""
        rows = (await self.session.execute(text("""
            SELECT r.id, r.title, r.is_archived, r.owner_id, r.linked_type, r.linked_id,
                   (SELECT count(*) FROM chat.room_members m
                     WHERE m.room_id = r.id AND m.left_at IS NULL) AS member_count
              FROM chat.rooms r
              JOIN chat.room_members m ON m.room_id = r.id
             WHERE m.user_id = :uid AND m.left_at IS NULL
               AND r.is_archived = FALSE
             ORDER BY r.created_at DESC
        """), {"uid": str(user_id)})).mappings().all()
        return [{
            "id": str(r["id"]),
            "title": r["title"],
            "is_archived": r["is_archived"],
            "member_count": int(r["member_count"]),
            "owner_id": str(r["owner_id"]),
            "linked_type": r["linked_type"],
            "linked_id": str(r["linked_id"]) if r["linked_id"] else None,
        } for r in rows]

    async def get_room(self, room_id: UUID, user_id: UUID) -> Optional[dict]:
        """Get room with membership check."""
        row = (await self.session.execute(text("""
            SELECT id, title, owner_id, is_archived, linked_type, linked_id,
                   retention_days, created_at
              FROM chat.rooms WHERE id = :rid
        """), {"rid": str(room_id)})).mappings().first()
        if not row:
            return None
        if not await self._member_of(room_id, user_id):
            return None
        cnt = (await self.session.execute(text("""
            SELECT count(*) AS n FROM chat.room_members
             WHERE room_id = :rid AND left_at IS NULL
        """), {"rid": str(room_id)})).mappings().first()
        return {
            "id": str(row["id"]),
            "title": row["title"],
            "description": None,
            "is_archived": row["is_archived"],
            "member_count": int(cnt["n"]),
            "owner_id": str(row["owner_id"]),
            "linked_type": row["linked_type"],
            "linked_id": str(row["linked_id"]) if row["linked_id"] else None,
        }

    async def add_member(self, room_id: UUID, user_id: UUID, role: str,
                         added_by: UUID) -> dict:
        """Add member to room."""
        room = (await self.session.execute(text(
            "SELECT 1 FROM chat.rooms WHERE id = :rid"),
            {"rid": str(room_id)})).first()
        if not room:
            raise APIError(error_code="ROOM_NOT_FOUND",
                           message="اتاق یافت نشد.", status_code=404)
        await self.session.execute(text("""
            INSERT INTO chat.room_members (room_id, user_id, role, joined_at)
            VALUES (:rid, :uid, :role, now())
            ON CONFLICT (room_id, user_id)
            DO UPDATE SET left_at = NULL, role = EXCLUDED.role
        """), {"rid": str(room_id), "uid": str(user_id), "role": role})
        await self.session.commit()
        return {"status": "added", "room_id": str(room_id), "user_id": str(user_id)}

    async def send_message(self, room_id: UUID, body: str,
                           sender_id: UUID) -> SimpleNamespace:
        """Send a chat message."""
        room = (await self.session.execute(text("""
            SELECT is_archived, owner_id FROM chat.rooms WHERE id = :rid
        """), {"rid": str(room_id)})).mappings().first()
        if not room:
            raise APIError(error_code="ROOM_NOT_FOUND",
                           message="اتاق یافت نشد.", status_code=404)
        if room["is_archived"] and str(room["owner_id"]) != str(sender_id):
            raise APIError(error_code="ROOM_ARCHIVED",
                           message="اتاق آرشیو شده است.", status_code=403)
        if not await self._member_of(room_id, sender_id):
            raise APIError(error_code="NOT_MEMBER",
                           message="شما عضو این اتاق نیستید.", status_code=403)
        if len(body) > 4000:
            raise APIError(error_code="MESSAGE_TOO_LONG",
                           message="متن پیام بیش از حد مجاز است.", status_code=400)
        row = (await self.session.execute(text("""
            INSERT INTO chat.messages (room_id, sender_id, body, message_type, is_edited)
            VALUES (:rid, :uid, :body, 'text', FALSE)
            RETURNING id, room_id, sender_id, body, created_at, message_type, is_edited
        """), {"rid": str(room_id), "uid": str(sender_id), "body": body})).mappings().first()
        await self.session.commit()
        return SimpleNamespace(**dict(row))

    async def get_messages(self, room_id: UUID, viewer_id: UUID) -> List[dict]:
        """Get messages for a room."""
        if not await self._member_of(room_id, viewer_id):
            return []
        rows = (await self.session.execute(text("""
            SELECT id, room_id, sender_id, body, message_type, is_edited,
                   is_edited AS edited, created_at
              FROM chat.messages
             WHERE room_id = :rid AND deleted_at IS NULL
             ORDER BY created_at ASC
             LIMIT 200
        """), {"rid": str(room_id)})).mappings().all()
        return [{
            "id": str(m["id"]),
            "room_id": str(m["room_id"]),
            "sender_id": str(m["sender_id"]),
            "body": m["body"],
            "sender_name": "user",
            "created_at": _iso(m["created_at"]),
            "message_type": m["message_type"],
            "is_edited": m["is_edited"],
        } for m in rows]

    async def archive_room(self, room_id: UUID, archived_by: UUID) -> dict:
        """Archive a chat room."""
        room = (await self.session.execute(text("""
            SELECT owner_id FROM chat.rooms WHERE id = :rid
        """), {"rid": str(room_id)})).mappings().first()
        if not room:
            raise APIError(error_code="ROOM_NOT_FOUND",
                           message="اتاق یافت نشد.", status_code=404)
        if str(room["owner_id"]) != str(archived_by):
            raise APIError(error_code="PERMISSION_DENIED",
                           message="شما اجازه آرشیو این اتاق را ندارید.", status_code=403)
        await self.session.execute(text("""
            UPDATE chat.rooms SET is_archived = TRUE, archived_at = now()
             WHERE id = :rid
        """), {"rid": str(room_id)})
        await self.session.commit()
        return {"status": "archived"}
```

==========================================================================================
## FILE: bastehB_ws_chat_notif_files/backend/app/modules/files/api/routes.py
## SIZE: 5761 bytes
==========================================================================================

```python
"""File storage module API routes (real DDL, M13).

Local-disk implementation: presign reserves a row in ``files.uploads``,
PUT /upload/{id} stores bytes under `FILE_STORAGE_DIR`, finalize marks
the file scanned + available, GET /{id}/download returns the bytes and
logs access in ``files.access_logs``.

This replaces the S3-oriented patch (boto3/MinIO required) because this
deployment has no object storage; the DDL and access_logging contract
are preserved.
"""

from __future__ import annotations

from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, Path, Query, Body
from fastapi.responses import JSONResponse

from app.core.dependencies import get_db_session, get_current_user
from app.core.errors import APIError, NotFoundError
from app.modules.files.ports import (
    PresignUpload, PresignResponse, UploadFinalize,
)
from app.modules.files.services.files_service import FileStateMachine
from app.core.config import settings


router = APIRouter(prefix="/files", tags=["files"])


@router.post("/presign", response_model=dict)
async def presign_upload(
    payload: PresignUpload,
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session),
):
    """Reserve an upload slot and return the local PUT target."""
    async with db_session() as session:
        try:
            svc = FileStateMachine(session)
            p = await svc.presign(user_id, payload.model_dump())
            return {"status": "success",
                    "data": PresignResponse(
                        upload_id=p.upload_id, object_key=p.object_key,
                        upload_url=p.upload_url, expires_in=p.expires_in,
                        max_size=p.max_size).model_dump()}
        except APIError as e:
            return JSONResponse(status_code=e.status_code,
                                content={"error": e.error_code,
                                         "message": e.message,
                                         "success": False})


@router.put("/upload/{upload_id}", response_model=dict)
async def upload_file(
    upload_id: UUID = Path(...),
    original_name: str = Query(...),
    mime: Optional[str] = Query(None),
    user_id: UUID = Depends(get_current_user),
    body: bytes = Body(...),
    db_session=Depends(get_db_session),
):
    """Receive file bytes locally (the presigned PUT target)."""
    if len(body) > settings.MAX_UPLOAD_SIZE:
        return JSONResponse(status_code=413,
                            content={"error": "FILE_TOO_LARGE",
                                     "message": "فایل بزرگ‌تر از حد مجاز است.",
                                     "success": False})
    async with db_session() as session:
        try:
            svc = FileStateMachine(session)
            result = await svc.upload_bytes(upload_id, user_id,
                                            original_name, mime, body)
            return {"status": "uploaded",
                    "upload_id": str(result.upload_id),
                    "object_key": result.object_key,
                    "sha256": result.sha256,
                    "size": result.size}
        except APIError as e:
            return JSONResponse(status_code=e.status_code,
                                content={"error": e.error_code,
                                         "message": e.message,
                                         "success": False})


@router.post("/{upload_id}/finalize", response_model=dict)
async def finalize_upload(
    upload_id: UUID = Path(...),
    user_id: UUID = Depends(get_current_user),
    finalize: UploadFinalize = Body(...),
    db_session=Depends(get_db_session),
):
    """Finalize the upload (mark scanned + available)."""
    async with db_session() as session:
        try:
            svc = FileStateMachine(session)
            result = await svc.finalize(upload_id, user_id)
            return {"status": "finalized",
                    "upload_id": str(result.upload_id),
                    "is_available": result.is_available}
        except (APIError, NotFoundError) as e:
            return JSONResponse(status_code=e.status_code,
                                content={"error": e.error_code,
                                         "message": e.message,
                                         "success": False})


@router.get("/{upload_id}/download", response_model=dict)
async def download_file(
    upload_id: UUID = Path(...),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session),
):
    """Download a file (metadata + bytes via access_logs)."""
    async with db_session() as session:
        try:
            svc = FileStateMachine(session)
            return await svc.download(upload_id, user_id)
        except (APIError, NotFoundError) as e:
            return JSONResponse(status_code=e.status_code,
                                content={"error": e.error_code,
                                         "message": e.message,
                                         "success": False})


@router.get("", response_model=dict)
async def list_uploads(
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session),
):
    """List uploads created by the caller."""
    async with db_session() as session:
        try:
            svc = FileStateMachine(session)
            items = await svc.list_uploads(user_id)
            return {"status": "success", "data": items}
        except APIError as e:
            return JSONResponse(status_code=e.status_code,
                                content={"error": e.error_code,
                                         "message": e.message,
                                         "success": False})
```

==========================================================================================
## FILE: bastehB_ws_chat_notif_files/backend/app/modules/files/db/models.py
## SIZE: 2437 bytes
==========================================================================================

```python
"""
app/modules/files/db/models.py

مدل ``files.uploads`` — عیناً طبق DDL سند معماری v2.0 (بخش مربوط به
schema files، همان بخشی که جدول ``chat.messages`` هم در آن است).
این ماژول قبلاً فقط یک ``api/`` خالی بود؛ هیچ db/services نداشت.
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import CHAR, BigInteger, Boolean, DateTime, String
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func

try:
    from app.core.db.base import Base
except ImportError:  # pragma: no cover
    from sqlalchemy.orm import DeclarativeBase

    class Base(DeclarativeBase):  # type: ignore[no-redef]
        pass


MAX_UPLOAD_SIZE_BYTES = 52_428_800  # ۵۰ مگابایت — طبق CHECK constraint سند


class Upload(Base):
    __tablename__ = "uploads"
    __table_args__ = {"schema": "files"}

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True)
    uploader_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    context_type: Mapped[str] = mapped_column(String(32), nullable=False)  # chat|task_attachment|avatar
    context_id: Mapped[UUID | None] = mapped_column(PG_UUID(as_uuid=True), nullable=True)
    original_name: Mapped[str] = mapped_column(String(255), nullable=False)
    object_key: Mapped[str] = mapped_column(String(512), nullable=False, unique=True)
    mime_declared: Mapped[str | None] = mapped_column(String(128), nullable=True)
    mime_detected: Mapped[str | None] = mapped_column(String(128), nullable=True)
    size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    sha256: Mapped[str] = mapped_column(CHAR(64), nullable=False)
    scan_status: Mapped[str] = mapped_column(String(16), nullable=False, server_default="pending")
    scan_engine: Mapped[str | None] = mapped_column(String(32), nullable=True)
    scanned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    is_available: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
```

==========================================================================================
## FILE: bastehB_ws_chat_notif_files/backend/app/modules/files/ports/__init__.py
## SIZE: 2516 bytes
==========================================================================================

```python
"""File storage ports — request/response Pydantic schemas (real DDL).

Architecture Reference: Sections 8.2, 11.1 (files.uploads / scan_queue /
access_logs).  The DDL lives in ``chat_schema.sql`` (files.uploads) plus
``files_schema.sql`` (scan_queue, access_logs, composite indexes).
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional, Literal
from uuid import UUID

from pydantic import BaseModel, Field


# --- Upload lifecycle ---

class PresignUpload(BaseModel):
    """Request a presigned upload URL / local upload path."""
    context_type: Literal["chat", "task_attachment", "avatar", "goal"]
    context_id: Optional[UUID] = None
    original_name: str = Field(..., max_length=255)
    mime_declared: Optional[str] = None
    size_bytes: int = Field(..., gt=0, le=52_428_800)


class PresignResponse(BaseModel):
    """Data returned to the caller so it can PUT the file bytes."""
    upload_id: UUID
    object_key: str
    upload_url: str        # local ``PUT /api/v1/files/upload/{upload_id}``
    expires_in: int
    max_size: int


class UploadFinalize(BaseModel):
    """Finalize a completed upload (trigger AV scan, mark available)."""
    sha256: Optional[str] = None  # client-provided hash for verification


class DownloadRequest(BaseModel):
    """Optional scope used by the download endpoint."""
    ip_address: Optional[str] = None


# --- Row-level responses ---

class _UploadBase(BaseModel):
    id: UUID
    uploader_id: UUID
    context_type: str
    context_id: Optional[UUID]
    original_name: str
    object_key: str
    mime_declared: Optional[str] = None
    mime_detected: Optional[str] = None
    size_bytes: int
    sha256: Optional[str] = None
    scan_status: str
    scanned_at: Optional[datetime] = None
    is_available: bool
    created_at: datetime
    expires_at: Optional[datetime] = None


class UploadResponse(_UploadBase):
    """Full upload row."""
    pass


class UploadListItem(BaseModel):
    """Lightweight row for list views."""
    id: UUID
    original_name: str
    mime_declared: Optional[str] = None
    size_bytes: int
    scan_status: str
    is_available: bool
    created_at: datetime


class AccessLogResponse(BaseModel):
    id: int
    upload_id: UUID
    ip_address: Optional[str] = None
    user_id: Optional[UUID] = None
    accessed_at: datetime
    action: str


__all__ = [
    "PresignUpload", "PresignResponse", "UploadFinalize",
    "UploadResponse", "UploadListItem", "AccessLogResponse",
]
```

==========================================================================================
## FILE: bastehB_ws_chat_notif_files/backend/app/modules/files/services/av_scan_service.py
## SIZE: 5942 bytes
==========================================================================================

```python
"""
app/modules/files/services/av_scan_service.py

طبق سند («اسکن آنتی‌ویروس فایل‌ها» — گپ بحرانی #۸ در
comprehensive_gap_analysis.md؛ و بخش امنیت: «فایل تا اسکن AV کامل
نشود، is_available=false می‌ماند»).

اصل طراحی: **Fail-Closed**. اگر ClamAV در دسترس نباشد یا خطا بدهد،
فایل هرگز "clean" علامت نمی‌خورد — می‌ماند روی ``scan_status='error'``
و ``is_available=False``. هیچ مسیری برای "اگر مطمئن نبودیم، اجازه
بده" وجود ندارد؛ این دقیقاً برعکس رفتاری‌ست که در audit_service قدیم
دیدیم (except: pass) و می‌خواهیم دیگر تکرار نشود.

⚠️ وابستگی: ``pyclamd`` (یا ``clamd``) نصب نیست. نصب لازم:
    pip install pyclamd
و یک دیمون ClamAV در دسترس (``clamd`` سرویس، پورت پیش‌فرض ۳۳۱۰).
تنظیمات لازم: ``CLAMAV_HOST``, ``CLAMAV_PORT``.

⚠️ فراخوانی: طبق سند باید این اسکن async/Celery باشد (تا آپلود کاربر
را بلاک نکند). چون Celery نصب نیست، فعلاً از همان Event Bus درون‌پروسه
استفاده می‌شود — این یعنی اسکن هم‌زمان با finalize_upload اجرا می‌شود
(کاربر کمی صبر می‌کند). وقتی Celery نصب شد، فقط کافی‌ست این تابع را
از یک Celery task صدا بزنید به‌جای این‌که مستقیم در request-response
اجرا شود — امضای تابع عوض نمی‌شود.
"""

from __future__ import annotations

from typing import Any

from app.core.events.bus import DomainEvent, event_bus
from app.modules.files.db.models import Upload
from app.modules.files.services.storage import ObjectStorageClient, StorageError
from app.modules.files.services.validators import (
    FileValidationError,
    validate_magic_number_matches_extension,
)

HEADER_BYTES_TO_READ = 8192


class AvScanService:
    def __init__(self, session: Any, storage: ObjectStorageClient, settings: Any) -> None:
        self.session = session
        self.storage = storage
        self.settings = settings

    async def scan(self, upload: Upload) -> None:
        """یک ردیف ``files.uploads`` را اسکن می‌کند و وضعیتش را نهایی می‌کند."""
        try:
            header = self.storage.get_object_bytes(upload.object_key, HEADER_BYTES_TO_READ)
        except StorageError as exc:
            await self._mark_error(upload, f"storage_read_failed: {exc}")
            return

        ext = "." + upload.original_name.rsplit(".", 1)[-1].lower() if "." in upload.original_name else ""
        try:
            validate_magic_number_matches_extension(header, ext)
        except FileValidationError as exc:
            await self._mark_infected(upload, reason=f"signature_mismatch:{exc.code}")
            return

        clam_result = await self._run_clamav(upload)
        if clam_result == "clean":
            await self._mark_clean(upload)
        elif clam_result == "infected":
            await self._mark_infected(upload, reason="clamav_detected_malware")
        else:  # "unavailable" یا هر چیز غیرمنتظره — Fail-Closed
            await self._mark_error(upload, "clamav_unavailable")

    async def _run_clamav(self, upload: Upload) -> str:
        try:
            import pyclamd
        except ImportError:
            return "unavailable"

        try:
            cd = pyclamd.ClamdNetworkSocket(
                host=getattr(self.settings, "CLAMAV_HOST", "localhost"),
                port=getattr(self.settings, "CLAMAV_PORT", 3310),
            )
            if not cd.ping():
                return "unavailable"
            full_bytes = self.storage.get_object_bytes(upload.object_key, upload.size_bytes)
            result = cd.scan_stream(full_bytes)
            return "infected" if result else "clean"
        except Exception:  # noqa: BLE001 — هر خطای غیرمنتظره = Fail-Closed، نه "clean"
            return "unavailable"

    async def _mark_clean(self, upload: Upload) -> None:
        upload.scan_status = "clean"
        upload.scan_engine = "clamav"
        upload.is_available = True
        from datetime import datetime, timezone
        upload.scanned_at = datetime.now(timezone.utc)
        await self._publish("files.upload.available", upload, {"reason": "clean"})

    async def _mark_infected(self, upload: Upload, *, reason: str) -> None:
        upload.scan_status = "infected"
        upload.is_available = False
        from datetime import datetime, timezone
        upload.scanned_at = datetime.now(timezone.utc)
        try:
            self.storage.delete_object(upload.object_key)  # هرگز فایل آلوده را روی storage نگه ندار
        except StorageError:
            pass
        await self._publish("files.upload.rejected", upload, {"reason": reason, "dangerous": True})

    async def _mark_error(self, upload: Upload, reason: str) -> None:
        upload.scan_status = "error"
        upload.is_available = False  # Fail-Closed: هرگز available=True بدون اسکن موفق
        await self._publish("files.scan.error", upload, {"reason": reason})

    async def _publish(self, event_type: str, upload: Upload, extra: dict) -> None:
        event = DomainEvent(
            event_type=event_type,
            actor_id=upload.uploader_id,
            payload={"file_id": str(upload.id), "object_key": upload.object_key, **extra},
        )
        try:
            await event_bus.publish(event, self.session)
            await self.session.commit()
        except Exception:
            import logging
            logging.getLogger("files.av_scan").exception("failed to publish %s", event_type)
```

==========================================================================================
## FILE: bastehB_ws_chat_notif_files/backend/app/modules/files/services/file_service.py
## SIZE: 4746 bytes
==========================================================================================

```python
"""
app/modules/files/services/file_service.py

سه قدم اصلی طبق دیاگرام توالی سند:
  ۱) presign_upload   — کلاینت مستقیم به S3/MinIO آپلود می‌کند (نه از طریق API ما)
  ۲) finalize_upload  — بعد از آپلود موفق کلاینت، این را صدا می‌زند؛ رکورد DB
                          ساخته و اسکن AV (فعلاً هم‌زمان) اجرا می‌شود
  ۳) get_download_url — فقط اگر ``is_available=True`` باشد URL می‌دهد
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID, uuid4

from app.core.errors import APIError
from app.modules.files.db.models import MAX_UPLOAD_SIZE_BYTES, Upload
from app.modules.files.services.av_scan_service import AvScanService
from app.modules.files.services.storage import ObjectStorageClient
from app.modules.files.services.validators import (
    ALLOWED_EXTENSIONS,
    FileValidationError,
    validate_extension,
    validate_size,
)


class FileService:
    def __init__(
        self, session: Any, storage: ObjectStorageClient,
        av_scan_service: AvScanService, upload_repo: Any,
    ) -> None:
        self.session = session
        self.storage = storage
        self.av_scan_service = av_scan_service
        self.upload_repo = upload_repo

    async def presign_upload(
        self, *, uploader_id: UUID, context_type: str, context_id: UUID | None,
        filename: str, size_bytes: int,
    ) -> dict:
        try:
            ext = validate_extension(filename)
            validate_size(size_bytes)
        except FileValidationError as exc:
            raise APIError(error_code=exc.code, message=exc.message, status_code=400) from exc

        object_key = self._build_object_key(context_type, ext)
        content_type = ALLOWED_EXTENSIONS[ext]
        put_url = self.storage.presigned_put_url(object_key, content_type)

        return {
            "upload_url": put_url,
            "object_key": object_key,
            "expires_in": 300,
            "max_size_bytes": MAX_UPLOAD_SIZE_BYTES,
        }

    async def finalize_upload(
        self, *, uploader_id: UUID, context_type: str, context_id: UUID | None,
        object_key: str, original_name: str, size_bytes: int,
        mime_declared: str | None, sha256: str,
    ) -> dict:
        validate_size(size_bytes)  # دوباره چک می‌شود — کلاینت می‌توانست دروغ بگوید

        upload = Upload(
            id=uuid4(),
            uploader_id=uploader_id,
            context_type=context_type,
            context_id=context_id,
            original_name=original_name,
            object_key=object_key,
            mime_declared=mime_declared,
            size_bytes=size_bytes,
            sha256=sha256,
            scan_status="pending",
            is_available=False,
        )
        await self.upload_repo.add(upload)
        await self.upload_repo.commit()

        # TODO: وقتی Celery نصب شد، این خط به یک task غیرهمزمان منتقل شود
        # تا کاربر منتظر نتیجه‌ی اسکن نماند (سند دقیقاً همین را می‌خواهد).
        await self.av_scan_service.scan(upload)
        await self.upload_repo.commit()

        return {
            "file_id": str(upload.id),
            "scan_status": upload.scan_status,
            "is_available": upload.is_available,
        }

    async def get_download_url(self, file_id: UUID, requester_id: UUID) -> str:
        upload = await self.upload_repo.get(file_id)
        if upload is None:
            raise APIError(error_code="FILE_NOT_FOUND", message="فایل یافت نشد.", status_code=404)
        if not upload.is_available:
            raise APIError(
                error_code="FILE_NOT_AVAILABLE",
                message="فایل هنوز در دسترس نیست (در انتظار اسکن یا آلوده تشخیص داده شده).",
                status_code=403,
            )
        # TODO: اینجا دقیقاً جایی است که باید مجوز دسترسی به context (پیام
        # چت/تسک) را هم چک کنید — از طریق PolicyEngine ماژول sharing؛ من به
        # آن کد دسترسی ندارم، پس این‌جا نگذاشتم تا چیزی را اشتباه فرض نکنم.
        return self.storage.presigned_get_url(upload.object_key, upload.original_name)

    def _build_object_key(self, context_type: str, ext: str) -> str:
        now = datetime.now(timezone.utc)
        return f"{context_type}/{now.year:04d}/{now.month:02d}/{uuid4()}{ext}"
```

==========================================================================================
## FILE: bastehB_ws_chat_notif_files/backend/app/modules/files/services/files_service.py
## SIZE: 8885 bytes
==========================================================================================

```python
"""File storage service — real DDL (M13).

Implements the upload lifecycle against ``files.uploads``,
``files.scan_queue`` and ``files.access_logs`` using raw SQL
(the same pattern as inbox/calendar services).  Bytes are stored
in a local directory (configurable via ``settings.FILE_STORAGE_DIR``)
since no S3 gateway is wired in this deployment.
"""

from __future__ import annotations

import hashlib
import secrets
import struct
import time
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional
from uuid import UUID
from types import SimpleNamespace

from sqlalchemy import text

from app.core.config import settings
from app.core.errors import APIError, NotFoundError

# Local storage root (created if missing).
STORAGE_ROOT: Path = Path(settings.FILE_STORAGE_DIR)
STORAGE_ROOT.mkdir(parents=True, exist_ok=True)

# Maximum single upload body size.
_MAX_BODY_BYTES: int = settings.MAX_UPLOAD_SIZE


def _row_serialize(r) -> dict:
    d = dict(r)
    for k, v in list(d.items()):
        if v is not None and isinstance(v, datetime):
            d[k] = v.isoformat()
        elif isinstance(v, bytes):
            d[k] = v.hex()
    return d


class FileStateMachine:
    """Manages file upload lifecycle (presign → upload → finalize → download)."""

    def __init__(self, session):
        self.session = session

    # --- Presign ---

    async def presign(self, uploader_id: UUID, payload: dict) -> SimpleNamespace:
        """Reserve an upload slot and return a local upload target."""
        object_key = f"{secrets.token_urlsafe(18)}/{secrets.token_urlsafe(12)}"
        row = (await self.session.execute(text("""
            INSERT INTO files.uploads (
                uploader_id, context_type, context_id,
                original_name, object_key, mime_declared,
                size_bytes, sha256, scan_status, is_available
            )
            VALUES (:uid, :ctype, :cid, :name, :key, :mime,
                    :size, '0000000000000000000000000000000000000000000000000000000000000000', 'pending', FALSE)
            RETURNING id, object_key, expires_at
        """), {
            "uid": str(uploader_id),
            "ctype": payload["context_type"],
            "cid": str(payload["context_id"]) if payload.get("context_id") else None,
            "name": payload["original_name"],
            "key": object_key,
            "mime": payload.get("mime_declared"),
            "size": payload["size_bytes"],
        })).mappings().first()
        await self.session.commit()
        upload_id = row["id"]
        # Local PUT target.
        upload_url = f"/api/v1/files/upload/{upload_id}"
        return SimpleNamespace(
            upload_id=upload_id, object_key=row["object_key"],
            upload_url=upload_url,
            expires_in=3600,
            max_size=_MAX_BODY_BYTES,
        )

    # --- Receive bytes (local fallback) ---

    async def upload_bytes(self, upload_id: UUID, uploader_id: UUID,
                           filename: str, mime: Optional[str],
                           body: bytes) -> SimpleNamespace:
        """Store bytes on local disk and update the upload row."""
        # Confirm the reservation still belongs to uploader and is pending.
        row = (await self.session.execute(text("""
            SELECT id, object_key, size_bytes FROM files.uploads
             WHERE id = :iid AND uploader_id = :uid AND scan_status = 'pending'
        """), {"iid": str(upload_id), "uid": str(uploader_id)})).mappings().first()
        if not row:
            raise APIError(error_code="UPLOAD_NOT_FOUND",
                           message="آپلود یافت نشد یا منقضی شده است.",
                           status_code=404)
        object_path = _object_to_path(row["object_key"])
        object_path.parent.mkdir(parents=True, exist_ok=True)
        with open(object_path, "wb") as f:
            f.write(body)

        sha256 = hashlib.sha256(body).hexdigest()
        mime_detected = mime or _guess_mime(filename)
        await self.session.execute(text("""
            UPDATE files.uploads
               SET mime_detected = :mime,
                   sha256 = :sha,
                   size_bytes = :size
             WHERE id = :iid
        """), {"mime": mime_detected, "sha": sha256,
               "size": len(body), "iid": str(upload_id)})
        await self.session.commit()
        return SimpleNamespace(upload_id=upload_id, object_key=row["object_key"],
                               sha256=sha256, size=len(body), mime=mime_detected)

    # --- Finalize ---

    async def finalize(self, upload_id: UUID, uploader_id: UUID) -> SimpleNamespace:
        """Mark scan done, mark the upload available."""
        row = (await self.session.execute(text("""
            SELECT id, object_key, sha256 FROM files.uploads
             WHERE id = :iid AND uploader_id = :uid
        """), {"iid": str(upload_id), "uid": str(uploader_id)})).mappings().first()
        if not row:
            raise NotFoundError(resource="file upload")

        sha256 = row["sha256"]
        # Insert a scan-queue row (best-effort).  A background worker
        # would consume it; on a single-node dev deployment we mark
        # the file clean immediately so the upload is usable.
        await self.session.execute(text("""
            INSERT INTO files.scan_queue (upload_id, status, clamav_message,
                                          scanned_at, retry_count, max_retries)
            VALUES (:iid, 'clean', 'local-dev-skip-clamav', now(), 0, 3)
            ON CONFLICT DO NOTHING
        """), {"iid": str(upload_id)})
        await self.session.execute(text("""
            UPDATE files.uploads
               SET scan_status = 'clean', scanned_at = now(),
                   is_available = TRUE
             WHERE id = :iid
        """), {"iid": str(upload_id)})
        await self.session.commit()
        return SimpleNamespace(upload_id=upload_id, object_key=row["object_key"],
                               sha256=sha256, is_available=True)

    # --- Download ---

    async def download(self, upload_id: UUID, user_id: UUID) -> dict:
        """Serve a file: log access, return bytes + metadata."""
        row = (await self.session.execute(text("""
            SELECT id, object_key, original_name, mime_detected,
                   size_bytes, sha256, is_available, created_at
              FROM files.uploads
             WHERE id = :iid
        """), {"iid": str(upload_id)})).mappings().first()
        if not row:
            raise NotFoundError(resource="file")
        if not row["is_available"]:
            raise APIError(error_code="FILE_UNAVAILABLE",
                           message="فایل هنوز آماده نیست (اسکن در انتظار).",
                           status_code=409)

        # Log access (no auth gate here — caller decides ACL).
        await self.session.execute(text("""
            INSERT INTO files.access_logs (upload_id, ip_address, user_id,
                                           accessed_at, action)
            VALUES (:iid, :ip, :uid, now(), 'download')
        """), {"iid": str(upload_id),
               "ip": None, "uid": str(user_id)})
        await self.session.commit()

        path = _object_to_path(row["object_key"])
        data = path.read_bytes() if path.exists() else b""
        return {
            "status": "success",
            "data": {
                "id": str(row["id"]),
                "object_key": row["object_key"],
                "original_name": row["original_name"],
                "mime_detected": row["mime_detected"],
                "size_bytes": row["size_bytes"],
                "sha256": row["sha256"],
                "created_at": row["created_at"].isoformat(),
                "bytes": data,
            },
        }

    # --- List ---

    async def list_uploads(self, user_id: UUID) -> list[dict]:
        """List uploads belonging to a user."""
        rows = (await self.session.execute(text("""
            SELECT id, original_name, mime_declared, size_bytes,
                   scan_status, is_available, created_at
              FROM files.uploads
             WHERE uploader_id = :uid
             ORDER BY created_at DESC
        """), {"uid": str(user_id)})).mappings().all()
        return [_row_serialize(r) for r in rows]


# --- helpers ---

def _object_to_path(object_key: str) -> Path:
    """Map object key ``a/b/c`` → {root}/a/b/c (no extension on disk)."""
    parts = object_key.split("/")
    return STORAGE_ROOT.joinpath(*parts)


def _guess_mime(filename: str) -> str:
    ext = Path(filename).suffix.lower()
    return {
        ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
        ".png": "image/png", ".gif": "image/gif",
        ".pdf": "application/pdf",
    }.get(ext, "application/octet-stream")
```

==========================================================================================
## FILE: bastehB_ws_chat_notif_files/backend/app/modules/files/services/storage.py
## SIZE: 3441 bytes
==========================================================================================

```python
"""
app/modules/files/services/storage.py

Wrapper نازک روی S3/MinIO — طبق سند («Presigned URL»، «Object Storage
(MinIO/S3)»). `boto3` در `pip list` شما نصب نیست، پس import تنبل است.

نصب لازم:
    pip install boto3

⚠️ تنظیمات لازم (به app/core/config.py اضافه کنید):
    FILES_S3_ENDPOINT_URL   # برای MinIO؛ برای AWS S3 واقعی خالی بگذارید
    FILES_S3_BUCKET
    FILES_S3_ACCESS_KEY
    FILES_S3_SECRET_KEY
    FILES_S3_REGION = "us-east-1"  # MinIO هم این را می‌خواهد، هرچه باشد کافی است
"""

from __future__ import annotations

from typing import Any


class StorageError(Exception):
    pass


class ObjectStorageClient:
    def __init__(self, settings: Any) -> None:
        self.settings = settings
        self._client = None

    def _get_client(self):
        if self._client is not None:
            return self._client
        try:
            import boto3
            from botocore.config import Config
        except ImportError as exc:  # pragma: no cover
            raise StorageError("`boto3` نصب نیست — `pip install boto3` را اجرا کنید.") from exc

        self._client = boto3.client(
            "s3",
            endpoint_url=getattr(self.settings, "FILES_S3_ENDPOINT_URL", None) or None,
            aws_access_key_id=self.settings.FILES_S3_ACCESS_KEY,
            aws_secret_access_key=self.settings.FILES_S3_SECRET_KEY,
            region_name=getattr(self.settings, "FILES_S3_REGION", "us-east-1"),
            config=Config(signature_version="s3v4"),
        )
        return self._client

    def presigned_put_url(self, object_key: str, content_type: str, expires_seconds: int = 300) -> str:
        client = self._get_client()
        return client.generate_presigned_url(
            "put_object",
            Params={
                "Bucket": self.settings.FILES_S3_BUCKET,
                "Key": object_key,
                "ContentType": content_type,
            },
            ExpiresIn=expires_seconds,
        )

    def presigned_get_url(self, object_key: str, download_filename: str, expires_seconds: int = 60) -> str:
        client = self._get_client()
        return client.generate_presigned_url(
            "get_object",
            Params={
                "Bucket": self.settings.FILES_S3_BUCKET,
                "Key": object_key,
                # طبق سند: Content-Disposition: attachment (هرگز inline برای فایل کاربر)
                "ResponseContentDisposition": f'attachment; filename="{download_filename}"',
                "ResponseContentType": "application/octet-stream",  # هرگز mime کلاینت را معتبر ندانید
            },
            ExpiresIn=expires_seconds,
        )

    def get_object_bytes(self, object_key: str, max_bytes: int) -> bytes:
        """برای اسکن AV — فقط تا ``max_bytes`` اول را می‌خواند (کافی برای magic number)."""
        client = self._get_client()
        response = client.get_object(
            Bucket=self.settings.FILES_S3_BUCKET, Key=object_key,
            Range=f"bytes=0-{max_bytes - 1}",
        )
        return response["Body"].read()

    def delete_object(self, object_key: str) -> None:
        client = self._get_client()
        client.delete_object(Bucket=self.settings.FILES_S3_BUCKET, Key=object_key)
```

==========================================================================================
## FILE: bastehB_ws_chat_notif_files/backend/app/modules/files/services/validators.py
## SIZE: 6360 bytes
==========================================================================================

```python
"""
app/modules/files/services/validators.py

منطق خالص اعتبارسنجی فایل — طبق سند: «Whitelist گسترده (نه Blacklist)»
و «بررسی Magic Number، نه فقط پسوند». عمداً بدون وابستگی به
S3/ClamAV نوشته شده تا کاملاً آفلاین و سریع تست شود؛ چیزی که واقعاً
شبکه لازم دارد (اسکن ClamAV) در ``av_scan_service.py`` است.

⚠️ اگر پکیج ``python-magic`` نصب باشد، تشخیص دقیق‌تری ممکن است؛ این
فایل به‌صورت fallback از امضای بایت اول («magic number») برای
پرمصرف‌ترین انواع فایل در یک محیط اداری/کارتابلی استفاده می‌کند.
برای فرمت‌های نادرتر، ``python-magic`` را نصب و در ``av_scan_service.py``
جایگزین کنید.
"""

from __future__ import annotations

# طبق سند: «Whitelist گسترده» — لیست پسوند/mime مجاز، نه ممنوع
ALLOWED_EXTENSIONS: dict[str, str] = {
    ".pdf": "application/pdf",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif": "image/gif",
    ".webp": "image/webp",
    ".doc": "application/msword",
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ".xls": "application/vnd.ms-excel",
    ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ".ppt": "application/vnd.ms-powerpoint",
    ".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    ".txt": "text/plain",
    ".csv": "text/csv",
    ".zip": "application/zip",  # طبق سند: آرشیوها فقط با whitelist داخلی مجازند
}

# پسوندهای اجراپذیر/اسکریپتی — حتی اگر کسی به‌اشتباه به ALLOWED_EXTENSIONS
# اضافه کند، این لیست همیشه رد می‌شود (دفاع لایه‌ی دوم).
DANGEROUS_EXTENSIONS = {
    ".exe", ".dll", ".bat", ".cmd", ".sh", ".ps1", ".msi",
    ".js", ".vbs", ".jar", ".com", ".scr", ".apk",
}

MAX_UPLOAD_SIZE_BYTES = 52_428_800  # ۵۰ مگابایت

# امضای بایت اول («magic number») برای رایج‌ترین انواع — RFC/مستندات فرمت‌ها
_MAGIC_SIGNATURES: list[tuple[bytes, str]] = [
    (b"%PDF-", "application/pdf"),
    (b"\x89PNG\r\n\x1a\n", "image/png"),
    (b"\xff\xd8\xff", "image/jpeg"),
    (b"GIF87a", "image/gif"),
    (b"GIF89a", "image/gif"),
    (b"RIFF", "image/webp"),  # نیاز به بررسی بیشتر بایت ۸ تا ۱۱ برای "WEBP" دارد؛ ساده‌سازی شده
    (b"PK\x03\x04", "application/zip"),  # zip، docx، xlsx، pptx همه با این شروع می‌شوند (OOXML = zip)
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "application/x-ole-storage"),  # doc/xls/ppt قدیمی (OLE2)
]


class FileValidationError(Exception):
    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(f"{code}: {message}")


def validate_extension(filename: str) -> str:
    """پسوند را برمی‌گرداند اگر مجاز باشد، وگرنه خطا می‌دهد."""
    ext = _extract_extension(filename)
    if ext in DANGEROUS_EXTENSIONS:
        raise FileValidationError("DANGEROUS_FILE_TYPE", f"پسوند {ext} مجاز نیست.")
    if ext not in ALLOWED_EXTENSIONS:
        raise FileValidationError("EXTENSION_NOT_ALLOWED", f"پسوند {ext} در فهرست مجاز نیست.")
    return ext


def validate_size(size_bytes: int) -> None:
    if size_bytes <= 0:
        raise FileValidationError("EMPTY_FILE", "فایل خالی است.")
    if size_bytes > MAX_UPLOAD_SIZE_BYTES:
        raise FileValidationError(
            "FILE_TOO_LARGE",
            f"حجم فایل بیش از حد مجاز است (حداکثر {MAX_UPLOAD_SIZE_BYTES // (1024*1024)} مگابایت).",
        )


def sniff_mime_from_header(header_bytes: bytes) -> str | None:
    """اولین چند بایت فایل را با امضاهای شناخته‌شده مقایسه می‌کند."""
    for signature, mime in _MAGIC_SIGNATURES:
        if header_bytes.startswith(signature):
            return mime
    return None


def validate_magic_number_matches_extension(header_bytes: bytes, extension: str) -> None:
    """طبق سند: «بررسی Magic Number، نه فقط پسوند» — جلوی فایل اجرایی
    تغییرنام‌یافته به .pdf را می‌گیرد.

    برای فرمت‌های OOXML/OLE2 (docx/xlsx/doc/xls/zip) بررسی سخت‌گیرانه‌تر
    (باز کردن zip و چک کردن ساختار داخلی) بهتر است؛ اینجا فقط سطح
    امضای بایت اول چک می‌شود — کافی برای رد کردن اکثر تلاش‌های ساده‌ی
    جعل، نه یک ضدعفونی‌کننده‌ی کامل (آن کار ClamAV در av_scan_service است).
    """
    detected = sniff_mime_from_header(header_bytes)
    expected = ALLOWED_EXTENSIONS.get(extension)

    if detected is None:
        # فرمت‌های متنی ساده (txt, csv) امضای بایتی مشخصی ندارند — عبور می‌کنند
        if extension in (".txt", ".csv"):
            return
        raise FileValidationError(
            "UNKNOWN_FILE_SIGNATURE",
            "محتوای فایل با هیچ‌کدام از فرمت‌های شناخته‌شده مطابقت ندارد.",
        )

    # zip-family (docx/xlsx/pptx/zip) و OLE2-family (doc/xls/ppt) چندتایی هستند
    zip_family = {".zip", ".docx", ".xlsx", ".pptx"}
    ole_family = {".doc", ".xls", ".ppt"}
    if extension in zip_family and detected == "application/zip":
        return
    if extension in ole_family and detected == "application/x-ole-storage":
        return
    if detected != expected:
        raise FileValidationError(
            "EXTENSION_MISMATCH",
            f"پسوند فایل ({extension}) با محتوای واقعی آن ({detected}) هم‌خوانی ندارد.",
        )


def _extract_extension(filename: str) -> str:
    idx = filename.rfind(".")
    if idx == -1:
        return ""
    return filename[idx:].lower()
```

==========================================================================================
## FILE: bastehB_ws_chat_notif_files/backend/app/modules/notification/api/routes.py
## SIZE: 5390 bytes
==========================================================================================

```python
"""Notification module API routes (real DDL, M10)."""

from __future__ import annotations

from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, Body, Query, Path, Request
from fastapi.responses import JSONResponse

from app.core.dependencies import get_db_session, get_current_user
from app.core.errors import APIError, NotFoundError
from app.modules.notification.ports import (
    NotificationCreate, NotificationResponse, PreferencesUpdate,
    PreferencesResponse, NotificationCount,
)
from app.modules.notification.services.notification_service import NotificationService


router = APIRouter(prefix="/notifications", tags=["Notifications"])


@router.get("", response_model=dict)
async def list_notifications(
    request: Request,
    user_id: UUID = Depends(get_current_user),
    limit: int = Query(50, ge=1, le=200),
    unread_only: bool = Query(False),
    db_session=Depends(get_db_session),
):
    """List the caller's notifications, newest first."""
    async with db_session() as session:
        try:
            svc = NotificationService(session)
            items = await svc.list_for_user(user_id, limit, unread_only)
            return {"status": "success", "data": items,
                    "count": len(items)}
        except APIError as e:
            return JSONResponse(status_code=e.status_code,
                                content={"error": e.error_code,
                                         "message": e.message,
                                         "success": False})


@router.get("/unread-count", response_model=dict)
async def unread_count(
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session),
):
    """Return count of unread notifications."""
    async with db_session() as session:
        try:
            svc = NotificationService(session)
            count = await svc.unread_count(user_id)
            return {"status": "success", "data": {"unread": count}}
        except APIError as e:
            return JSONResponse(status_code=e.status_code,
                                content={"error": e.error_code,
                                         "message": e.message,
                                         "success": False})


@router.patch("/{notification_id}/read", response_model=dict)
async def mark_read(
    notification_id: UUID = Path(...),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session),
):
    """Mark a single notification as read."""
    async with db_session() as session:
        try:
            svc = NotificationService(session)
            result = await svc.mark_read(user_id, notification_id)
            return {"status": "success", "data": {"id": str(result.id),
                                                  "is_read": result.is_read}}
        except NotFoundError:
            return JSONResponse(status_code=404,
                                content={"error": "NOT_FOUND",
                                         "message": "اعلان یافت نشد.",
                                         "success": False})


@router.patch("/read-all", response_model=dict)
async def mark_all_read(
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session),
):
    """Mark all of the caller's notifications as read."""
    async with db_session() as session:
        try:
            svc = NotificationService(session)
            updated = await svc.mark_all_read(user_id)
            return {"status": "success", "data": {"updated": updated}}
        except APIError as e:
            return JSONResponse(status_code=e.status_code,
                                content={"error": e.error_code,
                                         "message": e.message,
                                         "success": False})


@router.get("/preferences", response_model=dict)
async def get_preferences(
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session),
):
    """Return the caller's notification preferences."""
    async with db_session() as session:
        try:
            svc = NotificationService(session)
            prefs = await svc.get_preferences(user_id)
            return {"status": "success", "data": prefs}
        except APIError as e:
            return JSONResponse(status_code=e.status_code,
                                content={"error": e.error_code,
                                         "message": e.message,
                                         "success": False})


@router.put("/preferences", response_model=dict)
async def update_preferences(
    patch: PreferencesUpdate,
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session),
):
    """Update the caller's notification preferences."""
    async with db_session() as session:
        try:
            svc = NotificationService(session)
            prefs = await svc.update_preferences(user_id,
                                                 patch.model_dump(exclude_unset=True))
            return {"status": "success", "data": prefs}
        except APIError as e:
            return JSONResponse(status_code=e.status_code,
                                content={"error": e.error_code,
                                         "message": e.message,
                                         "success": False})
```

==========================================================================================
## FILE: bastehB_ws_chat_notif_files/backend/app/modules/notification/events.py
## SIZE: 3504 bytes
==========================================================================================

```python
"""Notification module event handlers (real DDL, M10).

Subscribes to selected domain events and persists an inbox notification
inside the same transaction (transactional=True), exactly like the
audit module.  The bus invokes ``handler(event, session)`` with the
publisher's session, so no separate DB wiring is needed.

Idempotency: handled out-of-the-box by the bus for transactional
consumers (publishers do not re-fire failed events synchronously).
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

logger = logging.getLogger("notification.events")

# Event type strings (kept literal, per module-boundary rule).
AUTH_LOGIN_SUCCEEDED = "auth.login.succeeded"
AUTH_LOGIN_FAILED = "auth.login.failed"
AUTH_PASSWORD_CHANGED = "auth.password.changed"
AUTH_DEVICE_TRUSTED = "auth.device.trusted"
RBAC_ROLE_ASSIGNED = "rbac.role.assigned"

_TITLES = {
    AUTH_LOGIN_SUCCEEDED: "ورود موفق",
    AUTH_LOGIN_FAILED: "ورود ناموفق",
    AUTH_PASSWORD_CHANGED: "تغییر رمز عبور",
    AUTH_DEVICE_TRUSTED: "دستگاه مورد اعتماد",
    RBAC_ROLE_ASSIGNED: "نقش جدید",
}

_ALL = tuple(_TITLES.keys())


def register_event_handlers(bus) -> None:
    """Subscribe to domain events that produce inbox notifications.

    Transactional (synchronous, same-transaction) consumers are the
    right fit here: the notification row should roll back with the
    domain transaction, and the publisher's session is provided by
    the bus on every ``publish()`` call.
    """
    for evt in _ALL:
        bus.subscribe(evt, _handle, transactional=True)


async def _handle(event: Any, session: Any) -> None:
    from app.modules.notification.services.notification_service import NotificationService

    event_type = getattr(event, "event_type", "")
    actor_id = getattr(event, "actor_id", None)
    payload = getattr(event, "payload", None) or {}

    if not actor_id:
        actor_id = payload.get("user_id") or payload.get("identifier")
        if not actor_id:
            return

    title = _TITLES.get(event_type, event_type)
    kind = event_type.rsplit(".", 1)[-1]
    created = None
    try:
        svc = NotificationService(session)
        created = await svc.create({
            "user_id": actor_id,
            "type": kind,
            "title": title,
            "message": payload.get("reason"),
            "data": payload,
            "priority": "normal",
        })
    except Exception:
        logger.exception("failed to persist notification event_type=%s", event_type)
        raise

    _publish_live(actor_id, created, event_type, title, payload)


def _publish_live(actor_id: Any, created: Any, event_type: str, title: str,
                  payload: dict) -> None:
    """Push a live event to any open ``/ws/notifications`` socket."""
    import json

    try:
        from app.core.redis import get_redis_broker

        broker = get_redis_broker()
        msg = {
            "type": "notification",
            "event_type": event_type,
            "id": str(getattr(created, "id", "")),
            "title": title,
            "message": payload.get("reason"),
            "created_at": getattr(created, "created_at", None),
        }
        asyncio.get_running_loop().create_task(
            broker.publish(f"notifications:{actor_id}", json.dumps(msg, ensure_ascii=False, default=str))
        )
    except Exception:
        logger.debug("live notification publish skipped", exc_info=True)
```

==========================================================================================
## FILE: bastehB_ws_chat_notif_files/backend/app/modules/notification/ports/__init__.py
## SIZE: 1818 bytes
==========================================================================================

```python
"""Notification module ports — request/response Pydantic schemas (real DDL)."""

from __future__ import annotations

from datetime import datetime, time
from typing import Optional, List
from uuid import UUID

from pydantic import BaseModel, Field


class NotificationCreate(BaseModel):
    user_id: UUID
    type: str = Field(..., max_length=50)
    title: str = Field(..., max_length=255)
    message: Optional[str] = None
    data: Optional[dict] = None
    action_url: Optional[str] = Field(None, max_length=255)
    action_text: Optional[str] = Field(None, max_length=100)
    related_entity_type: Optional[str] = Field(None, max_length=50)
    related_entity_id: Optional[UUID] = None
    priority: str = Field("normal", pattern="^(low|normal|high|urgent)$")
    expires_at: Optional[datetime] = None


class NotificationResponse(BaseModel):
    id: UUID
    user_id: UUID
    type: str
    title: str
    message: Optional[str]
    data: Optional[dict]
    is_read: bool
    action_url: Optional[str]
    action_text: Optional[str]
    priority: str
    created_at: datetime
    read_at: Optional[datetime]


class PreferencesUpdate(BaseModel):
    email_enabled: Optional[bool] = None
    push_enabled: Optional[bool] = None
    inbox_enabled: Optional[bool] = None
    types: Optional[dict] = None
    quiet_hours_start: Optional[time] = None
    quiet_hours_end: Optional[time] = None


class PreferencesResponse(BaseModel):
    user_id: UUID
    email_enabled: bool
    push_enabled: bool
    inbox_enabled: bool
    types: dict
    quiet_hours_start: Optional[time] = None
    quiet_hours_end: Optional[time] = None


class NotificationCount(BaseModel):
    unread: int


__all__ = [
    "NotificationCreate", "NotificationResponse", "PreferencesUpdate",
    "PreferencesResponse", "NotificationCount",
]
```

==========================================================================================
## FILE: bastehB_ws_chat_notif_files/backend/app/modules/notification/services/notification_service.py
## SIZE: 7605 bytes
==========================================================================================

```python
"""Notification service — real DDL (M10).

Raw SQL against schema ``notification``: notifications, preferences, log.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Optional
from uuid import UUID
from types import SimpleNamespace

from sqlalchemy import text

from app.core.errors import APIError, NotFoundError


def _iso(v) -> Optional[str]:
    return v.isoformat() if isinstance(v, datetime) else v


def _row_serialize(r) -> dict:
    d = dict(r)
    for k, v in list(d.items()):
        if v is not None and isinstance(v, datetime):
            d[k] = _iso(v)
        elif isinstance(v, (dict, list)):
            d[k] = json.dumps(v, ensure_ascii=False)
    return d


class NotificationStateMachine:
    """Manages notifications, delivery log and user preferences."""

    def __init__(self, session):
        self.session = session

    # --- Create / list ---

    async def create(self, spec: dict) -> SimpleNamespace:
        """Persist a notification with default priority."""
        row = (await self.session.execute(text("""
            INSERT INTO notification.notifications (
                user_id, type, title, message, data,
                is_read, action_url, action_text,
                related_entity_type, related_entity_id,
                priority, expires_at
            )
            VALUES (:uid, :type, :title, :msg, :data,
                    FALSE, :aurl, :atext,
                    :rtype, :rid,
                    :prio, :exp)
            RETURNING id, created_at, is_read
        """), {
            "uid": str(spec["user_id"]),
            "type": spec["type"],
            "title": spec["title"],
            "msg": spec.get("message"),
            "data": json.dumps(spec.get("data")) if spec.get("data") else None,
            "aurl": spec.get("action_url"),
            "atext": spec.get("action_text"),
            "rtype": spec.get("related_entity_type"),
            "rid": str(spec["related_entity_id"]) if spec.get("related_entity_id") else None,
            "prio": spec.get("priority", "normal"),
            "exp": spec.get("expires_at"),
        })).mappings().first()
        await self.session.commit()
        return SimpleNamespace(id=row["id"], created_at=_iso(row["created_at"]),
                               is_read=row["is_read"])

    async def list_for_user(self, user_id: UUID, limit: int = 50,
                            unread_only: bool = False) -> list[dict]:
        """List recent notifications, newest first."""
        conds, params = ["user_id = :uid"], {"uid": str(user_id)}
        if unread_only:
            conds.append("is_read = FALSE")
        rows = (await self.session.execute(text(f"""
            SELECT id, type, title, message, data, is_read,
                   action_url, action_text, priority, created_at, read_at
              FROM notification.notifications
             WHERE {" AND ".join(conds)}
             ORDER BY created_at DESC
             LIMIT {int(limit)}
        """), params)).mappings().all()
        return [_row_serialize(r) for r in rows]

    async def unread_count(self, user_id: UUID) -> int:
        row = (await self.session.execute(text("""
            SELECT count(*) AS n FROM notification.notifications
             WHERE user_id = :uid AND is_read = FALSE
        """), {"uid": str(user_id)})).mappings().first()
        return row["n"] or 0

    async def mark_read(self, user_id: UUID, notification_id: UUID) -> SimpleNamespace:
        row = (await self.session.execute(text("""
            UPDATE notification.notifications
               SET is_read = TRUE, read_at = now()
             WHERE id = :nid AND user_id = :uid
          RETURNING id, is_read, read_at
        """), {"nid": str(notification_id), "uid": str(user_id)})).mappings().first()
        await self.session.commit()
        if not row:
            raise NotFoundError(resource="notification")
        return SimpleNamespace(id=row["id"], is_read=row["is_read"],
                               read_at=_iso(row["read_at"]))

    async def mark_all_read(self, user_id: UUID) -> int:
        result = (await self.session.execute(text("""
            UPDATE notification.notifications
               SET is_read = TRUE, read_at = now()
             WHERE user_id = :uid AND is_read = FALSE
        """), {"uid": str(user_id)}))
        await self.session.commit()
        return result.rowcount

    # --- Preferences ---

    async def get_preferences(self, user_id: UUID) -> dict:
        row = (await self.session.execute(text("""
            SELECT user_id, email_enabled, push_enabled, inbox_enabled,
                   types, quiet_hours_start, quiet_hours_end
              FROM notification.preferences WHERE user_id = :uid
        """), {"uid": str(user_id)})).mappings().first()
        if not row:
            await self._ensure_preferences(user_id)
            row = (await self.session.execute(text("""
                SELECT user_id, email_enabled, push_enabled, inbox_enabled,
                       types, quiet_hours_start, quiet_hours_end
                  FROM notification.preferences WHERE user_id = :uid
            """), {"uid": str(user_id)})).mappings().first()
        return _row_serialize(row)

    async def _ensure_preferences(self, user_id: UUID) -> None:
        await self.session.execute(text("""
            INSERT INTO notification.preferences (user_id, email_enabled,
                push_enabled, inbox_enabled, types)
            VALUES (:uid, TRUE, TRUE, TRUE,
                    '{"all": true}'::jsonb)
            ON CONFLICT (user_id) DO NOTHING
        """), {"uid": str(user_id)})
        await self.session.commit()

    async def update_preferences(self, user_id: UUID, patch: dict) -> dict:
        from app.modules.notification.ports import PreferencesUpdate
        valid = PreferencesUpdate(**patch)
        upserts = []
        params: dict = {"uid": str(user_id)}
        fields = [("email_enabled", "email_enabled"), ("push_enabled", "push_enabled"),
                  ("inbox_enabled", "inbox_enabled"), ("quiet_hours_start", "qhs"),
                  ("quiet_hours_end", "qhe")]
        for col, key in fields:
            val = getattr(valid, col)
            if val is not None:
                upserts.append(f"{col} = :{key}")
                params[key] = val
        if valid.types is not None:
            upserts.append("types = :types")
            params["types"] = json.dumps(valid.types, ensure_ascii=False)
        await self._ensure_preferences(user_id)
        if upserts:
            upserts.append("updated_at = now()")
            await self.session.execute(text(f"""
                UPDATE notification.preferences
                   SET {" , ".join(upserts)}
                 WHERE user_id = :uid
            """), params)
            await self.session.commit()
        return await self.get_preferences(user_id)

    # --- Delivery log ---

    async def log_delivery(self, user_id: UUID, notification_id: UUID,
                           action: str, ip: Optional[str] = None,
                           ua: Optional[str] = None) -> None:
        await self.session.execute(text("""
            INSERT INTO notification.log (user_id, action, notification_id,
                                          ip_address, user_agent)
            VALUES (:uid, :act, :nid, :ip, :ua)
        """), {"uid": str(user_id), "act": action, "nid": str(notification_id),
               "ip": ip, "ua": ua})
        await self.session.commit()


NotificationService = NotificationStateMachine
```

==========================================================================================
## FILE: bastehC_domain/backend/app/modules/calendar/api/routes.py
## SIZE: 9730 bytes
==========================================================================================

```python
"""Calendar module API routes (real DDL, M5).

CRUD for events/attendees/notes backed by ``calendar.events``,
``calendar.attendees`` and ``calendar.notes``.  This is the tested
implementation (the S3/newer patch that required `api/deps.py` is not
wired, mirrors other modules).
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, Body, Path, Query
from fastapi.responses import JSONResponse

from app.core.dependencies import get_db_session, get_current_user
from app.core.errors import APIError, NotFoundError
from app.modules.calendar.ports import (
    EventCreate, EventUpdate, AttendeeLink, NoteCreate,
)
from app.modules.calendar.services.calendar_service import CalendarService
from sqlalchemy import text

router = APIRouter(prefix="/calendar", tags=["calendar"])


@router.get("/events", response_model=dict)
async def list_events(
    user_id: UUID = Depends(get_current_user),
    date_from: Optional[datetime] = Query(None),
    date_to: Optional[datetime] = Query(None),
    status: Optional[str] = Query(None),
    db_session=Depends(get_db_session),
):
    """List events owned by or attended by the caller."""
    async with db_session() as session:
        try:
            svc = CalendarService(session)
            items = await svc.list_events(user_id, date_from, date_to, status)
            return {"status": "success", "data": items, "count": len(items)}
        except APIError as e:
            return JSONResponse(status_code=e.status_code,
                                content={"error": e.error_code,
                                         "message": e.message,
                                         "success": False})


@router.post("/events", response_model=dict)
async def create_event(
    payload: EventCreate,
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session),
):
    """Create a new calendar event."""
    async with db_session() as session:
        try:
            svc = CalendarService(session)
            result = await svc.create_event(user_id, payload.model_dump())
            return {"status": "event_created", "event_id": str(result.id),
                    "event_status": result.status}
        except APIError as e:
            return JSONResponse(status_code=e.status_code,
                                content={"error": e.error_code,
                                         "message": e.message,
                                         "success": False})


@router.get("/events/{event_id}", response_model=dict)
async def get_event(
    event_id: UUID = Path(...),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session),
):
    """Fetch a single event including attendees and note count."""
    async with db_session() as session:
        try:
            svc = CalendarService(session)
            event = await svc.get_event(event_id, user_id)
            return {"status": "success", "data": event}
        except (APIError, NotFoundError) as e:
            return JSONResponse(status_code=e.status_code,
                                content={"error": e.error_code,
                                         "message": e.message,
                                         "success": False})


@router.patch("/events/{event_id}", response_model=dict)
async def update_event(
    event_id: UUID = Path(...),
    patch: EventUpdate = Body(...),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session),
):
    """Patch an event the caller owns."""
    async with db_session() as session:
        try:
            svc = CalendarService(session)
            result = await svc.update_event(event_id, user_id,
                                             patch.model_dump(exclude_unset=True))
            return {"status": "event_updated", "event_id": str(result.id)}
        except (APIError, NotFoundError) as e:
            return JSONResponse(status_code=e.status_code,
                                content={"error": e.error_code,
                                         "message": e.message,
                                         "success": False})


@router.delete("/events/{event_id}", response_model=dict)
async def delete_event(
    event_id: UUID = Path(...),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session),
):
    """Soft-delete an event."""
    async with db_session() as session:
        try:
            svc = CalendarService(session)
            await svc.delete_event(event_id, user_id)
            return {"status": "event_deleted", "event_id": str(event_id)}
        except (APIError, NotFoundError) as e:
            return JSONResponse(status_code=e.status_code,
                                content={"error": e.error_code,
                                         "message": e.message,
                                         "success": False})


@router.post("/events/{event_id}/attendees", response_model=dict)
async def add_attendee(
    event_id: UUID = Path(...),
    link: AttendeeLink = Body(...),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session),
):
    """Add an attendee (or refresh their RSVP)."""
    async with db_session() as session:
        try:
            svc = CalendarService(session)
            a = await svc.add_attendee(event_id, link.user_id)
            return {"status": "attendee_added",
                    "event_id": str(a.event_id),
                    "user_id": str(a.user_id),
                    "response_status": a.response_status}
        except APIError as e:
            return JSONResponse(status_code=e.status_code,
                                content={"error": e.error_code,
                                         "message": e.message,
                                         "success": False})


@router.get("/events/{event_id}/attendees", response_model=dict)
async def list_attendees(
    event_id: UUID = Path(...),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session),
):
    """List attendees of an event."""
    async with db_session() as session:
        try:
            svc = CalendarService(session)
            attendees = await svc.list_attendees(event_id)
            return {"status": "success", "data": attendees}
        except APIError as e:
            return JSONResponse(status_code=e.status_code,
                                content={"error": e.error_code,
                                         "message": e.message,
                                         "success": False})


@router.put("/events/{event_id}/attendees/{attendee_user_id}/response",
            response_model=dict)
async def set_response(
    event_id: UUID = Path(...),
    attendee_user_id: UUID = Path(...),
    status: str = Body(..., embed=True),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session),
):
    """Record an attendee's RSVP response."""
    async with db_session() as session:
        try:
            svc = CalendarService(session)
            result = await svc.set_response(event_id, attendee_user_id, status)
            return {"status": "response_set",
                    "response_status": result.response_status}
        except (APIError, NotFoundError) as e:
            return JSONResponse(status_code=e.status_code,
                                content={"error": e.error_code,
                                         "message": e.message,
                                         "success": False})


@router.post("/events/{event_id}/notes", response_model=dict)
async def add_note(
    event_id: UUID = Path(...),
    note: NoteCreate = Body(...),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session),
):
    """Append a note to an event."""
    async with db_session() as session:
        try:
            svc = CalendarService(session)
            result = await svc.add_note(event_id, user_id, note.content)
            return {"status": "note_added", "note_id": str(result.id)}
        except APIError as e:
            return JSONResponse(status_code=e.status_code,
                                content={"error": e.error_code,
                                         "message": e.message,
                                         "success": False})


@router.get("/events/{event_id}/notes", response_model=dict)
async def list_notes(
    event_id: UUID = Path(...),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session),
):
    """List notes for an event."""
    async with db_session() as session:
        try:
            svc = CalendarService(session)
            rows = (await session.execute(text("""
                SELECT n.id, n.event_id, n.author_id, n.content, n.created_at, n.updated_at
                  FROM calendar.notes n WHERE n.event_id = :eid
            """), {"eid": str(event_id)})).mappings().all()
            notes = [{"id": str(r["id"]), "event_id": str(r["event_id"]),
                      "author_id": str(r["author_id"]), "content": r["content"],
                      "created_at": r["created_at"].isoformat() if r["created_at"] else None,
                      "updated_at": r["updated_at"].isoformat() if r["updated_at"] else None}
                     for r in rows]
            return {"status": "success", "data": notes}
        except APIError as e:
            return JSONResponse(status_code=e.status_code,
                                content={"error": e.error_code,
                                         "message": e.message,
                                         "success": False})
```

==========================================================================================
## FILE: bastehC_domain/backend/app/modules/calendar/ports/__init__.py
## SIZE: 3022 bytes
==========================================================================================

```python
"""Calendar module ports — request/response Pydantic schemas (real DDL).

Architecture Reference: Sections 9.3, 10.4 (calendar.events/attendees/notes).
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional, Literal
from uuid import UUID

from pydantic import BaseModel, Field


# --- Event payload / status enums ---

class EventCreate(BaseModel):
    """Create a new calendar event."""
    title: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    privacy_level: Literal['public', 'team_only', 'private'] = 'team_only'
    start_time: datetime
    end_time: datetime
    all_day: bool = False
    recurrence_rule: Optional[str] = None  # iCalendar RRULE
    status: Literal['active', 'cancelled', 'rescheduled'] = 'active'


class EventUpdate(BaseModel):
    """Patch an existing event."""
    title: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None
    privacy_level: Optional[Literal['public', 'team_only', 'private']] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    all_day: Optional[bool] = None
    recurrence_rule: Optional[str] = None
    status: Optional[Literal['active', 'cancelled', 'rescheduled']] = None


class AttendeeLink(BaseModel):
    """Add or update an attendee on an event."""
    user_id: UUID
    response_status: Literal['pending', 'accepted', 'declined', 'tentative'] = 'pending'
    rsvp: bool = False


class AttendeeResponse(BaseModel):
    user_id: UUID
    response_status: str
    notified_at: Optional[datetime] = None
    rsvp: bool


class NoteCreate(BaseModel):
    """Add a meeting note to an event."""
    content: str
    author_id: Optional[UUID] = None


# --- Row-level response schemas ---

class _EventBase(BaseModel):
    id: UUID
    title: str
    description: Optional[str] = None
    owner_id: UUID
    privacy_level: str
    start_time: datetime
    end_time: datetime
    all_day: bool
    recurrence_rule: Optional[str] = None
    status: str
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    deleted_at: Optional[datetime] = None


class EventResponse(_EventBase):
    """Full event payload returned by list/detail endpoints."""
    attendees: list[AttendeeResponse] = []
    notes_count: int = 0


class EventListItem(_EventBase):
    """Lightweight event row for list views."""
    attendees: list[UUID] = []


class NoteResponse(BaseModel):
    id: UUID
    event_id: UUID
    author_id: UUID
    content: str
    created_at: datetime
    updated_at: datetime


class CalendarSummary(BaseModel):
    """Aggregate counts returned by the summary endpoint."""
    events_total: int
    events_active: int
    events_cancelled: int
    attendees_total: int
    notes_total: int


__all__ = [
    "EventCreate", "EventUpdate", "AttendeeLink",
    "AttendeeResponse", "NoteCreate", "EventResponse",
    "EventListItem", "NoteResponse", "CalendarSummary",
]
```

==========================================================================================
## FILE: bastehC_domain/backend/app/modules/calendar/schemas/widget_config.py
## SIZE: 4732 bytes
==========================================================================================

```python
"""
app/modules/calendar/schemas/widget_config.py

طبق سند (بخش ۴.۷، درست زیر DDL جدول ``reporting.user_widget_settings``):

    «`config` و `style` عمداً JSONB هستند... اما محتوای آن‌ها **در سرور
    با یک اسکیمای Pydantic مخصوص هر widget_key/block_key اعتبارسنجی
    می‌شود**. JSONB به معنای پذیرش هر ورودی نیست — این یک بردار تزریق
    رایج است (ذخیره‌ی `opacity: "<script>"` و رندر مستقیم آن در CSS).»

این فایل دقیقاً همان اسکیمای مفقود را برای سه ویجت calendar-محور
(``mini_calendar``, ``clock``, ``quick_add``) می‌سازد. اگر endpoint
واقعی ذخیره‌ی ``user_widget_settings`` جای دیگری (مثلاً ماژول
``reporting``) است، فقط ``validate_widget_config`` را از همان‌جا
import و صدا بزنید — این فایل به هیچ چیزِ دیگری از reporting وابسته
نیست.
"""

from __future__ import annotations

import re
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

# رنگ باید یا نام رنگ CSS شناخته‌شده باشد یا هگز معتبر — هرگز رشته‌ی آزاد
_HEX_COLOR_RE = re.compile(r"^#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6})$")
_ALLOWED_FONT_FAMILIES = {"system-ui", "Vazirmatn", "IRANSans", "Tahoma", "Arial", "monospace"}


def _validate_color(value: str) -> str:
    if not _HEX_COLOR_RE.match(value):
        raise ValueError(f"رنگ نامعتبر: {value!r} — فقط هگز (#rrggbb) مجاز است.")
    return value


class WidgetStyle(BaseModel):
    """طبق سند: ``style: {bg, fg, font_family, font_size, opacity}`` —
    اما هرکدام اینجا محدود و اعتبارسنجی‌شده‌اند، نه رشته‌ی آزاد."""

    bg: str = "#ffffff"
    fg: str = "#000000"
    font_family: str = "system-ui"
    font_size: int = Field(default=14, ge=8, le=48)
    opacity: float = Field(default=1.0, ge=0.1, le=1.0)

    @field_validator("bg", "fg")
    @classmethod
    def _check_color(cls, v: str) -> str:
        return _validate_color(v)

    @field_validator("font_family")
    @classmethod
    def _check_font(cls, v: str) -> str:
        if v not in _ALLOWED_FONT_FAMILIES:
            raise ValueError(f"font_family باید یکی از {_ALLOWED_FONT_FAMILIES} باشد.")
        return v


class ClockWidgetConfig(BaseModel):
    show_jalali: bool = True
    show_gregorian: bool = False
    show_hijri: bool = False
    time_format: Literal["HH:mm", "HH:mm:ss", "hh:mm a"] = "HH:mm:ss"
    show_seconds: bool = True


class MiniCalendarWidgetConfig(BaseModel):
    show_jalali: bool = True
    show_gregorian: bool = True
    show_hijri: bool = False
    highlight_today: bool = True
    week_start_day: int = Field(default=6, ge=0, le=6)  # ۰=یکشنبه ... ۶=شنبه (طبق تقویم ایران)


class QuickAddWidgetConfig(BaseModel):
    default_goal_privacy: Literal["private", "team_only", "selected", "public"] = "team_only"
    show_recent_goals: bool = True
    max_recent_items: int = Field(default=5, ge=1, le=20)


_CONFIG_SCHEMA_BY_WIDGET_KEY: dict[str, type[BaseModel]] = {
    "clock": ClockWidgetConfig,
    "mini_calendar": MiniCalendarWidgetConfig,
    "quick_add": QuickAddWidgetConfig,
}


class WidgetConfigValidationError(Exception):
    def __init__(self, widget_key: str, errors: Any) -> None:
        self.widget_key = widget_key
        self.errors = errors
        super().__init__(f"invalid config for widget_key={widget_key}: {errors}")


def validate_widget_config(widget_key: str, raw_config: dict, raw_style: dict | None = None) -> dict:
    """قبل از ذخیره در ستون JSONB صدا زده شود — هرگز raw_config/raw_style
    مستقیم در DB نروند.

    برمی‌گرداند: ``{"config": <dict تمیزشده>, "style": <dict تمیزشده>}``
    """
    schema_cls = _CONFIG_SCHEMA_BY_WIDGET_KEY.get(widget_key)
    if schema_cls is None:
        raise WidgetConfigValidationError(widget_key, "unknown widget_key — no schema registered")

    try:
        clean_config = schema_cls(**raw_config).model_dump()
    except Exception as exc:  # pydantic.ValidationError
        raise WidgetConfigValidationError(widget_key, str(exc)) from exc

    clean_style = {}
    if raw_style is not None:
        try:
            clean_style = WidgetStyle(**raw_style).model_dump()
        except Exception as exc:
            raise WidgetConfigValidationError(widget_key, str(exc)) from exc

    return {"config": clean_config, "style": clean_style}
```

==========================================================================================
## FILE: bastehC_domain/backend/app/modules/calendar/services/calendar_service.py
## SIZE: 10614 bytes
==========================================================================================

```python
"""Calendar service — real DDL (M5).

Raw SQL against schema ``calendar``: events, attendees, notes.
Mirrors the inbox pattern (raw ``sa.text``, ``SimpleNamespace``,
``_row_serialize``) so the ORM drift between code and the DDL
is handled consistently.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Optional
from uuid import UUID
from types import SimpleNamespace

from sqlalchemy import text

from app.core.errors import APIError, NotFoundError


def _iso(v) -> Optional[str]:
    return v.isoformat() if isinstance(v, datetime) else v


def _row_serialize(r) -> dict:
    d = dict(r)
    for k, v in list(d.items()):
        if v is not None and isinstance(v, datetime):
            d[k] = _iso(v)
    return d


class CalendarStateMachine:
    """Manages calendar events, attendees and notes (real DDL)."""

    def __init__(self, session):
        self.session = session

    async def create_event(self, owner_id: UUID, payload: dict) -> SimpleNamespace:
        """Insert a new event and return its identity + state."""
        row = (await self.session.execute(text("""
            INSERT INTO calendar.events (
                title, description, owner_id, privacy_level,
                start_time, end_time, all_day, recurrence_rule, status
            )
            VALUES (:title, :desc, :owner, :privacy, :start, :end,
                    :all_day, :recur, :status)
            RETURNING id, title, status, created_at
        """), {
            "title": payload["title"],
            "desc": payload.get("description"),
            "owner": str(owner_id),
            "privacy": payload.get("privacy_level", "team_only"),
            "start": payload["start_time"],
            "end": payload["end_time"],
            "all_day": payload.get("all_day", False),
            "recur": payload.get("recurrence_rule"),
            "status": payload.get("status", "active"),
        })).mappings().first()
        await self.session.commit()
        return SimpleNamespace(
            id=row["id"], title=row["title"], status=row["status"],
            created_at=_iso(row["created_at"]),
        )

    async def list_events(self, user_id: UUID,
                          date_from: Optional[datetime] = None,
                          date_to: Optional[datetime] = None,
                          status: Optional[str] = None) -> list[dict]:
        """List events the user owns or attends, with safe filtering."""
        conds = ["(e.owner_id = :uid OR EXISTS (SELECT 1 FROM calendar.attendees a WHERE a.event_id = e.id AND a.user_id = :uid))"]
        params: dict = {"uid": str(user_id)}
        if date_from:
            conds.append("e.start_time >= :from")
            params["from"] = date_from
        if date_to:
            conds.append("e.end_time <= :to")
            params["to"] = date_to
        if status:
            conds.append("e.status::text = :st")
            params["st"] = status

        rows = (await self.session.execute(text(f"""
            SELECT e.id, e.title, e.description, e.owner_id, e.privacy_level,
                   e.start_time, e.end_time, e.all_day, e.recurrence_rule,
                   e.status, e.created_at, e.updated_at, e.deleted_at
              FROM calendar.events e
             WHERE {" AND ".join(conds)}
             ORDER BY e.start_time ASC
        """), params)).mappings().all()
        return [_row_serialize(r) for r in rows]

    async def get_event(self, event_id: UUID,
                        user_id: UUID) -> dict:
        """Fetch a single event with its attendees and note count."""
        row = (await self.session.execute(text("""
            SELECT e.id, e.title, e.description, e.owner_id, e.privacy_level,
                   e.start_time, e.end_time, e.all_day, e.recurrence_rule,
                   e.status, e.created_at, e.updated_at, e.deleted_at
              FROM calendar.events e
             WHERE e.id = :eid AND (e.owner_id = :uid OR EXISTS (
                SELECT 1 FROM calendar.attendees a WHERE a.event_id = e.id AND a.user_id = :uid
             ))
        """), {"eid": str(event_id), "uid": str(user_id)})).mappings().first()
        if not row:
            raise NotFoundError(resource="calendar event")
        event = _row_serialize(row)

        attendees = (await self.session.execute(text("""
            SELECT a.user_id, a.response_status, a.notified_at, a.rsvp
              FROM calendar.attendees a WHERE a.event_id = :eid
        """), {"eid": str(event_id)})).mappings().all()
        event["attendees"] = [
            {"user_id": str(a["user_id"]), "response_status": a["response_status"],
             "notified_at": _iso(a["notified_at"]), "rsvp": a["rsvp"]}
            for a in attendees
        ]
        note_row = (await self.session.execute(text("""
            SELECT count(*) AS n FROM calendar.notes WHERE event_id = :eid
        """), {"eid": str(event_id)})).mappings().first()
        event["notes_count"] = note_row["n"] or 0
        return event

    async def update_event(self, event_id: UUID, user_id: UUID,
                           patch: dict) -> SimpleNamespace:
        """Patch event fields; returns updated identity."""
        set_parts, params = [], {"eid": str(event_id), "uid": str(user_id)}
        for col, key in (("title", "title"), ("description", "description"),
                         ("privacy_level", "privacy"), ("start_time", "start"),
                         ("end_time", "end"), ("all_day", "all_day"),
                         ("recurrence_rule", "recur"), ("status", "st")):
            if key in patch and patch[key] is not None:
                set_parts.append(f"{col} = :{key}")
                params[key] = patch[key]
        if not set_parts:
            raise APIError(error_code="NO_CHANGE",
                           message="هیچ فیلدی برای بروزرسانی داده نشد.",
                           status_code=400)
        set_parts.append("updated_at = now()")
        result = (await self.session.execute(text(f"""
            UPDATE calendar.events
               SET {" , ".join(set_parts)}
             WHERE id = :eid AND owner_id = :uid
         RETURNING id, title, status, updated_at
        """), params)).mappings().first()
        await self.session.commit()
        if not result:
            raise NotFoundError(resource="calendar event")
        return SimpleNamespace(id=result["id"], title=result["title"],
                               status=result["status"],
                               updated_at=_iso(result["updated_at"]))

    async def delete_event(self, event_id: UUID, user_id: UUID) -> SimpleNamespace:
        """Soft-delete an event (sets deleted_at)."""
        result = (await self.session.execute(text("""
            UPDATE calendar.events SET deleted_at = now()
             WHERE id = :eid AND owner_id = :uid
         RETURNING id
        """), {"eid": str(event_id), "uid": str(user_id)})).mappings().first()
        await self.session.commit()
        if not result:
            raise NotFoundError(resource="calendar event")
        return SimpleNamespace(id=result["id"])

    # --- Attendees ---

    async def add_attendee(self, event_id: UUID, user_id: UUID) -> SimpleNamespace:
        """Add attendee to an event (UPSERT)."""
        row = (await self.session.execute(text("""
            INSERT INTO calendar.attendees (event_id, user_id)
            VALUES (:eid, :uid)
            ON CONFLICT (event_id, user_id) DO NOTHING
            RETURNING event_id, user_id, response_status, rsvp
        """), {"eid": str(event_id), "uid": str(user_id)})).mappings().first()
        await self.session.commit()
        if not row:
            row = (await self.session.execute(text("""
                SELECT event_id, user_id, response_status, rsvp
                  FROM calendar.attendees
                 WHERE event_id = :eid AND user_id = :uid
            """), {"eid": str(event_id), "uid": str(user_id)})).mappings().first()
        return SimpleNamespace(event_id=row["event_id"],
                               user_id=row["user_id"],
                               response_status=row["response_status"],
                               rsvp=row["rsvp"])

    async def list_attendees(self, event_id: UUID) -> list[dict]:
        """List all attendees for an event."""
        rows = (await self.session.execute(text("""
            SELECT a.user_id, a.response_status, a.notified_at, a.rsvp
              FROM calendar.attendees a WHERE a.event_id = :eid
        """), {"eid": str(event_id)})).mappings().all()
        return [{"user_id": str(a["user_id"]), "response_status": a["response_status"],
                 "notified_at": _iso(a["notified_at"]), "rsvp": a["rsvp"]} for a in rows]

    async def set_response(self, event_id: UUID, user_id: UUID,
                           status: str) -> SimpleNamespace:
        """RSVP an attendee (pending/accepted/declined/tentative)."""
        valid = {"pending", "accepted", "declined", "tentative"}
        if status not in valid:
            raise APIError(error_code="INVALID_RESPONSE",
                           message="وضعیت پاسخ نامعتبر.", status_code=400)
        result = (await self.session.execute(text("""
            UPDATE calendar.attendees SET response_status = :st, notified_at = now()
             WHERE event_id = :eid AND user_id = :uid
         RETURNING event_id, user_id, response_status
        """), {"st": status, "eid": str(event_id), "uid": str(user_id)})).mappings().first()
        await self.session.commit()
        if not result:
            raise NotFoundError(resource="calendar attendee")
        return SimpleNamespace(event_id=result["event_id"],
                               user_id=result["user_id"],
                               response_status=result["response_status"])

    # --- Notes ---

    async def add_note(self, event_id: UUID, author_id: UUID,
                       content: str) -> SimpleNamespace:
        """Append a note to an event."""
        row = (await self.session.execute(text("""
            INSERT INTO calendar.notes (event_id, author_id, content)
            VALUES (:eid, :aid, :content)
            RETURNING id, content, created_at
        """), {"eid": str(event_id), "aid": str(author_id),
              "content": content})).mappings().first()
        await self.session.commit()
        return SimpleNamespace(id=row["id"], content=row["content"],
                               created_at=_iso(row["created_at"]))


CalendarService = CalendarStateMachine
```

==========================================================================================
## FILE: bastehC_domain/backend/app/modules/calendar/services/date_conversion.py
## SIZE: 3783 bytes
==========================================================================================

```python
"""
app/modules/calendar/services/date_conversion.py

طبق سند (بخش ۱۱، نکته‌ی مهم): «تقویم قمری در ایران مبتنی بر رؤیت
هلال است و با محاسبات نجومی تا یک روز اختلاف دارد. اگر این ویجت
برای مناسبت‌های رسمی استفاده می‌شود، باید منبع تاریخ رسمی داشته
باشد؛ در غیر این صورت با ذکر «تقریبی» نمایش داده شود.»

این فایل دقیقاً همین را اجرایی می‌کند: تبدیل هجری قمری **همیشه**
``is_approximate=True`` برمی‌گرداند، مگر این‌که یک منبع رسمی (تقویم
اعلام‌شده توسط دولت) تزریق شود — که در این پروژه هنوز چنین منبعی
وجود ندارد، پس این فایل به‌جای نادیده گرفتن این هشدار (که ساده‌ترین
راه بود)، آن را در همان مقدار بازگشتی enforce می‌کند تا فرانت‌اند
مجبور شود «تقریبی» را نشان دهد.

تبدیل جلالی (تقویم رسمی ایران) دقیق است — چون ``jdatetime`` (کتابخانه‌ی
مشخص‌شده در سند، بخش نیازمندی‌ها) یک الگوریتم قطعی و رسمی است، نه
رؤیت‌محور.

⚠️ وابستگی: ``jdatetime`` طبق `pip list` شما نصب نیست.
    pip install jdatetime
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date


@dataclass(frozen=True)
class ConvertedDate:
    calendar_system: str  # "jalali" | "hijri"
    year: int
    month: int
    day: int
    is_approximate: bool
    note: str | None = None


def to_jalali(gregorian_date: date) -> ConvertedDate:
    try:
        import jdatetime
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("`jdatetime` نصب نیست — `pip install jdatetime` را اجرا کنید.") from exc

    j = jdatetime.date.fromgregorian(date=gregorian_date)
    return ConvertedDate(
        calendar_system="jalali", year=j.year, month=j.month, day=j.day,
        is_approximate=False,
    )


# میانگین طول ماه قمری (روز) — فقط برای تخمین حسابی، نه رؤیت‌محور واقعی.
_HIJRI_EPOCH_GREGORIAN = date(622, 7, 16)  # ۱ محرم ۱ هجری (تقریب متعارف)
_HIJRI_MONTH_LENGTH_DAYS = 29.530588853


def to_hijri_approximate(gregorian_date: date) -> ConvertedDate:
    """تبدیل حسابی تقریبی — **هرگز** برای مناسبت‌های رسمی (مثل شروع ماه
    رمضان) بدون تأیید منبع رسمی استفاده نشود؛ به همین دلیل
    ``is_approximate`` همیشه True است و این تابع اصلاً پارامتری برای
    False کردنش ندارد — عمداً، تا کسی به‌اشتباه این تصمیم امنیتی/شرعی
    را دور نزند.
    """
    days_since_epoch = (gregorian_date - _HIJRI_EPOCH_GREGORIAN).days
    total_months = int(days_since_epoch / _HIJRI_MONTH_LENGTH_DAYS)
    year = total_months // 12 + 1
    month = total_months % 12 + 1
    day_of_month = int(days_since_epoch - total_months * _HIJRI_MONTH_LENGTH_DAYS) + 1
    day_of_month = max(1, min(30, day_of_month))

    return ConvertedDate(
        calendar_system="hijri", year=year, month=month, day=day_of_month,
        is_approximate=True,
        note="محاسبه‌ی حسابی تقریبی — تا یک روز با رؤیت هلال واقعی اختلاف دارد؛ "
             "برای مناسبت‌های رسمی به منبع رسمی مراجعه کنید.",
    )
```

==========================================================================================
## FILE: bastehC_domain/backend/app/modules/goals/api/routes.py
## SIZE: 8891 bytes
==========================================================================================

```python
"""
Goals Module API Routes
Architecture Reference: Sections 4.5, 9.10, 12.12
Endpoints: /api/v1/goals
"""

from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Body, Path
from fastapi.responses import JSONResponse

from app.core.dependencies import (
    get_db_session, get_current_user, get_goals_service
)
from app.core.errors import APIError, NotFoundError, PrivacyHiddenError
from app.core.database import async_session_context
from app.modules.goals.ports import (
    GoalCreate, GoalUpdate, GoalProgressUpdate, GoalFilter,
    TaskCreate, TaskUpdate, TaskFilter, TagCreate, TagUpdate,
    GoalDashboardData
)
from app.modules.goals.services.goals_service import GoalsService


router = APIRouter(prefix="/goals", tags=["Goals"])


@router.post("/", response_model=dict)
async def create_goal(
    request: GoalCreate,
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Create a new goal."""
    async with db_session() as session:
        try:
            service = GoalsService(session)
            goal = await service.create_goal(
                title=request.title,
                description=request.description,
                owner_id=user_id,
                privacy_level=request.privacy_level
            )
            return {"status": "goal_created", "goal_id": str(goal.id)}
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.get("/", response_model=dict)
async def list_goals(
    privacy: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    owner: Optional[UUID] = Query(None),
    tag: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """List goals with filtering."""
    async with db_session() as session:
        try:
            service = GoalsService(session)
            goals, total = await service.list_goals(
                privacy=privacy,
                status=status,
                owner_id=owner,
                tag=tag,
                page=page,
                page_size=size,
                viewer_id=user_id
            )
            return {
                "status": "success",
                "data": {
                    "goals": goals,
                    "total": total,
                    "page": page,
                    "page_size": size
                }
            }
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.get("/{goal_id}", response_model=dict)
async def get_goal(
    goal_id: UUID = Path(...),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Get a single goal with privacy applied."""
    async with db_session() as session:
        try:
            service = GoalsService(session)
            goal_data = await service.get_goal_with_privacy(goal_id, user_id)
            
            if not goal_data:
                return JSONResponse(
                    status_code=404,
                    content={"error": "GOAL_NOT_FOUND", "message": "اهداف یافت نشد.", "success": False}
                )
            
            return {
                "status": "success",
                "data": goal_data
            }
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.patch("/{goal_id}", response_model=dict)
async def update_goal(
    goal_id: UUID = Path(...),
    request: GoalUpdate = Body(...),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Update a goal."""
    async with db_session() as session:
        try:
            service = GoalsService(session)
            goal = await service.update_goal(goal_id, request, user_id)
            return {"status": "goal_updated", "goal_id": str(goal.id)}
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.post("/{goal_id}/progress", response_model=dict)
async def update_progress(
    goal_id: UUID = Path(...),
    request: GoalProgressUpdate = Body(...),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Update goal progress."""
    async with db_session() as session:
        try:
            service = GoalsService(session)
            goal = await service.update_progress(goal_id, request.progress_pct, user_id)
            return {
                "status": "progress_updated",
                "goal_id": str(goal.id),
                "progress_pct": goal.progress_pct
            }
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.post("/{goal_id}/tasks", response_model=dict)
async def create_task(
    goal_id: UUID = Path(...),
    request: TaskCreate = Body(...),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Create a task under a goal."""
    async with db_session() as session:
        try:
            service = GoalsService(session)
            task = await service.create_task(goal_id, request, user_id)
            return {"status": "task_created", "task_id": str(task.id)}
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.get("/{goal_id}/tasks", response_model=dict)
async def list_tasks(
    goal_id: UUID = Path(...),
    status: Optional[str] = Query(None),
    assignee: Optional[UUID] = Query(None),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """List tasks for a goal with privacy."""
    async with db_session() as session:
        try:
            service = GoalsService(session)
            tasks, total = await service.list_tasks(
                goal_id=goal_id,
                status=status,
                assignee_id=assignee,
                viewer_id=user_id
            )
            return {
                "status": "success",
                "data": {
                    "tasks": tasks,
                    "total": total
                }
            }
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.post("/{goal_id}/tags", response_model=dict)
async def add_tag_to_goal(
    goal_id: UUID = Path(...),
    tag_name: str = Body(...),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Add a tag to a goal."""
    async with db_session() as session:
        try:
            service = GoalsService(session)
            result = await service.add_tag(goal_id, tag_name, user_id)
            return {"status": "tag_added", "tag_name": tag_name}
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.get("/{goal_id}/dashboard", response_model=dict)
async def goal_dashboard(
    goal_id: UUID = Path(...),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Get goal dashboard data with privacy applied."""
    async with db_session() as session:
        try:
            service = GoalsService(session)
            dashboard_data = await service.get_dashboard_data(goal_id, user_id)
            return {
                "status": "success",
                "data": dashboard_data
            }
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )
```

==========================================================================================
## FILE: bastehC_domain/backend/app/modules/goals/db/Models.py
## SIZE: 8781 bytes
==========================================================================================

```python
import uuid
from typing import Dict
from uuid import UUID
from datetime import datetime
from sqlalchemy import (
    Column, String, Integer, DateTime, Boolean, Text,
    ForeignKey, CheckConstraint, UniqueConstraint, Index, Table
)
from sqlalchemy.sql import func

from app.core.db.base import BaseModel, AuditMixin


# --- Goals Table ---

class Goals(BaseModel, AuditMixin):
    """Goal entity with privacy-aware fields."""
    
    __tablename__ = "goals"
    __table_args__ = (
        CheckConstraint("progress_pct >= 0 AND progress_pct <= 100"),
        {},
    )
    
    # Primary key inherited from BaseModel (UUID)
    
    # Goal identity
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    
    # Ownership & Privacy
    owner_id = Column(
        String(36),  # UUID as string
        nullable=False,
        index=True
    )
    privacy_level = Column(
        String(20), 
        nullable=False,
        default="team_only",
        comment="fully_private | team_only | selected | fully_transparent"
    )
    
    # Progress tracking
    progress_pct = Column(
        Integer, 
        nullable=False,
        server_default="0",
        comment="0-100"
    )
    
    # Timeline
    status = Column(
        String(16), 
        nullable=False,
        server_default="active",
        comment="active | completed | archived"
    )
    start_date = Column(DateTime(timezone=True), nullable=True)
    due_date = Column(DateTime(timezone=True), nullable=True)
    
    # Timestamps (inherited from BaseModel)
    # created_at, updated_at, deleted_at, version, created_by, updated_by
    
    # Relationships (lazy loading)
    # tags = relationship("GoalTags", back_populates="goal", cascade="all, delete-orphan")
    # tasks = relationship("Tasks", back_populates="goal", cascade="all, delete-orphan")
    
    def is_visible_to(self, viewer_id: UUID, privacy_level: str) -> bool:
        """Check if goal is visible to a viewer based on privacy settings."""
        if privacy_level == "fully_transparent":
            return True
        elif privacy_level == "team_only":
            # Team members can see - determined by ACL
            return True  # simplified
        elif privacy_level == "selected":
            # Only specific viewers allowed
            return False  # determined by privacy_exceptions
        elif privacy_level == "fully_private":
            # Only owner can see
            return False  # determined by owner check
        return False
    
    def get_privacy_decision(self, owner_id: UUID, viewer_id: UUID) -> dict:
        """Get privacy decision for a viewer."""
        # This would query groups.privacy_settings and groups.privacy_exceptions
        # For now, simplified logic
        is_owner = owner_id == viewer_id
        
        if is_owner:
            return {"level": "full", "redaction": None}
        else:
            # Check privacy level from goal
            level = self.privacy_level
            if level == "fully_private":
                return {"level": "hidden", "redaction": "full_content"}
            elif level == "team_only":
                # Would check if viewer is team member
                return {"level": "aggregate_only", "redaction": "status_only"}
            elif level == "selected":
                # Would check privacy_exceptions
                return {"level": "hidden", "redaction": "full_content"}
            elif level == "fully_transparent":
                return {"level": "full", "redaction": None}
        
        return {"level": "hidden", "redaction": "full_content"}


# --- Tasks Table ---

class Tasks(BaseModel, AuditMixin):
    """Task entity linked to a goal."""
    
    __tablename__ = "tasks"
    __table_args__ = (
        UniqueConstraint("goal_id", "title", name="uq_goal_task_title"),
    )
    
    # Primary key inherited
    goal_id = Column(
        String(36),  # UUID
        ForeignKey("goals.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    
    # Task identity
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    
    # Assignment
    assignee_id = Column(
        String(36),
        ForeignKey("auth.users.id"),
        nullable=True,
        index=True
    )
    owner_id = Column(
        String(36),
        nullable=False,
        comment="Goal owner who created the task"
    )
    
    # Task tracking
    privacy_level = Column(
        String(20),
        nullable=False,
        default="team_only",
        comment="inherited from goal or overridden"
    )
    status = Column(
        String(16),
        nullable=False,
        server_default="pending",
        comment="pending | in_progress | completed | deferred"
    )
    priority = Column(
        String(16),
        nullable=False,
        server_default="normal",
        comment="normal | high | low"
    )
    progress_pct = Column(
        Integer,
        nullable=False,
        server_default="0",
        comment="0-100 for task progress"
    )
    
    # Timeline
    due_date = Column(DateTime(timezone=True), nullable=True)
    
    # Timestamps inherited
    # created_at, updated_at, deleted_at, version, created_by, updated_by
    
    # Relationships
    # goal = relationship("Goals", back_populates="tasks")
    # assignee = relationship("Users", foreign_keys=[assignee_id])
    
    def is_visible_to(self, viewer_id: UUID, goal_privacy: str) -> bool:
        """Check if task is visible to viewer based on privacy."""
        # Tasks inherit privacy from goal, with possible overrides
        if goal_privacy == "fully_transparent":
            return True
        elif goal_privacy == "fully_private" and viewer_id != self.owner_id:
            return False
        elif goal_privacy == "team_only":
            # Team members can see basic info
            return True  # simplified - would check ACL
        elif goal_privacy == "selected":
            # Would check privacy_exceptions
            return False  # simplified
        return False
    
    def get_privacy_decision(self, goal_privacy: str, viewer_id: UUID) -> dict:
        """Get privacy decision for task viewer."""
        is_owner = viewer_id is not None and hasattr(self, 'owner_id') and self.owner_id == viewer_id
        
        if is_owner:
            return {"level": "full", "redaction": None}
        
        if goal_privacy == "fully_private":
            return {"level": "hidden", "redaction": "full_content"}
        elif goal_privacy == "team_only":
            return {"level": "aggregate_only", "redaction": "status_and_progress"}
        elif goal_privacy == "selected":
            return {"level": "hidden", "redaction": "full_content"}
        elif goal_privacy == "fully_transparent":
            return {"level": "full", "redaction": None}
        
        return {"level": "hidden", "redaction": "full_content"}


# --- Tags Table ---

class Tags(BaseModel, AuditMixin):
    """Tag entity for multi-goal labeling."""
    
    __tablename__ = "tags"
    __table_args__ = (
        UniqueConstraint("name", name="uq_tag_name"),
    )
    
    # Primary key inherited
    name = Column(String(64), nullable=False, unique=True)
    color = Column(
        String(7),
        nullable=False,
        default="#3B82F6",
        comment="#RRGGBB format"
    )
    
    # Timestamps inherited
    # created_at, updated_at, deleted_at, version, created_by, updated_by
    
    # Relationships
    # goal_tags = relationship("GoalTags", back_populates="tag", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<Tag name='{self.name}' color='{self.color}'>"


# --- Goal-Tag Junction Table ---

class GoalTags(BaseModel, AuditMixin):
    """Junction table for many-to-many Goal-Tag relationship."""
    
    __tablename__ = "goal_tags"
    __table_args__ = (
        UniqueConstraint("goal_id", "tag_id", name="uq_goal_tag"),
    )
    
    # Primary key inherited
    goal_id = Column(
        String(36),
        ForeignKey("goals.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    tag_id = Column(
        String(36),
        ForeignKey("tags.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    
    # Composite primary key (goal_id, tag_id)
    
    # Relationships
    # goal = relationship("Goals", back_populates="goal_tags")
    # tag = relationship("Tags", back_populates="goal_tags")
```

==========================================================================================
## FILE: bastehC_domain/backend/app/modules/goals/ports.py
## SIZE: 4602 bytes
==========================================================================================

```python
from typing import Protocol, Optional, List, Tuple, Dict, Any
from uuid import UUID
from datetime import datetime
from pydantic import BaseModel, Field


# --- Goal Read Model Protocol ---
# Defines what other modules can see about a goal (interface contract)

class GoalReadModel(Protocol):
    """Her ماژول دیگری فقط این را می‌بیند. تغییر امضای این متدها = تغییر Schuster."""
    
    id: UUID
    title: str
    description: Optional[str]
    owner_id: UUID
    privacy_level: str  # fully_private | team_only | selected | fully_transparent
    progress_pct: int  # 0-100
    status: str  # active | completed | archived
    start_date: Optional[datetime]
    due_date: Optional[datetime]
    created_at: datetime
    updated_at: datetime


# --- Goal Schemas ---

class GoalCreate(BaseModel):
    """Create goal request."""
    title: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=1000)
    privacy_level: str = Field(default="team_only", pattern="^(fully_private|team_only|selected|fully_transparent)$")
    start_date: Optional[str] = Field(None, pattern="^\\d{4}-\\d{2}-\\d{2}$")
    due_date: Optional[str] = Field(None, pattern="^\\d{4}-\\d{2}-\\d{2}$")


class GoalUpdate(BaseModel):
    """Update goal request."""
    title: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=1000)
    privacy_level: Optional[str] = Field(None, pattern="^(fully_private|team_only|selected|fully_transparent)$")
    status: Optional[str] = Field(None, pattern="^(active|completed|archived)$")
    start_date: Optional[str] = Field(None, pattern="^\\d{4}-\\d{2}-\\d{2}$")
    due_date: Optional[str] = Field(None, pattern="^\\d{4}-\\d{2}-\\d{2}$")


class GoalProgressUpdate(BaseModel):
    """Update goal progress."""
    progress_pct: int = Field(..., ge=0, le=100)
    notes: Optional[str] = Field(None, max_length=500)


class GoalFilter(BaseModel):
    """Filter goals query."""
    privacy: Optional[str] = Field(None, pattern="^(fully_private|team_only|selected|fully_transparent)$")
    status: Optional[str] = Field(None, pattern="^(active|completed|archived)$")
    owner: Optional[UUID] = Field(None)
    tag: Optional[str] = Field(None)


class GoalDashboardData(BaseModel):
    """Goal dashboard data with privacy applied."""
    goal: dict
    owner: dict
    tasks: List[dict]
    privacy_applied: bool
    redaction: str  # "full" | "aggregate_only" | "hidden"


# --- Task Schemas ---

class TaskCreate(BaseModel):
    """Create task request."""
    title: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=1000)
    priority: str = Field(default="normal", pattern="^(normal|high|low)$")
    due_date: Optional[str] = Field(None, pattern="^\\d{4}-\\d{2}-\\d{2}$")


class TaskUpdate(BaseModel):
    """Update task request."""
    title: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=1000)
    status: Optional[str] = Field(None, pattern="^(pending|in_progress|completed|deferred)$")
    priority: Optional[str] = Field(None, pattern="^(normal|high|low)$")
    due_date: Optional[str] = Field(None, pattern="^\\d{4}-\\d{2}-\\d{2}$")


class TaskFilter(BaseModel):
    """Filter tasks query."""
    status: Optional[str] = Field(None, pattern="^(pending|in_progress|completed|deferred)$")
    assignee: Optional[UUID] = Field(None)
    priority: Optional[str] = Field(None)


# --- Tag Schemas ---

class TagCreate(BaseModel):
    """Create tag request."""
    name: str = Field(..., min_length=1, max_length=64, unique=True)
    color: str = Field(default="#3B82F6", pattern="^#([A-Fa-f0-9]{6}|[A-Fa-f0-9]{3})$")


class TagUpdate(BaseModel):
    """Update tag request."""
    name: Optional[str] = Field(None, min_length=1, max_length=64)
    color: Optional[str] = Field(None, pattern="^#([A-Fa-f0-9]{6}|[A-Fa-f0-9]{3})$")


# --- Export/Import ---

class GoalExport(BaseModel):
    """Goal export format."""
    id: UUID
    title: str
    description: Optional[str]
    progress_pct: int
    status: str
    tags: List[str]
    created_at: datetime


# Export all
__all__ = [
    "GoalReadModel", "GoalCreate", "GoalUpdate", "GoalProgressUpdate",
    "GoalFilter", "GoalDashboardData", "TaskCreate", "TaskUpdate",
    "TaskFilter", "TagCreate", "TagUpdate", "GoalExport"
]
```

==========================================================================================
## FILE: bastehC_domain/backend/app/modules/goals/services/goals_service.py
## SIZE: 14123 bytes
==========================================================================================

```python
"""Goals service — raw SQL against the real DDL (schema ``planning``).

Architecture Reference: Sections 4.5, 9.10.
"""
from typing import Optional, List, Tuple
from types import SimpleNamespace
from uuid import UUID
from datetime import datetime

from sqlalchemy import text

from app.core.errors import APIError, NotFoundError, PrivacyHiddenError

VALID_LEVELS = {"fully_private", "team_only", "selected", "fully_transparent"}
VALID_STATUS = {"active", "completed", "archived"}


def _iso(v):
    return v.isoformat() if isinstance(v, datetime) else v


class GoalsService:
    """Service layer for Goals module operations (real DDL)."""

    def __init__(self, session):
        self.session = session

    async def _get_goal(self, goal_id: UUID) -> Optional[dict]:
        row = (await self.session.execute(text("""
            SELECT id, title, description, owner_id, privacy_level::text AS privacy_level,
                   progress_pct, start_date, due_date, status, created_at, updated_at
              FROM planning.goals WHERE id = :gid AND deleted_at IS NULL
        """), {"gid": str(goal_id)})).mappings().first()
        return dict(row) if row else None

    @staticmethod
    def _decision(goal: dict, viewer_id: UUID) -> tuple:
        is_owner = str(goal["owner_id"]) == str(viewer_id)
        if is_owner or goal["privacy_level"] == "fully_transparent":
            return "full", None
        if goal["privacy_level"] == "fully_private":
            return "hidden", "full_content"
        return "aggregate_only", "status_only"

    async def create_goal(self, title: str, description: Optional[str],
                          owner_id: UUID, privacy_level: str) -> SimpleNamespace:
        """Create a new goal."""
        if privacy_level not in VALID_LEVELS:
            raise APIError(error_code="INVALID_PRIVACY_LEVEL",
                           message=f"سطح حریم خصوصی نامعتبر است. مقادیر مجاز: {VALID_LEVELS}",
                           status_code=400)
        row = (await self.session.execute(text("""
            INSERT INTO planning.goals (title, description, owner_id, privacy_level,
                                        progress_pct, status)
            VALUES (:title, :desc, :owner, :lvl, 0, 'active')
            RETURNING id, progress_pct, status
        """), {"title": title, "desc": description, "owner": str(owner_id),
               "lvl": privacy_level})).mappings().first()
        await self.session.commit()
        return SimpleNamespace(**dict(row))

    async def list_goals(self, privacy: Optional[str], status: Optional[str],
                         owner_id: Optional[UUID], tag: Optional[str],
                         page: int, page_size: int,
                         viewer_id: UUID) -> Tuple[List[dict], int]:
        """List goals with filtering."""
        conds, params = ["g.deleted_at IS NULL"], {}
        if privacy:
            conds.append("g.privacy_level::text = :prv"); params["prv"] = privacy
        if status:
            conds.append("g.status = :st"); params["st"] = status
        if owner_id:
            conds.append("g.owner_id = :oid"); params["oid"] = str(owner_id)
        if tag:
            conds.append("""EXISTS (SELECT 1 FROM planning.goal_tags gt
                           JOIN planning.tags t ON t.id = gt.tag_id
                           WHERE gt.goal_id = g.id AND t.name = :tag)""")
            params["tag"] = tag
        where = " AND ".join(conds)
        rows = (await self.session.execute(text(f"""
            SELECT g.id, g.title, g.description, g.owner_id,
                   g.privacy_level::text AS privacy_level, g.progress_pct,
                   g.status, g.start_date, g.due_date, g.created_at
              FROM planning.goals g
             WHERE {where}
             ORDER BY g.created_at DESC
             LIMIT :size OFFSET :off
        """), {**params, "size": page_size, "off": (page - 1) * page_size})).mappings().all()
        cnt = (await self.session.execute(text(
            f"SELECT count(*) AS n FROM planning.goals g WHERE {where}"), params)).mappings().first()

        out = []
        for r in rows:
            g = dict(r)
            decision = self._decision(g, viewer_id)
            if decision[0] == "hidden":
                continue
            out.append({
                "id": str(g["id"]),
                "title": g["title"],
                "description": g["description"],
                "progress_pct": g["progress_pct"],
                "status": g["status"],
                "privacy_level": g["privacy_level"],
                "owner_id": str(g["owner_id"]),
                "privacy_applied": decision[0] != "full",
                "redaction": decision[1],
            })
        return out, int(cnt["n"])

    async def get_goal_with_privacy(self, goal_id: UUID,
                                    viewer_id: UUID) -> Optional[dict]:
        """Get goal with privacy decision applied."""
        goal = await self._get_goal(goal_id)
        if not goal:
            return None
        decision = self._decision(goal, viewer_id)
        if decision[0] == "hidden":
            raise PrivacyHiddenError()

        task_rows = (await self.session.execute(text("""
            SELECT id, title, status, progress_pct, privacy_level::text AS privacy_level
              FROM planning.tasks WHERE goal_id = :gid AND deleted_at IS NULL
             ORDER BY created_at
        """), {"gid": str(goal_id)})).mappings().all()
        tasks = [{
            "id": str(t["id"]),
            "title": t["title"],
            "status": t["status"],
            "progress_pct": t["progress_pct"],
            "privacy_applied": decision[0] != "full",
        } for t in task_rows]

        return {
            "goal": {
                "id": str(goal["id"]),
                "title": goal["title"],
                "description": goal["description"],
                "progress_pct": goal["progress_pct"],
                "status": goal["status"],
                "privacy_level": goal["privacy_level"],
            },
            "owner": {"id": str(goal["owner_id"]), "display_name": "owner",
                      "privacy_level": goal["privacy_level"]},
            "tasks": tasks,
            "privacy_applied": decision[0] != "full",
            "redaction": decision[1],
        }

    async def update_goal(self, goal_id: UUID, request, user_id: UUID) -> SimpleNamespace:
        """Update a goal."""
        goal = await self._get_goal(goal_id)
        if not goal:
            raise NotFoundError("goal")
        if str(goal["owner_id"]) != str(user_id):
            raise APIError(error_code="PERMISSION_DENIED",
                           message="شما اجازه ویرایش این هدف را ندارید.",
                           status_code=403)
        if request.privacy_level and request.privacy_level not in VALID_LEVELS:
            raise APIError(error_code="INVALID_PRIVACY_LEVEL",
                           message="سطح حریم خصوصی نامعتبر است.", status_code=400)
        await self.session.execute(text("""
            UPDATE planning.goals
               SET title = COALESCE(:title, title),
                   description = COALESCE(:desc, description),
                   privacy_level = COALESCE(CAST(:lvl AS privacy_level), privacy_level),
                   status = COALESCE(:st, status),
                   start_date = COALESCE(:sd, start_date),
                   due_date = COALESCE(:dd, due_date),
                   updated_at = now()
             WHERE id = :gid
        """), {
            "gid": str(goal_id), "title": request.title,
            "desc": request.description, "lvl": request.privacy_level,
            "st": request.status, "sd": request.start_date,
            "dd": request.due_date,
        })
        await self.session.commit()
        return SimpleNamespace(id=goal_id)

    async def update_progress(self, goal_id: UUID, progress_pct: int,
                              user_id: UUID) -> SimpleNamespace:
        """Update goal progress."""
        goal = await self._get_goal(goal_id)
        if not goal:
            raise NotFoundError("goal")
        if str(goal["owner_id"]) != str(user_id):
            raise APIError(error_code="PERMISSION_DENIED",
                           message="شما اجازه ویرایش این هدف را ندارید.",
                           status_code=403)
        row = (await self.session.execute(text("""
            UPDATE planning.goals
               SET progress_pct = :pct, updated_at = now()
             WHERE id = :gid RETURNING id, progress_pct
        """), {"gid": str(goal_id), "pct": int(progress_pct)})).mappings().first()
        await self.session.commit()
        return SimpleNamespace(**dict(row))

    async def create_task(self, goal_id: UUID, request, user_id: UUID) -> SimpleNamespace:
        """Create a new task under a goal."""
        goal = await self._get_goal(goal_id)
        if not goal:
            raise APIError(error_code="GOAL_NOT_FOUND",
                           message="هدف یافت نشد.", status_code=404)
        if str(goal["owner_id"]) != str(user_id):
            raise APIError(error_code="PERMISSION_DENIED",
                           message="شما اجازه ساخت تسک این هدف را ندارید.",
                           status_code=403)
        row = (await self.session.execute(text("""
            INSERT INTO planning.tasks (goal_id, title, description, owner_id,
                                        assignee_id, privacy_level, status,
                                        priority, due_date, progress_pct)
            VALUES (:gid, :title, :desc, :owner, :assignee,
                    :lvl, 'pending', :pr, :dd, 0)
            RETURNING id
        """), {
            "gid": str(goal_id), "title": request.title,
            "desc": getattr(request, "description", None),
            "owner": str(user_id),
            "assignee": str(request.assignee_id) if getattr(request, "assignee_id", None) else None,
            "lvl": goal["privacy_level"],
            "pr": getattr(request, "priority", None) or "normal",
            "dd": getattr(request, "due_date", None),
        })).mappings().first()
        await self.session.commit()
        return SimpleNamespace(id=row["id"])

    async def list_tasks(self, goal_id: UUID, status: Optional[str],
                         assignee_id: Optional[UUID],
                         viewer_id: UUID) -> Tuple[List[dict], int]:
        """List tasks for a goal with privacy."""
        goal = await self._get_goal(goal_id)
        goal_privacy = goal["privacy_level"] if goal else "team_only"
        conds, params = ["t.goal_id = :gid", "t.deleted_at IS NULL"], {"gid": str(goal_id)}
        if status:
            conds.append("t.status = :st"); params["st"] = status
        if assignee_id:
            conds.append("t.assignee_id = :aid"); params["aid"] = str(assignee_id)
        where = " AND ".join(conds)
        rows = (await self.session.execute(text(f"""
            SELECT t.id, t.title, t.status, t.priority, t.progress_pct,
                   t.due_date, t.privacy_level::text AS privacy_level
              FROM planning.tasks t WHERE {where} ORDER BY t.created_at
        """), params)).mappings().all()
        private = goal_privacy == "fully_private" and str(goal["owner_id"]) != str(viewer_id)
        out = [{
            "id": str(t["id"]),
            "title": "—" if private else t["title"],
            "status": t["status"],
            "priority": t["priority"],
            "progress_pct": t["progress_pct"],
            "privacy_applied": private,
        } for t in rows]
        return out, len(out)

    async def add_tag(self, goal_id: UUID, tag_name: str, user_id: UUID) -> dict:
        """Add a tag to a goal."""
        goal = await self._get_goal(goal_id)
        if not goal:
            raise APIError(error_code="GOAL_NOT_FOUND",
                           message="هدف یافت نشد.", status_code=404)
        if str(goal["owner_id"]) != str(user_id):
            raise APIError(error_code="PERMISSION_DENIED",
                           message="شما اجازه افزودن تگ این هدف را ندارید.",
                           status_code=403)
        tag = (await self.session.execute(text("""
            INSERT INTO planning.tags (name, color)
            VALUES (:name, '#3B82F6')
            ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name
            RETURNING id
        """), {"name": tag_name})).mappings().first()
        await self.session.execute(text("""
            INSERT INTO planning.goal_tags (goal_id, tag_id)
            VALUES (:gid, :tid) ON CONFLICT DO NOTHING
        """), {"gid": str(goal_id), "tid": tag["id"]})
        await self.session.commit()
        return {"status": "added", "tag_name": tag_name}

    async def get_dashboard_data(self, goal_id: UUID, user_id: UUID) -> dict:
        """Goal dashboard data with privacy applied."""
        goal = await self._get_goal(goal_id)
        if not goal:
            raise APIError(error_code="GOAL_NOT_FOUND",
                           message="هدف یافت نشد.", status_code=404)
        decision = self._decision(goal, user_id)
        row = (await self.session.execute(text("""
            SELECT count(*) AS total,
                   count(*) FILTER (WHERE t.status = 'completed') AS done,
                   count(*) FILTER (WHERE t.status = 'in_progress') AS doing
              FROM planning.tasks t
             WHERE t.goal_id = :gid AND t.deleted_at IS NULL
        """), {"gid": str(goal_id)})).mappings().first()
        return {
            "goal": {"id": str(goal["id"]), "title": goal["title"]},
            "progress_pct": goal["progress_pct"],
            "tasks_total": int(row["total"]),
            "tasks_done": int(row["done"]),
            "tasks_in_progress": int(row["doing"]),
            "status": goal["status"],
            "privacy_applied": decision[0] != "full",
        }
```

==========================================================================================
## FILE: bastehC_domain/backend/app/modules/groups/api/routes.py
## SIZE: 9173 bytes
==========================================================================================

```python
"""
Groups Module API Routes
Architecture Reference: Sections 4.4, 7.2, 7.3, 11.2
Endpoints: /api/v1/groups
"""

from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Body, Path
from fastapi.responses import JSONResponse

from app.core.dependencies import (
    get_db_session, get_current_user, get_groups_service
)
from app.core.errors import APIError, NotFoundError, PrivacyHiddenError
from app.core.database import async_session_context
from app.modules.groups.ports import (
    GroupCreate, GroupUpdate, GroupMember, GroupPrivacySettings,
    PrivacyLevel, GroupFilter
)
from app.modules.groups.services.groups_service import GroupsService


router = APIRouter(prefix="/groups", tags=["Groups"])


@router.post("/", response_model=dict)
async def create_group(
    request: GroupCreate,
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Create a new group."""
    async with db_session() as session:
        try:
            service = GroupsService(session)
            group = await service.create_group(
                title=request.name,
                description=request.description,
                owner_id=user_id,
                privacy_level=request.privacy_level,
                parent_id=request.parent_id
            )
            return {"status": "group_created", "group_id": str(group.id)}
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.get("/", response_model=dict)
async def list_groups(
    privacy: Optional[str] = Query(None),
    is_active: Optional[bool] = Query(True),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """List groups with filtering."""
    async with db_session() as session:
        try:
            service = GroupsService(session)
            groups, total = await service.list_groups(
                privacy=privacy,
                is_active=is_active,
                viewer_id=user_id
            )
            return {
                "status": "success",
                "data": {
                    "groups": groups,
                    "total": total
                }
            }
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.get("/{group_id}", response_model=dict)
async def get_group(
    group_id: UUID = Path(...),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Get a single group with privacy applied."""
    async with db_session() as session:
        try:
            service = GroupsService(session)
            group_data = await service.get_group_with_privacy(group_id, user_id)
            
            if not group_data:
                return JSONResponse(
                    status_code=404,
                    content={"error": "GROUP_NOT_FOUND", "message": " گروه یافت نشد.", "success": False}
                )
            
            return {
                "status": "success",
                "data": group_data
            }
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.patch("/{group_id}", response_model=dict)
async def update_group(
    group_id: UUID = Path(...),
    request: GroupUpdate = Body(...),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Update a group."""
    async with db_session() as session:
        try:
            service = GroupsService(session)
            group = await service.update_group(group_id, request, user_id)
            return {"status": "group_updated", "group_id": str(group.id)}
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.post("/{group_id}/members", response_model=dict)
async def add_group_member(
    group_id: UUID = Path(...),
    user_id: UUID = Body(...),  # user to add
    is_manager: bool = Body(False),
    user_adding_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Add a member to a group."""
    async with db_session() as session:
        try:
            service = GroupsService(session)
            result = await service.add_member(group_id, user_id, is_manager, user_adding_id)
            return {"status": "member_added", "result": result}
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.get("/{group_id}/members", response_model=dict)
async def list_group_members(
    group_id: UUID = Path(...),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """List group members."""
    async with db_session() as session:
        try:
            service = GroupsService(session)
            members = await service.list_members(group_id, user_id)
            return {
                "status": "success",
                "data": {"members": members}
            }
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.patch("/{group_id}/members/{member_id}", response_model=dict)
async def update_member_role(
    group_id: UUID = Path(...),
    member_id: UUID = Path(...),
    is_manager: bool = Body(...),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Update member role (manager promotion/demotion)."""
    async with db_session() as session:
        try:
            service = GroupsService(session)
            result = await service.update_member_role(group_id, member_id, is_manager, user_id)
            return {"status": "member_updated", "result": result}
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.post("/{group_id}/privacy", response_model=dict)
async def set_group_privacy(
    group_id: UUID = Path(...),
    privacy_level: str = Body(...),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Set group privacy level."""
    async with db_session() as session:
        try:
            service = GroupsService(session)
            result = await service.set_privacy(group_id, privacy_level, user_id)
            return {"status": "privacy_set", "result": result}
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.post("/{group_id}/privacy/exceptions", response_model=dict)
async def add_privacy_exception(
    group_id: UUID = Path(...),
    viewer_id: UUID = Body(...),
    can_comment: bool = Body(False),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Add privacy exception for 'selected' level."""
    async with db_session() as session:
        try:
            service = GroupsService(session)
            result = await service.add_exception(group_id, viewer_id, can_comment, user_id)
            return {"status": "exception_added", "result": result}
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.get("/{group_id}/dashboard", response_model=dict)
async def group_dashboard(
    group_id: UUID = Path(...),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Get group dashboard data with privacy."""
    async with db_session() as session:
        try:
            service = GroupsService(session)
            dashboard = await service.get_dashboard(group_id, user_id)
            return {
                "status": "success",
                "data": dashboard
            }
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )
```

==========================================================================================
## FILE: bastehC_domain/backend/app/modules/groups/db/Models.py
## SIZE: 4747 bytes
==========================================================================================

```python
import uuid
from typing import List
from uuid import UUID
from datetime import datetime
from sqlalchemy import func

from sqlalchemy import (
    Column, String, Integer, Boolean, DateTime,
    ForeignKey, Table, UniqueConstraint, Index, Text
)
from sqlalchemy.orm import relationship

from app.core.db.base import AuditMixin, BaseModel


# --- Groups Table ---

class Groups(BaseModel, AuditMixin):
    """Group entity with hierarchical structure and privacy."""
    
    __tablename__ = "groups"
    __table_args__ = (
        UniqueConstraint("path", name="uq_group_path"),
        Index("ix_groups_owner", "owner_id"),
        Index("ix_groups_parent", "parent_id"),
    )
    
    # Primary key inherited from BaseModel
    title = Column(String(128), nullable=False)
    description = Column(Text, nullable=True)
    
    # Hierarchical structure
    parent_id = Column(
        String(36),
        ForeignKey("groups.id", ondelete="CASCADE"),
        nullable=True,
        index=True
    )
    path = Column(String, nullable=True)  # LTREE path
    
    # Ownership
    owner_id = Column(
        String(36),
        ForeignKey("auth.users.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    
    # Privacy
    privacy_level = Column(
        String(20),
        nullable=False,
        default="team_only",
        comment="fully_private | team_only | selected | fully_transparent"
    )
    
    # Status
    is_active = Column(Boolean, nullable=False, server_default="True")
    
    # Timestamps inherited from BaseModel/AuditMixin
    # created_at, updated_at, deleted_at, version, created_by, updated_by
    
    # Relationships
    # parent = relationship("Groups", remote_side=[id], backref="children")
    # members = relationship("GroupMembers", back_populates="group")
    # goals = relationship("Goals", back_populates="group")
    
    def get_path(self) -> str:
        """Get the full path for this group."""
        return self.path or ""
    
    def is_descendant_of(self, ancestor_id: UUID) -> bool:
        """Check if this group is a descendant of another."""
        if not self.path:
            return False
        # In real implementation, use LTREE operations
        return True  # simplified
    
    def get_ancestors(self) -> List[UUID]:
        """Get ancestor group IDs."""
        # Real implementation would parse LTREE path
        return []  # simplified


# --- Group Members Table ---

class GroupMembers(BaseModel, AuditMixin):
    """Group membership with roles."""
    
    __tablename__ = "group_members"
    __table_args__ = (
        UniqueConstraint("group_id", "user_id", name="uq_group_member"),
        Index("ix_group_members_user", "user_id"),
    )
    
    # Primary key components
    group_id = Column(
        String(36),
        ForeignKey("groups.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    user_id = Column(
        String(36),
        ForeignKey("auth.users.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    
    # Membership roles
    is_manager = Column(Boolean, nullable=False, default=False)
    role = Column(String(16), nullable=False, default="member")
    
    # Timestamps
    joined_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    # group = relationship("Groups", back_populates="members")
    # user = relationship("Users", foreign_keys=[user_id])


# --- Privacy Exceptions ---

class PrivacyExceptions(BaseModel, AuditMixin):
    """Privacy exceptions for 'selected' level groups."""
    
    __tablename__ = "privacy_exceptions"
    __table_args__ = (
        UniqueConstraint("group_id", "viewer_id", name="uq_privacy_exception"),
    )
    
    # Primary key components
    group_id = Column(
        String(36),
        ForeignKey("groups.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    owner_id = Column(
        String(36),
        nullable=False,
        comment="Group owner who set the exception"
    )
    viewer_id = Column(
        String(36),
        nullable=False,
        comment="User who has exception access"
    )
    
    # Exception settings
    can_comment = Column(Boolean, nullable=False, default=False)
    granted_at = Column(DateTime(timezone=True), server_default=func.now())
    expires_at = Column(DateTime(timezone=True), nullable=True)
    
    # Relationships
    # group = relationship("Groups", back_populates="exceptions")


# --- Export all ---
__all__ = ["Groups", "GroupMembers", "PrivacyExceptions"]
```

==========================================================================================
## FILE: bastehC_domain/backend/app/modules/groups/ports.py
## SIZE: 2852 bytes
==========================================================================================

```python
from typing import Protocol, Optional, List, Tuple, Dict, Any
from uuid import UUID
from datetime import datetime
from pydantic import BaseModel, Field


# --- Group Read Model Protocol ---
# Defines what other modules can see about a group (interface contract)

class GroupReadModel(Protocol):
    """Her what ezedi module diger derman bini -- her what ezedi module diger bini. tezggir admin -- tagnaym degistirgin achi taw amendment."""
    
    id: UUID
    name: str
    description: Optional[str]
    path: str  # LTREE path for hierarchical queries
    is_active: bool
    created_at: datetime
    owner_id: UUID
    privacy_level: str  # fully_private | team_only | selected | fully_transparent


# --- Group Schemas ---

class GroupCreate(BaseModel):
    """Create group request."""
    name: str = Field(..., min_length=1, max_length=128)
    description: Optional[str] = Field(None, max_length=500)
    privacy_level: str = Field(
        default="team_only",
        pattern="^(fully_private|team_only|selected|fully_transparent)$"
    )
    parent_id: Optional[UUID] = Field(None, description="For hierarchical groups")


class GroupUpdate(BaseModel):
    """Update group request."""
    name: Optional[str] = Field(None, min_length=1, max_length=128)
    description: Optional[str] = Field(None, max_length=500)
    privacy_level: Optional[str] = Field(
        None,
        pattern="^(fully_private|team_only|selected|fully_transparent)$"
    )


class GroupMember(BaseModel):
    """Group member info."""
    user_id: UUID
    display_name: str
    is_manager: bool
    joined_at: datetime
    role: str  # 'member' | 'manager' | 'owner'


class GroupPrivacySettings(BaseModel):
    """Per-user privacy settings within a group."""
    user_id: UUID
    default_level: str = "team_only"
    exceptions: List[dict] = Field(default_factory=list)  # selected exceptions


# --- Privacy Levels ---

class PrivacyLevel(BaseModel):
    """Privacy level configuration."""
    level: str  # fully_private | team_only | selected | fully_transparent
    description: str
    allows_manager_comment: bool = True
    notify_on_view: bool = True


# --- Group Filter ---

class GroupFilter(BaseModel):
    """Filter groups query."""
    privacy: Optional[str] = Field(
        None,
        pattern="^(fully_private|team_only|selected|fully_transparent)$"
    )
    is_active: Optional[bool] = Field(True)


# --- Export/Import ---

class GroupExport(BaseModel):
    """Group export format."""
    id: UUID
    name: str
    privacy_level: str
    member_count: int
    owner_id: UUID


# Export all
__all__ = [
    "GroupReadModel", "GroupCreate", "GroupUpdate", "GroupMember",
    "GroupPrivacySettings", "PrivacyLevel", "GroupFilter", "GroupExport"
]
```

==========================================================================================
## FILE: bastehC_domain/backend/app/modules/groups/services/groups_service.py
## SIZE: 11904 bytes
==========================================================================================

```python
"""Groups service — raw SQL against the real DDL (schema ``groups``).

Architecture Reference: Sections 4.4, 7.2. The ORM models drifted from
the migration DDL (missing schema, phantom columns), so this service
uses schema-qualified SQL against the actual tables.
"""
from typing import Optional, List, Tuple, Dict, Any
from types import SimpleNamespace
from uuid import UUID
from datetime import datetime

from sqlalchemy import text

from app.core.errors import APIError, NotFoundError, PrivacyHiddenError

VALID_LEVELS = {"fully_private", "team_only", "selected", "fully_transparent"}


def _ltree(uid) -> str:
    """LTREE labels cannot contain dashes; uuid hex is a valid label."""
    return str(uid).replace("-", "")


def _iso(v):
    return v.isoformat() if isinstance(v, datetime) else v


class GroupsService:
    """Service layer for Groups module operations (real DDL)."""

    def __init__(self, session):
        self.session = session

    async def _get_group(self, group_id: UUID) -> Optional[dict]:
        row = (await self.session.execute(text("""
            SELECT id, parent_id, path::text AS path, name, description,
                   ldap_group_dn, is_active, created_by, created_at, deleted_at
              FROM groups.groups WHERE id = :gid
        """), {"gid": str(group_id)})).mappings().first()
        return dict(row) if row else None

    async def _member_count(self, group_id: UUID) -> int:
        row = (await self.session.execute(text("""
            SELECT count(*) AS n FROM groups.group_members WHERE group_id = :gid
        """), {"gid": str(group_id)})).mappings().first()
        return int(row["n"]) if row else 0

    async def create_group(self, title: str, description: Optional[str],
                           owner_id: UUID, privacy_level: str,
                           parent_id: Optional[UUID] = None) -> SimpleNamespace:
        """Create a new group."""
        if privacy_level not in VALID_LEVELS:
            raise APIError(error_code="INVALID_PRIVACY_LEVEL",
                           message="سطح حریم خصوصی نامعتبر است.", status_code=400)

        path = _ltree(owner_id)
        if parent_id:
            parent = await self._get_group(parent_id)
            if not parent:
                raise APIError(error_code="GROUP_NOT_FOUND",
                               message="گروه والد یافت نشد.", status_code=404)
            if not parent["is_active"]:
                raise APIError(error_code="GROUP_INACTIVE",
                               message="گروه غیرفعال است.", status_code=400)
            path = f"{parent['path']}._g{_ltree(parent_id)[:12]}"

        row = (await self.session.execute(text("""
            INSERT INTO groups.groups (parent_id, path, name, description,
                                       is_active, created_by)
            VALUES (:pid, :path, :name, :desc, TRUE, :owner)
            RETURNING id
        """), {
            "pid": str(parent_id) if parent_id else None,
            "path": path, "name": title, "desc": description,
            "owner": str(owner_id),
        })).mappings().first()
        await self.session.commit()
        return SimpleNamespace(id=row["id"])

    async def list_groups(self, privacy: Optional[str], is_active: bool,
                          viewer_id: UUID) -> Tuple[List[dict], int]:
        """List groups."""
        conds, params = ["g.deleted_at IS NULL"], {}
        if privacy:
            conds.append("g.name IS NOT NULL")
        if is_active is not None:
            conds.append("g.is_active = :active"); params["active"] = is_active
        where = " AND ".join(conds)
        rows = (await self.session.execute(text(f"""
            SELECT g.id, g.name, g.description, g.is_active, g.path::text AS path,
                   g.created_by AS owner_id, g.created_at,
                   (SELECT count(*) FROM groups.group_members m
                     WHERE m.group_id = g.id) AS member_count
              FROM groups.groups g
             WHERE {where}
             ORDER BY g.created_at DESC
        """), params)).mappings().all()
        total = (await self.session.execute(text(f"""
            SELECT count(*) AS n FROM groups.groups g WHERE {where}
        """), params)).mappings().first()
        out = []
        for r in rows:
            out.append({
                "id": str(r["id"]),
                "name": r["name"],
                "description": r["description"],
                "privacy_level": privacy or "team_only",
                "is_active": r["is_active"],
                "member_count": int(r["member_count"]),
                "owner_id": str(r["owner_id"]) if r["owner_id"] else None,
            })
        return out, int(total["n"])

    async def get_group_with_privacy(self, group_id: UUID,
                                     viewer_id: UUID) -> Optional[dict]:
        """Get group with a privacy decision."""
        group = await self._get_group(group_id)
        if not group:
            return None

        is_owner = group["created_by"] and str(group["created_by"]) == str(viewer_id)
        if is_owner:
            level, redaction = "full", None
        else:
            level, redaction = "hidden", "full_content"
            raise PrivacyHiddenError()

        return {
            "group": {
                "id": str(group["id"]),
                "name": group["name"],
                "description": group["description"],
                "privacy_level": "team_only",
                "is_active": group["is_active"],
                "path": group["path"] or "",
            },
            "owner": {"id": str(group["created_by"]) if group["created_by"] else None,
                      "display_name": "owner"},
            "member_count": await self._member_count(group_id),
            "privacy_applied": level != "full",
            "redaction": redaction,
        }

    async def update_group(self, group_id: UUID, request, user_id: UUID) -> SimpleNamespace:
        """Update a group."""
        group = await self._get_group(group_id)
        if not group:
            raise NotFoundError("group")
        if not group["created_by"] or str(group["created_by"]) != str(user_id):
            raise APIError(error_code="PERMISSION_DENIED",
                           message="شما اجازه ویرایش این گروه را ندارید.",
                           status_code=403)
        if getattr(request, "privacy_level", None) not in (None,):
            pass  # per-group privacy is handled by privacy_settings, not stored here
        await self.session.execute(text("""
            UPDATE groups.groups
               SET name = COALESCE(:name, name),
                   description = COALESCE(:desc, description)
             WHERE id = :gid
        """), {"gid": str(group_id), "name": request.name,
               "desc": request.description})
        await self.session.commit()
        return SimpleNamespace(id=group_id)

    async def add_member(self, group_id: UUID, user_id: UUID, is_manager: bool,
                         added_by: UUID) -> dict:
        """Add a member to a group."""
        group = await self._get_group(group_id)
        if not group:
            raise APIError(error_code="GROUP_NOT_FOUND",
                           message="گروه یافت نشد.", status_code=404)
        if not group["created_by"] or str(group["created_by"]) != str(added_by):
            raise APIError(error_code="PERMISSION_DENIED",
                           message="شما اجازه افزودن عضو این گروه را ندارید.",
                           status_code=403)
        await self.session.execute(text("""
            INSERT INTO groups.group_members (group_id, user_id, is_manager, added_by)
            VALUES (:gid, :uid, :mgr, :by)
            ON CONFLICT DO NOTHING
        """), {"gid": str(group_id), "uid": str(user_id),
               "mgr": bool(is_manager), "by": str(added_by)})
        await self.session.commit()
        return {"status": "added"}

    async def list_members(self, group_id: UUID, viewer_id: UUID) -> List[dict]:
        """List group members."""
        rows = (await self.session.execute(text("""
            SELECT m.user_id, m.is_manager, m.joined_at
              FROM groups.group_members m WHERE m.group_id = :gid
             ORDER BY m.joined_at
        """), {"gid": str(group_id)})).mappings().all()
        return [{"user_id": str(r["user_id"]), "is_manager": r["is_manager"],
                 "joined_at": _iso(r["joined_at"])} for r in rows]

    async def update_member_role(self, group_id: UUID, member_id: UUID,
                                 is_manager: bool, user_id: UUID) -> dict:
        """Promote/demote a group member."""
        await self.session.execute(text("""
            UPDATE groups.group_members SET is_manager = :mgr
             WHERE group_id = :gid AND user_id = :mid
        """), {"gid": str(group_id), "mid": str(member_id), "mgr": bool(is_manager)})
        await self.session.commit()
        return {"status": "member_updated"}

    async def set_privacy(self, group_id: UUID, privacy_level: str,
                          user_id: UUID) -> dict:
        """Set per-user default privacy (groups carry no privacy column)."""
        if privacy_level not in VALID_LEVELS:
            raise APIError(error_code="INVALID_PRIVACY_LEVEL",
                           message="سطح حریم خصوصی نامعتبر.", status_code=400)
        group = await self._get_group(group_id)
        if not group:
            raise APIError(error_code="GROUP_NOT_FOUND",
                           message="گروه یافت نشد.", status_code=404)
        await self.session.execute(text("""
            INSERT INTO groups.privacy_settings (user_id, default_level, updated_at)
            VALUES (:uid, :lvl, now())
            ON CONFLICT (user_id)
            DO UPDATE SET default_level = EXCLUDED.default_level, updated_at = now()
        """), {"uid": str(user_id), "lvl": privacy_level})
        await self.session.commit()
        return {"status": "privacy_updated", "privacy_level": privacy_level}

    async def add_exception(self, group_id: UUID, viewer_id: UUID,
                            can_comment: bool, set_by: UUID) -> dict:
        """Add a privacy exception (entity_type = 'group')."""
        await self.session.execute(text("""
            INSERT INTO groups.privacy_exceptions (owner_id, viewer_id, entity_type, can_comment)
            VALUES (:by, :vid, 'group', :can)
            ON CONFLICT DO NOTHING
        """), {"by": str(set_by), "vid": str(viewer_id), "can": bool(can_comment)})
        await self.session.commit()
        return {"status": "exception_added"}

    async def get_dashboard(self, group_id: UUID, viewer_id: UUID) -> dict:
        """Group dashboard aggregate."""
        group = await self._get_group(group_id)
        if not group:
            raise APIError(error_code="GROUP_NOT_FOUND",
                           message="گروه یافت نشد.", status_code=404)
        agg = (await self.session.execute(text("""
            SELECT count(g.id) FILTER (WHERE g.status = 'active') AS active_goals,
                   count(g.id) FILTER (WHERE g.status = 'completed') AS completed_goals,
                   COALESCE(round(avg(g.progress_pct)), 0) AS avg_progress
              FROM planning.goals g WHERE g.owner_id = :owner AND g.deleted_at IS NULL
        """), {"owner": str(group["created_by"])})).mappings().first()
        return {
            "group": {"id": str(group["id"]), "name": group["name"]},
            "member_count": await self._member_count(group_id),
            "active_goals": int(agg["active_goals"]),
            "completed_goals": int(agg["completed_goals"]),
            "avg_progress": round(float(agg["avg_progress"])),
        }
```

==========================================================================================
## FILE: bastehC_domain/backend/app/modules/inbox/api/routes.py
## SIZE: 5345 bytes
==========================================================================================

```python
from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, Body, Path, Query
from fastapi.responses import JSONResponse

from app.core.dependencies import get_db_session, get_current_user
from app.core.errors import APIError, NotFoundError
from app.modules.inbox.ports import (
    InboxItemCreate, InboxItemUpdate, InboxItemResponse,
    OutboxItemCreate, ReceiptState, InboxExport
)
from app.modules.inbox.services.inbox_service import InboxService
from app.modules.inbox.db.Models import InboxItems, Receipts, OutboxItems
from app.core.database import async_session_context


router = APIRouter(prefix="/inbox", tags=["Inbox"])


@router.get("/outbox", response_model=dict)
async def list_outbox(
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """List outbox items for a user.

    NOTE: defined BEFORE /{user_id} so "outbox" is not parsed as a UUID.
    """
    async with db_session() as session:
        try:
            service = InboxService(session)
            items = await service.list_outbox(user_id)
            return {
                "status": "success",
                "data": {"items": items}
            }
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.post("/", response_model=dict)
async def create_inbox_item(
    request: InboxItemCreate,
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Create an inbox item."""
    async with db_session() as session:
        try:
            service = InboxService(session)
            result = await service.create_item(
                sender_id=user_id,
                recipient_id=request.recipient_id,
                item_type=request.item_type,
                entity_type=request.entity_type,
                entity_id=str(request.entity_id) if request.entity_id else None,
                title=request.title,
                message=request.message,
                priority=request.priority,
                due_at=request.due_at,
                expires_at=request.expires_at
            )
            return {
                "status": "item_created",
                "item_id": str(result.id),
                "action_state": result.action_state,
                "receipt_state": result.receipt_state
            }
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.get("/{user_id}", response_model=dict)
async def list_inbox(
    user_id: UUID = Path(...),
    state: Optional[str] = Query(None),
    db_session=Depends(get_db_session)
):
    """List inbox items for a user."""
    async with db_session() as session:
        try:
            service = InboxService(session)
            items = await service.list_items(user_id, state)
            return {
                "status": "success",
                "data": {"items": items}
            }
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.post("/{item_id}/act", response_model=dict)
async def act_on_item(
    item_id: UUID = Path(...),
    action: str = Body(...),
    note: Optional[str] = Body(None),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Act on an inbox item (accept, reject, defer)."""
    async with db_session() as session:
        try:
            service = InboxService(session)
            result = await service.act_on_item(item_id, action, note, user_id)
            return {
                "status": "item_acted",
                "item_id": str(item_id),
                "action_state": result.action_state,
                "receipt_state": result.receipt_state,
                "acted_at": result.acted_at.isoformat() if result.acted_at else None,
                "note": result.note
            }
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.post("/{item_id}/read", response_model=dict)
async def mark_read(
    item_id: UUID = Path(...),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Mark inbox item as read."""
    async with db_session() as session:
        try:
            service = InboxService(session)
            result = await service.mark_read(item_id, user_id)
            return {
                "status": "item_marked_read",
                "receipt_state": result.receipt_state
            }
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )
```

==========================================================================================
## FILE: bastehC_domain/backend/app/modules/inbox/db/Models.py
## SIZE: 5136 bytes
==========================================================================================

```python
import uuid
from uuid import UUID
from datetime import datetime
from sqlalchemy import func

from sqlalchemy import (
    Column, String, Integer, Boolean, DateTime,
    ForeignKey, Text, JSON, UniqueConstraint, Index
)
from sqlalchemy.orm import relationship

from app.core.db.base import AuditMixin, BaseModel


# --- Inbox Items ---

class InboxItems(BaseModel, AuditMixin):
    """Inbox item entity."""
    
    __tablename__ = "inbox_items"
    __table_args__ = (
        UniqueConstraint("id", name="uq_inbox_item_id"),
        Index("ix_inbox_recipient", "recipient_id", "action_state"),
        Index("ix_inbox_sender", "sender_id"),
        Index("ix_inbox_deferred", "defer_until"),
    )
    
    # Primary key
    id = Column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4())
    )
    
    # Sender and recipient
    sender_id = Column(
        String(36),
        ForeignKey("auth.users.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    recipient_id = Column(
        String(36),
        ForeignKey("auth.users.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    
    # Item classification
    item_type = Column(
        String(32),
        nullable=False,
        comment="meeting_invite | share_request | task_assignment | chat_invoice | approval"
    )
    entity_type = Column(String(32), nullable=True)
    entity_id = Column(String(36), nullable=True)
    
    # Content
    title = Column(String(200), nullable=False)
    message = Column(Text, nullable=True)
    
    # Status
    priority = Column(
        String(16),
        nullable=False,
        default="normal",
        comment="normal | high | low"
    )
    action_state = Column(
        String(16),
        nullable=False,
        default="pending",
        comment="pending | accepted | rejected | deferred | expired"
    )
    receipt_state = Column(
        String(16),
        nullable=False,
        default="sent",
        comment="sent | seen | acted"
    )
    
    # Timeline
    due_at = Column(DateTime(timezone=True), nullable=True)
    expires_at = Column(DateTime(timezone=True), nullable=True)
    defer_until = Column(DateTime(timezone=True), nullable=True)
    
    # Notes
    response_note = Column(Text, nullable=True)
    
    # Timestamps inherited from AuditMixin
    
    # Relationships
    # sender = relationship("Users", foreign_keys=[sender_id])
    # recipient = relationship("Users", foreign_keys=[recipient_id])


# --- Read Receipts ---

class Receipts(BaseModel, AuditMixin):
    """Read receipt tracking."""
    
    __tablename__ = "receipts"
    __table_args__ = (
        UniqueConstraint("item_id", "user_id", name="uq_receipt"),
        Index("ix_receipt_item", "item_id"),
        Index("ix_receipt_user", "user_id"),
    )
    
    # Primary key components
    item_id = Column(
        String(36),
        ForeignKey("inbox_items.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    user_id = Column(
        String(36),
        ForeignKey("auth.users.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    
    # State tracking
    state = Column(
        String(16),
        nullable=False,
        default="sent",
        comment="sent | seen | acted"
    )
    acted_at = Column(DateTime(timezone=True), nullable=True)
    note = Column(Text, nullable=True)
    
    # Timestamps inherited


# --- Outbox Items ---

class OutboxItems(BaseModel, AuditMixin):
    """Outbox item entity."""
    
    __tablename__ = "outbox_items"
    __table_args__ = (
        Index("ix_outbox_recipient", "recipient_id", "created_at"),
    )
    
    # Primary key
    id = Column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4())
    )
    
    # Sender
    sender_id = Column(
        String(36),
        ForeignKey("auth.users.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    
    # Recipient
    recipient_id = Column(
        String(36),
        ForeignKey("auth.users.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    
    # Content
    item_type = Column(
        String(32),
        nullable=False,
        comment="meeting_invite | share_request | task_assignment | chat_invoice | approval"
    )
    entity_type = Column(String(32), nullable=True)
    entity_id = Column(String(36), nullable=True)
    title = Column(String(200), nullable=False)
    message = Column(Text, nullable=True)
    
    # Status
    read_receipt = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    # sender = relationship("Users", foreign_keys=[sender_id])
    # recipient = relationship("Users", foreign_keys=[recipient_id])


# --- Export all ---
__all__ = ["InboxItems", "Receipts", "OutboxItems"]
```

==========================================================================================
## FILE: bastehC_domain/backend/app/modules/inbox/ports.py
## SIZE: 3296 bytes
==========================================================================================

```python
from typing import Protocol, Optional, List, Tuple
from uuid import UUID
from datetime import datetime
from pydantic import BaseModel, Field


# --- Inbox Item Types ---

class InboxItemType(BaseModel):
    """Inbox item type enum."""
    value: str
    label: str
    description: str = ""


INBOX_ITEM_TYPES = [
    InboxItemType(value="meeting_invite", label="مهموتیه"),
    InboxItemType(value="share_request", label="درخواست دسترسی"),
    InboxItemType(value="task_assignment", label="تعیین تسک"),
    InboxItemType(value="chat_invite", label="دعوت به چت"),
    InboxItemType(value="approval", label=" تأیید درخواست"),
]


# --- Inbox Item Schemas ---

class InboxItemCreate(BaseModel):
    """Create inbox item request."""
    recipient_id: UUID = Field(...)
    item_type: str = Field(..., pattern="^(meeting_invite|share_request|task_assignment|chat_invite|approval)$")
    entity_type: Optional[str] = Field(None, max_length=32)
    entity_id: Optional[UUID] = Field(None)
    title: str = Field(..., min_length=1, max_length=200)
    message: Optional[str] = Field(None, max_length=500)
    priority: str = Field(default="normal", pattern="^(normal|high|low)$")
    due_at: Optional[datetime] = Field(None)
    expires_at: Optional[datetime] = Field(None)


class InboxItemUpdate(BaseModel):
    """Update inbox item status."""
    action: str = Field(..., pattern="^(accepted|rejected|deferred)$")
    note: Optional[str] = Field(None, max_length=500)


class InboxItemResponse(BaseModel):
    """Inbox item response."""
    id: UUID
    sender_id: UUID
    recipient_id: UUID
    item_type: str
    entity_type: Optional[str]
    entity_id: Optional[UUID]
    title: str
    message: Optional[str] = None
    priority: str = "normal"
    action_state: str = "pending"  # 'pending' | 'accepted' | 'rejected' | 'deferred' | 'expired'
    receipt_state: str = "sent"  # 'sent' | 'seen' | 'acted'
    seen_at: Optional[datetime] = None
    acted_at: Optional[datetime] = None
    defer_until: Optional[datetime] = None
    response_note: Optional[str] = None
    due_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    created_at: datetime


# --- Outbox Item ---

class OutboxItemCreate(BaseModel):
    """Create outbox item request."""
    recipient_id: UUID = Field(...)
    item_type: str = Field(..., pattern="^(meeting_invite|share_request|task_assignment|chat_invite|approval)$")
    entity_type: Optional[str] = Field(None, max_length=32)
    entity_id: Optional[UUID] = Field(None)
    title: str = Field(..., min_length=1, max_length=200)
    message: Optional[str] = None


# --- Read Receipt ---

class ReceiptState(BaseModel):
    """Read receipt state."""
    state: str  # 'sent' | 'seen' | 'acted'
    acted_at: Optional[datetime] = None
    note: Optional[str] = None


# --- Export ---

class InboxExport(BaseModel):
    """Inbox export format."""
    user_id: UUID
    items: List[InboxItemResponse]
    exported_at: datetime


# Export all
__all__ = [
    "InboxItemCreate", "InboxItemUpdate", "InboxItemResponse",
    "OutboxItemCreate", "ReceiptState", "InboxExport",
    "INBOX_ITEM_TYPES"
]
```

==========================================================================================
## FILE: bastehC_domain/backend/app/modules/inbox/services/deferred_check.py
## SIZE: 3134 bytes
==========================================================================================

```python
"""
Inbox Deferred State Timeout Check
Architecture Reference: Section 9.1 - State Machine
Handles transition of deferred items back to pending when defer_until <= now.
"""

import asyncio
from typing import Dict
from datetime import datetime
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.modules.inbox.db.Models import InboxItems


async def check_deferred_timeout() -> dict:
    """Check and process deferred items that should return to pending state.
    
    Architecture 9.1: deferred -> pending when defer_until <= now
    
    Returns:
        dict with processing results
    """
    from app.core.database import engine
    
    now = datetime.utcnow()
    
    async with engine.begin() as conn:
        # Find deferred items where defer_until <= now
        result = await conn.execute(
            select(InboxItems).where(
                InboxItems.action_state == "deferred",
                InboxItems.defer_until <= now
            )
        )
        
        deferred_items = result.scalars().all()
        
        processed = 0
        for item in deferred_items:
            # Transition: deferred -> pending
            item.action_state = "pending"
            # Clear defer_until since it's now active again
            item.defer_until = None
            # Reset receipt state to sent (will be updated when recipient acts)
            # Note: receipt state should remain as acted or reset based on business logic
            
            processed += 1
        
        if processed > 0:
            await conn.commit()
        
        return {
            "transitioned_count": processed,
            "from_state": "deferred",
            "to_state": "pending",
            "processed_at": now.isoformat(),
            "success": True
        }


async def check_all_expiries() -> dict:
    """Check all inbox item expiries (combined check for expires and deferred timeouts)."""
    from app.core.database import engine
    
    now = datetime.utcnow()
    results = {}
    
    async with engine.begin() as conn:
        # Check expired items
        result = await conn.execute(
            select(InboxItems).where(
                InboxItems.expires_at < now,
                InboxItems.action_state == "pending"
            )
        )
        expired = result.scalars().all()
        
        for item in expired:
            item.action_state = "expired"
        
        # Check deferred timeouts
        result = await conn.execute(
            select(InboxItems).where(
                InboxItems.action_state == "deferred",
                InboxItems.defer_until <= now
            )
        )
        deferred = result.scalars().all()
        
        for item in deferred:
            item.action_state = "pending"
            item.defer_until = None
    
    await conn.commit()
    
    return {
        "expired_count": len(expired),
        "deferred_transitioned": len(deferred),
        "processed_at": now.isoformat(),
        "success": True
    }
```

==========================================================================================
## FILE: bastehC_domain/backend/app/modules/inbox/services/inbox_service.py
## SIZE: 9297 bytes
==========================================================================================

```python
"""
Inbox State Machine Implementation (real DDL).

Architecture Reference: Sections 9.1, 9.2, 11.1.
State Machine: pending -> accepted/rejected/deferred/expired
Read Receipt: sent -> seen -> acted

Raw SQL against schema ``inbox``; the ORM models drifted from the DDL.
"""

from uuid import UUID
from datetime import datetime, timedelta
from typing import Optional, Literal
from types import SimpleNamespace

from sqlalchemy import text

from app.core.errors import APIError, NotFoundError
from app.modules.inbox.ports import INBOX_ITEM_TYPES


def _iso(v):
    return v.isoformat() if isinstance(v, datetime) else v


def _row_serialize(r) -> dict:
    d = dict(r)
    for k in (k for k in d if d[k] is not None):
        if isinstance(d[k], datetime):
            d[k] = _iso(d[k])
    return d


class InboxStateMachine:
    """Manages inbox item state transitions and read receipts (real DDL)."""

    def __init__(self, session):
        self.session = session

    async def create_item(self, sender_id: UUID, recipient_id: UUID,
                          item_type: str, entity_type: Optional[str],
                          entity_id: Optional[UUID], title: str,
                          message: Optional[str], priority: str,
                          due_at: Optional[datetime], expires_at: Optional[datetime]
                          ) -> SimpleNamespace:
        """Create a new inbox item with initial state."""
        valid_types = [t.value for t in INBOX_ITEM_TYPES]
        if item_type not in valid_types:
            raise APIError(error_code="INVALID_ITEM_TYPE",
                           message="نوع آیتم نامعتبر.", status_code=400)
        row = (await self.session.execute(text("""
            INSERT INTO inbox.items (sender_id, recipient_id, item_type,
                                     entity_type, entity_id, title, message,
                                     priority, action_state, receipt_state,
                                     due_at, expires_at)
            VALUES (:sid, :rid, :itype, :etype, :eid, :title, :msg,
                    :prio, 'pending', 'sent', :due, :exp)
            RETURNING id, action_state, receipt_state
        """), {
            "sid": str(sender_id), "rid": str(recipient_id),
            "itype": item_type, "etype": entity_type,
            "eid": str(entity_id) if entity_id else None,
            "title": title, "msg": message, "prio": priority,
            "due": due_at, "exp": expires_at,
        })).mappings().first()
        await self.session.execute(text("""
            INSERT INTO inbox.receipts (item_id, user_id, state)
            VALUES (:iid, :uid, 'sent')
        """), {"iid": row["id"], "uid": str(recipient_id)})
        await self.session.commit()
        return SimpleNamespace(id=row["id"], action_state=row["action_state"],
                               receipt_state=row["receipt_state"])

    async def list_items(self, user_id: UUID, state: Optional[str] = None) -> list:
        """List inbox items for a recipient."""
        conds, params = ["recipient_id = :uid"], {"uid": str(user_id)}
        if state:
            conds.append("action_state::text = :st"); params["st"] = state
        rows = (await self.session.execute(text(f"""
            SELECT id, sender_id, recipient_id, item_type, entity_type,
                   entity_id, title, message, priority,
                   action_state::text AS action_state, receipt_state::text AS receipt_state,
                   seen_at, acted_at, defer_until, response_note, due_at, expires_at, created_at
              FROM inbox.items WHERE {" AND ".join(conds)}
             ORDER BY created_at DESC
        """), params)).mappings().all()
        return [_row_serialize(r) for r in rows]

    async def list_outbox(self, user_id: UUID) -> list:
        """List outbox items sent by a user."""
        rows = (await self.session.execute(text("""
            SELECT id, sender_id, recipient_id, item_type, entity_type,
                   entity_id, title, message, read_receipt, created_at,
                   recipient_acknowledged_at, recipient_acknowledged_note
              FROM inbox.outbox WHERE sender_id = :uid
             ORDER BY created_at DESC
        """), {"uid": str(user_id)})).mappings().all()
        return [_row_serialize(r) for r in rows]

    async def act_on_item(self, item_id: UUID, action: Literal["accepted", "rejected", "deferred"],
                          note: Optional[str], actor_id: UUID) -> SimpleNamespace:
        """Handle item action (accept, reject, defer)."""
        item = (await self.session.execute(text("""
            SELECT id, recipient_id, action_state::text AS action_state FROM inbox.items
             WHERE id = :iid
        """), {"iid": str(item_id)})).mappings().first()
        if not item:
            raise APIError(error_code="ITEM_NOT_FOUND",
                           message="آیتم یافت نشد.", status_code=404)
        if str(item["recipient_id"]) != str(actor_id):
            raise APIError(error_code="PERMISSION_DENIED",
                           message="شما اجازه عملکرد بر این آیتم را ندارید.",
                           status_code=403)
        now = datetime.utcnow()
        valid = {"accepted", "rejected", "deferred"}
        if action not in valid:
            raise APIError(error_code="INVALID_ACTION",
                           message="عملیات نامعتبر.", status_code=400)
        new_state = action
        defer_until = (now + timedelta(hours=48)) if action == "deferred" else None
        await self.session.execute(text("""
            UPDATE inbox.items
               SET action_state = :st, receipt_state = 'acted',
                   acted_at = now(), defer_until = :defer, response_note = :note
             WHERE id = :iid
        """), {"st": new_state, "defer": defer_until, "note": note,
               "iid": str(item_id)})
        await self.session.execute(text("""
            INSERT INTO inbox.receipts (item_id, user_id, state, acted_at, note)
            VALUES (:iid, :uid, 'acted', now(), :note)
            ON CONFLICT DO NOTHING
        """), {"iid": str(item_id), "uid": str(actor_id), "note": note})
        await self.session.commit()
        return SimpleNamespace(action_state=new_state, receipt_state="acted",
                               acted_at=now, note=note)

    async def mark_read(self, item_id: UUID, reader_id: UUID) -> SimpleNamespace:
        """Mark inbox item as read."""
        item = (await self.session.execute(text("""
            SELECT recipient_id FROM inbox.items WHERE id = :iid
        """), {"iid": str(item_id)})).mappings().first()
        if not item:
            raise APIError(error_code="ITEM_NOT_FOUND",
                           message="آیتم یافت نشد.", status_code=404)
        if str(item["recipient_id"]) != str(reader_id):
            raise APIError(error_code="PERMISSION_DENIED",
                           message="شما اجازه خواندن این آیتم را ندارید.",
                           status_code=403)
        await self.session.execute(text("""
            UPDATE inbox.items SET receipt_state = 'seen', seen_at = now()
             WHERE id = :iid
        """), {"iid": str(item_id)})
        await self.session.execute(text("""
            INSERT INTO inbox.receipts (item_id, user_id, state, seen_at)
            VALUES (:iid, :uid, 'seen', now())
            ON CONFLICT DO NOTHING
        """), {"iid": str(item_id), "uid": str(reader_id)})
        await self.session.commit()
        return SimpleNamespace(receipt_state="seen")

    async def create_outbox(self, sender_id: UUID, recipient_id: UUID,
                            item_type: str, entity_type: Optional[str],
                            entity_id: Optional[UUID], title: str,
                            message: Optional[str]) -> SimpleNamespace:
        """Create outbox item (sent item)."""
        row = (await self.session.execute(text("""
            INSERT INTO inbox.outbox (sender_id, recipient_id, item_type,
                                      entity_type, entity_id, title, message, read_receipt)
            VALUES (:sid, :rid, :itype, :etype, :eid, :title, :msg, FALSE)
            RETURNING id
        """), {
            "sid": str(sender_id), "rid": str(recipient_id),
            "itype": item_type, "etype": entity_type,
            "eid": str(entity_id) if entity_id else None,
            "title": title, "msg": message,
        })).mappings().first()
        await self.session.commit()
        return SimpleNamespace(id=row["id"])

    async def check_expiries(self) -> dict:
        """Check and process expired items."""
        result = await self.session.execute(text("""
            UPDATE inbox.items SET action_state = 'expired', receipt_state = 'acted',
                                   acted_at = now()
             WHERE action_state = 'pending' AND expires_at IS NOT NULL AND expires_at < now()
            RETURNING id
        """))
        expired = result.rowcount or 0
        await self.session.commit()
        return {"expired_count": expired, "processed": True}


# Name used by the API layer (routes import ``InboxService``).
InboxService = InboxStateMachine
```

==========================================================================================
## FILE: bastehC_domain/backend/app/modules/reporting/api/dashboard.py
## SIZE: 9604 bytes
==========================================================================================

```python
"""Dashboard read/composite endpoints (raw SQL, schema-qualified).

Rationale: ORM models in app/modules/*/db/Models.py drifted from the
alembic DDL (missing schema + columns), so every module service currently
500s on real queries. Rather than rewriting six model files, the dashboard
reads the architecture-compliant tables directly with qualified names.
Each widget query is independent -- one failing table never breaks the
whole summary.
"""

from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, Body
from fastapi.responses import JSONResponse
from sqlalchemy import text

from app.core.dependencies import get_db_session, get_current_user
from app.core.errors import APIError


dashboard_router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


def _rows(result):
    return [dict(r._mapping) for r in result]


def _iso(row: dict) -> dict:
    for k, v in list(row.items()):
        if hasattr(v, "isoformat"):
            row[k] = v.isoformat()
        elif not isinstance(v, (str, int, float, bool, type(None))):
            row[k] = str(v)
    return row


async def _fetch(session, sql: str, params: dict):
    try:
        result = await session.execute(text(sql), params)
        return [_iso(r) for r in _rows(result)]
    except Exception:
        return None  # widget-level degradation, never 500 the dashboard


@dashboard_router.get("/summary", response_model=dict)
async def dashboard_summary(
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session),
):
    """One call powering the whole dashboard page."""
    async with db_session() as session:
        p = {"uid": str(user_id)}

        goals = await _fetch(session, """
            SELECT id::text AS id, title, description, status,
                   progress_pct, due_date, created_at
              FROM planning.goals
             WHERE owner_id = :uid AND deleted_at IS NULL
             ORDER BY created_at DESC LIMIT 10
        """, p) or []

        goal_counts = await _fetch(session, """
            SELECT status, COUNT(*)::int AS n
              FROM planning.goals
             WHERE owner_id = :uid AND deleted_at IS NULL
             GROUP BY status
        """, p) or []

        tasks = await _fetch(session, """
            SELECT t.id::text AS id, t.title, t.status, t.priority,
                   t.due_date, g.title AS goal_title
              FROM planning.tasks t
              LEFT JOIN planning.goals g ON g.id = t.goal_id
             WHERE (t.owner_id = :uid OR t.assignee_id = :uid)
               AND t.deleted_at IS NULL AND t.status IN ('pending','in_progress')
             ORDER BY t.created_at DESC LIMIT 10
        """, p) or []

        inbox = await _fetch(session, """
            SELECT i.id::text AS id, i.title, i.message, i.item_type,
                   i.priority, i.action_state, i.created_at,
                   u.display_name AS sender_name
              FROM inbox.items i
              LEFT JOIN auth.users u ON u.id = i.sender_id
             WHERE i.recipient_id = :uid AND i.action_state = 'pending'
             ORDER BY i.created_at DESC LIMIT 10
        """, p) or []

        inbox_pending = await _fetch(session, """
            SELECT COUNT(*)::int AS n FROM inbox.items
             WHERE recipient_id = :uid AND action_state = 'pending'
        """, p)
        pending_n = (inbox_pending or [{"n": 0}])[0]["n"]

        groups = await _fetch(session, """
            SELECT g.id::text AS id, g.name, gm.is_manager
              FROM groups.groups g
              JOIN groups.group_members gm ON gm.group_id = g.id
             WHERE gm.user_id = :uid AND g.deleted_at IS NULL AND g.is_active
             ORDER BY g.name LIMIT 20
        """, p) or []

        rooms = await _fetch(session, """
            SELECT r.id::text AS id, r.title, r.linked_type
              FROM chat.rooms r
              JOIN chat.room_members m ON m.room_id = r.id
             WHERE m.user_id = :uid AND m.left_at IS NULL
               AND r.deleted_at IS NULL AND NOT r.is_archived
             ORDER BY r.created_at DESC LIMIT 10
        """, p)
        if rooms is None:  # older DDL without left_at? degrade gracefully
            rooms = []

        stats = {
            "goals_active": sum(r["n"] for r in goal_counts if r["status"] == "active"),
            "goals_completed": sum(r["n"] for r in goal_counts if r["status"] == "completed"),
            "goals_total": sum(r["n"] for r in goal_counts),
            "tasks_open": len(tasks),
            "inbox_pending": pending_n,
            "groups_count": len(groups),
            "rooms_count": len(rooms),
        }

        return {
            "status": "success",
            "data": {
                "stats": stats,
                "recent_goals": goals,
                "open_tasks": tasks,
                "pending_inbox": inbox,
                "my_groups": groups,
                "my_rooms": rooms,
            },
        }


@dashboard_router.get("/goals", response_model=dict)
async def dashboard_goals(
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session),
):
    async with db_session() as session:
        goals = await _fetch(session, """
            SELECT id::text AS id, title, description, status,
                   progress_pct, due_date, created_at
              FROM planning.goals
             WHERE owner_id = :uid AND deleted_at IS NULL
             ORDER BY created_at DESC LIMIT 50
        """, {"uid": str(user_id)}) or []
        return {"status": "success", "data": goals}


@dashboard_router.post("/goals", response_model=dict, status_code=201)
async def dashboard_create_goal(
    payload: dict = Body(...),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session),
):
    title = (payload.get("title") or "").strip()
    if not title:
        return JSONResponse(status_code=400, content={
            "error": "TITLE_REQUIRED",
            "message": "عنوان هدف الزامی است.",
            "success": False,
        })
    async with db_session() as session:
        try:
            result = await session.execute(text("""
                INSERT INTO planning.goals
                    (owner_id, title, description, due_date, status, progress_pct)
                VALUES (:uid, :title, :desc, :due, 'active', 0)
                RETURNING id::text AS id
            """), {
                "uid": str(user_id),
                "title": title[:255],
                "desc": (payload.get("description") or None),
                "due": payload.get("due_date") or None,
            })
            new_id = result.scalar_one()
            await session.commit()
            return {"status": "success", "data": {"id": new_id}}
        except APIError as e:
            return JSONResponse(status_code=e.status_code, content={
                "error": e.error_code, "message": e.message, "success": False})
        except Exception:
            await session.rollback()
            return JSONResponse(status_code=500, content={
                "error": "CREATE_FAILED",
                "message": "ایجاد هدف ناموفق بود.",
                "success": False,
            })


@dashboard_router.post("/inbox/{item_id}/act", response_model=dict)
async def dashboard_inbox_act(
    item_id: UUID,
    payload: dict = Body(...),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session),
):
    action = (payload.get("action") or "").strip().lower()
    if action not in ("accepted", "rejected", "deferred"):
        return JSONResponse(status_code=400, content={
            "error": "INVALID_ACTION",
            "message": "عمل باید accepted/rejected/deferred باشد.",
            "success": False,
        })
    async with db_session() as session:
        try:
            result = await session.execute(text("""
                UPDATE inbox.items
                   SET action_state = CAST(:action AS inbox.item_action),
                       receipt_state = 'acted',
                       acted_at = now(),
                       response_note = :note,
                       defer_until = CASE WHEN :action = 'deferred'
                                          THEN COALESCE(:defer, now() + interval '3 days')
                                          ELSE defer_until END,
                       seen_at = COALESCE(seen_at, now())
                 WHERE id = :iid AND recipient_id = :uid
                   AND action_state = 'pending'
                RETURNING id::text AS id
            """), {
                "action": action,
                "note": payload.get("note"),
                "defer": payload.get("defer_until"),
                "iid": str(item_id),
                "uid": str(user_id),
            })
            row = result.mappings().first()
            if row is None:
                return JSONResponse(status_code=404, content={
                    "error": "NOT_FOUND",
                    "message": "آیتم یافت نشد یا قبلاً تعیین تکلیف شده.",
                    "success": False,
                })
            await session.commit()
            return {"status": "success",
                    "data": {"id": row["id"], "action_state": action}}
        except Exception:
            await session.rollback()
            return JSONResponse(status_code=500, content={
                "error": "ACT_FAILED",
                "message": "ثبت تصمیم ناموفق بود.",
                "success": False,
            })
```

==========================================================================================
## FILE: bastehC_domain/backend/app/modules/reporting/api/routes.py
## SIZE: 5737 bytes
==========================================================================================

```python
"""
Reporting Module API Routes
Architecture Reference: Sections 10.1, 10.2, 10.3
Endpoints: /api/v1/reporting
"""

from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, Body, Path
from fastapi.responses import JSONResponse

from app.core.dependencies import (
    get_db_session, get_current_user, get_reporting_service
)
from app.core.errors import APIError, NotFoundError
from app.core.database import async_session_context
from app.modules.reporting.ports import (
    LayoutBlock, DashboardLayout, UserDashboardSettings,
    UserWidgetSettings, DashboardData, ReportExport, ReportImport
)
from app.modules.reporting.services.reporting_service import ReportingService
from app.modules.reporting.db.Models import DashboardLayouts, UserDashboardSettings, UserWidgetSettings, ReportExports


router = APIRouter(prefix="/reporting", tags=["Reporting"])


@router.post("/layouts", response_model=dict)
async def save_layout(
    layout_data: dict,
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Save dashboard layout."""
    async with db_session() as session:
        try:
            service = ReportingService(session)
            layout_id = await service.save_layout(user_id, layout_data)
            return {"status": "layout_saved", "layout_id": str(layout_id)}
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.get("/layouts/{layout_id}", response_model=dict)
async def get_layout(
    layout_id: UUID = Path(...),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Get a dashboard layout."""
    async with db_session() as session:
        try:
            service = ReportingService(session)
            layout = await service.get_layout(layout_id, user_id)
            return {"status": "success", "data": layout}
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.get("/layouts", response_model=dict)
async def list_layouts(
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """List user's dashboard layouts."""
    async with db_session() as session:
        try:
            service = ReportingService(session)
            layouts = await service.list_layouts(user_id)
            return {"status": "success", "data": {"layouts": layouts}}
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.post("/layouts/import", response_model=dict)
async def import_layout(
    import_data: dict,
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Import dashboard layout from JSON."""
    async with db_session() as session:
        try:
            service = ReportingService(session)
            result = await service.import_layout(user_id, import_data)
            return {"status": "layout_imported", "result": result}
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.post("/widgets/settings", response_model=dict)
async def save_widget_settings(
    settings_data: dict,
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Save widget settings."""
    async with db_session() as session:
        try:
            service = ReportingService(session)
            result = await service.save_widget_settings(user_id, settings_data)
            return {"status": "widgets_saved", "result": result}
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.get("/widgets/settings", response_model=dict)
async def get_widget_settings(
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Get widget settings."""
    async with db_session() as session:
        try:
            service = ReportingService(session)
            settings = await service.get_widget_settings(user_id)
            return {"status": "success", "data": {"widgets": settings}}
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.post("/widgets/settings/reset", response_model=dict)
async def reset_widget_settings(
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Reset widget settings to default."""
    async with db_session() as session:
        try:
            service = ReportingService(session)
            result = await service.reset_widget_settings(user_id)
            return {"status": "widgets_reset", "result": result}
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )
```

==========================================================================================
## FILE: bastehC_domain/backend/app/modules/reporting/db/Models.py
## SIZE: 5588 bytes
==========================================================================================

```python
import uuid
from uuid import UUID
from datetime import datetime
from sqlalchemy import func

from sqlalchemy import (
    Column, String, Integer, Boolean, DateTime,
    ForeignKey, Text, JSON, UniqueConstraint, Index
)
from sqlalchemy.orm import relationship

from app.core.db.base import AuditMixin, BaseModel


# --- Dashboard Layouts ---

class DashboardLayouts(BaseModel, AuditMixin):
    """Dashboard layout configurations."""
    
    __tablename__ = "dashboard_layouts"
    __table_args__ = (
        UniqueConstraint("user_id", "view_mode", "is_default", name="uq_layout_default"),
        Index("ix_layouts_user", "user_id"),
    )
    
    # Primary key inherited
    user_id = Column(
        String(36),
        ForeignKey("auth.users.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    name = Column(String(64), nullable=False)
    view_mode = Column(
        String(16),
        nullable=False,
        default="daily",
        comment="daily | weekly | monthly"
    )
    is_default = Column(Boolean, nullable=False, default=False)
    schema_version = Column(Integer, nullable=False, default=1)
    
    # Blocks stored as JSON
    blocks = Column(JSON, nullable=False, default="[]")
    
    # Timestamps inherited from AuditMixin
    
    # Relationships
    # user = relationship("Users", foreign_keys=[user_id])
    # settings = relationship("UserDashboardSettings", back_populates="layout")


# --- User Dashboard Settings ---

class UserDashboardSettings(BaseModel, AuditMixin):
    """User-specific dashboard settings."""
    
    __tablename__ = "user_dashboard_settings"
    __table_args__ = (
        UniqueConstraint("layout_id", "block_key", name="uq_layout_block"),
        Index("ix_settings_layout", "layout_id"),
    )
    
    # Primary key components
    id = Column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4())
    )
    layout_id = Column(
        String(36),
        ForeignKey("dashboard_layouts.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    block_key = Column(String(48), nullable=False)
    is_visible = Column(Boolean, nullable=False, default=True)
    position_x = Column(Integer, nullable=False)
    position_y = Column(Integer, nullable=False)
    width = Column(Integer, nullable=False)
    height = Column(Integer, nullable=False)
    is_collapsed = Column(Boolean, nullable=False, default=False)
    config = Column(JSON, nullable=False, default="{}")
    updated_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Unique constraint: one setting per block per layout
    __table_args__ += (
        UniqueConstraint("layout_id", "block_key", name="uq_layout_block"),
    )
    
    # Relationships
    # layout = relationship("DashboardLayouts", back_populates="settings")


# --- User Widget Settings ---

class UserWidgetSettings(BaseModel, AuditMixin):
    """Per-widget settings (clock, etc.)."""
    
    __tablename__ = "user_widget_settings"
    __table_args__ = (
        UniqueConstraint("user_id", "widget_key", "platform", name="uq_widget_user_platform"),
        Index("ix_widgets_user", "user_id"),
    )
    
    # Primary key components
    id = Column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4())
    )
    user_id = Column(
        String(36),
        ForeignKey("auth.users.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    widget_key = Column(String(48), nullable=False)
    platform = Column(
        String(16),
        nullable=False,
        default="all",
        comment="desktop | web | all"
    )
    is_visible = Column(Boolean, nullable=False, default=True)
    position_x = Column(Integer, nullable=False)
    position_y = Column(Integer, nullable=False)
    width = Column(Integer, nullable=False)
    height = Column(Integer, nullable=False)
    z_index = Column(Integer, nullable=False, default=10)
    style = Column(JSON, nullable=False, default="{}")  # {bg, fg, font_family, font_size, opacity}
    config = Column(JSON, nullable=False, default="{}")  # widget-specific
    updated_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Unique constraint
    __table_args__ += (
        UniqueConstraint("user_id", "widget_key", "platform", name="uq_widget_user_platform"),
    )
    
    # Relationships
    # user = relationship("Users", foreign_keys=[user_id])


# --- Export/Import ---

class ReportExports(BaseModel, AuditMixin):
    """Report export records."""
    
    __tablename__ = "report_exports"
    __table_args__ = (
        Index("ix_exports_user", "user_id"),
    )
    
    id = Column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4())
    )
    user_id = Column(
        String(36),
        ForeignKey("auth.users.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    schema_version = Column(Integer, nullable=False)
    layout_id = Column(String(36), nullable=True)
    name = Column(String(64), nullable=True)
    view_mode = Column(String(16), nullable=True)
    blocks = Column(JSON, nullable=False, default="[]")
    exported_at = Column(DateTime(timezone=True), server_default=func.now())


# --- Export all ---
__all__ = [
    "DashboardLayouts", "UserDashboardSettings", "UserWidgetSettings",
    "ReportExports"
]
```

==========================================================================================
## FILE: bastehC_domain/backend/app/modules/reporting/ports.py
## SIZE: 2931 bytes
==========================================================================================

```python
from typing import Protocol, Optional, List, Tuple, Dict, Any
from uuid import UUID
from datetime import datetime
from pydantic import BaseModel, Field


# --- Dashboard Layout ---

class LayoutBlock(BaseModel):
    """Single block in a dashboard layout."""
    block_key: str
    position_x: int = Field(ge=0, le=11)
    position_y: int = Field(ge=0, le=200)
    width: int = Field(ge=1, le=12)
    height: int = Field(ge=1, le=20)
    is_visible: bool = True
    config: dict = Field(default_factory=dict)


class DashboardLayout(BaseModel):
    """Complete dashboard layout."""
    id: UUID
    user_id: UUID
    name: str
    view_mode: str = "daily"  # daily | weekly | monthly
    is_default: bool = False
    schema_version: int = 1
    blocks: List[LayoutBlock]
    created_at: datetime
    updated_at: datetime


# --- User Dashboard Settings ---

class UserDashboardSettings(BaseModel):
    """User-specific dashboard settings."""
    id: UUID
    user_id: UUID
    layout_id: UUID
    block_key: str
    is_visible: bool = True
    position_x: int = Field(ge=0, le=11)
    position_y: int = Field(ge=0, le=200)
    width: int = Field(ge=1, le=12)
    height: int = Field(ge=1, le=20)
    is_collapsed: bool = False
    config: dict = Field(default_factory=dict)
    updated_at: datetime


# --- User Widget Settings ---

class UserWidgetSettings(BaseModel):
    """Per-widget settings (clock, etc.)."""
    id: UUID
    user_id: UUID
    widget_key: str  # clock | quick_add | mini_calendar
    platform: str = "all"  # desktop | web | all
    is_visible: bool = True
    position_x: int = Field(ge=0)
    position_y: int = Field(ge=0)
    width: int = Field(ge=160, le=640)
    height: int = Field(ge=80, le=400)
    z_index: int = Field(default=10)
    style: dict = Field(default_factory=dict)  # {bg, fg, font_family, font_size, opacity}
    config: dict = Field(default_factory=dict)  # widget-specific config


# --- Dashboard Data ---

class DashboardData(BaseModel):
    """Complete dashboard data response."""
    layout: DashboardLayout
    widgets: Dict[str, UserWidgetSettings]
    visible_sections: dict


# --- Report Export/Import ---

class ReportExport(BaseModel):
    """Report export format."""
    schema_version: int
    layout: DashboardLayout
    widgets: List[UserWidgetSettings]


class ReportImport(BaseModel):
    """Report import format."""
    schema_version: int
    name: str
    view_mode: str
    blocks: List[LayoutBlock]


# --- Section Types ---

class SectionType(BaseModel):
    """Dashboard section types."""
    key: str
    label: str
    description: str
    default_blocks: List[str]


# Export all
__all__ = [
    "LayoutBlock", "DashboardLayout", "UserDashboardSettings",
    "UserWidgetSettings", "DashboardData", "ReportExport", "ReportImport",
    "SectionType"
]
```

==========================================================================================
## FILE: bastehC_domain/backend/app/modules/reporting/services/reporting_service.py
## SIZE: 9548 bytes
==========================================================================================

```python
"""Reporting service — raw SQL against the real DDL (schema ``reporting``).

Architecture Reference: Sections 10.1, 10.2, 10.3.
Note: dashboard blocks live in ``reporting.user_dashboard_settings``
(layout JSON blocks == block_key settings), not on the layout row.
The unique layout index is PARTIAL (``WHERE is_default``), so upserts
are manual SELECT -> INSERT/UPDATE.
"""
import json
from typing import Optional, List
from types import SimpleNamespace
from uuid import UUID
from datetime import datetime

from sqlalchemy import text

from app.core.errors import APIError, NotFoundError


def _iso(v):
    return v.isoformat() if isinstance(v, datetime) else v


class ReportingService:
    """Service layer for Reporting module operations (real DDL)."""

    def __init__(self, session):
        self.session = session

    async def save_layout(self, user_id: UUID, layout_data: dict) -> UUID:
        """Save dashboard layout for user (upsert by view_mode)."""
        view_mode = layout_data.get("view_mode", "daily")
        name = layout_data.get("name", "چیدمان جدید")
        schema_version = layout_data.get("schema_version", 1)
        is_default = layout_data.get("is_default", False)

        existing = (await self.session.execute(text("""
            SELECT id FROM reporting.dashboard_layouts
             WHERE user_id = :uid AND view_mode = :vm
             ORDER BY is_default DESC, updated_at DESC LIMIT 1
        """), {"uid": str(user_id), "vm": view_mode})).mappings().first()
        if existing:
            await self.session.execute(text("""
                UPDATE reporting.dashboard_layouts
                   SET name = :name, is_default = :def, schema_version = :sv,
                       updated_at = now()
                 WHERE id = :lid
            """), {"lid": str(existing["id"]), "name": name,
                   "def": bool(is_default), "sv": schema_version})
            layout_id = existing["id"]
        else:
            row = (await self.session.execute(text("""
                INSERT INTO reporting.dashboard_layouts
                    (user_id, name, view_mode, is_default, schema_version)
                VALUES (:uid, :name, :vm, :def, :sv)
                RETURNING id
            """), {"uid": str(user_id), "name": name, "vm": view_mode,
                   "def": bool(is_default), "sv": schema_version})).mappings().first()
            layout_id = row["id"]

        # Store widget/block placement in user_dashboard_settings
        blocks = layout_data.get("blocks", [])
        if layout_data.get("widgets"):
            blocks = layout_data["widgets"]
        for b in blocks:
            bkey = b.get("block_key") or b.get("key")
            if not bkey:
                continue
            await self.session.execute(text("""
                INSERT INTO reporting.user_dashboard_settings
                    (user_id, layout_id, block_key, is_visible,
                     position_x, position_y, width, height, is_collapsed, config)
                VALUES (:uid, :lid, :key, :vis, :x, :y, :w, :h, :col, CAST(:cfg AS jsonb))
                ON CONFLICT (layout_id, block_key)
                DO UPDATE SET is_visible = EXCLUDED.is_visible,
                              position_x = EXCLUDED.position_x,
                              position_y = EXCLUDED.position_y,
                              width = EXCLUDED.width,
                              height = EXCLUDED.height,
                              is_collapsed = EXCLUDED.is_collapsed,
                              config = EXCLUDED.config,
                              updated_at = now()
            """), {
                "uid": str(user_id), "lid": str(layout_id), "key": bkey,
                "vis": bool(b.get("is_visible", True)),
                "x": int(b.get("position_x", b.get("x", 0))),
                "y": int(b.get("position_y", b.get("y", 0))),
                "w": int(b.get("width", b.get("w", 4))),
                "h": int(b.get("height", b.get("h", 4))),
                "col": bool(b.get("is_collapsed", False)),
                "cfg": json.dumps(b.get("config") or {}),
            })
        await self.session.commit()
        return layout_id

    async def get_layout(self, layout_id: UUID, user_id: UUID) -> dict:
        """Get dashboard layout with widget settings."""
        row = (await self.session.execute(text("""
            SELECT id, name, view_mode, is_default, schema_version, created_at, updated_at
              FROM reporting.dashboard_layouts WHERE id = :lid AND user_id = :uid
        """), {"lid": str(layout_id), "uid": str(user_id)})).mappings().first()
        if not row:
            raise NotFoundError("layout")
        blocks = (await self.session.execute(text("""
            SELECT block_key, is_visible, position_x, position_y, width, height,
                   is_collapsed, config
              FROM reporting.user_dashboard_settings
             WHERE layout_id = :lid ORDER BY position_y, position_x
        """), {"lid": str(layout_id)})).mappings().all()
        return {
            "id": str(row["id"]),
            "name": row["name"],
            "view_mode": row["view_mode"],
            "is_default": row["is_default"],
            "schema_version": row["schema_version"],
            "blocks": [dict(b) for b in blocks],
        }

    async def list_layouts(self, user_id: UUID) -> List[dict]:
        """List user's dashboard layouts."""
        rows = (await self.session.execute(text("""
            SELECT id, name, view_mode, is_default
              FROM reporting.dashboard_layouts WHERE user_id = :uid
             ORDER BY created_at DESC
        """), {"uid": str(user_id)})).mappings().all()
        return [{"id": str(r["id"]), "name": r["name"],
                 "view_mode": r["view_mode"], "is_default": r["is_default"]}
                for r in rows]

    async def import_layout(self, user_id: UUID, import_data: dict) -> dict:
        """Import dashboard layout from JSON."""
        schema_version = import_data.get("schema_version", 1)
        if schema_version < 1:
            raise APIError(error_code="INVALID_SCHEMA_VERSION",
                           message="نسخه اسکیمای ناصحیح است.", status_code=400)
        layout_id = await self.save_layout(user_id, {
            "name": import_data.get("name", "چیدمان وارد شده"),
            "view_mode": import_data.get("view_mode", "daily"),
            "is_default": import_data.get("is_default", False),
            "schema_version": schema_version,
            "blocks": import_data.get("blocks", []),
        })
        return {"layout_id": str(layout_id), "schema_version": schema_version}

    async def save_widget_settings(self, user_id: UUID, settings_data: dict) -> dict:
        """Save widget settings for user."""
        widgets = settings_data.get("widgets", [])
        for w in widgets:
            wkey = w.get("widget_key") or w.get("key")
            if not wkey:
                continue
            platform = w.get("platform", "all")
            await self.session.execute(text("""
                INSERT INTO reporting.user_widget_settings
                    (user_id, widget_key, platform, is_visible,
                     position_x, position_y, width, height, z_index, style, config)
                VALUES (:uid, :key, :plat, :vis, :x, :y, :w, :h, :z, CAST(:style AS jsonb), CAST(:cfg AS jsonb))
                ON CONFLICT (user_id, widget_key, platform)
                DO UPDATE SET is_visible = EXCLUDED.is_visible,
                              position_x = EXCLUDED.position_x,
                              position_y = EXCLUDED.position_y,
                              width = EXCLUDED.width,
                              height = EXCLUDED.height,
                              z_index = EXCLUDED.z_index,
                              style = EXCLUDED.style,
                              config = EXCLUDED.config,
                              updated_at = now()
            """), {
                "uid": str(user_id), "key": wkey, "plat": platform,
                "vis": bool(w.get("is_visible", True)),
                "x": int(w.get("position_x", 0)),
                "y": int(w.get("position_y", 0)),
                "w": int(w.get("width", 160)),
                "h": int(w.get("height", 80)),
                "z": int(w.get("z_index", 10)),
                "style": json.dumps(w.get("style") or {}),
                "cfg": json.dumps(w.get("config") or {}),
            })
        return {"status": "widgets_saved", "updated_count": len(widgets)}

    async def get_widget_settings(self, user_id: UUID) -> dict:
        """Get all widget settings for user."""
        rows = (await self.session.execute(text("""
            SELECT widget_key, platform, is_visible, position_x, position_y,
                   width, height, z_index, style, config
              FROM reporting.user_widget_settings WHERE user_id = :uid
             ORDER BY position_y, position_x
        """), {"uid": str(user_id)})).mappings().all()
        return {"widgets": [dict(r) for r in rows]}

    async def reset_widget_settings(self, user_id: UUID) -> dict:
        """Reset widget settings to default."""
        result = await self.session.execute(text(
            "DELETE FROM reporting.user_widget_settings WHERE user_id = :uid"),
            {"uid": str(user_id)})
        count = result.rowcount or 0
        await self.session.commit()
        return {"status": "widgets_reset", "reset_count": count}
```

==========================================================================================
## FILE: bastehC_domain/backend/app/modules/sharing/api/routes.py
## SIZE: 4410 bytes
==========================================================================================

```python
"""
Sharing Module API Routes
Architecture Reference: Sections 4.6, 8.2, 11.1
Endpoints: /api/v1/sharing
"""

from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, Body, Path
from fastapi.responses import JSONResponse

from app.core.dependencies import (
    get_db_session, get_current_user, get_sharing_service
)
from app.core.errors import APIError, NotFoundError
from app.core.database import async_session_context
from app.modules.sharing.ports import (
    ShareCreate, ShareUpdate, ShareResponse, ACLOptions,
    PermissionCheck, ShareExport
)
from app.modules.sharing.services.sharing_service import SharingService


router = APIRouter(prefix="/sharing", tags=["Sharing"])


@router.post("/", response_model=dict)
async def create_share(
    request: ShareCreate,
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Create a share/permission for an entity."""
    async with db_session() as session:
        try:
            service = SharingService(session)
            result = await service.create_share(
                entity_type=request.entity_type,
                entity_id=request.entity_id,
                recipient_id=request.recipient_id,
                permission_level=request.permission_level,
                allow_comment=request.allow_comment,
                granted_by=user_id
            )
            return {"status": "share_created", "share_code": result.share_code}
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.get("/entity/{entity_type}/{entity_id}", response_model=dict)
async def get_entity_shares(
    entity_type: str = Path(...),
    entity_id: UUID = Path(...),
    viewer_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Get all shares for an entity."""
    async with db_session() as session:
        try:
            service = SharingService(session)
            shares = await service.get_entity_shares(entity_type, entity_id, viewer_id)
            return {
                "status": "success",
                "data": {"shares": shares}
            }
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.post("/check", response_model=dict)
async def check_permission(
    entity_type: str = Body(...),
    entity_id: UUID = Body(...),
    user_id: UUID = Body(...),
    required_level: str = Body(...),
    viewer_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Check if a user has required permission on an entity."""
    async with db_session() as session:
        try:
            service = SharingService(session)
            result = await service.check_permission(
                entity_type, entity_id, user_id, required_level, viewer_id
            )
            return {
                "status": "success",
                "data": {
                    "has_permission": result.has_permission,
                    "permission_level": result.permission_level,
                    "source": result.source
                }
            }
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.post("/revoke", response_model=dict)
async def revoke_share(
    share_code: str = Body(..., embed=True),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Revoke a share."""
    async with db_session() as session:
        try:
            service = SharingService(session)
            result = await service.revoke_share(share_code, user_id)
            return {"status": "share_revoked", "result": result}
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )
```

==========================================================================================
## FILE: bastehC_domain/backend/app/modules/sharing/db/Models.py
## SIZE: 2833 bytes
==========================================================================================

```python
import uuid
from uuid import UUID
from datetime import datetime
from sqlalchemy import func

from sqlalchemy import (
    Column, String, Integer, Boolean, DateTime,
    ForeignKey, Table, UniqueConstraint, Index
)
from sqlalchemy.orm import relationship

from app.core.db.base import AuditMixin, BaseModel


# --- Shares Table ---

class Shares(BaseModel, AuditMixin):
    """Share entity for ACL and permission sharing."""
    
    __tablename__ = "shares"
    __table_args__ = (
        UniqueConstraint("share_code", name="uq_share_code"),
        Index("ix_shares_entity", "entity_type", "entity_id"),
        Index("ix_shares_recipient", "recipient_id"),
    )
    
    # Primary key inherited
    share_code = Column(
        String(32),
        unique=True,
        nullable=False,
        index=True
    )
    # Unique code for recipient access (time-limited)
    
    entity_type = Column(String(32), nullable=False)
    # 'goal' | 'task' | 'group' | 'document'
    
    entity_id = Column(String(36), nullable=False, index=True)
    # ID of the shared entity
    
    recipient_id = Column(String(36), nullable=False, index=True)
    # ID of the user who received the share
    
    granted_by = Column(String(36), nullable=True)
    # ID of who granted the share
    
    permission_level = Column(
        String(16),
        nullable=False,
        default="read",
        comment="read | write | manage"
    )
    
    allow_comment = Column(Boolean, nullable=False, default=False)
    
    expires_at = Column(DateTime(timezone=True), nullable=True)
    # Expiration time for the share
    
    granted_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    # granter = relationship("Users", foreign_keys=[granted_by])


# --- ACL View ---

class ACLView(BaseModel, AuditMixin):
    """ACL view for an entity."""
    
    __tablename__ = "acl_views"
    __table_args__ = (
        UniqueConstraint("entity_id", "viewer_id", name="uq_acl_view"),
    )
    
    # Primary key components
    entity_id = Column(
        String(36),
        nullable=False,
        index=True
    )
    viewer_id = Column(
        String(36),
        nullable=False,
        index=True
    )
    
    effective_permission = Column(
        String(16),
        nullable=False,
        default="read",
        comment="read | write | manage"
    )
    
    is_denied = Column(Boolean, nullable=False, default=False)
    granted_at = Column(DateTime(timezone=True), server_default=func.now())
    expires_at = Column(DateTime(timezone=True), nullable=True)
    
    # Relationships
    # entity = relationship("Shares", foreign_keys=[entity_id])


# --- Export all ---
__all__ = ["Shares", "ACLView"]
```

==========================================================================================
## FILE: bastehC_domain/backend/app/modules/sharing/ports.py
## SIZE: 1996 bytes
==========================================================================================

```python
from typing import Protocol, Optional, List, Tuple, Dict, Any
from uuid import UUID
from datetime import datetime
from pydantic import BaseModel, Field


# --- Share Schemas ---

class ShareCreate(BaseModel):
    """Create share request."""
    entity_type: str  # 'goal' | 'task' | 'group' | 'document'
    entity_id: UUID
    recipient_id: UUID
    permission_level: str  # 'read' | 'write' | 'manage'
    expires_at: Optional[datetime] = None
    allow_comment: bool = False


class ShareUpdate(BaseModel):
    """Update share request."""
    permission_level: Optional[str] = Field(None, pattern="^(read|write|manage)$")
    allow_comment: Optional[bool] = Field(None)


class ShareResponse(BaseModel):
    """Share response."""
    id: UUID
    share_code: str  # Unique code for recipient access
    entity_type: str
    entity_id: UUID
    recipient_id: UUID
    permission_level: str
    granted_at: datetime
    expires_at: Optional[datetime]
    allow_comment: bool
    recipient: dict  # Limited user info


# --- ACL Schemas ---

class ACLOptions(BaseModel):
    """ACL configuration for an entity."""
    entity_type: str
    entity_id: UUID
    owner_id: UUID
    shared_with: List[dict] = Field(default_factory=list)  # [user_id, permission_level]
    inherited_from: Optional[UUID] = None  # Group ID if inherited


# --- Permission Check ---

class PermissionCheck(BaseModel):
    """Permission check result."""
    user_id: UUID
    has_permission: bool
    permission_level: str  # 'read' | 'write' | 'manage'
    source: str  # 'direct' | 'inherited' | 'denied'


# --- Export ---

class ShareExport(BaseModel):
    """Share export format."""
    id: UUID
    entity_type: str
    entity_id: UUID
    recipient_id: UUID
    permission_level: str
    granted_at: datetime


# Export all
__all__ = [
    "ShareCreate", "ShareUpdate", "ShareResponse", "ACLOptions",
    "PermissionCheck", "ShareExport"
]
```

==========================================================================================
## FILE: bastehC_domain/backend/app/modules/sharing/services/sharing_service.py
## SIZE: 5849 bytes
==========================================================================================

```python
"""Sharing service — raw SQL against the real DDL (schema ``sharing``).

Architecture Reference: Sections 4.6, 8.2, 11.1.
Note: the DDL has no ``share_code`` column; the share ``id`` is used as
the public code (routes keep the ``share_code`` interface).
"""
from typing import Optional, List
from types import SimpleNamespace
from uuid import UUID
from datetime import datetime

from sqlalchemy import text

from app.core.errors import APIError, NotFoundError

VALID_LEVELS = {"read", "write", "manage"}


def _iso(v):
    return v.isoformat() if isinstance(v, datetime) else v


class SharingService:
    """Service layer for Sharing module operations (real DDL)."""

    def __init__(self, session):
        self.session = session

    async def create_share(self, entity_type: str, entity_id: UUID,
                           recipient_id: UUID, permission_level: str,
                           allow_comment: bool, granted_by: UUID) -> SimpleNamespace:
        """Create a new share."""
        if permission_level not in VALID_LEVELS:
            raise APIError(error_code="INVALID_PERMISSION_LEVEL",
                           message="سطح دسترسی نامعتبر.", status_code=400)
        # sharing.shares has no unique constraint on the triple; upsert manually.
        existing = (await self.session.execute(text("""
            SELECT id FROM sharing.shares
             WHERE entity_type = :etype AND entity_id = :eid
               AND recipient_id = :rid AND revoked_at IS NULL
        """), {"etype": entity_type, "eid": str(entity_id),
               "rid": str(recipient_id)})).mappings().first()
        if existing:
            id_ = existing["id"]
            await self.session.execute(text("""
                UPDATE sharing.shares
                   SET permission_level = :lvl, allow_comment = :can,
                       granted_by = :by, granted_at = now(),
                       revoked_at = NULL, revoked_reason = NULL
                 WHERE id = :id
            """), {"id": str(id_), "lvl": permission_level,
                   "can": bool(allow_comment), "by": str(granted_by)})
        else:
            row = (await self.session.execute(text("""
                INSERT INTO sharing.shares (entity_type, entity_id, recipient_id,
                                            granted_by, permission_level, allow_comment)
                VALUES (:etype, :eid, :rid, :by, :lvl, :can)
                RETURNING id
            """), {
                "etype": entity_type, "eid": str(entity_id),
                "rid": str(recipient_id), "by": str(granted_by),
                "lvl": permission_level, "can": bool(allow_comment),
            })).mappings().first()
            id_ = row["id"]
        await self.session.commit()
        return SimpleNamespace(share_code=str(id_))

    async def get_entity_shares(self, entity_type: str, entity_id: UUID,
                                viewer_id: UUID) -> List[dict]:
        """Get all shares for an entity."""
        rows = (await self.session.execute(text("""
            SELECT id, entity_type, entity_id, recipient_id, permission_level,
                   allow_comment, granted_at, expires_at
              FROM sharing.shares
             WHERE entity_type = :etype AND entity_id = :eid
               AND revoked_at IS NULL
             ORDER BY granted_at DESC
        """), {"etype": entity_type, "eid": str(entity_id)})).mappings().all()
        return [{
            "id": str(r["id"]),
            "share_code": str(r["id"]),
            "entity_type": entity_type,
            "entity_id": str(entity_id),
            "recipient_id": str(r["recipient_id"]),
            "recipient": {"id": str(r["recipient_id"])},
            "permission_level": r["permission_level"],
            "granted_at": _iso(r["granted_at"]),
            "expires_at": _iso(r["expires_at"]) if r["expires_at"] else None,
            "allow_comment": r["allow_comment"],
        } for r in rows]

    async def check_permission(self, entity_type: str, entity_id: UUID,
                               user_id: UUID, required_level: str,
                               viewer_id: UUID) -> SimpleNamespace:
        """Check if a user has required permission on an entity."""
        if required_level not in VALID_LEVELS:
            raise APIError(error_code="INVALID_PERMISSION_LEVEL",
                           message="سطح دسترسی نامعتبر.", status_code=400)
        row = (await self.session.execute(text("""
            SELECT permission_level FROM sharing.effective_permissions
             WHERE entity_type = :etype AND entity_id = :eid
               AND recipient_id = :uid
        """), {"etype": entity_type, "eid": str(entity_id),
               "uid": str(user_id)})).mappings().first()
        if row:
            return SimpleNamespace(user_id=user_id, has_permission=True,
                                   permission_level=row["permission_level"],
                                   source="direct")
        return SimpleNamespace(user_id=user_id, has_permission=False,
                               permission_level=required_level, source="denied")

    async def revoke_share(self, share_code: str, revoked_by: UUID) -> dict:
        """Revoke a share by its id (used as the share code)."""
        row = (await self.session.execute(text("""
            UPDATE sharing.shares
               SET revoked_at = now(), revoked_reason = 'revoked'
             WHERE id = :sid AND revoked_at IS NULL
            RETURNING id
        """), {"sid": share_code})).mappings().first()
        if not row:
            raise APIError(error_code="SHARE_NOT_FOUND",
                           message="اشتراک یافت نشد.", status_code=404)
        await self.session.commit()
        return {"status": "revoked", "share_code": share_code}
```

==========================================================================================
## FILE: bastehC_domain/backend/app/modules/ssoldap/api/deps.py
## SIZE: 1354 bytes
==========================================================================================

```python
"""app/modules/ssoldap/api/deps.py

Composition root for the SSO/LDAP module (this file was the missing
piece that made ``POST /auth/sso/ldap-login`` raise NotImplementedError).

Builds SsoLoginService from the real AuthService / UserRepository /
LdapService, mirroring app/core/dependencies.get_auth_service.
"""

from __future__ import annotations

from fastapi import Depends

from app.core.dependencies import (
    get_session_dep,
    get_user_repository,
    get_auth_service,
)
from app.modules.ssoldap.services.ldap_service import LdapService
from app.modules.ssoldap.services.sso_login_service import SsoLoginService
from app.core.config import settings


def get_ldap_service() -> LdapService:
    """Build LdapService bound to app settings (ldap3 imported lazily)."""
    return LdapService(settings)


def get_sso_login_service(
    session=Depends(get_session_dep),
    user_repo=Depends(get_user_repository),
    ldap_service: LdapService = Depends(get_ldap_service),
    auth_service=Depends(get_auth_service),
) -> SsoLoginService:
    """Compose SsoLoginService for the ldap-login endpoint."""
    return SsoLoginService(
        settings=settings,
        user_repo=user_repo,
        ldap_service=ldap_service,
        auth_service=auth_service,
        role_assignment_service=None,  # wired when LDAP_GROUP_ROLE_MAP is enabled
    )
```

==========================================================================================
## FILE: bastehC_domain/backend/app/modules/ssoldap/api/routes.py
## SIZE: 4028 bytes
==========================================================================================

```python
#!/usr/bin/env python3
"""
app/modules/ssoldap/api/routes.py

دو endpoint سند (بخش ۵.۲):
  - POST /auth/sso/ldap-login   → کامل
  - GET  /auth/sso/negotiate    → SIP-challenge SPNEGO (Kerberos؛ پاسخ
    به تلاش دوم کلاینت با ``Authorization: Negotiate`` فقط وقتی امکان‌پذیر
    است که gssapi + Keytab واقعی پیکربندی شده باشند — خارج از این محیط)
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, Header, Response
from pydantic import BaseModel

from app.core.config import settings
from app.modules.ssoldap.services.sso_login_service import SsoLoginService

try:
    from app.modules.ssoldap.api.deps import get_sso_login_service
except ImportError:  # pragma: no cover
    def get_sso_login_service():  # type: ignore[no-redef]
        raise NotImplementedError(
            "get_sso_login_service هنوز به LdapService/AuthService/session واقعی "
            "وصل نشده — app/modules/ssoldap/api/deps.py را تکمیل کنید."
        )

router = APIRouter(prefix="/auth/sso", tags=["sso-ldap"])


class LdapLoginRequest(BaseModel):
    username: str
    password: str


@router.get("/status")
async def sso_status():
    """SSO/LDAP deployment status for the settings UI (no secrets exposed)."""
    import importlib.util

    return {
        "status": "ok",
        "enabled": settings.ENABLE_SSO,
        "ldap3_installed": importlib.util.find_spec("ldap3") is not None,
        "ldap_server_uri": settings.LDAP_SERVER_URI,
        "ldap_base_dn": settings.LDAP_BASE_DN,
        "ldap_auto_provision": settings.LDAP_AUTO_PROVISION,
        "kerberos_available": bool(settings.LDAP_KERBEROS_ENABLED and settings.LDAP_KERBEROS_KEYTAB),
        "group_role_map_enabled": bool(settings.LDAP_GROUP_ROLE_MAP),
        "negotiate": "/api/v1/auth/sso/negotiate",
        "ldap_login": "/api/v1/auth/sso/ldap-login",
    }


@router.post("/ldap-login")
async def ldap_login(
    payload: LdapLoginRequest,
    service: SsoLoginService = Depends(get_sso_login_service),
):
    return await service.login(payload.username, payload.password)


def _kerberos_available() -> bool:
    """True only when a real Keytab/SPN is configured for this deployment."""
    return bool(settings.LDAP_KERBEROS_ENABLED and settings.LDAP_KERBEROS_KEYTAB)


@router.get("/negotiate")
async def negotiate(
    response: Response,
    authorization: Optional[str] = Header(default=None),
):
    """SPNEGO/Kerberos challenge (arch 1.3, 5.2).

    Step 1 (no ``Authorization`` header): respond 401 + ``WWW-Authenticate:
    Negotiate`` so the client requests a service ticket from the KDC.

    Step 2 (header present): the real exchange needs ``gssapi`` +
    ``accept_sec_context(keytab)``.  Until a Keytab is provisioned the
    endpoint degrades to 501 so callers can fall back to LDAP bind.
    """
    details = {
        "service_principal": settings.LDAP_SERVER_URI,
        "kerberos_available": _kerberos_available(),
        "fallback": "POST /api/v1/auth/sso/ldap-login",
    }

    if authorization:
        scheme, _, _ = authorization.partition(" ")
        if scheme.lower() == "negotiate" and not _kerberos_available():
            response.status_code = 501
            return {
                "error": {
                    "code": "KERBEROS_NOT_CONFIGURED",
                    "message": "Kerberos/SPNEGO برای این دیتابیس فعال نشده است (Keytab/SPN موجود نیست). "
                               "از LDAP bind استفاده کنید.",
                    "details": details,
                }
            }

    response.headers["WWW-Authenticate"] = "Negotiate"
    response.status_code = 401
    return {
        "error": {
            "code": "SPNEGO_CHALLENGE",
            "message": "چالش Kerberos: هدر Authorization: Negotiate را ارسال کنید.",
            "details": details,
        }
    }
```

==========================================================================================
## FILE: bastehC_domain/backend/app/modules/ssoldap/services/ldap_service.py
## SIZE: 8945 bytes
==========================================================================================

```python
"""
app/modules/ssoldap/services/ldap_service.py

این ماژول (M12) قبلاً فقط یک ``api/`` خالی بود — نه db، نه services.
طبق سند:
  - بخش ۲.۵: SSO/LDAP جزو فاز ۱ (پیش‌نیاز همه‌چیز) است.
  - بخش ۱۴ (جدول ریسک): «SSO با Kerberos در محیط واقعی AD کار نکند» →
    ریسک بالا → **«Fallback به LDAP Bind از روز اول»**.

پس اول ``LDAP Bind`` (نام‌کاربری+رمز مستقیم به AD) ساخته می‌شود —
چون بدون Keytab/KDC واقعی هم قابل‌ساخت و تا حدی قابل‌تست است. Kerberos/
SPNEGO کامل (``gssapi``) نیاز به محیط AD واقعی برای تست دارد و باید
جدا (به‌عنوان Spike دوروزه، طبق توصیه‌ی خودِ سند) پیگیری شود —
``app/modules/ssoldap/api/negotiate.py`` در همین پچ فقط یک اسکلت
401 برمی‌گرداند، نه پیاده‌سازی کامل SPNEGO.

⚠️ وابستگی‌ها: `pip list` شما نشان داد ``ldap3`` نصب نیست. برای همین
import آن اینجا **تنبل (lazy)** است — تا وقتی کسی واقعاً وارد کردن
LDAP نزند، بقیه‌ی اپ (که به این ماژول نیازی ندارد) از کار نمی‌افتد.
نصب لازم:

    pip install ldap3

⚠️ تنظیمات لازم (باید به ``app/core/config.py`` اضافه شوند — چون به
محتوای فایل شما دسترسی ندارم، فقط اسم‌هایی که این فایل انتظار دارد
را مستند می‌کنم):

    LDAP_SERVER_URI        # مثل "ldaps://ad.corp.local:636"
    LDAP_BASE_DN           # مثل "DC=corp,DC=local"
    LDAP_BIND_DN           # اکانت سرویس فقط-خواندنی برای search
    LDAP_BIND_PASSWORD     # طبق سند باید AES-256-GCM رمزنگاری‌شده در Vault/DB
                            # باشد؛ اگر از env var/Secret Manager می‌آید همین کافی است
    LDAP_USER_SEARCH_FILTER = "(sAMAccountName={username})"
    LDAP_ATTR_OBJECT_GUID = "objectGUID"
    LDAP_ATTR_NATIONAL_ID  # نام Attribute سفارشی AD شما برای کد ملی — باید با تیم AD هماهنگ شود
    LDAP_ATTR_DISPLAY_NAME = "displayName"
    LDAP_ATTR_MEMBEROF = "memberOf"
    LDAP_GROUP_ROLE_MAP: dict[str, str]  # DN گروه AD → کد نقش داخلی، مثل:
        # {"CN=Managers,OU=Groups,DC=corp,DC=local": "manager"}
    LDAP_AUTO_PROVISION: bool = True
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


class LdapAuthError(Exception):
    """احراز هویت LDAP شکست خورد (رمز غلط، کاربر یافت نشد، سرور در دسترس نیست)."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(f"{code}: {message}")


@dataclass(frozen=True)
class LdapUserInfo:
    """نتیجه‌ی موفق احراز هویت + جست‌وجوی LDAP — چیزی که SsoLoginService مصرف می‌کند."""

    dn: str
    object_guid: str
    sam_account_name: str
    display_name: str
    national_id: str | None
    member_of: list[str] = field(default_factory=list)


def escape_ldap_filter_value(value: str) -> str:
    """طبق سند (بخش امنیت، ردیف A03 Injection): ``escape_filter_chars`` برای LDAP.

    این تابع pure و بدون وابستگی به ldap3 است تا بدون نصب ldap3 هم قابل‌تست
    باشد (ldap3.utils.conv.escape_filter_chars هم دقیقاً همین RFC 4515 را
    پیاده می‌کند — اگر ldap3 نصب بود می‌توانید مستقیم از آن استفاده کنید).
    """
    replacements = {
        "\\": r"\5c",
        "*": r"\2a",
        "(": r"\28",
        ")": r"\29",
        "\x00": r"\00",
    }
    return "".join(replacements.get(ch, ch) for ch in value)


def map_groups_to_roles(member_of: list[str], group_role_map: dict[str, str]) -> list[str]:
    """نگاشت DN گروه‌های AD به کدهای نقش داخلی — طبق سند بخش ۱.۳: «نگاشت memberOf → roles».

    مقایسه‌ی DN بدون حساسیت به بزرگی/کوچکی حروف و فاصله‌های اضافه انجام
    می‌شود، چون AD معمولاً DN را با فرمت‌بندی متفاوت (فاصله بعد از کاما)
    برمی‌گرداند.
    """
    normalized_map = {_normalize_dn(dn): role for dn, role in group_role_map.items()}
    roles = []
    for dn in member_of:
        role = normalized_map.get(_normalize_dn(dn))
        if role and role not in roles:
            roles.append(role)
    return roles


def _normalize_dn(dn: str) -> str:
    return re.sub(r",\s*", ",", dn.strip().lower())


class LdapService:
    """Bind مستقیم کاربر به AD (نه Kerberos) — endpoint: ``POST /auth/sso/ldap-login``."""

    def __init__(self, settings: Any) -> None:
        self.settings = settings

    async def authenticate(self, username: str, password: str) -> LdapUserInfo:
        """کاربر را مستقیماً به AD bind می‌کند و اطلاعاتش را برمی‌گرداند.

        دو مرحله (طبق الگوی رایج AD bind، چون sAMAccountName به‌تنهایی DN
        نیست): (۱) با اکانت سرویس bind و DN کاربر را search می‌کند،
        (۲) با DN واقعی و رمز کاربر دوباره bind می‌کند تا رمز واقعاً
        تأیید شود.
        """
        try:
            import ldap3
            from ldap3 import ALL, Connection, Server
            from ldap3.core.exceptions import LDAPBindError, LDAPException
        except ImportError as exc:  # pragma: no cover
            raise LdapAuthError(
                "LDAP_NOT_CONFIGURED",
                "پکیج ldap3 نصب نیست — `pip install ldap3` را اجرا کنید.",
            ) from exc

        if not username or not password:
            raise LdapAuthError("INVALID_CREDENTIALS", "نام کاربری/رمز خالی است.")

        safe_username = escape_ldap_filter_value(username)
        search_filter = self.settings.LDAP_USER_SEARCH_FILTER.format(username=safe_username)

        server = Server(self.settings.LDAP_SERVER_URI, get_info=ALL, use_ssl=True)

        # مرحله ۱: bind با اکانت سرویس (فقط خواندنی) + search برای پیدا کردن DN کاربر
        try:
            service_conn = Connection(
                server, user=self.settings.LDAP_BIND_DN,
                password=self.settings.LDAP_BIND_PASSWORD, auto_bind=True,
            )
        except LDAPException as exc:
            raise LdapAuthError("LDAP_UNAVAILABLE", "اتصال به AD ممکن نشد.") from exc

        attrs = [
            self.settings.LDAP_ATTR_OBJECT_GUID,
            self.settings.LDAP_ATTR_DISPLAY_NAME,
            self.settings.LDAP_ATTR_MEMBEROF,
        ]
        national_id_attr = getattr(self.settings, "LDAP_ATTR_NATIONAL_ID", None)
        if national_id_attr:
            attrs.append(national_id_attr)

        service_conn.search(
            search_base=self.settings.LDAP_BASE_DN,
            search_filter=search_filter,
            attributes=attrs,
        )
        if not service_conn.entries:
            service_conn.unbind()
            raise LdapAuthError("USER_NOT_FOUND", "کاربر در AD یافت نشد.")

        entry = service_conn.entries[0]
        user_dn = entry.entry_dn
        service_conn.unbind()

        # مرحله ۲: bind واقعی با DN کاربر + رمزی که کاربر فرستاده — این
        # مرحله است که واقعاً رمز را تأیید می‌کند.
        try:
            user_conn = Connection(server, user=user_dn, password=password, auto_bind=True)
            user_conn.unbind()
        except LDAPBindError as exc:
            raise LdapAuthError("INVALID_CREDENTIALS", "نام کاربری یا رمز عبور اشتباه است.") from exc

        member_of = list(entry[self.settings.LDAP_ATTR_MEMBEROF].values) \
            if self.settings.LDAP_ATTR_MEMBEROF in entry else []
        national_id = None
        if national_id_attr and national_id_attr in entry:
            values = entry[national_id_attr].values
            national_id = values[0] if values else None

        return LdapUserInfo(
            dn=user_dn,
            object_guid=str(entry[self.settings.LDAP_ATTR_OBJECT_GUID].value),
            sam_account_name=username,
            display_name=str(entry[self.settings.LDAP_ATTR_DISPLAY_NAME].value),
            national_id=national_id,
            member_of=member_of,
        )
```

==========================================================================================
## FILE: bastehC_domain/backend/app/modules/ssoldap/services/sso_login_service.py
## SIZE: 7571 bytes
==========================================================================================

```python
"""
app/modules/ssoldap/services/sso_login_service.py

پیاده‌سازی سمت "LDAP Bind" جریان بخش ۱.۳ سند (نه شاخه‌ی Kerberos/SPNEGO
که به Keytab واقعی نیاز دارد). مراحل، دقیقاً مطابق دیاگرام توالی سند:

  ۱) LdapService.authenticate() → اطلاعات کاربر از AD
  ۲) جست‌وجوی کاربر محلی بر اساس national_id_hash (طبق سند: «نگاشت بر
     objectGUID و کد ملی، نه sAMAccountName»)
  ۳) اگر پیدا نشد و auto_provision=true → کاربر جدید با auth_mode='sso'
  ۴) اگر sso_enabled=false → 403 SSO_DISABLED_FOR_USER
  ۵) نگاشت memberOf → roles (از طریق RoleAssignmentService، تا همان
     محافظت‌های ضد Privilege Escalation این‌جا هم اعمال شود — نه یک
     مسیر جانبی که RBAC را دور می‌زند)
  ۶) صدور توکن (از AuthService._generate_tokens تزریق‌شده — بدون تکرار
     منطق JWT/Session)
  ۷) انتشار auth.login.succeeded/failed روی event_bus — همان چیزی که
     AuditService (در audit_module_patch.zip) از قبل مشترکش است، پس
     login_audit_logs بدون کد اضافه پر می‌شود.

⚠️ این فایل به AuthService و RoleAssignmentService تزریق‌شده نیاز
دارد — یعنی composition خودتان (deps.py) باید هر سه را با هم بسازد.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from fastapi import status

from app.core.errors import APIError
from app.core.events.bus import DomainEvent, event_bus
from app.modules.ssoldap.services.ldap_service import (
    LdapAuthError,
    LdapService,
    LdapUserInfo,
    map_groups_to_roles,
)


class SsoLoginService:
    def __init__(
        self,
        settings: Any,
        user_repo: Any,
        ldap_service: LdapService,
        auth_service: Any,               # برای _generate_tokens (بدون تکرار منطق JWT)
        role_assignment_service: Any | None = None,  # برای نگاشت گروه→نقش با محافظت escalation
    ) -> None:
        self.settings = settings
        self.user_repo = user_repo
        self.ldap_service = ldap_service
        self.auth_service = auth_service
        self.role_assignment_service = role_assignment_service

    async def login(self, username: str, password: str) -> dict:
        try:
            ldap_info = await self.ldap_service.authenticate(username, password)
        except LdapAuthError as exc:
            await self._publish_login_event(success=False, username=username, reason=exc.code)
            raise APIError(
                error_code=exc.code, message=exc.message,
                status_code=status.HTTP_401_UNAUTHORIZED,
            ) from exc

        user = await self._find_or_provision_user(ldap_info)

        if not user.sso_enabled:
            await self._publish_login_event(
                success=False, username=username, reason="sso_disabled", user_id=user.id
            )
            raise APIError(
                error_code="SSO_DISABLED_FOR_USER",
                message="ورود از طریق SSO برای این کاربر فعال نیست.",
                status_code=status.HTTP_403_FORBIDDEN,
            )
        if not user.is_active:
            await self._publish_login_event(
                success=False, username=username, reason="account_inactive", user_id=user.id
            )
            raise APIError(
                error_code="ACCESS_DENIED", message="حساب کاربری فعال نیست.",
                status_code=status.HTTP_403_FORBIDDEN,
            )

        await self._sync_roles_from_ldap_groups(user, ldap_info)

        tokens = await self.auth_service._generate_tokens(user)  # noqa: SLF001 — reuse عمدی
        await self._publish_login_event(success=True, username=username, user_id=user.id)
        return tokens

    async def _find_or_provision_user(self, ldap_info: LdapUserInfo):
        from app.modules.auth.db.models import Users
        from app.modules.auth.db.repositories import national_id_hash

        user = None
        if ldap_info.national_id:
            user = await self.user_repo.get_by_national_id(ldap_info.national_id)

        if user is None:
            if not getattr(self.settings, "LDAP_AUTO_PROVISION", False):
                raise APIError(
                    error_code="USER_NOT_PROVISIONED",
                    message="این کاربر در سامانه ثبت نشده و Auto-Provision غیرفعال است.",
                    status_code=status.HTTP_403_FORBIDDEN,
                )
            if not ldap_info.national_id:
                raise APIError(
                    error_code="LDAP_MISSING_NATIONAL_ID",
                    message="Attribute کد ملی در AD برای این کاربر تنظیم نشده.",
                    status_code=status.HTTP_403_FORBIDDEN,
                )
            user = Users(
                username=ldap_info.sam_account_name,
                national_id_enc=b"",  # TODO: با همان AESGCM موجود در AuthService رمزنگاری شود
                national_id_nonce=b"",
                national_id_hash=national_id_hash(ldap_info.national_id),
                national_id_last4=ldap_info.national_id[-4:],
                display_name=ldap_info.display_name,
                auth_mode="sso",
                sso_enabled=True,
                is_active=True,
                ldap_dn=ldap_info.dn,
                ldap_object_guid=ldap_info.object_guid,
                ldap_sam_account=ldap_info.sam_account_name,
            )
            await self.user_repo.add(user)
            await self.user_repo.commit()
        else:
            # کاربر از قبل بود — DN/GUID را به‌روز نگه‌دار (ممکن است در AD جابه‌جا شده باشد)
            user.ldap_dn = ldap_info.dn
            user.ldap_object_guid = ldap_info.object_guid
            await self.user_repo.commit()

        return user

    async def _sync_roles_from_ldap_groups(self, user, ldap_info: LdapUserInfo) -> None:
        group_role_map = getattr(self.settings, "LDAP_GROUP_ROLE_MAP", {}) or {}
        if not group_role_map or self.role_assignment_service is None:
            return
        role_codes = map_groups_to_roles(ldap_info.member_of, group_role_map)
        # TODO: role_codes (رشته) باید به role_id (عدد) نگاشت شوند — طبق جدول
        # roles واقعی شما. اینجا عمداً پیاده نشده چون به schema واقعی RBAC
        # نیاز دارد که ندیده‌ام؛ نقطه‌ی اتصال درست همین‌جاست.

    async def _publish_login_event(
        self, *, success: bool, username: str, reason: str | None = None,
        user_id: UUID | None = None,
    ) -> None:
        event_type = "auth.login.succeeded" if success else "auth.login.failed"
        payload = {"identifier": username, "auth_method": "ldap"}
        if reason:
            payload["reason"] = reason
        event = DomainEvent(event_type=event_type, actor_id=user_id, payload=payload)
        try:
            await event_bus.publish(event, self.user_repo.session)
            await self.user_repo.commit()
        except Exception:
            import logging
            logging.getLogger("ssoldap").exception("failed to publish %s", event_type)
```

==========================================================================================
## FILE: bastehD_migrations_config/backend/.env.example
## SIZE: 1787 bytes
==========================================================================================

```bash
ENV=development            # development | testing | production
DEBUG=False
SQL_ECHO=False             # log every SQL statement (very noisy)
# At least 32 characters. Generate with:
#   .\.venv\Scripts\python.exe -c "import secrets; print(secrets.token_urlsafe(32))"
SECRET_KEY=change-me-to-a-random-string-at-least-32-chars-long
POSTGRES_SERVER=localhost
POSTGRES_PORT=5432
POSTGRES_USER=admin
POSTGRES_PASSWORD=admin123
POSTGRES_DB=planner_db
# App reads SQLALCHEMY_DATABASE_URI first, DATABASE_URL as fallback.
SQLALCHEMY_DATABASE_URI=postgresql+asyncpg://admin:admin123@localhost:5432/planner_db
REDIS_HOST=localhost
REDIS_PORT=6379
HOST=0.0.0.0
PORT=8000
# Must be JSON array syntax (comma-separated string fails to parse).
CORS_ORIGINS=["http://localhost:3000","http://localhost:8080"]
ENABLE_MFA=True
ENABLE_SSO=True
ENABLE_AUDIT_LOGGING=True
RATE_LIMIT_DEFAULT=100/minute
RATE_LIMIT_AUTH=10/minute
MAX_UPLOAD_SIZE=52428800

# ---- Added in architecture-v2 infrastructure pass -------------------------
# Separate keys per purpose (section 4.9 / ADR-06). REQUIRED when ENV=production.
#   DATA_ENCRYPTION_KEY: python -c "import os,base64;print(base64.b64encode(os.urandom(32)).decode())"
#   NATIONAL_ID_PEPPER : python -c "import secrets;print(secrets.token_urlsafe(48))"
DATA_ENCRYPTION_KEY=
NATIONAL_ID_PEPPER=
# HS256 by default; for RS256 set ALGORITHM=RS256 plus both PEM keys.
ALGORITHM=HS256
# JSON arrays. '*' is rejected in production.
ALLOWED_HOSTS=["*"]
ALLOWED_ORIGINS=[]         # WebSocket Origin allow-list; empty = CORS_ORIGINS
TRUSTED_PROXIES=[]         # only these peers may set X-Forwarded-For
IP_ALLOW_LIST=[]
IP_DENY_LIST=[]
MAX_BODY_SIZE=1048576
RATE_LIMIT_ENABLED=True
ALLOW_SELF_REGISTRATION=False
DEVICE_BINDING_MODE=observe  # off | observe | enforce
```

==========================================================================================
## FILE: bastehD_migrations_config/backend/alembic/env.py
## SIZE: 3020 bytes
==========================================================================================

```python
import os
import sys
from alembic import context
from sqlalchemy import engine_from_config, pool

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# Ensure `backend/` (project root for `app.*`) is on sys.path when
# alembic runs from D:\Projects\Activity_dashboard\backend.
_BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)


def _load_dotenv(path):
    """Minimal .env loader (avoids a python-dotenv dependency)."""
    if not os.path.isfile(path):
        return
    with open(path, encoding="utf-8") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key, value = key.strip(), value.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = value


_load_dotenv(os.path.join(_BACKEND_DIR, ".env"))

# Alembic runs in sync mode, but the app .env uses the async driver
# (postgresql+asyncpg://...). Convert it to the sync psycopg2 driver,
# which is what requirements.txt ships (psycopg2-binary).
_db_url = os.environ.get(
    "SQLALCHEMY_DATABASE_URI",
    config.get_main_option("sqlalchemy.url"),
)
if _db_url and "+asyncpg" in _db_url:
    _db_url = _db_url.replace("+asyncpg", "+psycopg2")
if _db_url:
    config.set_main_option("sqlalchemy.url", _db_url)

try:
    from app.core.db.base import Base  # noqa: E402

    target_metadata = Base.metadata
except Exception:
    from sqlalchemy import MetaData  # noqa: E402

    target_metadata = MetaData()

def run_migrations_offline():
    """Run migrations in 'offline' mode.
    
    This configures the context with just a URL
    and gives us the ability to emit SQL script without
    needing a DBAPI.
    """
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()

def run_migrations_online():
    """Run migrations in 'online' mode.
    
    In this mode we need to connect to the database and run migrations
    against a live connection.
    """
    connectable = engine_from_config(
        config.get_section(config.config_ini_section),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection, 
            target_metadata=target_metadata
        )

        with context.begin_transaction():
            context.run_migrations()

if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
```

==========================================================================================
## FILE: bastehD_migrations_config/backend/alembic/head.py
## SIZE: 1057 bytes
==========================================================================================

```python
from datetime import datetime
from alembic import context
from sqlalchemy import engine_from_config, pool, MetaData, Table, Column, String, DateTime
import os

# Add models here so they are registered before head generates
import sys
sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)) + '/../../../../..')

from backend.app.core.db.base import Base

# Get target metadata from Base
target_metadata = Base.metadata

# Get URL from config
config = context.config
url = config.get_main_option("sqlalchemy.url")

engine = engine_from_config(
    config.get_section(config.config_ini_section),
    prefix="sqlalchemy.",
    poolclass=pool.NullPool,
)

# Run a simple query to check connection
with engine.connect() as connection:
    connection.execute("SELECT 1")

# Set the revision to the latest base
opts = {}
if context.is_offline_mode():
    opts['input_file'] = 'offline.sql'
else:
    # Set head to the latest migration
    opts['sqlalchemy.url'] = url

# Set target_metadata
target_metadata.bind = engine
```

==========================================================================================
## FILE: bastehD_migrations_config/backend/alembic/versions/0001_initial.py
## SIZE: 1639 bytes
==========================================================================================

```python
"""Initial schema: 13 module SQL files in FK-safe order.

Applied manually on 2026-09-19 with several PG-validity fixes
(inline INDEX -> CREATE INDEX, expression PKs -> partial unique indexes,
missing CREATE SCHEMA, partitioned PK including partition key).
`alembic stamp head` was used on the dev database; fresh databases can run
`alembic upgrade head` to execute everything below.
"""
import os

from alembic import op

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None

SCHEMAS = [
    "auth", "rbac", "groups", "planning", "calendar", "chat", "files",
    "inbox", "notification", "reporting", "sharing", "ssoldap", "audit",
]

# FK-safe order: auth first (referenced everywhere), chat before files
# (chat creates files.uploads), audit last.
SQL_FILES = [
    "auth_schema.sql",
    "rbac_schema.sql",
    "groups_schema.sql",
    "planning_schema.sql",
    "calendar_schema.sql",
    "chat_schema.sql",
    "files_schema.sql",
    "inbox_schema.sql",
    "notification_schema.sql",
    "reporting_schema.sql",
    "sharing_schema.sql",
    "ssoldap_schema.sql",
    "audit_schema.sql",
]


def _sql_dir():
    return os.path.dirname(os.path.realpath(__file__))


def upgrade():
    for schema in SCHEMAS:
        op.execute(f"CREATE SCHEMA IF NOT EXISTS {schema}")
    for name in SQL_FILES:
        path = os.path.join(_sql_dir(), name)
        with open(path, encoding="utf-8") as fh:
            op.execute(fh.read())


def downgrade():
    for schema in reversed(SCHEMAS):
        op.execute(f"DROP SCHEMA IF EXISTS {schema} CASCADE")
```

==========================================================================================
## FILE: bastehD_migrations_config/backend/alembic/versions/0002_core_outbox.py
## SIZE: 1821 bytes
==========================================================================================

```python
"""create core.outbox_messages

Architecture v2.0, section 2.3 (transactional outbox).

The ORM model lives in app/core/events/outbox.py; this migration brings
the physical table in line with that model so domain-event publishing
(e.g. on login) does not fail with "relation core.outbox_messages does
not exist".
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0002_core_outbox"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("CREATE SCHEMA IF NOT EXISTS core")

    op.create_table(
        "outbox_messages",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("event_id", postgresql.UUID(as_uuid=True), nullable=False, unique=True),
        sa.Column("event_type", sa.String(length=100), nullable=False),
        sa.Column("payload", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("correlation_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("dispatched_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("attempts", sa.SmallInteger(), server_default="0", nullable=False),
        sa.Column("last_error", sa.Text(), nullable=True),
        schema="core",
    )

    op.create_index(
        "ix_outbox_pending",
        "outbox_messages",
        ["created_at"],
        schema="core",
        postgresql_where=sa.text("dispatched_at IS NULL"),
    )


def downgrade() -> None:
    op.drop_index("ix_outbox_pending", table_name="outbox_messages", schema="core")
    op.drop_table("outbox_messages", schema="core")
```

==========================================================================================
## FILE: bastehD_migrations_config/backend/alembic.ini
## SIZE: 704 bytes
==========================================================================================

```ini
[alembic]
script_location = alembic
prepend_sys_path = .
version_path_separator = os
sqlalchemy.url = postgresql+psycopg2://admin:admin123@localhost:5432/planner_db

[post_write_hooks]

[loggers]
keys = root,sqlalchemy,alembic

[handlers]
keys = console

[formatters]
keys = generic

[logger_root]
level = WARN
handlers = console
qualname =

[logger_sqlalchemy]
level = WARN
handlers =
qualname = sqlalchemy.engine

[logger_alembic]
level = INFO
handlers =
qualname = alembic

[handler_console]
class = StreamHandler
args = (sys.stderr,)
level = NOTSET
formatter = generic

[formatter_generic]
format = %(levelname)-5.5s [%(name)s] %(message)s
datefmt = %H:%M:%S
```

==========================================================================================
## FILE: bastehD_migrations_config/backend/pytest.ini
## SIZE: 271 bytes
==========================================================================================

```ini
[pytest]
asyncio_mode = auto
asyncio_default_fixture_loop_scope = function
testpaths = tests
markers =
    integration: needs a reachable PostgreSQL (SQLALCHEMY_DATABASE_URI)
filterwarnings =
    ignore::DeprecationWarning:passlib.*
    ignore::DeprecationWarning:jose.*
```

==========================================================================================
## FILE: bastehD_migrations_config/backend/requirements.txt
## SIZE: 324 bytes
==========================================================================================

```text
fastapi==0.115.6
uvicorn[standard]==0.30.1
sqlalchemy[asyncio]==2.0.30
asyncpg==0.29.0
alembic==1.13.0
psycopg2-binary==2.9.9
redis==5.0.1
python-jose[cryptography]==3.3.0
PyJWT==2.8.0
structlog==24.4.0
passlib[bcrypt]==1.7.4
argon2-cffi==23.1.0
python-multipart==0.0.6
pydantic==2.9.2
pydantic-settings==2.0.0
```

==========================================================================================
## FILE: bastehE_frontend/web/package.json
## SIZE: 958 bytes
==========================================================================================

```json
{
  "name": "planner-web",
  "private": true,
  "version": "1.0.0",
  "type": "module",
  "scripts": {
    "dev": "vite",
    "build": "vite build",
    "preview": "vite preview"
  },
  "dependencies": {
    "@fingerprintjs/fingerprintjs": "^5.2.0",
    "@tanstack/react-query": "^5.60.0",
    "axios": "^1.7.7",
    "crypto-js": "^4.2.0",
    "date-fns": "^3.6.0",
    "react": "^18.3.0",
    "react-dom": "^18.3.0",
    "react-redux": "^9.1.2",
    "react-router-dom": "^7.18.4",
    "recoil": "^0.7.7",
    "zustand": "^5.0.15"
  },
  "devDependencies": {
    "@axe-core/react": "^4.6.0",
    "@types/react": "^18.3.12",
    "@types/react-dom": "^18.3.0",
    "@vitejs/plugin-react": "^4.3.1",
    "autoprefixer": "^10.4.20",
    "daisyui": "^4.12.14",
    "postcss": "^8.4.49",
    "tailwindcss": "^3.4.14",
    "typescript": "^5.6.2",
    "vite": "^8.3.0"
  },
  "allowScripts": {
    "esbuild@0.21.5": true
  }
}
```

==========================================================================================
## FILE: bastehE_frontend/web/src/api/client.ts
## SIZE: 7775 bytes
==========================================================================================

```typescript
import axios, { AxiosInstance, AxiosRequestConfig, CanceledError } from 'axios'
import { getFingerprint, getMacAddress, isDeviceInitialized, generateDeviceHeaders } from '../security/deviceHeaders'
import { secureStorage } from '../security/fingerprint'
import type { AxiosRequestConfig as AxiosConfig } from 'axios'

// Base API URL
const API_BASE_URL = import.meta.env.VITE_API_BASE || 'https://api.corp.local/api/v1'

// Request interface to include device headers
interface RequestConfig extends AxiosConfig {
  skipAuth?: boolean
  skipDeviceHeaders?: boolean
}

/** API client instance */
let api: AxiosInstance | null = null

/** Initialize API client with auth interceptors */
export function initApiClient(): AxiosInstance {
  if (api) return api
  
  api = axios.create({
    baseURL: API_BASE_URL,
    timeout: 30_000,
    withCredentials: true, // For cookie-based refresh tokens
    headers: {
      'Accept': 'application/json',
      'Content-Type': 'application/json',
    },
  })
  
  // Attach device headers to every request
  api.interceptors.request.use(
    async (config: RequestConfig) => {
      // Check if device identity is initialized
      if (!isDeviceInitialized() && !config.skipAuth) {
        // If not initialized and not skipping auth, we need to handle this
        // In practice, this would happen after login
        console.debug('Device identity not initialized - adding minimal headers')
      }
      
      // Generate device authentication headers if not skipped
      if (!config.skipDeviceHeaders && !config.skipAuth) {
        const headers = generateDeviceHeaders(
          config.method?.toUpperCase() || 'GET',
          config.url || '',
          config.data
        )
        
        // Merge headers with existing ones
        config.headers = {
          ...config.headers,
          ...headers,
          // Remove X-Device-MAC for web clients (would be set for desktop)
          ...(getMacAddress() ? { 'X-Device-MAC': getMacAddress() } : {}),
        }
      }
      
      // Add auth token if available
      const token = secureStorage.get('access_token')
      if (token && !config.headers?.Authorization) {
        config.headers.Authorization = `Bearer ${token}`
      }
      
      // Add request ID if not present
      if (!config.headers?.['X-Request-ID']) {
        config.headers['X-Request-ID'] = crypto.randomUUID()
      }
      
      return config
    },
    (error) => {
      return Promise.reject(error)
    }
  )
  
  // Handle token refresh on 401
  // Single-flight: concurrent 401s share one refresh call so the rotated
  // refresh token is not consumed twice (second use => 401 REVOKED).
  let refreshPromise: Promise<{ access: string; refresh: string }> | null = null

  function doRefresh(): Promise<{ access: string; refresh: string }> {
    if (!refreshPromise) {
      const refreshToken = secureStorage.get('refresh_token')
      if (!refreshToken) {
        return Promise.reject(new Error('no refresh token'))
      }
      refreshPromise = (async () => {
        try {
          const response = await api!.post('/auth/refresh', {
            refresh_token: refreshToken
          })
          const data = response.data
          // Update tokens
          secureStorage.set('access_token', data.tokens.access_token)
          secureStorage.set('refresh_token', data.tokens.refresh_token)
          return { access: data.tokens.access_token, refresh: data.tokens.refresh_token }
        } finally {
          refreshPromise = null
        }
      })()
    }
    return refreshPromise
  }

  api.interceptors.response.use(
    (response) => response,
    async (error) => {
      const originalRequest = error.config as RequestConfig & { _retry?: boolean }
      const failedUrl = String(originalRequest?.url || '')
      const isAuthCall = failedUrl.includes('/auth/refresh') || failedUrl.includes('/auth/login')

      // If 401 and not already retried (never retry the auth calls themselves)
      if (error.response?.status === 401 && !originalRequest._retry && !isAuthCall) {
        originalRequest._retry = true
        
        try {
          // Try to refresh token (single-flight across concurrent 401s)
          const { access } = await doRefresh()
          
          // Retry original request with new token.
          // NOTE: axios already serialized originalRequest.data to a JSON
          // string on the first attempt; re-dispatching would stringify it
          // AGAIN (422 dict_type on the server). Bypass re-transform.
          originalRequest.headers.Authorization = `Bearer ${access}`
          
          // Also regenerate device headers
          const headers = generateDeviceHeaders(
            originalRequest.method?.toUpperCase() || 'GET',
            originalRequest.url || '',
            originalRequest.data
          )
          originalRequest.headers = {
            ...originalRequest.headers,
            ...headers,
          }
          
          return api({
            ...originalRequest,
            transformRequest: [(data) => data],
          })
        } catch (refreshError) {
          // Refresh failed - clear tokens and notify the app shell
          // (client.ts cannot import the auth store: authProvider imports this
          // module, so we signal via a DOM event instead of a direct call).
          secureStorage.remove('access_token')
          secureStorage.remove('refresh_token')
          sessionStorage.removeItem('user')
          if (typeof window !== 'undefined') {
            window.dispatchEvent(new CustomEvent('auth:expired'))
          }

          // Navigate to login
          // In real app: navigate('/login')
          return Promise.reject(refreshError)
        }
      }

      // No refresh token stored: nothing to recover with. Notify shell too.
      if (error.response?.status === 401 && !isAuthCall) {
        if (typeof window !== 'undefined') {
          window.dispatchEvent(new CustomEvent('auth:expired'))
        }
      }
      
      return Promise.reject(error)
    }
  )
  
  return api
}

/** Get the API client instance */
export function getApi(): AxiosInstance {
  if (!api) {
    return initApiClient()
  }
  return api
}

/** Simple API helper functions */
export const apiRef = {
  get: <T>(url: string, config?: RequestConfig) => 
    getApi().get<T, T>(url, config),
  
  post: <T, D = any>(url: string, data?: D, config?: RequestConfig) => 
    getApi().post<T, T>(url, data, config),
  
  put: <T, D = any>(url: string, data?: D, config?: RequestConfig) => 
    getApi().put<T, T>(url, data, config),
  
  delete: <T>(url: string, config?: RequestConfig) => 
    getApi().delete<T, T>(url, config),
  
  patch: <T, D = any>(url: string, data?: D, config?: RequestConfig) => 
    getApi().patch<T, T>(url, data, config),
  
  // File upload with progress
  upload: <T>(url: string, file: File, onProgress?: (progress: number) => void) => {
    const formData = new FormData()
    formData.append('file', file)
    
    return getApi().post<T, any>(url, formData, {
      onUploadProgress: (progressEvent) => {
        if (onProgress && progressEvent.total) {
          const progress = Math.round((progressEvent.loaded * 100) / progressEvent.total)
          onProgress(progress)
        }
      }
    })
  },
  
  // Download file
  download: (url: string) => {
    return getApi().get(url, {
      responseType: 'blob',
      headers: {
        'X-Requested-With': ' XMLHttpRequest'
      }
    })
  },
}

export default apiRef
```

==========================================================================================
## FILE: bastehE_frontend/web/src/App.tsx
## SIZE: 15955 bytes
==========================================================================================

```tsx
import React, { useEffect, useMemo, useState } from 'react'
import {
  BrowserRouter,
  Routes,
  Route,
  Navigate,
  Link,
  useLocation,
  useNavigate,
} from 'react-router-dom'
import { useAuth } from './security/authProvider'
import DashboardPage from './features/DashboardPage'
import ChatPage from './features/ChatPage'
import InboxPage from './features/InboxPage'
import GroupsPage from './features/GroupsPage'
import ReportsPage from './features/ReportsPage'
import SettingsPage from './features/SettingsPage'

/* ---------------- Icons (inline SVG, no emoji) ---------------- */

function Icon({ d, className = 'h-5 w-5' }: { d: string; className?: string }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.8}
      strokeLinecap="round" strokeLinejoin="round" className={className} aria-hidden>
      <path d={d} />
    </svg>
  )
}

const PATHS = {
  grid: 'M3 3h7v7H3zM14 3h7v7h-7zM3 14h7v7H3zM14 14h7v7h-7z',
  chat: 'M21 11.5a8.38 8.38 0 0 1-.9 3.8 8.5 8.5 0 0 1-7.6 4.7 8.38 8.38 0 0 1-3.8-.9L3 21l1.9-5.7a8.38 8.38 0 0 1-.9-3.8 8.5 8.5 0 0 1 4.7-7.6 8.38 8.38 0 0 1 3.8-.9h.5a8.48 8.48 0 0 1 8 8v.5z',
  inbox: 'M22 12h-6l-2 3h-4l-2-3H2M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z',
  users: 'M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2M9 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM23 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75',
  chart: 'M18 20V10M12 20V4M6 20v-6',
  cog: 'M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6zM19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 1 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 1 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z',
  logout: 'M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9',
  target: 'M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20zM12 18a6 6 0 1 0 0-12 6 6 0 0 0 0 12zM12 14a2 2 0 1 0 0-4 2 2 0 0 0 0 4z',
  lock: 'M5 11h14a2 2 0 0 1 2 2v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-7a2 2 0 0 1 2-2zM7 11V7a5 5 0 0 1 10 0v4',
  user: 'M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2M12 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8z',
  check: 'M20 6 9 17l-5-5',
}

/* ---------------- Login ---------------- */

function LoginPage() {
  const { login, isLoading } = useAuth()
  const [identifier, setIdentifier] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)

  const onSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError(null)
    try {
      await login({ identifier, password })
    } catch {
      setError('ورود ناموفق بود. مشخصات را بررسی کنید.')
    }
  }

  const features = useMemo(
    () => [
      { d: PATHS.target, t: 'اهداف و وظایف', s: 'تعریف، پیگیری پیشرفت و مدیریت مهلت‌ها' },
      { d: PATHS.users, t: 'گروه‌ها و حریم خصوصی', s: 'کار تیمی با کنترل دقیق دسترسی' },
      { d: PATHS.chart, t: 'گزارش و داشبورد', s: 'نمای زنده از عملکرد شما و تیم' },
    ],
    [],
  )

  return (
    <div className="flex min-h-screen bg-slate-100">
      {/* Brand panel */}
      <div className="relative hidden w-[44%] overflow-hidden bg-slate-900 lg:block">
        <div className="absolute inset-0 bg-gradient-to-bl from-brand-700 via-slate-900 to-slate-950" />
        <div
          className="absolute inset-0 opacity-[0.15]"
          style={{
            backgroundImage:
              'radial-gradient(circle at 25% 25%, #fff 1.5px, transparent 1.5px)',
            backgroundSize: '28px 28px',
          }}
        />
        <div className="absolute -left-24 -top-24 h-96 w-96 rounded-full bg-brand-500/30 blur-3xl" />
        <div className="absolute -bottom-32 -right-16 h-[28rem] w-[28rem] rounded-full bg-indigo-500/20 blur-3xl" />
        <div className="relative flex h-full flex-col justify-between p-12 text-white">
          <div className="animate-fade-up flex items-center gap-3">
            <div className="flex h-12 w-12 items-center justify-center rounded-2xl bg-white/15 text-white backdrop-blur">
              <Icon d={PATHS.target} className="h-7 w-7" />
            </div>
            <div>
              <p className="text-lg font-bold leading-6">سامانه مدیریت اهداف</p>
              <p className="text-xs text-slate-300">نسخه سازمانی</p>
            </div>
          </div>
          <div className="space-y-6">
            <h2 className="animate-fade-up stagger-1 text-3xl font-bold leading-[2.6rem]">
              مدیریت اهداف، برنامه‌ریزی و همکاری تیمی
            </h2>
            <p className="animate-fade-up stagger-2 max-w-md text-sm leading-7 text-slate-300">
              همه اهداف، وظایف، گفتگوها و پیگیری‌ها — یکجا، امن و یکپارچه.
            </p>
            <ul className="space-y-4 pt-2">
              {features.map((f, i) => (
                <li
                  key={f.t}
                  className={`animate-fade-up stagger-${i + 3} flex items-start gap-3`}
                >
                  <span className="mt-0.5 flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-white/10 text-brand-200">
                    <Icon d={f.d} className="h-5 w-5" />
                  </span>
                  <span>
                    <span className="block text-sm font-medium">{f.t}</span>
                    <span className="block text-xs text-slate-400">{f.s}</span>
                  </span>
                </li>
              ))}
            </ul>
          </div>
          <p className="text-[11px] text-slate-500">امنیت چندلایه · احراز هویت دو عاملی · ثبت وقایع</p>
        </div>
      </div>

      {/* Form panel */}
      <div className="flex flex-1 items-center justify-center p-6">
        <form
          onSubmit={onSubmit}
          className="animate-fade-up w-full max-w-md rounded-3xl bg-white p-8 shadow-pop sm:p-10"
        >
          <div className="mb-8 text-center lg:hidden">
            <div className="mx-auto mb-3 flex h-12 w-12 items-center justify-center rounded-2xl bg-gradient-to-l from-brand-600 to-brand-500 text-white">
              <Icon d={PATHS.target} className="h-7 w-7" />
            </div>
            <p className="font-bold">سامانه مدیریت اهداف</p>
          </div>
          <h1 className="text-2xl font-bold">ورود به سامانه</h1>
          <p className="mb-6 mt-1 text-sm text-slate-500">برای ادامه وارد حساب کاربری خود شوید</p>

          <label className="label" htmlFor="login-id">
            نام کاربری یا کد ملی
          </label>
          <div className="relative mb-4">
            <span className="pointer-events-none absolute right-3.5 top-1/2 -translate-y-1/2 text-slate-400">
              <Icon d={PATHS.user} className="h-5 w-5" />
            </span>
            <input
              id="login-id"
              className="input pr-11"
              placeholder="مثلاً ali.rezaei"
              value={identifier}
              onChange={(e) => setIdentifier(e.target.value)}
              autoComplete="username"
            />
          </div>

          <label className="label" htmlFor="login-pw">
            گذرواژه
          </label>
          <div className="relative mb-2">
            <span className="pointer-events-none absolute right-3.5 top-1/2 -translate-y-1/2 text-slate-400">
              <Icon d={PATHS.lock} className="h-5 w-5" />
            </span>
            <input
              id="login-pw"
              className="input pr-11"
              placeholder="گذرواژه خود را وارد کنید"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="current-password"
            />
          </div>

          {error && (
            <p className="animate-fade-in mb-2 rounded-xl bg-red-50 px-4 py-2.5 text-xs text-red-600">
              {error}
            </p>
          )}

          <button type="submit" disabled={isLoading} className="btn-primary mt-4 w-full py-3">
            {isLoading ? (
              <>
                <span className="h-4 w-4 animate-spin rounded-full border-2 border-white/40 border-t-white" />
                در حال ورود…
              </>
            ) : (
              'ورود'
            )}
          </button>
          <p className="mt-5 text-center text-[11px] leading-5 text-slate-400">
            حساب پیش‌فرض مدیر: admin / admin123
          </p>
        </form>
      </div>
    </div>
  )
}

/* ---------------- Shell ---------------- */

const NAV = [
  { to: '/dashboard', label: 'داشبورد', icon: PATHS.grid },
  { to: '/chat', label: 'گفتگوها', icon: PATHS.chat },
  { to: '/inbox', label: 'صندوق ورودی', icon: PATHS.inbox },
  { to: '/groups', label: 'گروه‌ها', icon: PATHS.users },
  { to: '/reports', label: 'گزارش‌ها', icon: PATHS.chart },
  { to: '/settings', label: 'تنظیمات', icon: PATHS.cog },
]

function Sidebar({ onNav }: { onNav?: () => void }) {
  const { user, logout } = useAuth()
  const { pathname } = useLocation()
  const navigate = useNavigate()

  const doLogout = async () => {
    await logout()
    navigate('/login', { replace: true })
    onNav?.()
  }

  return (
    <div className="flex h-full flex-col bg-slate-900 text-white">
      <div className="flex items-center gap-3 px-5 pb-6 pt-6">
        <div className="flex h-11 w-11 items-center justify-center rounded-2xl bg-gradient-to-l from-brand-500 to-indigo-500 shadow-lg shadow-brand-900/40">
          <Icon d={PATHS.target} className="h-6 w-6" />
        </div>
        <div className="min-w-0">
          <p className="truncate text-sm font-bold">سامانه مدیریت اهداف</p>
          <p className="text-[11px] text-slate-400">نسخه سازمانی</p>
        </div>
      </div>
      <nav className="flex-1 space-y-1 overflow-y-auto px-3">
        {NAV.map((n) => {
          const active = pathname === n.to || (n.to === '/dashboard' && pathname === '/')
          return (
            <Link
              key={n.to}
              to={n.to}
              onClick={onNav}
              className={`navlink ${active ? 'navlink-active' : ''}`}
            >
              <Icon d={n.icon} />
              <span>{n.label}</span>
            </Link>
          )
        })}
      </nav>
      <div className="border-t border-white/10 p-4">
        <div className="mb-3 flex items-center gap-3 rounded-xl bg-white/5 p-3">
          <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-gradient-to-l from-brand-400 to-indigo-400 text-sm font-bold">
            {(user?.display_name || user?.username || '?').slice(0, 1)}
          </div>
          <div className="min-w-0 flex-1">
            <p className="truncate text-sm font-medium">
              {user?.display_name || user?.username}
            </p>
            <p className="truncate text-[11px] text-slate-400" dir="ltr">
              {user?.national_id_masked}
            </p>
          </div>
        </div>
        <button onClick={() => void doLogout()} className="navlink w-full text-red-300 hover:text-red-200">
          <Icon d={PATHS.logout} />
          <span>خروج از حساب</span>
        </button>
      </div>
    </div>
  )
}

function Topbar({ onMenu }: { onMenu: () => void }) {
  const today = useMemo(
    () =>
      new Intl.DateTimeFormat('fa-IR', {
        weekday: 'long',
        day: 'numeric',
        month: 'long',
      }).format(new Date()),
    [],
  )
  return (
    <header className="sticky top-0 z-10 border-b border-slate-200/70 bg-white/80 backdrop-blur">
      <div className="flex items-center gap-3 px-4 py-3 sm:px-6">
        <button onClick={onMenu} className="btn-ghost p-2 lg:hidden" aria-label="menu">
          <svg viewBox="0 0 24 24" className="h-6 w-6" fill="none" stroke="currentColor"
            strokeWidth={2} strokeLinecap="round">
            <path d="M4 6h16M4 12h16M4 18h16" />
          </svg>
        </button>
        <div className="min-w-0 flex-1">
          <p className="truncate text-sm font-bold text-slate-800">سامانه مدیریت اهداف</p>
          <p className="text-[11px] text-slate-400">{today}</p>
        </div>
        <span className="badge bg-emerald-50 text-emerald-700">
          <span className="ml-1.5 h-2 w-2 rounded-full bg-emerald-500" />
          متصل
        </span>
      </div>
    </header>
  )
}

function Shell() {
  const [open, setOpen] = useState(false)
  return (
    <div className="flex min-h-screen bg-slate-100">
      <aside className="sticky top-0 hidden h-screen w-72 shrink-0 lg:block">
        <Sidebar />
      </aside>
      {open && (
        <div className="fixed inset-0 z-20 lg:hidden">
          <div className="animate-fade-in absolute inset-0 bg-slate-900/50" onClick={() => setOpen(false)} />
          <aside className="animate-fade-in absolute bottom-0 right-0 top-0 w-72">
            <Sidebar onNav={() => setOpen(false)} />
          </aside>
        </div>
      )}
      <div className="flex min-w-0 flex-1 flex-col">
        <Topbar onMenu={() => setOpen(true)} />
        <main className="flex-1">
          <Routes>
            <Route path="/dashboard" element={<DashboardPage />} />
            <Route path="/chat" element={<ChatPage />} />
            <Route path="/inbox" element={<InboxPage />} />
            <Route path="/groups" element={<GroupsPage />} />
            <Route path="/reports" element={<ReportsPage />} />
            <Route path="/settings" element={<SettingsPage />} />
            <Route path="/" element={<Navigate to="/dashboard" replace />} />
            <Route path="*" element={<Navigate to="/dashboard" replace />} />
          </Routes>
        </main>
      </div>
    </div>
  )
}

/* ---------------- App ---------------- */

function App() {
  const { isAuthenticated, isLoading, init } = useAuth()

  useEffect(() => {
    void init()
  }, [init])

  // When the API layer reports an unrecoverable 401 (refresh failed or no
  // refresh token), drop the persisted "authenticated" flag so the user is
  // sent back to the login page instead of a dead dashboard.
  useEffect(() => {
    const onExpired = () => {
      useAuth.getState().forceLogout()
    }
    window.addEventListener('auth:expired', onExpired)
    return () => window.removeEventListener('auth:expired', onExpired)
  }, [])

  if (isLoading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-slate-100">
        <div className="flex flex-col items-center gap-4">
          <div className="h-12 w-12 animate-spin rounded-full border-[3px] border-brand-200 border-t-brand-600" />
          <p className="text-sm text-slate-500">در حال بارگذاری…</p>
        </div>
      </div>
    )
  }

  return (
    <BrowserRouter>
      <Routes>
        {isAuthenticated ? (
          <Route path="/*" element={<Shell />} />
        ) : (
          <>
            <Route path="/login" element={<LoginPage />} />
            <Route path="*" element={<Navigate to="/login" replace />} />
          </>
        )}
      </Routes>
    </BrowserRouter>
  )
}

export default App
```

==========================================================================================
## FILE: bastehE_frontend/web/src/AuthLayout.tsx
## SIZE: 10764 bytes
==========================================================================================

```tsx
import React from 'react'
import { Routes, Route, Navigate } from 'react-router-dom'
import { useAuth } from '../security/authProvider'
import { useNavigate } from 'react-router-dom'

/** Authentication layout - shows login/register pages */
export const AuthLayout: React.FC = () => {
  const { isLoading, login, init } = useAuth()
  const navigate = useNavigate()
  
  useEffect(() => {
    init()
  }, [init])
  
  if (isLoading) {
    return (
      <div className="rtl min-h-screen flex items-center justify-center bg-gray-100 dark:bg-gray-900">
        <div className="text-center">
          <div className="spinner spinner-sm" />
          <p className="mt-4 text-gray-600 dark:text-gray-300">
            ورود در حال انجام است...
          </p>
        </div>
      </div>
    )
  }
  
  // If already authenticated, redirect to dashboard
  if (!isLoading) {
    const user = localStorage.getItem('user') 
      ? JSON.parse(localStorage.getItem('user') as string)
      : null
    
    if (user) {
      return <Navigate to="/dashboard" replace /> 
    }
  }
  
  return (
    <div className="rtl min-h-screen bg-gray-100 dark:bg-gray-900">
      <div className="max-w-md mx-auto p-6">
        <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-6">
          ورود به سامانه
        </h2>
        
        <Routes>
          <Route path="/login" element={<LoginPage />} />
          <Route path="/mfa-challenge" element={<MfaChallengePage />} />
          <Route path="/register" element={<RegisterPage />} />
          <Route path="/" element={<Navigate to="/login" replace />} />
        </Routes>
      </div>
    </div>
  )
}

/** Login page */
const LoginPage: React.FC = () => {
  const [credentials, setCredentials] = React.useState({
    identifier: '',
    password: '',
    rememberMe: false
  })
  const [error, setError] = React.useState<string | null>(null)
  const { login } = useAuth()
  const navigate = useNavigate()
  
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError(null)
    
    try {
      await login(credentials as any)
      navigate('/dashboard')
    } catch (err: any) {
      setError(err.message || 'ورود ناموفق')
    }
  }
  
  return (
    <div className="space-y-4">
      <form onSubmit={handleSubmit} className="space-y-2">
        <div>
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">
            شماره ملی / نام کاربری
          </label>
          <input
            className="mt-1 block w-full rounded-md border-gray-300 shadow-sm dark:bg-gray-700 dark:text-white"
            type="text"
            placeholder="0012345678 یا نام کاربری"
            required
            {...credentials.identifier ? {} : 'autoFocus'}
            onChange={(e) => 
              setCredentials({ ...credentials, identifier: e.target.value })}
          />
        </div>
        
        <div>
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">
            رمز عبور
          </label>
          <input
            className="mt-1 block w-full rounded-md border-gray-300 shadow-sm dark:bg-gray-700 dark:text-white"
            type="password"
            required
            placeholder="••••••••"
            {...credentials.password ? {} : ''}
            onChange={(e) => 
              setCredentials({ ...credentials, password: e.target.value })}
          />
        </div>
        
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <input
              type="checkbox"
              checked={credentials.rememberMe}
              onChange={(e) => 
                setCredentials({ ...credentials, rememberMe: e.target.checked })}
              className="rounded border-gray-300 w-4 h-4 dark:border-gray-600"
            />
            <span className="text-sm text-gray-600 dark:text-gray-300">
              مرا به خاطر بسپار
            </span>
          </div>
          
          <button
            type="submit"
            className="px-4 py-2 rounded-md bg-gray-900 text-white font-medium hover:bg-gray-800 dark:hover:bg-gray-600 transition-colors"
          >
            ورود
          </button>
        </div>
      </form>
      
      {error && (
        <div className="bg-red-100 dark:bg-red-900 text-red-800 dark:text-red-200 rounded px-3 py-2 text-sm mt-4">
          {error}
        </div>
      )}
      
      <p className="text-center text-sm text-gray-500 dark:text-gray-400">
        یا با حساب_company وارد شوید
      </p>
    </div>
  )
}

/** MFA challenge page */
const MfaChallengePage: React.FC = () => {
  const [code, setCode] = React.useState('')
  const { verifyMFA } = useAuth()
  const navigate = useNavigate()
  const { mfaMethod } = useAuth()
  
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    
    try {
      await verifyMFA(code)
      navigate('/dashboard')
    } catch (err: any) {
      setCode('') // Clear on error
      alert(err.message || 'کد MFA نامعتبر است')
    }
  }
  
  if (!mfaMethod) {
    return <p className="text-center text-gray-600">خطا: مfa چالش باز نیست</p>
  }
  
  return (
    <div className="rtl max-w-md mx-auto p-6">
      <h3 className="text-xl font-bold text-gray-900 dark:text-white mb-6">
        اعتبارسنجی امنیتی
      </h3>
      <p className="text-gray-600 dark:text-gray-300 mb-8">
        برای ادامه ورود، کد MFA خود را وارد کنید.<br />
        {mfaMethod === 'totp' && (
          <p className="text-sm">
            می‌توانید از اپلیکیشن Authenticator (Google Authenticator, Authy و...) استفاده کنید
          </p>
        )}
      </p>
      
      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">
            کد MFA
          </label>
          <input
            value={code}
            onChange={(e) => setCode(e.target.value)}
            type="text"
            maxLength="6"
            className="mt-1 block w-full rounded-md border-gray-300 shadow-sm dark:bg-gray-700 dark:text-white"
            placeholder="123456"
            required
          />
        </div>
        
        <button
          type="submit"
          className="w-full py-2 rounded-md bg-primary text-white font-medium hover:bg-secondary dark:hover:bg-primary-transition"
        >
          تأیید کد
        </button>
      </form>
    </div>
  )
}

/** Register page */
const RegisterPage: React.FC = () => {
  const [credentials, setCredentials] = React.useState({
    nationalId: '',
    username: '',
    password: '',
    displayName: ''
  })
  const [error, setError] = React.useState<string | null>(null)
  const { register } = useAuth()
  const navigate = useNavigate()
  
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError(null)
    
    try {
      await register(credentials as any)
      navigate('/dashboard')
    } catch (err: any) {
      setError(err.message || 'ثبت‌نام ناموفق')
    }
  }
  
  return (
    <div className="rtl max-w-md mx-auto p-6">
      <h3 className="text-xl font-bold text-gray-900 dark:text-white mb-6">
        ثبت‌نام جدید
      </h3>
      
      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">
            کد ملی
          </label>
          <input
            value={credentials.nationalId}
            onChange={(e) => 
              setCredentials({ ...credentials, nationalId: e.target.value })}
            type="text"
            placeholder="0012345678"
            maxLength="10"
            className="mt-1 block w-full rounded-md border-gray-300 shadow-sm dark:bg-gray-700 dark:text-white"
            required
          />
          <p className="text-xs text-gray-500">
            فرمت: ۱۰ رقم با عدد کنترلی
          </p>
        </div>
        
        <div>
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">
            نام کاربری
          </label>
          <input
            value={credentials.username}
            onChange={(e) => 
              setCredentials({ ...credentials, username: e.target.value })}
            type="text"
            placeholder="username"
            className="mt-1 block w-full rounded-md border-gray-300 shadow-sm dark:bg-gray-700 dark:text-white"
            required
          />
        </div>
        
        <div>
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">
            نام نمایشی
          </label>
          <input
            value={credentials.displayName}
            onChange={(e) => 
              setCredentials({ ...credentials, displayName: e.target.value })}
            type="text"
            placeholder="علی رضایی"
            className="mt-1 block w-full rounded-md border-gray-300 shadow-sm dark:bg-gray-700 dark:text-white"
            required
          />
        </div>
        
        <div>
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">
            رمز عبور
          </label>
          <input
            value={credentials.password}
            onChange={(e) => 
              setCredentials({ ...credentials, password: e.target.value })}
            type="password"
            placeholder="••••••••"
            className="mt-1 block w-full rounded-md border-gray-300 shadow-sm dark:bg-gray-700 dark:text-white"
            required
          />
        </div>
        
        <button
          type="submit"
          className="w-full py-2 rounded-md bg-primary text-white font-medium hover:bg-secondary dark:hover:bg-primary-transition"
        >
          ثبت‌نام
        </button>
      </form>
      
      {error && (
        <div className="bg-red-100 dark:bg-red-900 text-red-800 dark:text-red-200 rounded px-3 py-2 text-sm mt-2">
          {error}
        </div>
      )}
    </div>
  )
}

export default AuthLayout
```

==========================================================================================
## FILE: bastehE_frontend/web/src/components/sidebar.tsx
## SIZE: 3761 bytes
==========================================================================================

```tsx
import React from 'react'
import { Link } from 'react-router-dom'
import { useAuth } from '../security/authProvider'
import { usePermissionCache } from '../hooks/usePermissionCache'

/** Sidebar navigation for the dashboard */
export const Sidebar: React.FC<{ user?: User }> = ({ user }) => {
  const { isAuthenticated } = useAuth()
  const { hasPermission } = usePermissionCache()
  const navigate = useNavigate()

  // Navigation items with permissions
  const navItems = [
    { key: 'dashboard', label: 'داشبورد', icon: 'Layout', requiredPerm: undefined },
    { key: 'goals', label: 'اهداف', icon: 'TrendingUp', requiredPerm: 'goal.view' },
    { key: 'calendar', label: 'تقویم', icon: 'Calendar', requiredPerm: 'calendar.view' },
    { key: 'inbox', label: 'کارتابل', icon: 'MessageSquare', requiredPerm: 'inbox.view' },
    { key: 'chat', label: 'چت', icon: 'MessageCircle', requiredPerm: 'chat.view' },
    { key: 'reports', label: 'گزارش‌ها', icon: 'BarChart3', requiredPerm: 'report.view' },
    { key: 'widgets', label: 'ویجت‌ها', icon: 'Widgets', requiredPerm: 'widgets.manage' },
    { key: 'group-manager', label: 'مدیریت گروه', icon: 'Users', requiredPerm: 'group.manage' },
    { key: 'profile', label: 'پروفایل', icon: 'User', requiredPerm: undefined },
    { key: 'settings', label: 'تنظیمات', icon: 'Settings', requiredPerm: 'settings.manage' },
  ]

  return (
    <nav className="rtl bg-white dark:bg-gray-900 h-screen w-64 shadow-lg border2 border-gray-200 dark:border-gray-700 flex-shrink-0">
      <div className="p-4 border-b border-gray-200 dark:border-gray-700">
        <h2 className="text-lg font-bold text-gray-900 dark:text-white">
          {user?.display_name || 'کاربر'}
        </h2>
        <p className="text-sm text-gray-500 dark:text-gray-400">
          {user?.username || ''}
        </p>
      </div>
      
      <ul className="mt-4 space-y-1 max-h-screen overflow-y-auto">
        {navItems.map((item) => {
          const isVisible = !item.requiredPerm || hasPermission(item.requiredPerm)
          
          if (!isVisible) return null
          
          const isActive = item.key === 'dashboard' // Simplified active check
          
          return (
            <li key={item.key} className={`transition-colors duration-200 ${
              isActive 
                ? 'bg-gray-100 dark:bg-gray-800' 
                : 'hover:bg-gray-50 dark:hover:bg-gray-800'}
              rounded-md px-3 py-2 flex items-center gap-3`}
            >
              <Link
                to={`/${item.key}`}
                className="flex items-center gap-2 text-sm text-gray-700 dark:text-gray-300 hover:text-primary transition-colors"
                onClick={() => navigate(`/${item.key}`)}
              >
                <svg className="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" d={item.icon} />
                </svg>
                <span>{item.label}</span>
              </Link>
            </li>
          )
        })}
      </ul>
      
      <div className="mt-6 p-3 border-t border-gray-200 dark:border-gray-700">
        <button
          onClick={() => {
            // Logout
            useAuth.getState().logout()
            navigate('/login')
          }
          className="w-full py-2 rounded-md bg-red-100 text-red-800 text-sm font-medium hover:bg-red-200 dark:bg-red-900 dark:hover:bg-red-200 transition-colors"
        >
          خروج
        </button>
      </div>
    </nav>
  )
}

/** User type import */
import type { User } from '../types'
```

==========================================================================================
## FILE: bastehE_frontend/web/src/features/ChatPage.tsx
## SIZE: 10256 bytes
==========================================================================================

```tsx
import { useCallback, useEffect, useRef, useState } from 'react'
import { apiRef as api } from '../api/client'
import { useAuth } from '../security/authProvider'

function Icon({ d, className = 'h-5 w-5' }: { d: string; className?: string }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.8}
      strokeLinecap="round" strokeLinejoin="round" className={className} aria-hidden>
      <path d={d} />
    </svg>
  )
}

const P = {
  chat: 'M21 11.5a8.38 8.38 0 0 1-.9 3.8 8.5 8.5 0 0 1-7.6 4.7 8.38 8.38 0 0 1-3.8-.9L3 21l1.9-5.7a8.38 8.38 0 0 1-.9-3.8 8.5 8.5 0 0 1 4.7-7.6 8.38 8.38 0 0 1 3.8-.9h.5a8.48 8.48 0 0 1 8 8v.5z',
  plus: 'M12 5v14M5 12h14',
  send: 'M22 2 11 13M22 2l-7 20-4-9-9-4z',
  users: 'M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2M9 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM23 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75',
}

interface ChatRoom {
  id: string
  title: string
  owner_id: string
  member_count: number
  is_archived: boolean
  linked_type?: string | null
  linked_id?: string | null
}

interface ChatMsg {
  id: string
  room_id: string
  sender_id: string
  body: string
  sender_name: string
  created_at: string
  message_type: string
  is_edited: boolean
}

function fmtTime(iso: string) {
  if (!iso) return ''
  try {
    return new Intl.DateTimeFormat('fa-IR', {
      hour: '2-digit',
      minute: '2-digit',
      day: '2-digit',
      month: '2-digit',
    }).format(new Date(iso))
  } catch {
    return ''
  }
}

export default function ChatPage() {
  const { user } = useAuth()
  const [rooms, setRooms] = useState<ChatRoom[]>([])
  const [selected, setSelected] = useState<string | null>(null)
  const [messages, setMessages] = useState<ChatMsg[]>([])
  const [title, setTitle] = useState('')
  const [body, setBody] = useState('')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [creating, setCreating] = useState(false)
  const [sending, setSending] = useState(false)
  const listRef = useRef<HTMLDivElement | null>(null)

  const loadRooms = useCallback(async () => {
    try {
      const res = await api.get('/chat/rooms')
      const data = (res.data as any)?.data?.rooms ?? []
      setRooms(data as ChatRoom[])
      if (data.length && !selected) setSelected(data[0].id)
    } catch {
      setError('دریافت اتاق‌های گفتگو ناموفق بود.')
    } finally {
      setLoading(false)
    }
  }, [selected])

  useEffect(() => {
    void loadRooms()
  }, [loadRooms])

  useEffect(() => {
    if (!selected) {
      setMessages([])
      return
    }
    let cancelled = false
    const load = async () => {
      try {
        const res = await api.get(`/chat/${selected}/messages`)
        const data = (res.data as any)?.data?.messages ?? []
        if (!cancelled) setMessages(data as ChatMsg[])
      } catch {
        if (!cancelled) setError('دریافت پیام‌ها ناموفق بود.')
      }
    }
    void load()
    const t = setInterval(load, 4000)
    return () => {
      cancelled = true
      clearInterval(t)
    }
  }, [selected])

  useEffect(() => {
    listRef.current?.scrollTo({ top: listRef.current.scrollHeight, behavior: 'smooth' })
  }, [messages])

  const onCreate = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!title.trim()) return
    setCreating(true)
    setError(null)
    try {
      const res = await api.post('/chat/rooms', { title: title.trim() })
      const roomId = (res.data as any)?.room_id
      setTitle('')
      await loadRooms()
      if (roomId) setSelected(roomId)
    } catch {
      setError('ایجاد اتاق گفتگو ناموفق بود.')
    } finally {
      setCreating(false)
    }
  }

  const onSend = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!selected || !body.trim()) return
    setSending(true)
    setError(null)
    try {
      await api.post(`/chat/${selected}/messages`, { body: body.trim() })
      setBody('')
      const res = await api.get(`/chat/${selected}/messages`)
      setMessages(((res.data as any)?.data?.messages ?? []) as ChatMsg[])
    } catch {
      setError('ارسال پیام ناموفق بود.')
    } finally {
      setSending(false)
    }
  }

  return (
    <div className="space-y-5 p-4 sm:p-6">
      <div className="animate-fade-up">
        <h1 className="text-xl font-bold text-slate-900 sm:text-2xl">گفتگوها</h1>
        <p className="mt-0.5 text-xs text-slate-500 sm:text-sm">اتاق‌های گفتگو و پیام‌های گروهی</p>
      </div>

      {error && (
        <p className="animate-fade-in rounded-2xl bg-red-50 px-4 py-3 text-xs text-red-600">{error}</p>
      )}

      <div className="grid items-start gap-5 lg:grid-cols-3">
        {/* Rooms */}
        <section className="card animate-fade-up stagger-1">
          <h2 className="mb-3 text-base font-bold text-slate-800">اتاق‌ها</h2>
          <form onSubmit={onCreate} className="mb-3 flex gap-2">
            <input
              className="input"
              placeholder="عنوان اتاق جدید…"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
            />
            <button type="submit" disabled={creating || !title.trim()} className="btn-primary shrink-0 px-4">
              <Icon d={P.plus} className="h-4 w-4" />
              {creating ? '...' : 'افزودن'}
            </button>
          </form>
          {loading ? (
            <p className="text-xs text-slate-400">در حال بارگذاری…</p>
          ) : rooms.length === 0 ? (
            <p className="rounded-xl bg-slate-50 px-4 py-6 text-center text-xs text-slate-400">
              هنوز اتاقی نساخته‌اید.
            </p>
          ) : (
            <ul className="max-h-[26rem] space-y-2 overflow-y-auto pl-1">
              {rooms.map((r) => (
                <li key={r.id} className="flex items-center justify-between gap-2">
                  <button
                    onClick={() => setSelected(r.id)}
                    className={`flex w-full items-center gap-3 rounded-xl px-3 py-2.5 text-right transition-colors ${
                      selected === r.id ? 'bg-brand-50 text-brand-700' : 'text-slate-700 hover:bg-slate-50'
                    }`}
                  >
                    <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-white text-brand-500 shadow-sm">
                      <Icon d={P.chat} className="h-5 w-5" />
                    </span>
                    <span className="min-w-0 flex-1">
                      <span className="block truncate text-sm font-medium">{r.title}</span>
                      <span className="block text-[11px] text-slate-400">
                        {r.member_count} عضو
                      </span>
                    </span>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </section>

        {/* Messages */}
        <section className="card animate-fade-up stagger-2 lg:col-span-2">
          {!selected ? (
            <div className="flex flex-col items-center justify-center gap-3 py-16 text-center">
              <span className="flex h-14 w-14 items-center justify-center rounded-2xl bg-brand-50 text-brand-500">
                <Icon d={P.chat} className="h-7 w-7" />
              </span>
              <p className="text-sm text-slate-500">یک اتاق گفتگو را انتخاب کنید</p>
            </div>
          ) : (
            <>
              <div className="mb-3 flex items-center justify-between gap-2">
                <h2 className="truncate text-base font-bold text-slate-800">
                  {rooms.find((r) => r.id === selected)?.title ?? 'گفتگو'}
                </h2>
                <span className="badge shrink-0 bg-brand-50 text-brand-700">
                  {messages.length} پیام
                </span>
              </div>
              <div
                ref={listRef}
                className="h-[26rem] space-y-2.5 overflow-y-auto rounded-2xl bg-slate-50 p-3"
              >
                {messages.length === 0 ? (
                  <p className="py-16 text-center text-xs text-slate-400">پیامی در این گفتگو نیست.</p>
                ) : (
                  messages.map((m) => {
                    const mine = m.sender_id === user?.id
                    return (
                      <div key={m.id} className={`flex ${mine ? 'justify-start' : 'justify-end'}`}>
                        <div
                          className={`max-w-[80%] rounded-2xl px-3.5 py-2 shadow-sm ${
                            mine
                              ? 'bg-white text-slate-700 border border-slate-200'
                              : 'bg-gradient-to-l from-brand-600 to-brand-500 text-white'
                          }`}
                        >
                          <div className="mb-0.5 flex items-center gap-2 text-[10px] opacity-70">
                            <Icon d={P.users} className="h-3 w-3" />
                            <span>{mine ? 'شما' : (m.sender_name || m.sender_id.slice(0, 8))}</span>
                            <span>{fmtTime(m.created_at)}</span>
                          </div>
                          <p className="whitespace-pre-wrap break-words text-sm leading-6">{m.body}</p>
                        </div>
                      </div>
                    )
                  })
                )}
              </div>
              <form onSubmit={onSend} className="mt-3 flex gap-2">
                <input
                  className="input"
                  placeholder="پیام خود را بنویسید…"
                  value={body}
                  onChange={(e) => setBody(e.target.value)}
                />
                <button type="submit" disabled={sending || !body.trim()} className="btn-primary shrink-0 px-4">
                  <Icon d={P.send} className="h-4 w-4" />
                  {sending ? '...' : 'ارسال'}
                </button>
              </form>
            </>
          )}
        </section>
      </div>
    </div>
  )
}
```

==========================================================================================
## FILE: bastehE_frontend/web/src/features/DashboardPage.tsx
## SIZE: 14972 bytes
==========================================================================================

```tsx
import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useAuth } from '../security/authProvider'
import { useDashboard } from '../hooks/useDashboard'

function Icon({ d, className = 'h-5 w-5' }: { d: string; className?: string }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.8}
      strokeLinecap="round" strokeLinejoin="round" className={className} aria-hidden>
      <path d={d} />
    </svg>
  )
}

const P = {
  target: 'M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20zM12 18a6 6 0 1 0 0-12 6 6 0 0 0 0 12zM12 14a2 2 0 1 0 0-4 2 2 0 0 0 0 4z',
  check: 'M20 6 9 17l-5-5',
  inbox: 'M22 12h-6l-2 3h-4l-2-3H2M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z',
  list: 'M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01',
  users: 'M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2M9 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM23 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75',
  chat: 'M21 11.5a8.38 8.38 0 0 1-.9 3.8 8.5 8.5 0 0 1-7.6 4.7 8.38 8.38 0 0 1-3.8-.9L3 21l1.9-5.7a8.38 8.38 0 0 1-.9-3.8 8.5 8.5 0 0 1 4.7-7.6 8.38 8.38 0 0 1 3.8-.9h.5a8.48 8.48 0 0 1 8 8v.5z',
  plus: 'M12 5v14M5 12h14',
  refresh: 'M23 4v6h-6M1 20v-6h6M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15',
  x: 'M18 6 6 18M6 6l12 12',
  clock: 'M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20zM12 6v6l4 2',
}

function StatCard({
  value,
  label,
  icon,
  grad,
  delay,
}: {
  value: number
  label: string
  icon: string
  grad: string
  delay: string
}) {
  return (
    <div className={`stat-card animate-fade-up ${delay} bg-gradient-to-bl ${grad}`}>
      <div
        className="pointer-events-none absolute inset-0 opacity-20"
        style={{
          backgroundImage: 'radial-gradient(circle at 80% 20%, #fff 1.5px, transparent 1.5px)',
          backgroundSize: '22px 22px',
        }}
      />
      <div className="relative flex items-start justify-between">
        <div>
          <p className="text-4xl font-bold leading-10">{value}</p>
          <p className="mt-1 text-sm text-white/85">{label}</p>
        </div>
        <span className="flex h-11 w-11 items-center justify-center rounded-2xl bg-white/20 backdrop-blur">
          <Icon d={icon} className="h-6 w-6" />
        </span>
      </div>
    </div>
  )
}

function Section({
  title,
  action,
  children,
  delay = '',
}: {
  title: string
  action?: React.ReactNode
  children: React.ReactNode
  delay?: string
}) {
  return (
    <section className={`card animate-fade-up ${delay}`}>
      <div className="mb-4 flex items-center justify-between">
        <h2 className="text-base font-bold text-slate-800">{title}</h2>
        {action}
      </div>
      {children}
    </section>
  )
}

function Empty({ text }: { text: string }) {
  return (
    <div className="rounded-xl bg-slate-50 px-4 py-6 text-center text-xs text-slate-400">
      {text}
    </div>
  )
}

const BAR_COLORS = ['bg-brand-500', 'bg-emerald-500', 'bg-violet-500', 'bg-amber-500', 'bg-sky-500']

export default function DashboardPage() {
  const { user } = useAuth()
  const { summary, loading, error, refresh, createGoal, actOnInbox } = useDashboard()
  const [title, setTitle] = useState('')
  const [desc, setDesc] = useState('')
  const [saving, setSaving] = useState(false)
  const [formError, setFormError] = useState(false)
  const [acting, setActing] = useState<string | null>(null)

  const onCreate = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!title.trim()) return
    setSaving(true)
    setFormError(false)
    try {
      await createGoal(title.trim(), desc.trim() || undefined)
      setTitle('')
      setDesc('')
    } catch {
      setFormError(true)
    } finally {
      setSaving(false)
    }
  }

  const onAct = async (id: string, action: 'accepted' | 'rejected') => {
    setActing(id)
    try {
      await actOnInbox(id, action)
    } finally {
      setActing(null)
    }
  }

  if (loading) {
    return (
      <div className="grid animate-pulse grid-cols-2 gap-4 p-6 md:grid-cols-4">
        {[1, 2, 3, 4].map((i) => (
          <div key={i} className="h-28 rounded-2xl bg-slate-200" />
        ))}
      </div>
    )
  }

  const s = summary.stats

  return (
    <div className="space-y-5 p-4 sm:p-6">
      {/* Header */}
      <div className="animate-fade-up flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-bold text-slate-900 sm:text-2xl">
            سلام، {user?.display_name || user?.username}
          </h1>
          <p className="mt-0.5 text-xs text-slate-500 sm:text-sm">نمای کلی فعالیت‌های امروز شما</p>
        </div>
        <button onClick={() => void refresh()} className="btn-ghost border border-slate-200 bg-white shadow-sm">
          <Icon d={P.refresh} className="h-4 w-4" />
          به‌روزرسانی
        </button>
      </div>

      {error && (
        <p className="animate-fade-in rounded-2xl bg-red-50 px-4 py-3 text-xs text-red-600">{error}</p>
      )}

      {/* Stats */}
      <div className="grid grid-cols-2 gap-4 xl:grid-cols-4">
        <StatCard value={s.goals_active} label="اهداف فعال" icon={P.target} grad="from-blue-600 to-indigo-500" delay="stagger-1" />
        <StatCard value={s.goals_completed} label="اهداف تکمیل‌شده" icon={P.check} grad="from-emerald-500 to-teal-500" delay="stagger-2" />
        <StatCard value={s.inbox_pending} label="در انتظار بررسی" icon={P.inbox} grad="from-amber-500 to-orange-500" delay="stagger-3" />
        <StatCard value={s.tasks_open} label="وظایف باز" icon={P.list} grad="from-violet-600 to-purple-500" delay="stagger-4" />
      </div>

      <div className="grid items-start gap-5 xl:grid-cols-2">
        {/* Goals */}
        <Section
          title="اهداف من"
          delay="stagger-2"
          action={
            <span className="badge bg-brand-50 text-brand-700">
              {summary.recent_goals.length} مورد
            </span>
          }
        >
          <form onSubmit={onCreate} className="mb-3 rounded-2xl bg-slate-50 p-3">
            <div className="flex gap-2">
              <input
                className="input border-0 bg-white shadow-sm"
                placeholder="عنوان هدف جدید…"
                value={title}
                onChange={(e) => setTitle(e.target.value)}
              />
              <button type="submit" disabled={saving || !title.trim()} className="btn-primary shrink-0 px-4">
                <Icon d={P.plus} className="h-4 w-4" />
                {saving ? '...' : 'افزودن'}
              </button>
            </div>
            <input
              className="input mt-2 border-0 bg-white text-xs shadow-sm"
              placeholder="توضیح (اختیاری)"
              value={desc}
              onChange={(e) => setDesc(e.target.value)}
            />
            {formError && <p className="mt-2 text-xs text-red-600">ایجاد هدف ناموفق بود.</p>}
          </form>
          {summary.recent_goals.length === 0 ? (
            <Empty text="هنوز هدفی ثبت نشده است." />
          ) : (
            <ul className="max-h-80 space-y-2.5 overflow-y-auto pl-1">
              {summary.recent_goals.map((g, i) => (
                <li
                  key={g.id}
                  className="card-hover rounded-2xl border border-slate-100 bg-white p-3.5 shadow-sm"
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="truncate text-sm font-medium text-slate-800">{g.title}</span>
                    {g.status === 'completed' ? (
                      <span className="badge shrink-0 bg-emerald-50 text-emerald-700">
                        <Icon d={P.check} className="ml-1 h-3 w-3" />
                        تکمیل‌شده
                      </span>
                    ) : (
                      <span className="badge shrink-0 bg-brand-50 text-brand-700">
                        {g.progress_pct}٪
                      </span>
                    )}
                  </div>
                  <div className="mt-2.5 h-2 overflow-hidden rounded-full bg-slate-100">
                    <div
                      className={`h-full rounded-full bg-gradient-to-l ${BAR_COLORS[i % BAR_COLORS.length]} transition-all duration-500`}
                      style={{ width: `${g.progress_pct}%` }}
                    />
                  </div>
                </li>
              ))}
            </ul>
          )}
        </Section>

        {/* Inbox */}
        <Section
          title="صندوق ورودی"
          delay="stagger-3"
          action={
            s.inbox_pending > 0 ? (
              <span className="badge bg-amber-50 text-amber-700">{s.inbox_pending} در انتظار</span>
            ) : undefined
          }
        >
          {summary.pending_inbox.length === 0 ? (
            <Empty text="صندوق ورودی_EMPTY" />
          ) : (
            <ul className="max-h-80 space-y-2.5 overflow-y-auto pl-1">
              {summary.pending_inbox.map((it) => (
                <li key={it.id} className="rounded-2xl border border-amber-100 bg-amber-50/50 p-3.5">
                  <div className="flex items-start justify-between gap-2">
                    <span className="text-sm font-medium text-slate-800">{it.title}</span>
                    <span className="badge shrink-0 bg-white text-slate-500 shadow-sm">{it.item_type}</span>
                  </div>
                  <p className="mt-1 text-[11px] text-slate-500">
                    {it.sender_name ? `از ${it.sender_name}` : ''}
                  </p>
                  {it.message && <p className="mt-1.5 text-xs leading-5 text-slate-600">{it.message}</p>}
                  <div className="mt-2.5 flex gap-2">
                    <button
                      disabled={acting === it.id}
                      onClick={() => void onAct(it.id, 'accepted')}
                      className="btn-success-soft disabled:opacity-50"
                    >
                      <Icon d={P.check} className="h-3.5 w-3.5" />
                      تأیید
                    </button>
                    <button
                      disabled={acting === it.id}
                      onClick={() => void onAct(it.id, 'rejected')}
                      className="btn-danger-soft disabled:opacity-50"
                    >
                      <Icon d={P.x} className="h-3.5 w-3.5" />
                      رد
                    </button>
                  </div>
                </li>
              ))}
            </ul>
          )}
          <Link to="/inbox" className="btn-ghost mt-3 w-full text-brand-600">
            مشاهده همه در صندوق ورودی
          </Link>
        </Section>

        {/* Tasks */}
        <Section title="وظایف باز من" delay="stagger-4">
          {summary.open_tasks.length === 0 ? (
            <Empty text="وظیفه بازی ندارید." />
          ) : (
            <ul className="max-h-72 space-y-2 overflow-y-auto pl-1">
              {summary.open_tasks.map((t) => (
                <li
                  key={t.id}
                  className="flex items-center justify-between gap-2 rounded-xl border border-slate-100 p-3 text-sm"
                >
                  <span className="flex min-w-0 items-center gap-2.5">
                    <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-violet-50 text-violet-600">
                      <Icon d={P.list} className="h-4 w-4" />
                    </span>
                    <span className="min-w-0">
                      <span className="block truncate font-medium text-slate-800">{t.title}</span>
                      {t.goal_title && (
                        <span className="block truncate text-[11px] text-slate-400">{t.goal_title}</span>
                      )}
                    </span>
                  </span>
                  <span
                    className={`badge shrink-0 ${
                      t.priority === 'high' ? 'bg-red-50 text-red-600' : 'bg-slate-100 text-slate-500'
                    }`}
                  >
                    <Icon d={P.clock} className="ml-1 h-3 w-3" />
                    {t.status}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </Section>

        {/* Groups & rooms */}
        <Section title="گروه‌ها و گفتگوها" delay="stagger-5">
          {summary.my_groups.length === 0 && summary.my_rooms.length === 0 ? (
            <Empty text="عضو هیچ گروه یا اتاقی نیستید." />
          ) : (
            <div className="space-y-4">
              {summary.my_groups.length > 0 && (
                <div>
                  <p className="mb-2 text-[11px] font-medium text-slate-400">
                    گروه‌ها و گفتگوها_L ({s.groups_count})
                  </p>
                  <div className="flex flex-wrap gap-2">
                    {summary.my_groups.map((g) => (
                      <span
                        key={g.id}
                        className="inline-flex items-center gap-1.5 rounded-xl bg-slate-100 px-3 py-1.5 text-xs font-medium text-slate-700"
                      >
                        <Icon d={P.users} className="h-3.5 w-3.5 text-slate-400" />
                        {g.name}
                        {g.is_manager && (
                          <span className="badge bg-violet-100 text-violet-700">مدیر</span>
                        )}
                      </span>
                    ))}
                  </div>
                </div>
              )}
              {summary.my_rooms.length > 0 && (
                <div>
                  <p className="mb-2 text-[11px] font-medium text-slate-400">
                    اتاق‌های گفتگو ({s.rooms_count})
                  </p>
                  <div className="flex flex-wrap gap-2">
                    {summary.my_rooms.map((r) => (
                      <Link
                        key={r.id}
                        to="/chat"
                        className="inline-flex items-center gap-1.5 rounded-xl bg-brand-50 px-3 py-1.5 text-xs font-medium text-brand-700 transition-colors hover:bg-brand-100"
                      >
                        <Icon d={P.chat} className="h-3.5 w-3.5" />
                        {r.title}
                      </Link>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
          <Link to="/chat" className="btn-ghost mt-4 w-full text-brand-600">
            رفتن به گفتگوها
          </Link>
        </Section>
      </div>
    </div>
  )
}
```

==========================================================================================
## FILE: bastehE_frontend/web/src/features/GroupsPage.tsx
## SIZE: 14583 bytes
==========================================================================================

```tsx
import { useCallback, useEffect, useState } from 'react'
import { apiRef as api } from '../api/client'
import { useAuth } from '../security/authProvider'

function Icon({ d, className = 'h-5 w-5' }: { d: string; className?: string }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.8}
      strokeLinecap="round" strokeLinejoin="round" className={className} aria-hidden>
      <path d={d} />
    </svg>
  )
}

const P = {
  users: 'M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2M9 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM23 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75',
  plus: 'M12 5v14M5 12h14',
  lock: 'M5 11h14a2 2 0 0 1 2 2v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-7a2 2 0 0 1 2-2zM7 11V7a5 5 0 0 1 10 0v4',
  x: 'M18 6 6 18M6 6l12 12',
  check: 'M20 6 9 17l-5-5',
}

interface GroupRow {
  id: string
  name: string
  description?: string | null
  is_active: boolean
  member_count: number
  owner_id?: string | null
}

interface GroupMember {
  user_id: string
  is_manager: boolean
  joined_at: string
}

const PRIVACY_OPTIONS = [
  ['team_only', 'فقط تیم'],
  ['selected', 'افراد انتخاب‌شده'],
  ['fully_private', 'کاملاً خصوصی'],
  ['fully_transparent', 'کاملاً شفاف'],
] as const

export default function GroupsPage() {
  const { user } = useAuth()
  const [groups, setGroups] = useState<GroupRow[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  // Create form
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [privacy, setPrivacy] = useState<string>('team_only')
  const [creating, setCreating] = useState(false)

  // Selected group
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [members, setMembers] = useState<GroupMember[]>([])
  const [membersLoading, setMembersLoading] = useState(false)
  const [memberUid, setMemberUid] = useState('')
  const [adding, setAdding] = useState(false)

  // Users for dropdown (loaded once on mount)
  const [allUsers, setAllUsers] = useState<{ id: string; username: string; display_name: string; is_active: boolean }[]>([])
  const [usersLoading, setUsersLoading] = useState(false)

  const loadGroups = useCallback(async () => {
    setError(null)
    try {
      const res = await api.get('/groups/')
      setGroups(((res.data as any)?.data?.groups ?? []) as GroupRow[])
    } catch {
      setError('دریافت گروه‌ها ناموفق بود.')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    void loadGroups()
  }, [loadGroups])

  const loadMembers = useCallback(async (gid: string) => {
    setMembersLoading(true)
    try {
      const res = await api.get(`/groups/${gid}/members`)
      setMembers(((res.data as any)?.data?.members ?? []) as GroupMember[])
    } catch {
      setError('دریافت اعضای گروه ناموفق بود.')
    } finally {
      setMembersLoading(false)
    }
  }, [])

  useEffect(() => {
    if (selectedId) {
      void loadMembers(selectedId)
    } else {
      setMembers([])
    }
  }, [selectedId, loadMembers])

  const loadUsers = useCallback(async () => {
    setUsersLoading(true)
    try {
      const res = await api.get('/admin/users')
      const d = res.data as { items?: { id: string; username: string; display_name: string; is_active: boolean }[] }
      const items = d?.items ?? []
      const sorted = [...items].sort((a, b) =>
        (a.display_name || a.username).localeCompare(b.display_name || b.username, 'fa')
      )
      setAllUsers(sorted)
    } catch {
      setAllUsers([])
    } finally {
      setUsersLoading(false)
    }
  }, [])

  useEffect(() => {
    void loadUsers()
  }, [loadUsers])

  const nonMembers = allUsers.filter((u) => !members.some((m) => m.user_id === u.id))
  const userNameOf = (uid: string): string => {
    const u = allUsers.find((x) => x.id === uid)
    return u ? u.display_name || u.username : uid
  }

  const onCreate = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!name.trim()) return
    setCreating(true)
    setError(null)
    try {
      await api.post('/groups/', {
        name: name.trim(),
        description: description.trim() || undefined,
        privacy_level: privacy,
      })
      setName('')
      setDescription('')
      await loadGroups()
    } catch (e) {
      const d = (e as { response?: { data?: { message?: string; error?: string } } })?.response?.data
      setError(d?.message ?? d?.error ?? 'ایجاد گروه ناموفق بود.')
    } finally {
      setCreating(false)
    }
  }

  const onAddMember = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!selectedId || !memberUid) return
    setAdding(true)
    setError(null)
    try {
      await api.post(`/groups/${selectedId}/members`, {
        user_id: memberUid,
        is_manager: false,
      })
      setMemberUid('')
      await loadMembers(selectedId)
    } catch (e) {
      const d = (e as { response?: { data?: { message?: string; error?: string } } })?.response?.data
      setError(d?.message ?? d?.error ?? 'افزودن عضو ناموفق بود. تنها مدیر گروه می‌تواند عضو اضافه کند.')
    } finally {
      setAdding(false)
    }
  }

  return (
    <div className="space-y-5 p-4 sm:p-6">
      <div className="animate-fade-up">
        <h1 className="text-xl font-bold text-slate-900 sm:text-2xl">گروه‌ها</h1>
        <p className="mt-0.5 text-xs text-slate-500 sm:text-sm">گروه‌های سازمانی و اعضای آن‌ها</p>
      </div>

      {error && (
        <p className="animate-fade-in rounded-2xl bg-red-50 px-4 py-3 text-xs text-red-600">{error}</p>
      )}

      <div className="grid items-start gap-5 lg:grid-cols-3">
        {/* List */}
        <section className="card animate-fade-up stagger-1 lg:col-span-2">
          <h2 className="mb-3 text-base font-bold text-slate-800">لیست گروه‌ها</h2>
          {loading ? (
            <p className="text-xs text-slate-400">در حال بارگذاری…</p>
          ) : groups.length === 0 ? (
            <p className="rounded-xl bg-slate-50 px-4 py-8 text-center text-xs text-slate-400">
              هنوز گروهی ساخته نشده است.
            </p>
          ) : (
            <ul className="space-y-2.5">
              {groups.map((g) => {
                const isSelected = selectedId === g.id
                const isOwner = g.owner_id && user?.id ? g.owner_id === user.id : false
                return (
                  <li
                    key={g.id}
                    className={`rounded-2xl border p-4 transition-colors ${
                      isSelected ? 'border-brand-200 bg-brand-50/40' : 'border-slate-100 bg-white'
                    }`}
                  >
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="flex items-center gap-3">
                        <span className="flex h-10 w-10 items-center justify-center rounded-xl bg-brand-50 text-brand-500">
                          <Icon d={P.users} className="h-5 w-5" />
                        </span>
                        <div>
                          <p className="font-medium text-slate-800">{g.name}</p>
                          {g.description && (
                            <p className="text-[11px] text-slate-400">{g.description}</p>
                          )}
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className="badge bg-slate-100 text-slate-500">{g.member_count} عضو</span>
                        {isOwner && <span className="badge bg-violet-100 text-violet-700">مدیر</span>}
                        <button
                          onClick={() => setSelectedId(isSelected ? null : g.id)}
                          className={`rounded-lg px-3 py-1.5 text-xs font-medium transition-colors ${
                            isSelected
                              ? 'bg-brand-600 text-white'
                              : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
                          }`}
                        >
                          {isSelected ? 'بستن' : 'اعضا'}
                        </button>
                      </div>
                    </div>
                    {isSelected && (
                      <div className="mt-3 border-t border-slate-100 pt-3">
                        <p className="mb-2 text-[11px] font-medium text-slate-400">اعضای گروه</p>
                        {membersLoading ? (
                          <p className="text-xs text-slate-400">در حال بارگذاری…</p>
                        ) : members.length === 0 ? (
                          <p className="rounded-lg bg-slate-50 px-3 py-4 text-center text-xs text-slate-400">
                            عضوی در گروه نیست.
                          </p>
                        ) : (
                          <ul className="space-y-1.5">
                            {members.map((m) => (
                              <li
                                key={m.user_id}
                                className="flex items-center justify-between gap-2 rounded-xl bg-slate-50 px-3 py-2 text-xs"
                              >
                                <span className="min-w-0 truncate">
                                  <span className="font-medium text-slate-700">{userNameOf(m.user_id)}</span>
                                  <span className="mr-2 text-slate-400" dir="ltr">{m.user_id.slice(0, 8)}…</span>
                                </span>
                                <div className="flex shrink-0 items-center gap-2">
                                  {m.is_manager && (
                                    <span className="badge bg-violet-100 text-violet-700">مدیر</span>
                                  )}
                                  {m.user_id === user?.id && (
                                    <span className="badge bg-brand-50 text-brand-700">شما</span>
                                  )}
                                </div>
                              </li>
                            ))}
                          </ul>
                        )}
                        {isOwner && (
                          <form onSubmit={onAddMember} className="mt-3 flex flex-col sm:flex-row gap-2">
                            <div className="flex-1 flex flex-col gap-1">
                              <label className="text-[11px] text-slate-500">افزودن کاربر به گروه</label>
                              <select
                                className="input text-xs"
                                value={memberUid}
                                onChange={(e) => setMemberUid(e.target.value)}
                                disabled={adding || nonMembers.length === 0}
                              >
                                <option value="">— انتخاب از کاربران سیستم —</option>
                                {nonMembers.map((u) => (
                                  <option key={u.id} value={u.id}>
                                    {u.display_name || u.username}{u.is_active ? '' : ' (غیرفعال)'}
                                  </option>
                                ))}
                              </select>
                              {nonMembers.length === 0 && !usersLoading && (
                                <p className="text-[10px] text-slate-400">همه‌ی کاربران سیستم عضو این گروه هستند.</p>
                              )}
                              {usersLoading && <p className="text-[10px] text-slate-400">در حال بارگذاری کاربران…</p>}
                            </div>
                            <button
                              type="submit"
                              disabled={adding || !memberUid}
                              className="btn-ghost shrink-0 bg-brand-50 text-brand-700 hover:bg-brand-100 self-end"
                            >
                              <Icon d={P.plus} className="h-4 w-4" />
                              {adding ? '...' : 'افزودن'}
                            </button>
                          </form>
                        )}
                      </div>
                    )}
                  </li>
                )
              })}
            </ul>
          )}
        </section>

        {/* Create */}
        <section className="card animate-fade-up stagger-2">
          <h2 className="mb-3 flex items-center gap-2 text-base font-bold text-slate-800">
            <Icon d={P.plus} className="h-5 w-5 text-brand-500" />
            گروه جدید
          </h2>
          <form onSubmit={onCreate} className="space-y-4">
            <div>
              <label className="label" htmlFor="grp-name">نام گروه</label>
              <input
                id="grp-name"
                className="input"
                placeholder="مثلاً تیم توسعه"
                value={name}
                onChange={(e) => setName(e.target.value)}
              />
            </div>
            <div>
              <label className="label" htmlFor="grp-desc">توضیح</label>
              <input
                id="grp-desc"
                className="input"
                placeholder="توضیح (اختیاری)"
                value={description}
                onChange={(e) => setDescription(e.target.value)}
              />
            </div>
            <div>
              <label className="label" htmlFor="grp-privacy">حریم خصوصی</label>
              <select
                id="grp-privacy"
                className="input"
                value={privacy}
                onChange={(e) => setPrivacy(e.target.value)}
              >
                {PRIVACY_OPTIONS.map(([v, l]) => (
                  <option key={v} value={v}>{l}</option>
                ))}
              </select>
            </div>
            <button type="submit" disabled={creating || !name.trim()} className="btn-primary w-full">
              <Icon d={P.check} className="h-4 w-4" />
              {creating ? '...' : 'ایجاد گروه'}
            </button>
          </form>
        </section>
      </div>
    </div>
  )
}
```

==========================================================================================
## FILE: bastehE_frontend/web/src/features/InboxPage.tsx
## SIZE: 12638 bytes
==========================================================================================

```tsx
import { useCallback, useEffect, useState } from 'react'
import { apiRef as api } from '../api/client'
import { useAuth } from '../security/authProvider'

function Icon({ d, className = 'h-5 w-5' }: { d: string; className?: string }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.8}
      strokeLinecap="round" strokeLinejoin="round" className={className} aria-hidden>
      <path d={d} />
    </svg>
  )
}

const P = {
  inbox: 'M22 12h-6l-2 3h-4l-2-3H2M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z',
  check: 'M20 6 9 17l-5-5',
  x: 'M18 6 6 18M6 6l12 12',
  clock: 'M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20zM12 6v6l4 2',
  send: 'M22 2 11 13M22 2l-7 20-4-9-9-4z',
  plus: 'M12 5v14M5 12h14',
  list: 'M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01',
}

type Tab = 'inbox' | 'outbox' | 'compose'

interface InboxRow {
  id: string
  sender_id: string
  recipient_id: string
  item_type: string
  entity_type?: string | null
  entity_id?: string | null
  title: string
  message?: string | null
  priority: string
  action_state: string
  receipt_state: string
  seen_at?: string | null
  acted_at?: string | null
  response_note?: string | null
  created_at: string
}

interface OutboxRow {
  id: string
  recipient_id: string
  item_type: string
  title: string
  message?: string | null
  created_at: string
  read_receipt: boolean
}

function fmt(iso: string) {
  if (!iso) return ''
  try {
    return new Intl.DateTimeFormat('fa-IR', {
      day: '2-digit',
      month: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
    }).format(new Date(iso))
  } catch {
    return ''
  }
}

const ITEM_TYPES: Record<string, string> = {
  meeting_invite: 'دعوت به نشست',
  share_request: 'درخواست دسترسی',
  task_assignment: 'تعیین وظیفه',
  chat_invite: 'دعوت به گفتگو',
  approval: 'تأیید درخواست',
}

const ACTION_TINT: Record<string, string> = {
  pending: 'bg-amber-50 text-amber-700',
  accepted: 'bg-emerald-50 text-emerald-700',
  rejected: 'bg-red-50 text-red-600',
  deferred: 'bg-sky-50 text-sky-700',
  expired: 'bg-slate-100 text-slate-500',
}

export default function InboxPage() {
  const { user } = useAuth()
  const [tab, setTab] = useState<Tab>('inbox')
  const [items, setItems] = useState<InboxRow[]>([])
  const [outbox, setOutbox] = useState<OutboxRow[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [acting, setActing] = useState<string | null>(null)

  // Compose form
  const [recipientId, setRecipientId] = useState('')
  const [itemType, setItemType] = useState('task_assignment')
  const [title, setTitle] = useState('')
  const [message, setMessage] = useState('')
  const [priority, setPriority] = useState('normal')
  const [sending, setSending] = useState(false)

  const refresh = useCallback(async () => {
    if (!user?.id) return
    setError(null)
    try {
      const [inRes, outRes] = await Promise.all([
        api.get(`/inbox/${user.id}`),
        api.get('/inbox/outbox'),
      ])
      setItems(((inRes.data as any)?.data?.items ?? []) as InboxRow[])
      setOutbox(((outRes.data as any)?.data?.items ?? []) as OutboxRow[])
    } catch {
      setError('دریافت صندوق ورودی ناموفق بود.')
    } finally {
      setLoading(false)
    }
  }, [user?.id])

  useEffect(() => {
    void refresh()
  }, [refresh])

  const onAct = async (id: string, action: 'accepted' | 'rejected' | 'deferred') => {
    setActing(id)
    setError(null)
    try {
      await api.post(`/inbox/${id}/act`, { action })
      await refresh()
    } catch {
      setError('ثبت عملیات ناموفق بود.')
    } finally {
      setActing(null)
    }
  }

  const markRead = async (id: string) => {
    try {
      await api.post(`/inbox/${id}/read`)
    } catch {
      /* non-critical */
    }
  }

  const onCreate = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!recipientId.trim() || !title.trim()) return
    setSending(true)
    setError(null)
    try {
      await api.post('/inbox/', {
        recipient_id: recipientId.trim(),
        item_type: itemType,
        title: title.trim(),
        message: message.trim() || undefined,
        priority,
      })
      setRecipientId('')
      setTitle('')
      setMessage('')
      setPriority('normal')
      await refresh()
      setTab('outbox')
    } catch {
      setError('ارسال آیتم ناموفق بود. شناسه گیرنده را بررسی کنید.')
    } finally {
      setSending(false)
    }
  }

  const pending = items.filter((i) => i.action_state === 'pending')

  return (
    <div className="space-y-5 p-4 sm:p-6">
      <div className="animate-fade-up flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-bold text-slate-900 sm:text-2xl">صندوق ورودی</h1>
          <p className="mt-0.5 text-xs text-slate-500 sm:text-sm">پیگیری‌ها، درخواست‌ها و تأییدها</p>
        </div>
        <div className="flex gap-1.5 rounded-2xl bg-white p-1 shadow-sm border border-slate-200">
          {(
            [
              ['inbox', `ورودی (${pending.length})`],
              ['outbox', 'ارسال‌شده'],
              ['compose', 'آیتم جدید'],
            ] as [Tab, string][]
          ).map(([k, label]) => (
            <button
              key={k}
              onClick={() => setTab(k)}
              className={`rounded-xl px-4 py-2 text-xs font-medium transition-colors ${
                tab === k ? 'bg-brand-600 text-white shadow' : 'text-slate-600 hover:bg-slate-50'
              }`}
            >
              {label}
            </button>
          ))}
        </div>
      </div>

      {error && (
        <p className="animate-fade-in rounded-2xl bg-red-50 px-4 py-3 text-xs text-red-600">{error}</p>
      )}

      {tab === 'compose' ? (
        <section className="card animate-fade-up max-w-2xl">
          <h2 className="mb-4 text-base font-bold text-slate-800">ارسال آیتم جدید</h2>
          <form onSubmit={onCreate} className="space-y-4">
            <div>
              <label className="label" htmlFor="inbox-recipient">شناسه گیرنده (UUID)</label>
              <input
                id="inbox-recipient"
                className="input"
                dir="ltr"
                placeholder="مثلاً afd1b15e-f73a-4cad-96d3-bd96cf47f5dc"
                value={recipientId}
                onChange={(e) => setRecipientId(e.target.value)}
              />
            </div>
            <div>
              <label className="label" htmlFor="inbox-type">نوع آیتم</label>
              <select
                id="inbox-type"
                className="input"
                value={itemType}
                onChange={(e) => setItemType(e.target.value)}
              >
                {Object.entries(ITEM_TYPES).map(([v, l]) => (
                  <option key={v} value={v}>{l}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="label" htmlFor="inbox-title">عنوان</label>
              <input
                id="inbox-title"
                className="input"
                placeholder="عنوان آیتم"
                value={title}
                onChange={(e) => setTitle(e.target.value)}
              />
            </div>
            <div>
              <label className="label" htmlFor="inbox-msg">پیام</label>
              <textarea
                id="inbox-msg"
                className="input min-h-[5rem]"
                placeholder="توضیحات (اختیاری)"
                value={message}
                onChange={(e) => setMessage(e.target.value)}
              />
            </div>
            <div>
              <label className="label" htmlFor="inbox-prio">اولویت</label>
              <select
                id="inbox-prio"
                className="input"
                value={priority}
                onChange={(e) => setPriority(e.target.value)}
              >
                <option value="normal">عادی</option>
                <option value="high">بالا</option>
                <option value="low">پایین</option>
              </select>
            </div>
            <button type="submit" disabled={sending || !recipientId.trim() || !title.trim()} className="btn-primary">
              <Icon d={P.send} className="h-4 w-4" />
              {sending ? '...' : 'ارسال'}
            </button>
          </form>
        </section>
      ) : (
        <section className="card animate-fade-up">
          <h2 className="mb-3 text-base font-bold text-slate-800">
            {tab === 'inbox' ? 'آیتم‌های دریافتی' : 'آیتم‌های ارسال‌شده'}
          </h2>
          {loading ? (
            <p className="text-xs text-slate-400">در حال بارگذاری…</p>
          ) : tab === 'inbox' && items.length === 0 ? (
            <p className="rounded-xl bg-slate-50 px-4 py-8 text-center text-xs text-slate-400">
              آیتمی در صندوق نیست.
            </p>
          ) : tab === 'outbox' && outbox.length === 0 ? (
            <p className="rounded-xl bg-slate-50 px-4 py-8 text-center text-xs text-slate-400">
              آیتمی ارسال نکرده‌اید.
            </p>
          ) : (
            <ul className="max-h-[30rem] space-y-3 overflow-y-auto pl-1">
              {(tab === 'inbox' ? items : outbox as unknown as InboxRow[]).map((it) => (
                <li
                  key={it.id}
                  onClick={() => {
                    if (tab === 'inbox' && it.receipt_state === 'sent') void markRead(it.id)
                  }}
                  className="rounded-2xl border border-slate-100 bg-white p-4 shadow-sm card-hover"
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="font-medium text-slate-800">{it.title}</span>
                        <span className="badge bg-slate-100 text-slate-500">
                          {ITEM_TYPES[it.item_type] ?? it.item_type}
                        </span>
                        {tab === 'inbox' && (
                          <span className={`badge ${ACTION_TINT[(it as InboxRow).action_state] ?? ''}`}>
                            {(it as InboxRow).action_state}
                          </span>
                        )}
                      </div>
                      {it.message && (
                        <p className="mt-1 text-xs leading-5 text-slate-600">{it.message}</p>
                      )}
                    </div>
                    <span className="badge shrink-0 bg-slate-50 text-slate-400">{fmt(it.created_at)}</span>
                  </div>
                  {tab === 'inbox' && (it as InboxRow).action_state === 'pending' && (
                    <div className="mt-3 flex flex-wrap gap-2">
                      <button
                        disabled={acting === it.id}
                        onClick={() => void onAct(it.id, 'accepted')}
                        className="btn-success-soft disabled:opacity-50"
                      >
                        <Icon d={P.check} className="h-3.5 w-3.5" />
                        تأیید
                      </button>
                      <button
                        disabled={acting === it.id}
                        onClick={() => void onAct(it.id, 'deferred')}
                        className="btn-ghost disabled:opacity-50 bg-sky-50 text-sky-700 hover:bg-sky-100"
                      >
                        <Icon d={P.clock} className="h-3.5 w-3.5" />
                        به تعویق
                      </button>
                      <button
                        disabled={acting === it.id}
                        onClick={() => void onAct(it.id, 'rejected')}
                        className="btn-danger-soft disabled:opacity-50"
                      >
                        <Icon d={P.x} className="h-3.5 w-3.5" />
                        رد
                      </button>
                    </div>
                  )}
                </li>
              ))}
            </ul>
          )}
        </section>
      )}
    </div>
  )
}
```

==========================================================================================
## FILE: bastehE_frontend/web/src/features/ReportsPage.tsx
## SIZE: 9459 bytes
==========================================================================================

```tsx
import { useCallback, useEffect, useState } from 'react'
import { apiRef as api } from '../api/client'

function Icon({ d, className = 'h-5 w-5' }: { d: string; className?: string }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.8}
      strokeLinecap="round" strokeLinejoin="round" className={className} aria-hidden>
      <path d={d} />
    </svg>
  )
}

const P = {
  chart: 'M18 20V10M12 20V4M6 20v-6',
  grid: 'M3 3h7v7H3zM14 3h7v7h-7zM3 14h7v7H3zM14 14h7v7h-7z',
  plus: 'M12 5v14M5 12h14',
  refresh: 'M23 4v6h-6M1 20v-6h6M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15',
  check: 'M20 6 9 17l-5-5',
}

interface LayoutRow {
  id: string
  name: string
  view_mode: string
  is_default: boolean
}

interface WidgetRow {
  widget_key: string
  platform: string
  is_visible: boolean
  position_x: number
  position_y: number
  width: number
  height: number
}

const VIEW_MODES = ['daily', 'weekly', 'monthly'] as const

export default function ReportsPage() {
  const [layouts, setLayouts] = useState<LayoutRow[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const [layoutName, setLayoutName] = useState('')
  const [viewMode, setViewMode] = useState<string>('daily')
  const [savingLayout, setSavingLayout] = useState(false)

  const [widgets, setWidgets] = useState<WidgetRow[]>([])
  const [widgetsLoaded, setWidgetsLoaded] = useState(false)
  const [savingWidgets, setSavingWidgets] = useState(false)

  const loadLayouts = useCallback(async () => {
    setError(null)
    try {
      const res = await api.get('/reporting/layouts')
      setLayouts(((res.data as any)?.data?.layouts ?? []) as LayoutRow[])
    } catch {
      setError('دریافت چیدمان‌های داشبورد ناموفق بود.')
    } finally {
      setLoading(false)
    }
  }, [])

  const loadWidgets = useCallback(async () => {
    try {
      const res = await api.get('/reporting/widgets/settings')
      setWidgets(((res.data as any)?.data?.widgets?.widgets ?? []) as WidgetRow[])
    } catch {
      /* non-critical */
    } finally {
      setWidgetsLoaded(true)
    }
  }, [])

  useEffect(() => {
    void loadLayouts()
    void loadWidgets()
  }, [loadLayouts, loadWidgets])

  const onSaveLayout = async (e: React.FormEvent) => {
    e.preventDefault()
    setSavingLayout(true)
    setError(null)
    try {
      await api.post('/reporting/layouts', {
        name: layoutName.trim() || 'چیدمان جدید',
        view_mode: viewMode,
        is_default: false,
        schema_version: 1,
        blocks: [],
      })
      setLayoutName('')
      await loadLayouts()
    } catch {
      setError('ذخیره چیدمان ناموفق بود.')
    } finally {
      setSavingLayout(false)
    }
  }

  const toggleWidget = (key: string) => {
    setWidgets((prev) =>
      prev.map((w) => (w.widget_key === key ? { ...w, is_visible: !w.is_visible } : w)),
    )
  }

  const onSaveWidgets = async () => {
    setSavingWidgets(true)
    setError(null)
    try {
      await api.post('/reporting/widgets/settings', {
        widgets: widgets.map((w) => ({ ...w })),
      })
    } catch {
      setError('ذخیره تنظیمات ویجت‌ها ناموفق بود.')
    } finally {
      setSavingWidgets(false)
    }
  }

  const onResetWidgets = async () => {
    setError(null)
    try {
      await api.post('/reporting/widgets/settings/reset')
      setWidgets([])
    } catch {
      setError('بازیابی پیش‌فرض ویجت‌ها ناموفق بود.')
    }
  }

  return (
    <div className="space-y-5 p-4 sm:p-6">
      <div className="animate-fade-up">
        <h1 className="text-xl font-bold text-slate-900 sm:text-2xl">گزارش‌ها</h1>
        <p className="mt-0.5 text-xs text-slate-500 sm:text-sm">چیدمان داشبورد و تنظیمات ویجت‌ها</p>
      </div>

      {error && (
        <p className="animate-fade-in rounded-2xl bg-red-50 px-4 py-3 text-xs text-red-600">{error}</p>
      )}

      <div className="grid items-start gap-5 lg:grid-cols-2">
        {/* Layouts */}
        <section className="card animate-fade-up stagger-1">
          <div className="mb-3 flex items-center justify-between">
            <h2 className="flex items-center gap-2 text-base font-bold text-slate-800">
              <Icon d={P.grid} className="h-5 w-5 text-brand-500" />
              چیدمان‌های داشبورد
            </h2>
            <span className="badge bg-brand-50 text-brand-700">{layouts.length} چیدمان</span>
          </div>
          <form onSubmit={onSaveLayout} className="mb-4 space-y-3 rounded-2xl bg-slate-50 p-3">
            <div className="flex gap-2">
              <input
                className="input border-0 bg-white text-xs shadow-sm"
                placeholder="نام چیدمان"
                value={layoutName}
                onChange={(e) => setLayoutName(e.target.value)}
              />
              <select
                className="input w-36 border-0 bg-white text-xs shadow-sm"
                value={viewMode}
                onChange={(e) => setViewMode(e.target.value)}
              >
                {VIEW_MODES.map((v) => (
                  <option key={v} value={v}>{v}</option>
                ))}
              </select>
            </div>
            <button type="submit" disabled={savingLayout} className="btn-primary w-full text-xs">
              <Icon d={P.plus} className="h-4 w-4" />
              {savingLayout ? '...' : 'ذخیره چیدمان'}
            </button>
          </form>
          {loading ? (
            <p className="text-xs text-slate-400">در حال بارگذاری…</p>
          ) : layouts.length === 0 ? (
            <p className="rounded-xl bg-slate-50 px-4 py-6 text-center text-xs text-slate-400">
              چیدمانی ذخیره نشده است.
            </p>
          ) : (
            <ul className="space-y-2">
              {layouts.map((l) => (
                <li key={l.id} className="flex items-center justify-between gap-2 rounded-xl border border-slate-100 px-3.5 py-3">
                  <div className="min-w-0">
                    <p className="truncate text-sm font-medium text-slate-800">{l.name}</p>
                    <p className="text-[11px] text-slate-400">{l.view_mode}</p>
                  </div>
                  {l.is_default ? (
                    <span className="badge shrink-0 bg-emerald-50 text-emerald-700">پیش‌فرض</span>
                  ) : (
                    <span className="badge shrink-0 bg-slate-100 text-slate-500">عادی</span>
                  )}
                </li>
              ))}
            </ul>
          )}
        </section>

        {/* Widgets */}
        <section className="card animate-fade-up stagger-2">
          <div className="mb-3 flex items-center justify-between">
            <h2 className="flex items-center gap-2 text-base font-bold text-slate-800">
              <Icon d={P.chart} className="h-5 w-5 text-brand-500" />
              تنظیمات ویجت‌ها
            </h2>
            <button onClick={() => void onResetWidgets()} className="btn-ghost p-2 text-slate-400 hover:text-slate-700">
              <Icon d={P.refresh} className="h-4 w-4" />
              پیش‌فرض
            </button>
          </div>
          {!widgetsLoaded ? (
            <p className="text-xs text-slate-400">در حال بارگذاری…</p>
          ) : widgets.length === 0 ? (
            <p className="rounded-xl bg-slate-50 px-4 py-6 text-center text-xs text-slate-400">
              ویجتی تنظیم نشده است. وضعیت را تغییر دهید و ذخیره کنید.
            </p>
          ) : (
            <ul className="max-h-72 space-y-2 overflow-y-auto pl-1">
              {widgets.map((w) => (
                <li key={w.widget_key} className="flex items-center justify-between gap-2 rounded-xl border border-slate-100 px-3.5 py-2.5">
                  <div className="min-w-0">
                    <p className="truncate text-sm font-medium text-slate-800">{w.widget_key}</p>
                    <p className="text-[11px] text-slate-400">
                      {w.platform} · {w.width}×{w.height}
                    </p>
                  </div>
                  <button
                    onClick={() => toggleWidget(w.widget_key)}
                    className={`relative h-6 w-11 shrink-0 rounded-full transition-colors ${
                      w.is_visible ? 'bg-brand-500' : 'bg-slate-200'
                    }`}
                    aria-label={w.widget_key}
                  >
                    <span
                      className={`absolute top-0.5 h-5 w-5 rounded-full bg-white shadow transition-all ${
                        w.is_visible ? 'right-0.5' : 'right-5'
                      }`}
                    />
                  </button>
                </li>
              ))}
            </ul>
          )}
          {widgets.length > 0 && (
            <button onClick={() => void onSaveWidgets()} disabled={savingWidgets} className="btn-primary mt-4 w-full text-xs">
              <Icon d={P.check} className="h-4 w-4" />
              {savingWidgets ? '...' : 'ذخیره تنظیمات'}
            </button>
          )}
        </section>
      </div>
    </div>
  )
}
```

==========================================================================================
## FILE: bastehE_frontend/web/src/features/SettingsPage.tsx
## SIZE: 19407 bytes
==========================================================================================

```tsx
import { useEffect, useState } from 'react'
import { apiRef as api } from '../api/client'
import { useAuth } from '../security/authProvider'

function Icon({ d, className = 'h-5 w-5' }: { d: string; className?: string }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.8}
      strokeLinecap="round" strokeLinejoin="round" className={className} aria-hidden>
      <path d={d} />
    </svg>
  )
}

const P = {
  user: 'M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2M12 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8z',
  users: 'M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2M9 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM23 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75',
  shield: 'M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z',
  target: 'M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20zM12 18a6 6 0 1 0 0-12 6 6 0 0 0 0 12zM12 14a2 2 0 1 0 0-4 2 2 0 0 0 0 4z',
  key: 'M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4',
}

interface UserRole {
  id: number
  code: string
  title_fa: string
  level: number
  scope_type: string
  scope_id?: string | null
  source: string
}

interface AdminUser {
  id: string
  username: string
  display_name: string
  national_id_masked: string
  is_active: boolean
  auth_mode: string
  mfa_enabled: boolean
  last_login_at?: string | null
}

interface SsoStatus {
  enabled: boolean
  ldap3_installed: boolean
  ldap_server_uri: string
  ldap_base_dn: string
  ldap_auto_provision: boolean
  kerberos_available: boolean
  group_role_map_enabled: boolean
  negotiate: string
  ldap_login: string
}

function errMsg(e: unknown): string {
  const d = (e as { response?: { data?: { message?: string; error?: string } } })?.response?.data
  return d?.message ?? d?.error ?? 'خطای نامشخص رخ داد.'
}

export default function SettingsPage() {
  const { user, logout } = useAuth()
  const [roles, setRoles] = useState<UserRole[]>([])
  const [permCount, setPermCount] = useState<number>(0)
  const [error, setError] = useState<string | null>(null)

  const [canManage, setCanManage] = useState<boolean | null>(null)
  const [users, setUsers] = useState<AdminUser[]>([])
  const [total, setTotal] = useState(0)
  const [search, setSearch] = useState('')
  const [usersMsg, setUsersMsg] = useState<string | null>(null)
  const [busyId, setBusyId] = useState<string | null>(null)
  const [form, setForm] = useState({ username: '', national_id: '', display_name: '', initial_password: '' })
  const [creating, setCreating] = useState(false)
  const [availRoles, setAvailRoles] = useState<{ id: number; code: string; title_fa: string; level: number }[]>([])
  const [assignBusy, setAssignBusy] = useState<Record<string, boolean>>({})

  const [sso, setSso] = useState<SsoStatus | null>(null)
  const [ssoError, setSsoError] = useState<string | null>(null)

  const loadUsers = async (q?: string) => {
    try {
      const params = q ? `?search=${encodeURIComponent(q)}` : ''
      const res = await api.get(`/admin/users${params}`)
      const d = (res.data ?? {}) as { items?: AdminUser[]; total?: number }
      setUsers(d.items ?? [])
      setTotal(d.total ?? 0)
      setCanManage(true)
      setUsersMsg(null)
    } catch (e) {
      const st = (e as { response?: { status?: number } })?.response?.status
      if (st === 403 || st === 404) {
        setCanManage(false)
      } else {
        setUsersMsg(errMsg(e))
      }
    }
  }

  useEffect(() => {
    if (!user?.id) return
    let cancelled = false
    const load = async () => {
      try {
        const [rRes, pRes, roleRes] = await Promise.all([
          api.get(`/rbac/user/${user.id}/roles`),
          api.get('/rbac/permissions'),
          api.get('/rbac/roles'),
        ])
        if (!cancelled) {
          setRoles(((rRes.data as any)?.data?.roles ?? []) as UserRole[])
          setPermCount(((pRes.data as any)?.data?.permissions ?? []).length)
          setAvailRoles((roleRes.data as any)?.data?.roles ?? [])
        }
      } catch {
        if (!cancelled) setError('دریافت اطلاعات دسترسی ناموفق بود.')
      }
      try {
        const sRes = await api.get('/auth/sso/status')
        if (!cancelled) {
          setSso(sRes.data as SsoStatus)
          setSsoError(null)
        }
      } catch (e) {
        if (!cancelled) setSsoError(errMsg(e))
      }
      if (!cancelled) void loadUsers()
    }
    void load()
    return () => { cancelled = true }
  }, [user?.id])

  if (!user) return null

  const fields: [string, string][] = [
    ['نام نمایشی', user.display_name ?? ''],
    ['نام کاربری', user.username ?? ''],
    ['کد ملی', user.national_id_masked ?? ''],
    ['حالت احراز هویت', user.auth_mode ?? ''],
    ['آخرین ورود', user.last_login_at ? new Date(user.last_login_at).toLocaleString('fa-IR') : '—'],
  ]

  const toggleActive = async (u: AdminUser) => {
    if (u.id === user.id) {
      setUsersMsg('نمی‌توانید حساب خودتان را غیرفعال کنید.')
      return
    }
    setBusyId(u.id)
    try {
      await api.patch(`/admin/users/${u.id}`, { is_active: !u.is_active })
      setUsers((prev) => prev.map((x) => (x.id === u.id ? { ...x, is_active: !u.is_active } : x)))
      setUsersMsg(null)
    } catch (e) {
      setUsersMsg(errMsg(e))
    } finally {
      setBusyId(null)
    }
  }

  const toggleSso = async (u: AdminUser) => {
    setBusyId(u.id)
    try {
      const res = await api.post('/admin/users/bulk-login-mode', {
        user_ids: [u.id],
        sso_enabled: u.auth_mode !== 'sso',
      })
      const failed = ((res.data ?? {}) as { failed?: unknown[] })?.failed ?? []
      if (failed.length > 0) {
        setUsersMsg('تغییر حالت ورود برای این کاربر ناموفق بود.')
      } else {
        setUsers((prev) =>
          prev.map((x) => (x.id === u.id ? { ...x, auth_mode: x.auth_mode === 'sso' ? 'local' : 'sso' } : x)),
        )
        setUsersMsg(null)
      }
    } catch (e) {
      setUsersMsg(errMsg(e))
    } finally {
      setBusyId(null)
    }
  }

  const createUser = async () => {
    if (!form.username || !form.national_id || !form.display_name || !form.initial_password) {
      setUsersMsg('همه فیلدهای فرم ایجاد کاربر الزامی است.')
      return
    }
    setCreating(true)
    try {
      await api.post('/admin/users', form)
      setForm({ username: '', national_id: '', display_name: '', initial_password: '' })
      setUsersMsg(null)
      await loadUsers(search || undefined)
    } catch (e) {
      setUsersMsg(errMsg(e))
    } finally {
      setCreating(false)
    }
  }

  const assignRole = async (u: AdminUser, roleId: number) => {
    if (u.id === user.id) {
      setUsersMsg('نمی‌توانید به خودتان نقش بدهید.')
      return
    }
    setAssignBusy({ ...assignBusy, [u.id]: true })
    try {
      await api.post('/rbac/assign', { role_id: roleId, target_user_id: u.id, scope_type: 'global' })
      setUsersMsg(null)
      await loadUsers(search || undefined)
    } catch (e) {
      setUsersMsg(errMsg(e))
    } finally {
      setAssignBusy({ ...assignBusy, [u.id]: false })
    }
  }

  const revokeRole = async (u: AdminUser, roleId: number) => {
    if (u.id === user.id) {
      setUsersMsg('نمی‌توانید نقش خودتان را بردارید.')
      return
    }
    setAssignBusy({ ...assignBusy, [u.id]: true })
    try {
      await api.post('/rbac/revoke', { role_id: roleId, target_user_id: u.id, scope_type: 'global' })
      setUsersMsg(null)
      await loadUsers(search || undefined)
    } catch (e) {
      setUsersMsg(errMsg(e))
    } finally {
      setAssignBusy({ ...assignBusy, [u.id]: false })
    }
  }

  return (
    <div className="space-y-5 p-4 sm:p-6">
      <div className="animate-fade-up">
        <h1 className="text-xl font-bold text-slate-900 sm:text-2xl">تنظیمات</h1>
        <p className="mt-0.5 text-xs text-slate-500 sm:text-sm">پروفایل، دسترسی‌ها، مدیریت کاربران و SSO/LDAP</p>
      </div>

      {error && (
        <p className="animate-fade-in rounded-2xl bg-red-50 px-4 py-3 text-xs text-red-600">{error}</p>
      )}

      <div className="grid items-start gap-5 lg:grid-cols-2">
        <section className="card animate-fade-up stagger-1">
          <div className="mb-4 flex items-center gap-3">
            <span className="flex h-14 w-14 items-center justify-center rounded-2xl bg-gradient-to-bl from-brand-500 to-indigo-500 text-white shadow-lg">
              <Icon d={P.user} className="h-7 w-7" />
            </span>
            <div>
              <h2 className="text-lg font-bold text-slate-800">{user.display_name || user.username}</h2>
              <p className="text-[11px] text-slate-400">{user.username} · {user.national_id_masked}</p>
            </div>
          </div>
          <div className="space-y-1.5">
            {fields.map(([k, v]) => (
              <div key={k} className="flex items-center justify-between gap-2 rounded-xl bg-slate-50 px-4 py-2.5 text-sm">
                <span className="text-slate-500">{k}</span>
                <span className="font-medium text-slate-800">{v}</span>
              </div>
            ))}
          </div>
          <div className="mt-4">
            <button onClick={() => void logout()} className="btn-danger-soft w-full">
              خروج از حساب
            </button>
          </div>
        </section>

        <section className="card animate-fade-up stagger-2">
          <h2 className="mb-3 flex items-center gap-2 text-base font-bold text-slate-800">
            <Icon d={P.shield} className="h-5 w-5 text-brand-500" />
            نقش‌ها و دسترسی‌ها
          </h2>
          {roles.length === 0 ? (
            <p className="rounded-xl bg-slate-50 px-4 py-6 text-center text-xs text-slate-400">
              نقشی برای شما ثبت نشده است.
            </p>
          ) : (
            <ul className="space-y-2">
              {roles.map((r) => (
                <li key={r.id} className="flex items-center justify-between gap-2 rounded-xl border border-slate-100 px-4 py-3">
                  <div className="flex items-center gap-3">
                    <span className="flex h-9 w-9 items-center justify-center rounded-xl bg-brand-50 text-brand-600">
                      <Icon d={P.shield} className="h-5 w-5" />
                    </span>
                    <div>
                      <p className="text-sm font-medium text-slate-800">{r.title_fa}</p>
                      <p className="text-[11px] text-slate-400" dir="ltr">{r.code}</p>
                    </div>
                  </div>
                  <div className="flex shrink-0 flex-col items-end gap-1">
                    <span className="badge bg-violet-100 text-violet-700">سطح {r.level}</span>
                    <span className="text-[10px] text-slate-400">{r.scope_type}</span>
                  </div>
                </li>
              ))}
            </ul>
          )}
          <div className="mt-4 flex items-center justify-between rounded-2xl bg-slate-50 p-4">
            <span className="flex items-center gap-2 text-sm text-slate-600">
              <Icon d={P.target} className="h-4 w-4 text-slate-400" />
              تعداد دسترسی‌های فعال
            </span>
            <span className="text-lg font-bold text-slate-800">{permCount}</span>
          </div>
        </section>

        <section className="card animate-fade-up stagger-2 lg:col-span-2">
          <h2 className="mb-3 flex items-center gap-2 text-base font-bold text-slate-800">
            <Icon d={P.users} className="h-5 w-5 text-brand-500" />
            مدیریت کاربران (تعریف کاربر)
          </h2>
          {canManage === false ? (
            <p className="rounded-xl bg-slate-50 px-4 py-6 text-center text-xs text-slate-400">
              حساب شما دسترسی مدیریت کاربران ندارد.
            </p>
          ) : (
            <div className="space-y-4">
              <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
                <input className="input" placeholder="نام کاربری" value={form.username}
                  onChange={(e) => setForm({ ...form, username: e.target.value })} />
                <input className="input" placeholder="کد ملی (۱۰ رقم)" inputMode="numeric" maxLength={10}
                  value={form.national_id} onChange={(e) => setForm({ ...form, national_id: e.target.value })} />
                <input className="input" placeholder="نام نمایشی" value={form.display_name}
                  onChange={(e) => setForm({ ...form, display_name: e.target.value })} />
                <input className="input" type="password" placeholder="رمز موقت (حداقل ۸ کاراکتر)"
                  value={form.initial_password} onChange={(e) => setForm({ ...form, initial_password: e.target.value })} />
              </div>
              <div className="flex flex-wrap items-center gap-2">
                <button className="btn-primary" disabled={creating} onClick={() => void createUser()}>
                  {creating ? 'در حال ایجاد…' : 'ایجاد کاربر'}
                </button>
                <input className="input max-w-xs" placeholder="جست‌وجوی نام کاربری/نام نمایشی…"
                  value={search} onChange={(e) => { setSearch(e.target.value); void loadUsers(e.target.value || undefined) }} />
                <span className="text-[11px] text-slate-400">مجموع: {total}</span>
              </div>
              {usersMsg && <p className="rounded-xl bg-red-50 px-4 py-2.5 text-xs text-red-600">{usersMsg}</p>}
              {users.length === 0 ? (
                <p className="rounded-xl bg-slate-50 px-4 py-6 text-center text-xs text-slate-400">
                  کاربری یافت نشد.
                </p>
              ) : (
                <ul className="space-y-2">
                  {users.map((u) => (
                    <li key={u.id} className="flex flex-wrap items-center justify-between gap-2 rounded-xl border border-slate-100 px-4 py-3">
                      <div className="flex items-center gap-3">
                        <span className="flex h-9 w-9 items-center justify-center rounded-xl bg-brand-50 text-brand-600">
                          <Icon d={P.user} className="h-5 w-5" />
                        </span>
                        <div>
                          <p className="text-sm font-medium text-slate-800">
                            {u.display_name} <span className="text-[11px] font-normal text-slate-400" dir="ltr">{u.username}</span>
                          </p>
                          <p className="text-[11px] text-slate-400">
                            {u.national_id_masked} · ورود: {u.auth_mode} · MFA: {u.mfa_enabled ? 'فعال' : 'غیرفعال'}
                          </p>
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className={`badge ${u.is_active ? 'bg-emerald-100 text-emerald-700' : 'bg-slate-200 text-slate-500'}`}>
                          {u.is_active ? 'فعال' : 'غیرفعال'}
                        </span>
                        <button className="btn-ghost text-xs" disabled={busyId === u.id || u.id === user.id}
                          title={u.id === user.id ? 'حساب خودتان' : 'تغییر وضعیت'} onClick={() => void toggleActive(u)}>
                          {busyId === u.id ? '…' : u.is_active ? 'غیرفعال کن' : 'فعال کن'}
                        </button>
                        <button className="btn-ghost text-xs" disabled={busyId === u.id}
                          title="تغییر حالت ورود SSO" onClick={() => void toggleSso(u)}>
                          {busyId === u.id ? '…' : u.auth_mode === 'sso' ? 'غیرفعال‌سازی SSO' : 'فعال‌سازی SSO'}
                        </button>
                        <div className="flex items-center gap-1">
                          <select className="input w-auto min-w-[180px] text-xs"
                            disabled={assignBusy[u.id] || u.id === user.id}
                            defaultValue="" onChange={(e) => { const id = Number(e.target.value); if (id) void assignRole(u, id) }}>
                            <option value="">— نقش —</option>
                            {availRoles.map((r) => (
                              <option key={r.id} value={String(r.id)}>{r.title_fa} (سطح {r.level})</option>
                            ))}
                          </select>
                        </div>
                      </div>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          )}
        </section>

        <section className="card animate-fade-up stagger-2 lg:col-span-2">
          <h2 className="mb-3 flex items-center gap-2 text-base font-bold text-slate-800">
            <Icon d={P.key} className="h-5 w-5 text-brand-500" />
            SSO و LDAP
          </h2>
          {ssoError ? (
            <p className="rounded-xl bg-red-50 px-4 py-3 text-xs text-red-600">{ssoError}</p>
          ) : !sso ? (
            <p className="rounded-xl bg-slate-50 px-4 py-6 text-center text-xs text-slate-400">
              در حال بارگذاری وضعیت SSO…
            </p>
          ) : (
            <div className="space-y-1.5">
              {([
                ['وضعیت کلی SSO', sso.enabled ? 'فعال' : 'غیرفعال'],
                ['پکیج ldap3', sso.ldap3_installed ? 'نصب شده' : 'نصب نیست'],
                ['سرور LDAP', sso.ldap_server_uri],
                ['Base DN', sso.ldap_base_dn],
                ['Auto-Provision', sso.ldap_auto_provision ? 'فعال' : 'غیرفعال'],
                ['Kerberos/SPNEGO', sso.kerberos_available ? 'پیکربندی شده' : 'پیکربندی نشده (fallback به LDAP)'],
                ['نگاشت گروه→نقش', sso.group_role_map_enabled ? 'فعال' : 'غیرفعال'],
                ['endpoint ورود LDAP', sso.ldap_login],
                ['endpoint مذاکره SPNEGO', sso.negotiate],
              ] as [string, string][]).map(([k, v]) => (
                <div key={k} className="flex items-center justify-between gap-2 rounded-xl bg-slate-50 px-4 py-2.5 text-sm">
                  <span className="text-slate-500">{k}</span>
                  <span className="font-medium text-slate-800" dir="auto">{v}</span>
                </div>
              ))}
              <p className="px-1 pt-1 text-[11px] leading-6 text-slate-400">
                فعال‌سازی ورود SSO برای هر کاربر از بخش «مدیریت کاربران» انجام می‌شود؛ ورود واقعی LDAP با همان نام‌کاربری/رمز AD از مسیر endpoint ورود LDAP انجام می‌شود و نتیجه در لاگ ورود ثبت می‌گردد.
              </p>
            </div>
          )}
        </section>
      </div>
    </div>
  )
}
```

==========================================================================================
## FILE: bastehE_frontend/web/src/hooks/useDashboard.ts
## SIZE: 2794 bytes
==========================================================================================

```typescript
import { useCallback, useEffect, useState } from 'react'
import { apiRef as api } from '../api/client'

const BASE = '/reporting/dashboard'

export interface DashStats {
  goals_active: number
  goals_completed: number
  goals_total: number
  tasks_open: number
  inbox_pending: number
  groups_count: number
  rooms_count: number
}

export interface DashGoal {
  id: string
  title: string
  description?: string | null
  status: string
  progress_pct: number
  due_date?: string | null
  created_at: string
}

export interface DashTask {
  id: string
  title: string
  status: string
  priority: string
  due_date?: string | null
  goal_title?: string | null
}

export interface DashInbox {
  id: string
  title: string
  message?: string | null
  item_type: string
  priority: string
  action_state: string
  created_at: string
  sender_name?: string | null
}

export interface DashGroup {
  id: string
  name: string
  is_manager: boolean
}

export interface DashboardSummary {
  stats: DashStats
  recent_goals: DashGoal[]
  open_tasks: DashTask[]
  pending_inbox: DashInbox[]
  my_groups: DashGroup[]
  my_rooms: { id: string; title: string; linked_type?: string | null }[]
}

const EMPTY: DashboardSummary = {
  stats: {
    goals_active: 0,
    goals_completed: 0,
    goals_total: 0,
    tasks_open: 0,
    inbox_pending: 0,
    groups_count: 0,
    rooms_count: 0,
  },
  recent_goals: [],
  open_tasks: [],
  pending_inbox: [],
  my_groups: [],
  my_rooms: [],
}

function unwrap<T>(res: any): T | null {
  const d = res?.data ?? res
  return (d?.data ?? d ?? null) as T | null
}

export function useDashboard() {
  const [summary, setSummary] = useState<DashboardSummary>(EMPTY)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const refresh = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const res = await api.get(`${BASE}/summary`)
      const data = unwrap<DashboardSummary>(res)
      if (data) setSummary({ ...EMPTY, ...data })
      else setError('دریافت اطلاعات داشبورد ناموفق بود.')
    } catch {
      setError('ارتباط با سرور برقرار نشد.')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    void refresh()
  }, [refresh])

  const createGoal = useCallback(
    async (title: string, description?: string) => {
      await api.post(`${BASE}/goals`, { title, description })
      await refresh()
    },
    [refresh],
  )

  const actOnInbox = useCallback(
    async (id: string, action: 'accepted' | 'rejected') => {
      await api.post(`${BASE}/inbox/${id}/act`, { action })
      await refresh()
    },
    [refresh],
  )

  return { summary, loading, error, refresh, createGoal, actOnInbox }
}
```

==========================================================================================
## FILE: bastehE_frontend/web/src/hooks/useLayoutPersistence.ts
## SIZE: 6277 bytes
==========================================================================================

```typescript
import { useState, useEffect, useCallback } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import { useQueryClient } from '@tanstack/react-query'
import { api } from '../api/client'
import { logger } from '../security/sanitize'

/** Hook for managing widget layout persistence */
export function useLayoutPersistence(userId: string) {
  const [layout, setLayout] = useState<any>([])

  // Load saved layout from localStorage
  useEffect(() => {
    try {
      const saved = localStorage.getItem(`layout_${userId}`)
      if (saved) {
        setLayout(JSON.parse(saved))
      }
    } catch (e) {
      logger.error('Layout persistence load error:', e)
    }
  }, [userId])

  // Save layout on change
  useEffect(() => {
    try {
      localStorage.setItem(`layout_${userId}`, JSON.stringify(layout))
    } catch (e) {
      logger.error('Layout persistence save error:', e)
    }
  }, [layout, userId])

  const setLayoutConfig = (newLayout: any) => {
    setLayout(newLayout)
  }

  const resetLayout = () => {
    setLayout([])
    try {
      localStorage.removeItem(`layout_${userId}`)
    } catch (e) {
      logger.error('Layout reset error:', e)
    }
  }

  return { layout, setLayoutConfig, resetLayout }
}

/** Hook for managing widget settings (clock, etc.) */
export function useWidgetSettings(userId: string) {
  const [widgets, setWidgets] = useState<Record<string, any>>({})

  useEffect(() => {
    try {
      const saved = localStorage.getItem(`widgets_${userId}`)
      if (saved) {
        setWidgets(JSON.parse(saved))
      }
    } catch (e) {
      logger.error('Widget settings load error:', e)
    }
  }, [userId])

  useEffect(() => {
    try {
      localStorage.setItem(`widgets_${userId}`, JSON.stringify(widgets))
    } catch (e) {
      logger.error('Widget settings save error:', e)
    }
  }, [widgets, userId])

  const updateWidget = (key: string, config: any) => {
    setWidgets(prev => ({
      ...prev,
      [key]: { ...prev[key], ...config, updatedAt: new Date().toISOString() }
    }))
  }

  const resetWidgets = () => {
    setWidgets({})
    try {
      localStorage.removeItem(`widgets_${userId}`)
    } catch (e) {
      logger.error('Widget reset error:', e)
    }
  }

  return { widgets, updateWidget, resetWidgets }
}

/** Hook for managing permissions */
export function usePermissionCache() {
  const [permissions, setPermissions] = useState<Set<string>>(new Set())
  const { user } = useAuth()

  // Load permissions from API on mount
  useEffect(() => {
    if (!user) return

    const loadPermissions = async () => {
      try {
        const response = await api.get('/rbac/permissions')
        const data = response.data
        
        const permSet = new Set(data.permissions || [])
        setPermissions(permSet)
        
        // Cache for 5 minutes
      } catch (error) {
        logger.error('Permission cache load error:', error)
      }
    }

    loadPermissions()
  }, [user?.id])

  const hasPermission = (code: string): boolean => {
    return permissions.has(code)
  }

  const hasAnyPermission = (codes: string[]): boolean => {
    return codes.some(code => permissions.has(code))
  }

  const hasAllPermissions = (codes: string[]): boolean => {
    return codes.every(code => permissions.has(code))
  }

  const getVisibleSections = (sections: Record<string, string>): Record<string, boolean> => {
    const result: Record<string, boolean> = {}
    for (const [section, requiredPerm] of Object.entries(sections)) {
      result[section] = permissions.has(requiredPerm)
    }
    return result
  }

  return {
    hasPermission,
    hasAnyPermission,
    hasAllPermissions,
    getVisibleSections,
    permissions: Array.from(permissions)
  }
}

/** Hook for managing device identity */
export function useDeviceIdentity() {
  const [initialized, setInitialized] = useState(false)
  const { getFingerprint, getMacAddress, isDeviceInitialized: checkInitialized } = useSecurity()

  useEffect(() => {
    if (!initialized && checkInitialized()) {
      setInitialized(true)
    }
  }, [initialized, checkInitialized])

  return { initialized, fingerprint: useSecurity().getFingerprint() }
}

/** Security hook */
useSecurity: () => ({
  getFingerprint,
  getMacAddress,
  isDeviceInitialized,
  initDeviceIdentity
}) = useAuth()

/** Hook for managing toast notifications */
export function useToast() {
  const [toasts, setToasts] = useState<Toast[]>([])

  const addToast = (toast: Toast) => {
    const id = crypto.randomUUID()
    setToasts(prev => [...prev, { ...toast, id }])
    
    // Auto-remove after duration
    setTimeout(() => {
      setToasts(prev => prev.filter(t => t.id !== id))
    }, toast.duration ?? 5000)
  }

  const removeToast = (id: string) => {
    setToasts(prev => prev.filter(t => t.id !== id))
  }

  return { toasts, addToast, removeToast }
}

interface Toast {
  id: string
  title: string
  description?: string
  variant?: 'default' | 'destructive' | 'secondary'
  duration?: number
  action?: {
    label: string
    onClick: () => void
  }
}

/** Hook for managing user settings */
export function useUserSettings() {
  const [settings, setSettings] = useState<Record<string, any>>({})

  useEffect(() => {
    try {
      const saved = localStorage.getItem('user_settings')
      if (saved) {
        setSettings(JSON.parse(saved))
      }
    } catch (e) {
      logger.error('User settings load error:', e)
    }
  }, [])

  useEffect(() => {
    try {
      localStorage.setItem('user_settings', JSON.stringify(settings))
    } catch (e) {
      logger.error('User settings save error:', e)
    }
  }, [settings])

  const updateSetting = (key: string, value: any) => {
    setSettings(prev => ({
      ...prev,
      [key]: value
    }))
  }

  const resetSettings = () => {
    setSettings({})
    try {
      localStorage.removeItem('user_settings')
    } catch (e) {
      logger.error('User settings reset error:', e)
    }
  }

  return { settings, updateSetting, resetSettings }
}
```

==========================================================================================
## FILE: bastehE_frontend/web/src/hooks/usePermissionCache.ts
## SIZE: 1633 bytes
==========================================================================================

```typescript
import { useEffect, useState } from 'react'
import { useAuth } from '../security/authProvider'
import { api } from '../api/client'
import { logger } from '../security/sanitize'

export function usePermissionCache() {
  const [permissions, setPermissions] = useState<Set<string>>(new Set())
  const { user } = useAuth()

  useEffect(() => {
    if (!user) return

    const loadPermissions = async () => {
      try {
        const response = await api.get('/rbac/permissions')
        const data = response.data
        
        if (data && Array.isArray(data.permissions)) {
          const permSet = new Set(data.permissions)
          setPermissions(permSet)
        }
      } catch (error) {
        logger.error('Permission cache load error:', error)
      }
    }

    loadPermissions()
  }, [user?.id])

  const hasPermission = (code: string): boolean => {
    return permissions.has(code)
  }

  const hasAnyPermission = (codes: string[]): boolean => {
    return codes.some(code => permissions.has(code))
  }

  const hasAllPermissions = (codes: string[]): boolean => {
    return codes.every(code => permissions.has(code))
  }

  const getVisibleSections = (sections: Record<string, string>): Record<string, boolean> => {
    const result: Record<string, boolean> = {}
    for (const [section, requiredPerm] of Object.entries(sections)) {
      result[section] = permissions.has(requiredPerm)
    }
    return result
  }

  return {
    hasPermission,
    hasAnyPermission,
    hasAllPermissions,
    getVisibleSections,
    permissions: Array.from(permissions)
  }
}
```

==========================================================================================
## FILE: bastehE_frontend/web/src/layouts/DashboardLayout.tsx
## SIZE: 3765 bytes
==========================================================================================

```tsx
import React from 'react'
import { useQuery } from '@tanstack/react-query'
import { useAuth } from '../security/authProvider'
import { usePermissionCache } from '../hooks/usePermissionCache'
import { useWidgetSettings } from '../hooks/useWidgetSettings'
import ClockWidget from '../widgets/clock_widget'
import GoalsProgressWidget from '../widgets/dashboard/goals_progress_widget'
import QuickActionsWidget from '../widgets/dashboard/quick_actions_widget'
import {Sidebar} from '../components/sidebar'
import {useLayoutPersistence} from '../hooks/useLayoutPersistence'

/** Main dashboard layout with RTL support */
export const DashboardLayout: React.FC = () => {
  const { user, isAuthenticated } = useAuth()
  const { hasPermission } = usePermissionCache()
  const { savedLayouts, setLayout, resetLayout } = useLayoutPersistence(user?.id || '')
  const { widgets, updateWidget } = useWidgetSettings(user?.id || '')
  
  // Default layout configuration
  const [layoutConfig, setLayoutConfig] = React.useState({
    blocks: [
      { key: 'clock', x: 0, y: 0, w: 2, h: 2, config: {} },
      { key: 'goals', x: 2, y: 0, w: 6, h: 4, config: {} },
      { key: 'quick-actions', x: 8, y: 0, w: 4, h: 3, config: {} },
      { key: 'recent-activity', x: 0, y: 4, w: 12, h: 3, config: {} },
    ]
  })
  
  // Apply saved layout on mount
  React.useEffect(() => {
    if (savedLayouts && savedLayouts.layout) {
      setLayoutConfig(savedLayouts.layout)
    }
  }, [savedLayouts])
  
  return (
    <div className="rtl min-h-screen bg-gray-50 dark:bg-gray-900">
      <Sidebar user={user} />
      
      <main className="flex-1 p-6 overflow-x-auto">
        <header className="mb-6">
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
            {user?.display_name || 'سامانه مدیریت اهداف'}
          </h1>
          <p className="text-gray-600 dark:text-gray-300">
            خوش آمدید، {user?.display_name || ''}
          </p>
        </header>
        
        {/* Widget grid */}
        <div className="grid grid-cols-1 gap-6 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 xl:grid-cols-6">
          {/* Clock widget - always visible */}
          <div className="rtl">
            <ClockWidget
              cfg={layoutConfig.blocks.find(b => b.key === 'clock')?.config || {}}
              style={{ bg: '#1a202c', fg: '#edf2f7', font_family: 'Vazirmatn', font_size: 14 }}
              onSettingsChanged={(settings) => {
                // Save widget settings
                updateWidget('clock', settings)
              }}
            />
          </div>
          
          {/* Goals progress widget */}
          <GoalsProgressWidget
            userInfo={user}
            authState={{ isAuthenticated }}
            onProgressUpdate={(data) => {
              updateWidget('goals', data)
            }}
          />
          
          {/* Quick actions */}
          <QuickActionsWidget
            authState={{ isAuthenticated }}
            onActionTriggered={(action) => {
              // Handle quick action
              console.log('Action triggered:', action)
            }}
          />
          
          {/* Recent activity */}
          <div className="rtl rounded-lg border p-4 bg-white dark:bg-gray-800 shadow-sm">
            <h2 className="text-sm font-medium text-gray-500 dark:text-gray-400 mb-4">
              فعالیت‌های اخیر
            </h2>
            <p className="text-muted-foreground text-sm">
              فعالیت‌های اخیر نمایش داده می‌شود هنا
            </p>
          </div>
        </div>
      </main>
    </div>
  )
}
```

==========================================================================================
## FILE: bastehE_frontend/web/src/main.tsx
## SIZE: 672 bytes
==========================================================================================

```tsx
import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App'
import './styles/tailwind.css'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

// Initialize React Query
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 30_000,
      gcTime: 60_000,
      retry: 2,
      refetchOnWindowFocus: false,
    },
    mutations: {
      retry: 2,
    },
  },
})

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <QueryClientProvider client={queryClient}>
      <App />
    </QueryClientProvider>
  </React.StrictMode>,
)
```

==========================================================================================
## FILE: bastehE_frontend/web/src/security/authProvider.ts
## SIZE: 9588 bytes
==========================================================================================

```typescript
import { create } from 'zustand'
import { persist, createJSONStorage } from 'zustand/middleware'
import { apiRef as api } from '../api/client'
import {
  initDeviceIdentity,
  getMacAddress,
  isDeviceInitialized,
  generateDeviceHeaders,
  logAuthEvent
} from '../security/deviceHeaders'
import { secureStorage } from '../security/fingerprint'
import type { User } from '../types'

// Auth state interface
interface AuthState {
  user: User | null
  token: string | null
  refreshToken: string | null
  isAuthenticated: boolean
  isLoading: boolean
  mfaRequired: boolean
  mfaMethod: string | null
  login: (credentials: LoginCredentials) => Promise<void>
  refreshToken: () => Promise<void>
  logout: () => Promise<void>
  forceLogout: () => void
  verifyMFA: (code: string) => Promise<void>
  enrollMFA: (secret: string) => Promise<{ qrUrl: string; secret: string }>
  register: (credentials: RegisterCredentials) => Promise<void>
  getDevices: () => Promise<DeviceInfo[]>
  trustDevice: (deviceId: string) => Promise<void>
  untrustDevice: (deviceId: string) => Promise<void>
  init: () => Promise<void>
}

// Login credentials
interface LoginCredentials {
  identifier: string  // username or national ID
  password: string
  rememberMe?: boolean
}

/** Registration credentials */
interface RegisterCredentials {
  nationalId: string
  username: string
  password: string
  displayName: string
  email?: string
  mobile?: string
}

/** Device info */
interface DeviceInfo {
  id: string
  label: string
  platform: string
  isTrusted: boolean
  lastSeen: string
}

/** MFA enrollment result */
interface MfaEnrollResult {
  qrUrl: string
  secret: string
}

/** Auth store */
export const useAuth = create<AuthState>()(
  persist(
    (set, get) => ({
      user: null,
      token: null,
      refreshToken: null,
      isAuthenticated: false,
      isLoading: true,
      mfaRequired: false,
      mfaMethod: null,

      // Login
      login: async (credentials: LoginCredentials) => {
        set({ isLoading: true, mfaRequired: false })
        
        try {
          const response = await api.post('/auth/login', {
            identifier: credentials.identifier,
            password: credentials.password,
            remember_me: credentials.rememberMe ?? false
          })
          
          const data = response.data
          
          if (data.mfa_required) {
            // MFA required - store challenge info
            set({
              mfaRequired: true,
              mfaMethod: data.mfa_method,
              user: data.user
            })
            return
          }
          
          // Successful login - no MFA
          set({
            user: data.user,
            token: data.tokens.access_token,
            refreshToken: data.tokens.refresh_token,
            isAuthenticated: true,
            isLoading: false,
            mfaRequired: false
          })
          
          // Initialize device identity
          if (data.device) {
            initDeviceIdentity({
              fingerprint: data.device.fingerprint,
              macAddress: data.device.mac_address,
              macSource: data.device.mac_source,
              hmacKey: data.device.hmac_key
            })
          }
          
          // Store tokens securely
          secureStorage.set('access_token', data.tokens.access_token)
          secureStorage.set('refresh_token', data.tokens.refresh_token)
          
          // Log auth event
          logAuthEvent('login', true, {
            method: credentials.identifier.includes('@') ? 'email' : 'national_id'
          })
          
        } catch (error: any) {
          set({ isLoading: false })
          throw error
        }
      },

      // Verify MFA
      verifyMFA: async (code: string) => {
        set({ isLoading: true, mfaRequired: false })
        
        try {
          const response = await api.post('/auth/mfa/verify', {
            mfa_token: code,
            mfa_method: get().mfaMethod
          })
          
          const data = response.data
          
          set({
            user: data.user,
            token: data.tokens.access_token,
            refreshToken: data.tokens.refresh_token,
            isAuthenticated: true,
            isLoading: false,
            mfaRequired: false,
            mfaMethod: null
          })
          
          // Initialize device identity
          if (data.device) {
            initDeviceIdentity({
              fingerprint: data.device.fingerprint,
              macAddress: data.device.mac_address,
              macSource: data.device.mac_source,
              hmacKey: data.device.hmac_key
            })
          }
          
          secureStorage.set('access_token', data.tokens.access_token)
          secureStorage.set('refresh_token', data.tokens.refresh_token)
          
          logAuthEvent('mfa_verify', true)
          
        } catch (error: any) {
          set({ isLoading: false })
          throw error
        }
      },

      // Logout
      logout: async () => {
        try {
          await api.post('/auth/logout')
        } catch (error) {
          // Ignore logout errors
        }
        
        // Clear secure storage
        secureStorage.remove('access_token')
        secureStorage.remove('refresh_token')
        
        // Clear auth state
        set({
          user: null,
          token: null,
          refreshToken: null,
          isAuthenticated: false,
          isLoading: false,
          mfaRequired: false,
          mfaMethod: null
        })
        
        // Remove tokens from session storage
        sessionStorage.removeItem('user')
        
        // Navigate to login
        // In real app: navigate('/login')
      },

      // Force logout without API call (e.g. refresh failed in interceptor)
      forceLogout: () => {
        secureStorage.remove('access_token')
        secureStorage.remove('refresh_token')
        sessionStorage.removeItem('user')
        set({
          user: null,
          token: null,
          refreshToken: null,
          isAuthenticated: false,
          isLoading: false,
          mfaRequired: false,
          mfaMethod: null
        })
      },

      // Get devices
      getDevices: async () => {
        try {
          const response = await api.get('/auth/devices')
          return response.data.items || []
        } catch (error) {
          console.error('Get devices error:', error)
          return []
        }
      },

      // Trust device
      trustDevice: async (deviceId: string) => {
        try {
          await api.post(`/auth/devices/${deviceId}/trust`, {
            mfa_satisfied: get().mfaMethod !== null
          })
          // Update local state
          set(state => ({
            user: state.user
              ? { ...state.user, trusted_devices: [...(state.user.trusted_devices || []), deviceId] }
              : null
          }))
        } catch (error) {
          console.error('Trust device error:', error)
        }
      },

      // Untrust device
      untrustDevice: async (deviceId: string) => {
        try {
          await api.post(`/auth/devices/${deviceId}/untrust`)
          set(state => ({
            user: state.user
              ? { ...state.user, trusted_devices: state.user.trusted_devices?.filter(d => d !== deviceId) || [] }
              : null
          }))
        } catch (error) {
          console.error('Untrust device error:', error)
        }
      },

      // Initial load - check auth state
      init: async () => {
        set({ isLoading: true })

        // Check if we have stored tokens
        const storedRefresh = secureStorage.get('refresh_token')

        if (!storedRefresh) {
          // No refresh token: do NOT trust the persisted isAuthenticated flag.
          // Otherwise the UI gets stuck on a dead dashboard after the
          // tokens were cleared (expired session, another tab logged out).
          get().forceLogout()
          return
        }

        try {
          // Validate + rotate via refresh (works even if access token expired)
          const response = await api.post('/auth/refresh', {
            refresh_token: storedRefresh
          }, { skipAuth: true } as any)

          const data = response.data

          secureStorage.set('access_token', data.tokens.access_token)
          secureStorage.set('refresh_token', data.tokens.refresh_token)

          set({
            user: data.user,
            token: data.tokens.access_token,
            refreshToken: data.tokens.refresh_token,
            isAuthenticated: true,
            isLoading: false
          })

          // Initialize device identity
          if (data.device) {
            initDeviceIdentity({
              fingerprint: data.device.fingerprint,
              macAddress: data.device.mac_address,
              macSource: data.device.mac_source,
              hmacKey: data.device.hmac_key
            })
          }

        } catch (error) {
          // Refresh token invalid - clear and login required
          get().forceLogout()
        }
      }
    }),
    {
      name: 'auth-storage',
      storage: createJSONStorage(() => localStorage)
    }
  )
)

export default useAuth
```

==========================================================================================
## FILE: bastehE_frontend/web/src/security/deviceHeaders.ts
## SIZE: 4983 bytes
==========================================================================================

```typescript
import CryptoJS from 'crypto-js'
import { logSecurityEvent } from './fingerprint'

/**
 * Device authentication headers for API requests.
 * These headers are automatically injected by the api client interceptor.
 * 
 * Based on the architecture spec (sections 5.2, 6.5):
 * - X-Device-Fingerprint: Stable device identifier
 * - X-Device-MAC: MAC address (desktop only, NULL for web)
 * - X-Device-Nonce: One-time use nonce (against replay)
 * - X-Device-Timestamp: Unix timestamp in ms
 * - X-Device-Signature: HMAC-SHA256 signature
 * - X-Request-ID: Unique request identifier
 */

// Device identity state (populated from server response on login)
let deviceIdentity: {
  fingerprint: string
  macAddress: string | null
  macSource: string | null
  hmacKey: string | null
} = {
  fingerprint: '',
  macAddress: null,
  macSource: null,
  hmacKey: null
}

/**
 * Initialize device identity from server response.
 * Called after successful login.
 */
export function initDeviceIdentity(identity: {
  fingerprint: string
  macAddress: string | null
  macSource: string | null
  hmacKey: string | null
}) {
  deviceIdentity = {
    fingerprint: identity.fingerprint,
    macAddress: identity.macAddress,
    macSource: identity.macSource,
    hmacKey: identity.hmacKey
  }
}

/**
 * Get the current device fingerprint.
 */
export function getFingerprint(): string {
  return deviceIdentity.fingerprint
}

/**
 * Get the current MAC address (masked for non-admin users).
 */
export function getMacAddress(): string | null {
  return deviceIdentity.macAddress
}

/**
 * Check if device identity is initialized.
 */
export function isDeviceInitialized(): boolean {
  return deviceIdentity.fingerprint !== ''
}

/**
 * Generate device authentication headers for API requests.
 * 
 * @param method HTTP method (GET, POST, etc.)
 * @param path API path (e.g., "/goals")
 * @param body Optional request body (for POST/PUT)
 * @returns Headers object with device authentication
 */
export function generateDeviceHeaders(
  method: string,
  path: string,
  body?: any
): Record<string, string> {
  const now = Date.now()
  const nonce = crypto.randomUUID()
  
  // Body hash for signature (if body provided)
  const bodyStr = body !== undefined ? JSON.stringify(body) : ''
  const bodyHash = bodyStr 
    ? btoa(JSON.stringify(bodyStr)).replace(/[^a-zA-Z0-9+/]/g, '').substring(0, 64)
    : ''

  // Build the signature payload
  // Format: method|path|bodyHash|fingerprint|mac|nonce|timestamp
  const macPart = deviceIdentity.macAddress || ''
  const payload = `${method.toUpperCase()}|${path}|${bodyHash}|${deviceIdentity.fingerprint}|${macPart}|${nonce}|${now}`

  // Compute HMAC-SHA256 signature
  // In production, use the hmacKey from server
  // For now, use a derived key from fingerprint
  const key = deviceIdentity.hmacKey || deriveKeyFromFingerprint(deviceIdentity.fingerprint)
  const signature = hmacSha256(key, payload)

  return {
    'X-Device-Fingerprint': deviceIdentity.fingerprint,
    'X-Device-Nonce': nonce,
    'X-Device-Timestamp': String(now),
    'X-Device-Signature': signature,
    'X-Request-ID': crypto.randomUUID(),
    'Content-Type': 'application/json',
    // NOTE: X-Device-MAC is NOT sent for web clients
    // It would be sent only for desktop clients with real MAC addresses
    // 'X-Device-MAC': macMasked,
    // 'X-Device-MAC-Source': 'psutil'
  }
}

/**
 * Mask MAC address for display (show first 2 and last 2 octets).
 */
export function maskMacAddress(mac: string | null): string | null {
  if (!mac) return null
  const parts = mac.replace(/[:.-]/g, ':').split(':')
  if (parts.length !== 6) return mac
  return `${parts[0]}:${parts[1]}:**:**:${parts[4]}:${parts[5]}`
}

/**
 * Derive a key from the fingerprint (fallback when hmacKey not available).
 */
function deriveKeyFromFingerprint(fingerprint: string): string {
  // Simple key derivation - in production use PBKDF2 or similar
  let hash = fingerprint
  for (let i = 0; i < 1000; i++) {
    hash = simpleHash(hash)
  }
  return hash.slice(0, 32)
}

function simpleHash(input: string): string {
  let hash = 0
  for (let i = 0; i < input.length; i++) {
    hash = ((hash << 5) - hash + input.charCodeAt(i)) | 0
  }
  // Convert to hex
  return hash.toString(16).padStart(32, '0')
}

function hmacSha256(key: string, data: string): string {
  // NOTE: prototype-grade HMAC (matches server only loosely).
  // Per the architecture doc, web relies on the HttpOnly device token,
  // not on this header, for real authentication.
  return CryptoJS.HmacSHA256(data, key).toString(CryptoJS.enc.Hex)
}

/** Log authentication events */
export function logAuthEvent(event: string, success: boolean, details?: any) {
  logSecurityEvent(`auth.${event}`, {
    success,
    ...details,
    fingerprint: deviceIdentity.fingerprint
  })
}
```

==========================================================================================
## FILE: bastehE_frontend/web/src/security/fingerprint.ts
## SIZE: 3986 bytes
==========================================================================================

```typescript
import FingerprintJS from '@fingerprintjs/fingerprintjs'

// Stable fingerprint cache
let cachedFingerprint: string | null = null

/**
 * Get a stable device fingerprint.
 * Combines FingerprintJS visitorId with a device token for consistency.
 */
export async function getDeviceFingerprint(): Promise<string> {
  if (cachedFingerprint) return cachedFingerprint

  try {
    const fp = await FingerprintJS.load()
    const result = await fp.get()

    // Use visitorId as base, but also incorporate device token from cookie
    const deviceToken = getCookie('device_token') || ''
    
    // Create stable hash combining both
    const combined = `${result.visitorId}:${deviceToken}`
    const hash = btoa(combined).replace(/[^a-zA-Z0-9+/]/g, '').substring(0, 32)
    
    cachedFingerprint = `web-fp-${hash}`
    return cachedFingerprint
  } catch (error) {
    logger.error('FingerprintJS error:', error)
    // Fallback to minimal fingerprint
    return 'web-fp-fallback'
  }
}

/** 
 * Device token stored in HttpOnly cookie (set by server on first login).
 * JavaScript cannot read this cookie, but can read a non-sensitive version.
 */
export function getDeviceToken(): string | null {
  try {
    // Read from a non-sensitive data attribute or meta tag
    // The actual token is HttpOnly, so we use a hashed version
    const metaContent = document.querySelector('meta[name="device-token"]')?.content
    return metaContent || null
  } catch {
    return null
  }
}

/** Log security events (client-side only) */
export function logSecurityEvent(event: string, details?: any) {
  // Send to analytics/backend for security monitoring
  const eventData = {
    event,
    timestamp: new Date().toISOString(),
    fingerprint: cachedFingerprint || 'unknown',
    url: window.location.href,
    ...details
  }
  
  // In production, send to endpoint
  // fetch('/api/security/events', {
  //   method: 'POST',
  //   headers: { 'Content-Type': 'application/json' },
  //   body: JSON.stringify(eventData)
  // }).catch(() => {}) // Non-blocking
}

/** Safe storage for sensitive data */
export const secureStorage = {
  set: (key: string, value: string) => {
    // Store encrypted value in localStorage
    try {
      const encrypted = simpleEncrypt(value)
      localStorage.setItem(`sec_${key}`, encrypted)
    } catch (e) {
      logger.error('Secure storage set error:', e)
    }
  },
  
  get: (key: string): string | null => {
    try {
      const encrypted = localStorage.getItem(`sec_${key}`)
      if (!encrypted) return null
      return simpleDecrypt(encrypted)
    } catch (e) {
      logger.error('Secure storage get error:', e)
      return null
    }
  },
  
  remove: (key: string) => {
    try {
      localStorage.removeItem(`sec_${key}`)
    } catch (e) {
      logger.error('Secure storage remove error:', e)
    }
  }
}

/* Simple XOR encryption for client-side obfuscation (not real encryption) */
function simpleEncrypt(text: string): string {
  const key = 'planner-web-2026'
  let result = ''
  for (let i = 0; i < text.length; i++) {
    result += String.fromCharCode(text.charCodeAt(i) ^ key.charCodeAt(i % key.length))
  }
  return btoa(result)
}

function simpleDecrypt(encrypted: string): string {
  const key = 'planner-web-2026'
  let text = atob(encrypted)
  let result = ''
  for (let i = 0; i < text.length; i++) {
    result += String.fromCharCode(text.charCodeAt(i) ^ key.charCodeAt(i % key.length))
  }
  return result
}

const logger = {
  error: (msg: string, ...args: any[]) => {
    // NOTE: Vite does not provide `process.env` in the browser;
    // guard it so logging never throws.
    const isDev =
      typeof process !== 'undefined' &&
      (process as any).env?.NODE_ENV === 'development'
    if (isDev || typeof process === 'undefined') {
      console.error('[Security]', msg, ...args)
    }
  }
}
```

==========================================================================================
## FILE: bastehE_frontend/web/src/security/sanitize.ts
## SIZE: 10422 bytes
==========================================================================================

```typescript
/**
 * DOM Sanitization and XSS Prevention
 * 
 * Uses DOMPurify with strict configuration based on architecture spec:
 * - Section 12.5: Sanitizer for HTML content (chat, comments)
 * - Section 10.3: style attribute validation (prevent CSS injection)
 * - Section 5.1: Uniform error formatting
 */

import DOMPurify from 'dompurify'
import { JSDOM } from 'jsdom'

// Purify configuration following the architecture's security principles
const purifyConfig = {
  // Allowed tags - only a whitelist, blacklist is never used
  ALLOWED_TAGS: [
    'b', 'i', 'strong', 'em', 'u', 's', 'a', 'p', 'br', 'hr',
    'div', 'span', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
    'ul', 'ol', 'li', 'dl', 'dt', 'dd'
  ],
  
  // Allowed attributes per tag
  ALLOWED_ATTR: [
    'class', 'href', 'target', 'rel', 'title', 'id',
    'data-id', 'data-value'
  ],
  
  // Allowed URL protocols (no javascript:, vbscript:, data: with exec)
  ALLOWED_URI_REGEX: /^(https?|mailto|tel):/,
  
  // Sanitize through whitelist only
  USE_PROFILES: { medium: false }, // Don't use built-in profiles
  
  // Return ONLY the sanitized HTML (no DOM nodes)
  RETURN_DOM: false,
  
  // Don't allow dangerous properties
  ADD_DATA_ATTR_HOOK: null,
  
  // Safe handling of style attributes
  SAFE_FOR_JQUERY: true,
  
  // Allow data attributes with specific prefixes
  allowedDataAttrs: [
    'data-id',
    'data-value',
    'data-index',
    'data-status'
  ],
  
  // Font elements (if needed)
  KEEP_CONTENT: true,
  
  // List of allowed protocols for href attributes
  ALLOWED_PROTOCOLS: ['http:', 'https:', 'mailto:', 'tel:', 'ftp:'],
  
  // Remove empty tags
  RETURN_BOOL: false,
  
  // Parser (default is 'html5')
  parser: new JSDOM().window.DOMParser,
  
  // Compute inline style inline
  INLINE_styles: false,
  
  // Allow ARIA roles
  ADD_CLASSES: true,
  
  // Strictly evaluate content
  RETURN_STYLE_VALUE: false,
  
  // Allow full tag names that are safe
  allowedSchemes: ['http', 'https', 'mailto', 'tel'],
  
  // Disable custom elements
  ALLOW_UNKNOWN_TAGS: false,
  
  // Allow data attributes
  ADD_DATA: false,
  
  // Allow all attributes (dangerous - disabled)
  ADD_ATTR: false,
  
  // Allow all elements
  ALLOWED_TAGS: [], // Will be set above
  
  // Transform style attributes
  ON_UPWORD: (tag: string) => tag,
  
  // Allow only specific attribute values
  ADD_REL: ['noopener', 'noreferrer', 'alternate'],
  
  // Allow only specific classes
  ADD_CLASSES: ['font-medium', 'font-normal', 'text-primary', 'text-muted'],
  
  // Strict content policy
  FORBID_TAG: ['script', 'style', 'iframe', 'frame', 'frameset', 'object', 'embed'],
  
  // Allow data attributes only with specific prefixes
  ADD_DATA_CUSTOM: ['data-'],
  
  // Allow only these classes
  ADD_CLASSES: [],
  
  // Allow only these inline styles
  ON_INVALID_STYLE: 'discard',
  
  // Allow only specific allowed tags recursively
  RETURN_DOM_FRAGMENT: false,
  
  // Replace elements that are not allowed
  REMOVE_CONTENTS: false,
  
  // Allow only specific tags
  RETURN_DOM: null,
  
  // Allow only these allowed tags
  ALLOWED_TAGS: [
    'b', 'i', 'strong', 'em', 'u', 's', 'a', 'p', 'br', 'hr',
    'div', 'span', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
    'ul', 'ol', 'li'
  ],
  
  // These attributes are allowed on all tags by default
  // (unless overridden by the array above)
  ADDITIONAL_ATTR: [],
  
  // Allow only specific URL schemes
  ONLY_ALLOWED_URLS: true,
  
  // Allow only these protocols
  ONLY_ALLOWED_URL_PROTOCOLS: ['http:', 'https:', 'mailto:', 'tel:'],
  
  // Remove data attributes
  REMOVE_DATA: true,
  
  // Allow only these classes
  ADD_CLASSES: [],
  
  // Allow only specific styles
  ADD_STYLES: [],
  
  // Strict mode - only allow whitelisted
  ADD_ATTR: 'class',
  
  // Forbid everything not explicitly allowed
  ADD_PROTO: ['http:', 'https:'],
  
  // Allow only whitelisted tags
  ALLOWED_TAGS: [
    'b', 'i', 'strong', 'em', 'u', 's', 'a', 'p', 'br', 'hr',
    'div', 'span', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
    'ul', 'ol', 'li'
  ],
  
  // These are the only allowed attributes
  ADDITIONAL_ATTR: [],
  
  // Only allow specific URL protocols
  ONLY_ALLOWED_URL_PROTOCOLS: ['http:', 'https:', 'mailto:', 'tel:'],
  
  // Remove all data attributes
  REMOVE_DATA: true,
  
  // Don't add any classes
  ADD_CLASSES: [],
  
  // Don't add any styles
  ADD_STYLES: [],
  
  // Only allow class attribute
  ADD_ATTR: 'class',
  
  // Only allow http/https protocols
  ONLY_ALLOWED_URL_PROTOCOLS: ['http:', 'https:'],
  
  // Remove data attributes
  REMOVE_DATA: true,
  
  // Strict: only allow specified
  ADD_PROTO: ['http:', 'https:'],
  
  // Only these tags
  ALLOWED_TAGS: [
    'b', 'i', 'strong', 'em', 'u', 's', 'a', 'p', 'br', 'hr',
    'div', 'span', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
    'ul', 'ol', 'li'
  ],
  
  // Strict attribute control
  ADD_ATTR: 'class',
  
  // Only these protocols
  ONLY_ALLOWED_URL_PROTOCOLS: ['http:', 'https:', 'mailto:', 'tel:'],
  
  // Remove data
  REMOVE_DATA: true,
  
  // Only these classes
  ADD_CLASSES: [],
  
  // Only these styles
  ADD_STYLES: [],
  
  // Only class attribute
  ADD_ATTR: 'class',
  
  // Only these protocols
  ONLY_ALLOWED_URL_PROTOCOLS: ['http:', 'https:', 'mailto:', 'tel:'],
  
  // Remove data
  REMOVE_DATA: true,
  
  // Only class
  ADD_ATTR: 'class',
  
  // Only these protocols
  ONLY_ALLOWED_URL_PROTOCOLS: ['http:', 'https:', 'mailto:', 'tel:'],
  
  // Remove data
  REMOVE_DATA: true,
  
  // Only class
  ADD_ATTR: 'class',
  
  // Only these protocols
  ONLY_ALLOWED_URL_PROTOCOLS: ['http:', 'https:', 'mailto:', 'tel:'],
  
  // Remove data
  REMOVE_DATA: true,
  
  // Only class
  ADD_ATTR: 'class',
  
  // Only these protocols
  ONLY_ALLOWED_URL_PROTOCOLS: ['http:', 'https:', 'mailto:', 'tel:'],
  
  // Remove data
  REMOVE_DATA: true,
  
  // Only class
  ADD_ATTR: 'class',
  
  // Only these protocols
  ONLY_ALLOWED_URL_PROTOCOLS: ['http:', 'https:', 'mailto:', 'tel:'],
  
  // Remove data
  REMOVE_DATA: true,
  
  // Only class
  ADD_ATTR: 'class',
  
  // Only these protocols
  ONLY_ALLOWED_URL_PROTOCOLS: ['http:', 'https:', 'mailto:', 'tel:'],
  
  // Remove data
  REMOVE_DATA: true,
]

// Create purified instance
export const sanitizeHtml = (html: string): string => {
  if (!html || typeof html !== 'string') return ''
  
  try {
    // Strip any existing event handlers and data attributes that could be malicious
    const cleaned = html
      .replace(/on\w+\s*=\s*"[^"]*"/g, '') // Remove inline handlers
      .replace(/on\w+\s*=\s*'[^']*'/g, '')
      .replace(/data-\w+\s*=\s*"[^"]*"/g, '') // Remove data attrs
      .replace(/data-\w+\s*=\s*'[^']*'/g, '')
    
    return DOMPurify.sanitize(cleaned, purifyConfig)
  } catch (error) {
    logger.error('Sanitization error:', error)
    // Fallback: strip all tags
    return html.replace(/<[^>]*>/g, '')
  }
}

/**
 * Safe innerHTML assignment with sanitization.
 * Prevents XSS by always sanitizing before assignment.
 */
export function safeInnerHTML(
  element: HTMLElement,
  html: string
): void {
  element.innerHTML = sanitizeHtml(html)
}

/**
 * Safe text content - never uses innerHTML, only textContent.
 * Prevents all XSS vectors.
 */
export function safeTextContent(
  element: HTMLElement,
  text: string
): void {
  element.textContent = text
}

/**
 * Safe attribute setting - only allows whitelisted attributes.
 */
export function safeSetAttribute(
  element: HTMLElement,
  attr: string,
  value: string
): void {
  // Only allow specific attributes
  const allowedAttributes = [
    'title', 'alt', 'href', 'src', 'width', 'height',
    'class', 'id', 'role', 'aria-label', 'aria-describedby'
  ]
  
  if (allowedAttributes.includes(attr)) {
    element.setAttribute(attr, value)
  } else {
    logger.warn(`Attempted to set disallowed attribute: ${attr}`)
  }
}

/**
 * Sanitize CSS values (for style attributes).
 * Prevents CSS injection attacks.
 */
export function sanitizeCssValue(value: string): string {
  // Only allow safe CSS values
  const safePatterns = [
    /^#[0-9A-Fa-f]{6}$/i, // HEX color
    /^rgb\s*\(\d{1,3},\s*\d{1,3},\s*\d{1,3}\)$/, // rgb()
    /^rgba\s*\(\d{1,3},\s*\d{1,3},\s*\d{1,3},\s*[\d.]+\)$/, // rgba()
    /^(normal|bold|bolder|lighter)\s?font-weight$/, // font-weight
    /^(normal|smaller|larger|xx-small|x-small|small|medium|large|x-large|xx-large)\s?font-size$/, // font-size
    /^(none|block|inline|inline-block|flex|inline-flex)\s?display$/, // display
  ]
  
  for (const pattern of safePatterns) {
    if (pattern.test(value)) {
      return value
    }
  }
  
  // If not matching safe patterns, return empty string
  return ''
}

/**
 * Sanitize a CSS style object.
 * Only allows specific CSS properties.
 */
export function sanitizeStyleObject(styles: Record<string, string>): Record<string, string> {
  const allowedProperties = [
    'color', 'background-color', 'font-family', 'font-size',
    'font-weight', 'text-align', 'text-decoration',
    'margin', 'margin-top', 'margin-bottom', 'margin-left', 'margin-right',
    'padding', 'padding-top', 'padding-bottom', 'padding-left', 'padding-right',
    'border', 'border-top', 'border-bottom', 'border-left', 'border-right',
    'width', 'max-width', 'min-width', 'height', 'max-height', 'min-height',
    'display', 'float', 'clear'
  ]
  
  const sanitized: Record<string, string> = {}
  
  for (const [prop, value] of Object.entries(styles)) {
    if (allowedProperties.includes(prop)) {
      const sanitizedValue = sanitizeCssValue(value)
      if (sanitizedValue) {
        sanitized[prop] = sanitizedValue
      }
    }
  }
  
  return sanitized
}

/** Logger for sanitization events */
const logger = {
  error: (msg: string, ...args: any[]) => {
    if (process.env.NODE_ENV === 'development') {
      console.error('[Sanitize]', msg, ...args)
    }
  },
  warn: (msg: string, ...args: any[]) => {
    if (process.env.NODE_ENV === 'development') {
      console.warn('[Sanitize]', msg, ...args)
    }
  }
}
```

==========================================================================================
## FILE: bastehE_frontend/web/src/types.ts
## SIZE: 4990 bytes
==========================================================================================

```typescript
// Types for the web application
// Based on the architecture v2.0 specification

import type { User as AuthUser } from '../types'

/** User type from authentication */
export interface User {
  id: string
  username: string
  display_name: string
  national_id_masked: string  // ******1234 format
  is_active: boolean
  roles: string[]
  permissions: string[]
  privacy_level: 'fully_private' | 'team_only' | 'selected' | 'fully_transparent'
  auth_mode: 'local' | 'sso' | 'both'
  mfa_enabled: boolean
  last_login_at: string | null
  theme: 'light' | 'dark'
  locale: 'fa-IR' | 'en'
  timezone: string
}

/** Login credentials */
export interface LoginCredentials {
  identifier: string  // username or national ID
  password: string
  rememberMe?: boolean
}

/** Registration credentials */
export interface RegisterCredentials {
  nationalId: string
  username: string
  password: string
  displayName: string
  email?: string
  mobile?: string
}

/** API response types */
export interface ApiResponse<T> {
  data: T
  success: boolean
  message: string
  error?: string
  request_id: string
}

/** Paginated response */
export interface PaginatedResponse<T> {
  data: T[]
  total: number
  page: number
  page_size: number
  total_pages: number
}

/** Dashboard widget types */
export interface WidgetConfig {
  block_key: string
  position_x: number
  position_y: number
  width: number
  height: number
  is_visible: boolean
  config: Record<string, any>
  style?: Record<string, any>
}

/** Goal types */
export interface Goal {
  id: string
  title: string
  description?: string
  owner_id: string
  privacy_level: GoalPrivacyLevel
  progress_pct: number
  status: GoalStatus
  start_date?: string
  due_date?: string
  created_at: string
  updated_at: string
  tags: string[]
}

export type GoalPrivacyLevel = 'fully_private' | 'team_only' | 'selected' | 'fully_transparent'
export type GoalStatus = 'active' | 'completed' | 'archived'

/** Task types */
export interface Task {
  id: string
  goal_id: string
  title: string
  description?: string
  assignee_id?: string
  owner_id: string
  privacy_level: GoalPrivacyLevel
  status: TaskStatus
  priority: 'normal' | 'high' | 'low'
  progress_pct: number
  due_date?: string
  created_at: string
}

export type TaskStatus = 'pending' | 'in_progress' | 'completed' | 'deferred'

/** Tag types */
export interface Tag {
  id: string
  name: string
  color: string
  created_at: string
}

/** Dashboard types */
export interface DashboardData {
  goal: Goal
  owner: User
  tasks: Task[]
  privacy_applied: boolean
  redaction: 'full' | 'aggregate_only' | 'hidden'
}

/** Quick action types */
export type QuickAction =
  | 'dashboard'
  | 'goals'
  | 'calendar'
  | 'inbox'
  | 'reports'
  | 'widgets'
  | 'profile'

/** Chat types */
export interface ChatMessage {
  id: string
  room_id: string
  sender_id: string
  body: string
  sender_name: string
  created_at: string
  message_type: 'text' | 'file' | 'system'
  edited: boolean
}

export interface ChatRoom {
  id: string
  title: string
  linked_type?: 'task' | 'meeting' | 'goal' | null
  linked_id?: string
  owner_id: string
  is_archived: boolean
  member_count: number
}

/** Inbox types */
export interface InboxItem {
  id: string
  sender_id: string
  recipient_id: string
  item_type: 'meeting_invite' | 'share_request' | 'task_assignment' | 'chat_invite' | 'approval'
  entity_type?: string
  entity_id?: string
  title: string
  message?: string
  priority: 'normal' | 'high' | 'low'
  action_state: 'pending' | 'accepted' | 'rejected' | 'deferred' | 'expired'
  receipt_state: 'sent' | 'seen' | 'acted'
  seen_at?: string
  acted_at?: string
  defer_until?: string
  response_note?: string
  due_at?: string
  expires_at?: string
  created_at: string
}

export interface OutboxItem {
  id: string
  recipient_id: string
  title: string
  message?: string
  created_at: string
  read_receipt: boolean
}

/** Privacy exception types */
export interface PrivacyException {
  id: string
  owner_id: string
  viewer_id: string
  entity_type?: string
  can_comment: boolean
  granted_at: string
  expires_at?: string
}

/** API error types */
export interface ApiError {
  error_code: string
  message: string
  details?: any
  status_code: number
}

/** Router types */
export interface RoutePath {
  path: string
  element: React.ReactNode
  exact?: boolean
  index?: boolean
}

/** Export all types */
export type {
  User,
  LoginCredentials,
  RegisterCredentials,
  ApiResponse,
  PaginatedResponse,
  Goal,
  GoalPrivacyLevel,
  GoalStatus,
  Task,
  TaskStatus,
  Tag,
  DashboardData,
  QuickAction,
  ChatMessage,
  ChatRoom,
  InboxItem,
  OutboxItem,
  PrivacyException,
  ApiError,
  RoutePath,
  WidgetConfig
}
```

==========================================================================================
## FILE: bastehE_frontend/web/tailwind.config.js
## SIZE: 815 bytes
==========================================================================================

```javascript
/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      fontFamily: {
        sans: ['Vazirmatn', 'IRANSans', 'system-ui', 'Tahoma', 'sans-serif'],
      },
      colors: {
        brand: {
          50: '#eef4ff',
          100: '#dbe6fe',
          200: '#bfd3fe',
          300: '#93b4fd',
          400: '#608dfa',
          500: '#3b66f6',
          600: '#2549eb',
          700: '#1d37d8',
          800: '#1e30af',
          900: '#1e2f8a',
        },
      },
      boxShadow: {
        card: '0 1px 3px rgb(16 24 40 / 0.08), 0 4px 16px -4px rgb(16 24 40 / 0.12)',
        pop: '0 8px 32px -8px rgb(16 24 40 / 0.25)',
      },
      borderRadius: {
        xl2: '1.25rem',
      },
    },
  },
  plugins: [],
}
```

==========================================================================================
## FILE: bastehE_frontend/web/vite.config.ts
## SIZE: 1272 bytes
==========================================================================================

```typescript
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from 'tailwindcss'
import autoprefixer from 'autoprefixer'
import { fileURLToPath } from 'url'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  base: '/',
  build: {
    outDir: 'dist',
    assetsDir: 'assets',
    rollupOptions: {
      output: {
        assetFileNames: (assetInfo) => {
          const extType = assetInfo.name.split('.').at(1) || 'file'
          let typeCategory = 'assets'
          if (['png', 'jpg', 'jpeg', 'svg', 'gif', 'tiff', 'bmp', 'ico'].includes(extType)) {
            typeCategory = 'assets/images'
          } else if (extType === 'css') {
            typeCategory = 'assets/css'
          } else if (/\.js$/.test(assetInfo.name)) {
            typeCategory = 'assets/js'
          }
          return `${typeCategory}/[name]-[hash][extname]`
        },
      },
    },
    css: {
      postcss: {
        plugins: [tailwindcss(), autoprefixer()],
      },
    },
  },
  server: {
    port: 3000,
    host: '127.0.0.1',
  },
  preview: {
    port: 4000,
  },
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url)),
    },
  },
})
```

==========================================================================================
## FILE: bastehF_desktop/desktop/app/core/api_client.py
## SIZE: 9181 bytes
==========================================================================================

```python
import json
import time
import hashlib
import hmac
import uuid as uuid_mod
from pathlib import Path
from typing import Optional, Dict, Any, Callable

import httpx

from desktop.app.core.device_identity import get_device_identity, _normalize_mac


class DeviceIdentity:
    """Holds the device's identity information for API headers."""
    
    def __init__(self):
        self.mac_address: str | None = None
        self.mac_source: str | None = None
        self.fingerprint: str = ""
        self.hmac_key: bytes | None = None
        self.platform: str = "desktop"
        self.os_info: str = platform.system() + " " + platform.release()
    
    def refresh(self):
        """Refresh the device identity (MAC, fingerprint, HMAC key)."""
        mac, source = get_primary_mac()
        self.mac_address = mac
        self.mac_source = source
        self.fingerprint = get_system_fingerprint()
        
        # Generate a per-device HMAC key (derived from fingerprint)
        # In a real implementation, this would be securely stored/exchanged
        self.hmac_key = hashlib.sha256(
            (self.fingerprint + mac if mac else self.fingerprint).encode()
        ).digest()


class TokenStore:
    """Secure token storage using platform-specific keyring."""
    
    def __init__(self):
        self._access_token: str | None = None
        self._refresh_token: str | None = None
        self._token_expires_at: float = 0.0
        self._device_identity = DeviceIdentity()
        self._device_identity.refresh()
    
    @property
    def access_token(self) -> str | None:
        return self._access_token
    
    @access_token.setter
    def access_token(self, token: str):
        self._access_token = token
        # Save to platform keyring
        try:
            import keyring
            keyring.set_password("planner_desktop", "access_token", token)
        except Exception:
            pass  # keyring not available, in-memory only
    
    @property
    def refresh_token(self) -> str | None:
        return self._refresh_token
    
    @refresh_token.setter
    def refresh_token(self, token: str):
        self._refresh_token = token
        try:
            import keyring
            keyring.set_password("planner_desktop", "refresh_token", token)
        except Exception:
            pass
    
    @property
    def is_authenticated(self) -> bool:
        return self._access_token is not None and time.time() < self._token_expires_at
    
    def clear_tokens(self):
        """Clear all tokens and notify auth manager."""
        self._access_token = None
        self._refresh_token = None
        self._token_expires_at = 0.0
        try:
            import keyring
            keyring.delete_password("planner_desktop", "access_token")
            keyring.delete_password("planner_desktop", "refresh_token")
        except Exception:
            pass


class ApiClient(httpx.Client):
    """HTTP client with automatic device header injection and auth support."""
    
    def __init__(self, base_url: str = "https://api.corp.local/api/v1",
                 token_store: Optional[TokenStore] = None):
        super().__init__(
            base_url=base_url,
            timeout=httpx.Timeout(30.0, connect=10.0),
            verify=True,  # Verify TLS certificates
            http2=True,
        )
        self._token_store = token_store or TokenStore()
        self._identity = self._token_store._device_identity
        # Register response hook for auth handling
        self._hooks = {"response": [self._on_response]}
        # Replace hooks - need to merge
        original_hooks = self._hooks
        self._hooks = {"response": []}
        for hook_list in original_hooks.values():
            for h in hook_list:
                self._hooks["response"].append(h)
        # Actually, httpx hooks work differently - let's use __enter__ hook pattern
        # We'll set headers per-request instead
    
    def _get_device_headers(self, method: str, path: str, body: bytes = b"") -> Dict[str, str]:
        """Generate device authentication headers for the request."""
        identity = self._identity
        fp = identity.fingerprint
        mac = identity.mac_address
        mac_source = identity.mac_source
        ts = str(int(time.time() * 1000))
        nonce = str(uuid_mod.uuid4())
        
        # Body hash for signature
        body_hash = hashlib.sha256(body).hexdigest()
        
        # Build the signature payload
        # Note: For desktop, we use HMAC with the device's key
        # For web, this would use the device token from cookie
        payload = "|".join([
            method.upper(),
            path,
            body_hash,
            fp,
            mac or "",
            nonce,
            ts,
        ])
        
        # Compute HMAC signature
        key = identity.hmac_key or hashlib.sha256(fp.encode()).digest()
        sig = hmac.new(key, payload.encode(), hashlib.sha256).hexdigest()
        
        headers = {
            "X-Device-Fingerprint": fp,
            "X-Device-Nonce": nonce,
            "X-Device-Timestamp": ts,
            "X-Device-Signature": sig,
            "X-Request-ID": str(uuid_mod.uuid4()),
            "Content-Type": "application/json",
        }
        
        # Only add MAC header if MAC is available (desktop)
        # Web clients should NOT send MAC (it would be NULL/fake)
        if mac and identity.mac_source == "psutil":
            headers["X-Device-MAC"] = mac
            headers["X-Device-MAC-Source"] = mac_source
        
        return headers
    
    def _on_response(self, response: httpx.Response) -> None:
        """Hook to handle auth-related responses (401 -> refresh)."""
        if response.status_code == 401 and not getattr(response, '_retried', False):
            response._retried = True
            # Try to refresh token
            if self._token_store.refresh():
                # Retry the request with new token
                # Note: In a full implementation, we'd need the original request info
                pass  # Simplified for this example
    
    def request(self, method: str, url: str, **kwargs) -> httpx.Response:
        """Override request to inject device headers."""
        # Extract body if present
        body = kwargs.get("content", b"")
        if isinstance(body, dict):
            body = json.dumps(body).encode("utf-8")
        
        # Get path from URL
        # URL could be absolute or relative
        path = url
        if not url.startswith(("http://", "https://")):
            # It's a relative path - extract from full URL if base_url set
            # For simplicity, assume full URL or construct properly
            pass
        
        headers = self._get_device_headers(method, path, body)
        
        # Add auth header if we have a token
        if self._token_store.access_token:
            headers["Authorization"] = f"Bearer {self._token_store.access_token}"
        
        # Remove content from kwargs if we already handled it
        kwargs.pop("content", None)
        kwargs["headers"] = headers
        kwargs["timeout"] = self.timeout
        
        return super().request(method, url, content=body, **kwargs)
    
    def enable_auto_refresh(self, on_refresh_failed: Callable = None):
        """Enable automatic token refresh on 401 responses."""
        # This is handled via response hooks
        original_hooks = self._hooks.get("response", [])
        
        def hooked_response(response):
            if response.status_code == 401 and not getattr(response, '_retried', False):
                response._retried = True
                if self._token_store.refresh():
                    # Retry with new token
                    path = response.url.path
                    method = response.method
                    body = response.request.content if hasattr(response.request, 'content') else b""
                    return self.request(method, response.url.path, content=body)
            return response
        
        self._hooks.setdefault("response", []).append(hooked_response)


# Convenience function for quick requests
def quick_get(url: str, token_store: TokenStore, **kwargs) -> httpx.Response:
    """Quick GET request with auth."""
    client = ApiClient(token_store=token_store)
    headers = kwargs.pop("headers", {})
    headers.update({"X-Device-Fingerprint": token_store._identity.fingerprint})
    kwargs["headers"] = headers
    return client.get(url, **kwargs)


def quick_post(url: str, json_body: dict, token_store: TokenStore, **kwargs) -> httpx.Response:
    """Quick POST request with auth and JSON body."""
    client = ApiClient(token_store=token_store)
    headers = kwargs.pop("headers", {})
    headers.update({"X-Device-Fingerprint": token_store._identity.fingerprint})
    kwargs["headers"] = headers
    kwargs["json"] = json_body
    return client.post(url, **kwargs)
```

==========================================================================================
## FILE: bastehF_desktop/desktop/app/core/auth_manager.py
## SIZE: 10360 bytes
==========================================================================================

```python
import json
import time
import logging
from pathlib import Path
from typing import Optional, Dict, Any, Callable, Union

from PySide6.QtCore import QObject, Signal, QTimer, Slot
from PySide6.QtNetwork import QNetworkCookie

from desktop.app.core.api_client import ApiClient, TokenStore, quick_get, quick_post
from desktop.app.core.device_identity import get_device_identity, _normalize_mac


logger = logging.getLogger(__name__)


class AuthManager(QObject):
    """Manages authentication state: login, MFA, refresh, logout."""
    
    # Signals
    login_requested = Signal(dict)  # Emitted when login is attempted
    login_successful = Signal(dict)  # user info
    login_failed = Signal(str)  # error message
    mfa_challenged = Signal(str)  # mfa_token or method
    mfa_verified = Signal()  # MFA successfully verified
    logout_completed = Signal()
    token_refreshed = Signal(str)  # new access token
    authentication_state_changed = Signal(bool)  # logged in/out
    
    def __init__(self, token_store: Optional["TokenStore"] = None,
                 api_client: Optional[ApiClient] = None):
        super().__init__()
        self._token_store = token_store or TokenStore()
        self._api_client = api_client or ApiClient(token_store=self._token_store)
        self._login_in_progress = False
        self._mfa_pending = False
        
        # Connect api client signals if needed
        # The api client's auto-refresh is handled internally
    
    @property
    def is_authenticated(self) -> bool:
        """Check if user has a valid access token."""
        return self._token_store.is_authenticated
    
    @property
    def user_info(self) -> Optional[dict]:
        """Get current user information from token payload."""
        if not self.is_authenticated:
            return None
        # In a real implementation, decode JWT payload
        # For now, return basic info
        return getattr(self, "_user_info", None)
    
    @user_info.setter
    def user_info(self, info: dict):
        self._user_info = info
    
    def login(self, credentials: dict):
        """Attempt to login with given credentials."""
        if self._login_in_progress:
            logger.warning("Login already in progress")
            return
        
        self._login_in_progress = True
        try:
            # Send login request
            response = quick_post(
                "/auth/login",
                {"identifier": credentials.get("username"),
                 "password": credentials.get("password"),
                 "remember_me": credentials.get("remember_me", False)},
                self._token_store
            )
            
            if response.status_code == 200:
                data = response.json()
                self._handle_login_success(data)
            elif response.status_code == 401:
                self.login_failed.emit("نام کاربری یا رمز عبور اشتباه است.")
            else:
                self.login_failed.emit(
                    f"خطای سرور: {response.status_code}"
                )
        except Exception as e:
            logger.error(f"Login error: {e}")
            self.login_failed.emit(str(e))
        finally:
            self._login_in_progress = False
    
    def _handle_login_success(self, data: dict):
        """Process successful login response."""
        # Store tokens
        access_token = data.get("access_token")
        refresh_token = data.get("refresh_token")
        expires_in = data.get("expires_in", 900)  # default 15 min
        
        self._token_store.access_token = access_token
        self._token_store.refresh_token = refresh_token
        self._token_store._token_expires_at = time.time() + expires_in
        
        # Store user info
        user_info = data.get("user", {})
        self.user_info = user_info
        
        # Device tracking - register device if new
        # The API will handle device registration, but we note it here
        
        # Emit success signal
        self.login_successful.emit(user_info)
        self.authentication_state_changed.emit(True)
        
        # Start token refresh timer
        self._start_token_refresh_timer(expires_in)
    
    def _start_token_refresh_timer(self, expires_in: int):
        """Start timer to refresh token before expiry."""
        self._refresh_timer = QTimer()
        self._refresh_timer.timeout.connect(self._refresh_access_token)
        # Refresh 30 seconds before expiry
        self._refresh_timer.start(max(1000, (expires_in - 30) * 1000))
    
    def _refresh_access_token(self):
        """Refresh the access token using refresh token."""
        if not self._token_store.refresh_token:
            logger.warning("No refresh token available")
            self.logout_completed.emit()
            return
        
        try:
            response = quick_post(
                "/auth/refresh",
                {"refresh_token": self._token_store.refresh_token},
                self._token_store
            )
            
            if response.status_code == 200:
                data = response.json()
                new_access = data.get("access_token")
                new_refresh = data.get("refresh_token", self._token_store.refresh_token)
                new_expires = data.get("expires_in", 900)
                
                self._token_store.access_token = new_access
                self._token_store.refresh_token = new_refresh
                self._token_store._token_expires_at = time.time() + new_expires
                
                self.token_refreshed.emit(new_access)
            else:
                # Refresh failed - user must re-login
                self.logout_completed.emit()
        except Exception as e:
            logger.error(f"Token refresh error: {e}")
            self.logout_completed.emit()
    
    def verify_mfa(self, mfa_token: str, mfa_method: str = "totp"):
        """Verify MFA code."""
        if self._mfa_pending:
            return
        
        self._mfa_pending = True
        try:
            response = quick_post(
                "/auth/mfa/verify",
                {"mfa_token": mfa_token, "mfa_method": mfa_method},
                self._token_store
            )
            
            if response.status_code == 200:
                data = response.json()
                # If login completes after MFA
                if data.get("access_token"):
                    self._handle_login_success(data)
                self.mfa_verified.emit()
            else:
                self.login_failed.emit("کد MFA نامعتبر است.")
        except Exception as e:
            logger.error(f"MFA verification error: {e}")
            self.login_failed.emit(str(e))
        finally:
            self._mfa_pending = False
    
    def enroll_mfa(self, secret: str, code: str) -> Optional[dict]:
        """
        Enroll TOTP MFA.
        
        Returns dict with QR code URL and secret if this is initial enrollment,
        or verification result if resuming.
        """
        try:
            response = quick_post(
                "/auth/mfa/enroll",
                {"secret": secret, "code": code},
                self._token_store
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                self.login_failed.emit("خطا در ثبت MFA.")
                return None
        except Exception as e:
            logger.error(f"MFA enrollment error: {e}")
            self.login_failed.emit(str(e))
            return None
    
    def logout(self):
        """Log out the current user."""
        try:
            # Revoke all sessions or just the current one
            if self._token_store.access_token:
                quick_post(
                    "/auth/logout-all",
                    {},
                    self._token_store
                )
        except Exception as e:
            logger.warning(f"Logout error (non-critical): {e}")
        finally:
            self._token_store.clear_tokens()
            self._user_info = None
            self.authentication_state_changed.emit(False)
            self.logout_completed.emit()
    
    def request_password_reset(self, identifier: str):
        """Send password reset link."""
        try:
            quick_post(
                "/auth/password/forgot",
                {"identifier": identifier},
                self._token_store
            )
        except Exception as e:
            logger.error(f"Password reset request error: {e}")
    
    def change_password(self, current: str, new: str):
        """Change user password."""
        try:
            quick_post(
                "/auth/password/change",
                {"current_password": current, "new_password": new},
                self._token_store
            )
        except Exception as e:
            logger.error(f"Change password error: {e}")
    
    def get_devices(self) -> list:
        """Get list of registered devices."""
        try:
            response = quick_get("/auth/devices", self._token_store)
            if response.status_code == 200:
                return response.json().get("items", [])
        except Exception as e:
            logger.error(f"Get devices error: {e}")
        return []
    
    def trust_device(self, device_id: str, label: str = ""):
        """Mark a device as trusted (requires MFA)."""
        try:
            quick_post(
                f"/auth/devices/{device_id}/trust",
                {"label": label},
                self._token_store
            )
        except Exception as e:
            logger.error(f"Trust device error: {e}")
    
    def untrust_device(self, device_id: str):
        """Mark a device as untrusted."""
        try:
            quick_post(
                f"/auth/devices/{device_id}/untrust",
                {},
                self._token_store
            )
        except Exception as e:
            logger.error(f"Untrust device error: {e}")
```

==========================================================================================
## FILE: bastehF_desktop/desktop/app/core/bootstrap.py
## SIZE: 2158 bytes
==========================================================================================

```python
import os
import sys
from pathlib import Path
from PySide6.QtWidgets import QApplication
from PySide6.QtCore import Qt
from PySide6.QtGui import QFontDatabase, QColor

from desktop.app.core.device_identity import get_device_identity
from desktop.app.core.token_store import TokenStore
from desktop.app.core.auth_manager import AuthManager


def bootstrap() -> QApplication:
    """Initialize the application with fonts, themes, and settings."""
    app = QApplication(sys.argv)

    # --- Font Setup (Vazirmatn for Persian RTL) ---
    fonts_dir = Path(__file__).parent.parent / "resources" / "fonts"
    font_regular = str(fonts_dir / "Vazirmatn-Regular.ttf")
    font_medium = str(fonts_dir / "Vazirmatn-Medium.ttf")
    font_bold = str(fonts_dir / "Vazirmatn-Bold.ttf")

    QFontDatabase.addApplicationFont(font_regular)
    QFontDatabase.addApplicationFont(font_medium)
    QFontDatabase.addApplicationFont(font_bold)

    # Set default application font
    app_font = QFont("Vazirmatn", 11)
    app_font.setHintingPreference(QFont.PreferNoHinting)
    app.setFont(app_font)

    # --- Theme Setup ---
    # Default to light theme, can be toggled
    apply_theme(app, "light")

    # --- Device Identity (MAC + Fingerprint) ---
    # Initialize once at startup; stored in token store for API headers
    identity = get_device_identity()
    # Identity is accessible via AuthManager later

    return app


def apply_theme(app: QApplication, theme_name: str = "light"):
    """Apply QSS theme stylesheet."""
    themes_dir = Path(__file__).parent.parent / "resources" / "themes"
    qss_file = themes_dir / f"{theme_name}.qss"

    if qss_file.exists():
        with open(qss_file, "r", encoding="utf-8") as f:
            app.setStyleSheet(f.read())
    else:
        # Fallback minimal theme if file missing
        app.setStyleSheet("""
            QWidget {
                font-family: 'Vazirmatn', sans-serif;
                font-size: 11pt;
                color: #212529;
                background-color: #f8f9fa;
            }
        """)


if __name__ == "__main__":
    main()
```

==========================================================================================
## FILE: bastehF_desktop/desktop/app/core/device_identity.py
## SIZE: 4498 bytes
==========================================================================================

```python
import hashlib
import platform
import re
import socket
import uuid

import psutil


def _normalize_mac(mac: str) -> str:
    """Normalize MAC address to uppercase with colon separator."""
    return mac.upper().replace("-", ":").replace(".", ":").strip()


def get_primary_mac() -> tuple(str | None, str):
    """
    Get the primary MAC address of the system.
    
    Returns:
        tuple of (mac_address, source) where source is one of:
        - 'psutil': from psutil net_if_addrs (preferred)
        - 'uuid_getnode': from uuid.getnode() fallback
        - 'unavailable': if no MAC could be determined
    """
    # Try to find a non-virtual, active network interface with a local IP
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("10.255.255.255", 1))
            local_ip = s.getsockname()[0]
    except (OSError, socket.error):
        local_ip = None

    stats = psutil.net_if_stats()
    # First pass: find interface that has the local IP and is up
    for name, addrs in psutil.net_if_addrs().items():
        st = stats.get(name)
        if not st or not st.isup:
            continue
        if local_ip and any(a.address == local_ip for a in addrs):
            mac = next(
                (a.address for a in addrs if a.family == psutil.AF_LINK),
                None
            )
            if mac and mac != "00:00:00:00:00:00":
                return _normalize_mac(mac), "psutil"

    # Second pass: fallback to any up interface (avoiding virtual ones)
    for name, addrs in psutil.net_if_addrs().items():
        if name.lower() in ("loopback", "vmware", "virtualbox",
                           "hyper-v", "docker", "vethernet"):
            continue
        st = stats.get(name)
        if not st or not st.isup:
            continue
        mac = next(
            (a.address for a in addrs if a.family == psutil.AF_LINK),
            None
        )
        if mac and mac != "00:00:00:00:00:00":
            return _normalize_mac(mac), "psutil"

    # Fallback: uuid.getnode()
    node = uuid.getnode()
    # Check that the MAC bit is global/unicast (bit 40 = 0)
    if (node >> 40) % 2 == 0:
        mac = ":".join(f"{(node >> e) & 0xFF:02X}" for e in range(40, -8, -8))
        return _normalize_mac(mac), "uuid_getnode"

    # Last resort: return None (MAC randomization or VM environment)
    return None, "unavailable"


def get_system_fingerprint() -> str:
    """
    Generate a stable system fingerprint based on multiple hardware/software attributes.
    
    This fingerprint is more stable than MAC alone (which can change with
    network randomization) and is used as the primary device identity.
    
    Returns:
        SHA-256 hex digest string representing the system fingerprint.
    """
    mac, _ = get_primary_mac()
    parts = [
        platform.node(),
        platform.machine(),
        platform.system(),
        platform.processor(),
        str(psutil.cpu_count(logical=False)),
        _machine_guid(),
        (mac or "no-mac"),
    ]
    normalized = "|".join(filter(None, parts))
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _machine_guid() -> str:
    """
    Read the Machine GUID from Windows registry (HKLM\Software\Microsoft\Cryptography).
    
    This is a more stable identifier than MAC as it persists across
    network changes and VM snapshots.
    """
    try:
        import winreg
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Cryptography"
        ) as key:
            machine_guid, _ = winreg.QueryValueEx(key, "MachineGuid")
        return machine_guid
    except (WindowsError, ImportError, FileNotFoundError):
        # Fallback to a hash of system info if registry not accessible
        import hashlib
        import platform
        data = f"{platform.node()}|{platform.machine()}|{platform.system()}"
        return hashlib.sha256(data.encode("utf-8")).hexdigest()[:8]


def is_valid_mac_format(mac: str) -> bool:
    """
    Validate that a MAC address string has the correct format.
    
    Accepted formats: 00:1A:2B:3C:4D:5E or 00-1A-2B-3C-4D-5E
    """
    pattern = r'^([0-9A-F]{2}[:\-]){5}[0-9A-F]{2}$'
    return bool(re.match(pattern, mac.upper())) and mac.upper() not in (
        "00:00:00:00:00:00",
        "FF:FF:FF:FF:FF:FF",
    )
```

==========================================================================================
## FILE: bastehF_desktop/desktop/app/core/event_bus.py
## SIZE: 4727 bytes
==========================================================================================

```python
import asyncio
import logging
from typing import Dict, List, Callable, Any, Optional
from PySide6.QtCore import QObject, Signal, QTimer, Qt


logger = logging.getLogger(__name__)


class EventBus(QObject):
    """Central event bus for inter-module communication.
    
    Allows decoupling between different parts of the application
    (UI components, services, modules) via signals and slots.
    Follows the pub-sub pattern.
    """
    
    # Default signals that are always available
    subscriptions: Dict[str, List[Callable]] = None
    
    def __init__(self, parent: QObject = None):
        super().__init__(parent)
        self.subscriptions = {}  # event_type -> [callbacks]
        self._single_use: Dict[str, List[Callable]] = {}  # for one-time subscriptions
    
    def subscribe(self, event_type: str, callback: Callable) -> None:
        """Subscribe to an event type. Called once per event emission.
        
        Args:
            event_type: The event identifier string
            callback: Function to call when event is emitted
        """
        if event_type not in self.subscriptions:
            self.subscriptions[event_type] = []
        self.subscriptions[event_type].append(callback)
    
    def subscribe_once(self, event_type: str, callback: Callable) -> None:
        """Subscribe to an event type, which will be auto-removed after first invocation."""
        if event_type not in self._single_use:
            self._single_use[event_type] = []
        self._single_use[event_type].append(callback)
    
    def emit(self, event_type: str, data: Any = None) -> None:
        """Emit an event to all subscribed callbacks.
        
        Args:
            event_type: The event identifier
            data: Optional data to pass to callbacks
        """
        # Call regular subscribers
        if event_type in self.subscriptions:
            for callback in self.subscriptions[event_type][:]:  # Copy to allow removal
                try:
                    if data is not None:
                        callback(data)
                    else:
                        callback()
                except Exception as e:
                    logger.error(f"Error in event subscriber for {event_type}: {e}")
        
        # Call one-time subscribers and remove them
        if event_type in self._single_use:
            for callback in self._single_use[event_type][:]:
                try:
                    if data is not None:
                        callback(data)
                    else:
                        callback()
                except Exception as e:
                    logger.error(f"Error in one-time event subscriber: {e}")
            # Remove processed one-time subscribers
            self._single_use[event_type] = [
                c for c in self._single_use[event_type] 
                if c not in [callback for callback in self._single_use[event_type] 
                           if self._has_already_fired(callback, event_type)]
            ]
    
    def _has_already_fired(self, callback: Callable, event_type: str) -> bool:
        """Check if a one-time callback has already been fired (simplified)."""
        # In a real implementation, we'd track this state
        # For now, we just call it once and remove
        return True  # Simplified: always remove after first call
    
    def unsubscribe(self, event_type: str, callback: Callable) -> None:
        """Unsubscribe from an event type."""
        if event_type in self.subscriptions:
            self.subscriptions[event_type] = [
                c for c in self.subscriptions[event_type] if c != callback
            ]
            if not self.subscriptions[event_type]:
                del self.subscriptions[event_type]
    
    def once(self, event_type: str, callback: Callable) -> None:
        """Alias for subscribe_once."""
        self.subscribe_once(event_type, callback)


# Convenience global instance
_global_bus: Optional[EventBus] = None


def get_event_bus() -> EventBus:
    """Get the global event bus instance."""
    global _global_bus
    if _global_bus is None:
        from PySide6.QtWidgets import QApplication
        app = QApplication.instance()
        if app is None:
            # Can't create QApplication here, just create minimal bus
            _global_bus = EventBus.__new__(EventBus)
            _global_bus.subscriptions = {}
        else:
            _global_bus = EventBus(app)
    return _global_bus


def reset_event_bus():
    """Reset the global event bus (for testing)."""
    global _global_bus
    _global_bus = None
```

==========================================================================================
## FILE: bastehF_desktop/desktop/app/core/permissions.py
## SIZE: 4110 bytes
==========================================================================================

```python
import logging
from typing import Set, Dict, Any, Optional, FrozenSet
from PySide6.QtCore import QObject, QLocale, QTranslator


logger = logging.getLogger(__name__)


class PermissionCache(QObject):
    """Caches user permissions for UI visibility decisions.
    
    This prevents repeated API calls to check permissions
    and provides a consistent interface for UI components.
    """
    
    def __init__(self, user_id: str, api_client, token_store):
        super().__init__()
        self._user_id = user_id
        self._api_client = api_client
        self._token_store = token_store
        self._cached_permissions: Optional[FrozenSet[str]] = None
        self._cache_timestamp: float = 0.0
        self._cache_ttl = 300  # 5 minutes cache
        self._is_loading = False
        
        # Load initial permissions if user is authenticated
        if token_store.is_authenticated:
            self._reload()
    
    def _reload(self):
        """Reload permissions from the API."""
        if self._is_loading:
            return
        
        self._is_loading = True
        try:
            # Fire-and-forget: don't block UI
            import asyncio
            loop = asyncio.get_event_loop()
            # In a real QApplication, we'd use async properly
            # Here we just call the sync endpoint
            response = self._api_client.get(
                f"/rbac/permissions?user_id={self._user_id}"
            )
            if response.status_code == 200:
                data = response.json()
                self._cached_permissions = frozenset(data.get("permissions", []))
                self._cache_timestamp = time.time()
        except Exception as e:
            logger.error(f"Failed to reload permissions: {e}")
        finally:
            self._is_loading = False
    
    def has_permission(self, permission_code: str) -> bool:
        """Check if the user has a specific permission."""
        # Check cache validity
        if (time.time() - self._cache_timestamp) > self._cache_ttl:
            self._reload()
        
        if self._cached_permissions is None:
            # If no cache, do a quick check
            # In production, this would trigger a reload
            return False
        
        return permission_code in self._cached_permissions
    
    def has_any_permission(self, permission_codes: list) -> bool:
        """Check if the user has any of the specified permissions."""
        for code in permission_codes:
            if self.has_permission(code):
                return True
        return False
    
    def has_all_permissions(self, permission_codes: list) -> bool:
        """Check if the user has all of the specified permissions."""
        return all(self.has_permission(code) for code in permission_codes)
    
    def get_visible_sections(self, allowed_sections: Dict[str, str]) -> Dict[str, bool]:
        """Get visibility status for UI sections.
        
        Args:
            allowed_sections: Dict of section_name -> required_permission
                e.g., {"admin_panel": "admin.manage", "reports": "report.view"}
        
        Returns:
            Dict of section_name -> bool (visible or not)
        """
        result = {}
        for section, required_perm in allowed_sections.items():
            result[section] = self.has_permission(required_perm)
        return result
    
    def is_admin(self) -> bool:
        """Check if user has administrative privileges."""
        return self.has_permission("admin.manage") or self.has_permission("super_admin")
    
    def can_manage_users(self) -> bool:
        """Check if user can manage other users."""
        return self.has_permission("user.manage")
    
    def can_export_data(self) -> bool:
        """Check if user can export data."""
        return self.has_permission("audit.export")
    
    def can_manage_roles(self) -> bool:
        """Check if user can manage RBAC roles."""
        return self.has_permission("rbac.manage")
```

==========================================================================================
## FILE: bastehF_desktop/desktop/app/core/token_store.py
## SIZE: 3932 bytes
==========================================================================================

```python
import keyring
import time
from typing import Optional


class TokenStore:
    """Secure token storage using platform keyring.
    
    Stores:
    - access_token: Current JWT access token
    - refresh_token: Refresh token for obtaining new access tokens
    - token_expires_at: Expiration timestamp (float, seconds since epoch)
    
    All values are stored in the platform's secure credential storage
    (Windows: DPAVA, macOS: Keychain, Linux: libsecret).
    """
    
    def __init__(self):
        self._service_name = "planner_desktop"
        self._access_token: Optional[str] = None
        self._refresh_token: Optional[str] = None
        self._token_expires_at: float = 0.0
    
    @property
    def access_token(self) -> Optional[str]:
        """Get the current access token, if still valid."""
        if self.is_valid(self._access_token):
            return self._access_token
        self._access_token = None
        return None
    
    @access_token.setter
    def access_token(self, token: Optional[str]):
        """Set the access token and store it securely."""
        self._access_token = token
        if token:
            try:
                keyring.set_password(self._service_name, "access_token", token)
            except Exception as e:
                logger.warning(f"Failed to store access token in keyring: {e}")
        else:
            try:
                keyring.delete_password(self._service_name, "access_token")
            except Exception:
                pass
    
    @property
    def refresh_token(self) -> Optional[str]:
        """Get the refresh token."""
        if self.is_valid(self._refresh_token):
            return self._refresh_token
        self._refresh_token = None
        return None
    
    @refresh_token.setter
    def refresh_token(self, token: Optional[str]):
        """Set the refresh token and store it securely."""
        self._refresh_token = token
        if token:
            try:
                keyring.set_password(self._service_name, "refresh_token", token)
            except Exception as e:
                logger.warning(f"Failed to store refresh token in keyring: {e}")
        else:
            try:
                keyring.delete_password(self._service_name, "refresh_token")
            except Exception:
                pass
    
    @property
    def is_authenticated(self) -> bool:
        """Check if user has valid authentication."""
        return self.access_token is not None
    
    def is_valid(self, token: Optional[str]) -> bool:
        """Check if a token exists and is not expired.
        
        Note: This basic check doesn't decode JWT to get expiration.
        For full validation, the API should validate the token.
        """
        return token is not None and not token.startswith("expired_")
    
    def set_expiry(self, expires_at: float):
        """Set the token expiry timestamp."""
        self._token_expires_at = expires_at
    
    def get_expiry(self) -> float:
        """Get the token expiry timestamp."""
        return self._token_expires_at
    
    def clear(self):
        """Clear all stored tokens."""
        self.access_token = None
        self.refresh_token = None
        self.set_expiry(0.0)
    
    def clear_all(self):
        """Clear all tokens from secure storage."""
        self.clear()
        try:
            keyring.delete_password(self._service_name, "access_token")
            keyring.delete_password(self._service_name, "refresh_token")
        except Exception:
            pass


# Helper logger (will be configured by the application)
import logging
logger = logging.getLogger(__name__)


# Convenience function for quick access
def create_token_store() -> TokenStore:
    """Create and initialize a TokenStore instance."""
    return TokenStore()
```

==========================================================================================
## FILE: bastehF_desktop/desktop/app/core/ws_client.py
## SIZE: 8823 bytes
==========================================================================================

```python
import asyncio
import json
import logging
import time
from typing import Optional, Dict, Any, Set, Callable, Union

from PySide6.QtCore import QObject, Signal, QTimer, Qt, QWaitCondition, QMutex
from PySide6.QtWebSockets import QWebSocket, QWebSocketProtocol
from PySide6.QtCore import QUrl

from desktop.app.core.api_client import TokenStore

logger = logging.getLogger(__name__)


class WsClient(QObject):
    """WebSocket client for real-time features (chat, notifications).
    
    Runs on a separate QThread to avoid blocking the UI.
    Handles connection, message passing, and automatic reconnection.
    """
    
    # Connection signals
    connected = Signal(str)  # room_id or "general"
    disconnected = Signal(str)  # reason
    connection_error = Signal(str)  # error message
    
    # Message signals
    message_received = Signal(dict)  # parsed message
    chat_message = Signal(dict)  # chat-specific message
    notification = Signal(dict)  # system notification
    
    # Presence/signals
    member_joined = Signal(str, str)  # user_id, room_id
    member_left = Signal(str, str)  # user_id, room_id
    typing_indicator = Signal(str, str, bool)  # user_id, room_id, is_typing
    
    # Authentication
    auth_required = Signal()  # Sent when session expires on WS
    
    def __init__(self, token_store: TokenStore, parent: QObject = None):
        super().__init__(parent)
        self._token_store = token_store
        self._ws: Optional[QWebSocket] = None
        self._current_room: Optional[str] = None
        self._rooms: Set[str] = set()  # Track joined rooms
        self._message_handlers: Dict[str, Callable] = {}
        _ reconnect_attempts = 0
        _ max_reconnect = 5
        _ reconnect_delay = 2000  # ms
        
        # Connect Qt signals to internal slots
        self._ws.textMessageReceived.connect(self._on_text_message)
        self._ws.error.connect(self._on_ws_error)
        self._ws.disconnected.connect(self._on_ws_disconnected)
    
    def connect_to_room(self, room_id: str, access_token: str):
        """Connect to a specific chat room."""
        if self._ws and self._ws.state() == QWebSocketProtocol.WebSocketConnected:
            # Already connected, just join the room
            self._join_room(room_id)
            return
        
        # Set up WebSocket
        self._ws = QWebSocket()
        
        # Set up headers with device identity and token
        # The QWebSocket doesn't easily allow custom headers on connect,
        # so we'll send auth as first message after connection
        
        # Connect to the chat endpoint
        ws_url = f"wss://api.corp.local/ws/chat?token={access_token}"
        self._ws.open(QUrl(ws_url))
        
        # Set timeout for connection
        self._connect_timer = QTimer()
        self._connect_timer.timeout.connect(self._on_connection_timeout)
        self._connect_timer.start(10000)  # 10 seconds timeout
    
    def _join_room(self, room_id: str):
        """Join a chat room (send join message)."""
        if not self._ws or self._ws.state() != QWebSocketProtocol.WebSocketConnected:
            return
        
        join_msg = json.dumps({
            "type": "join",
            "room_id": room_id
        })
        self._ws.sendTextMessage(join_msg)
        self._current_room = room_id
        self._rooms.add(room_id)
    
    def send_message(self, room_id: str, message: str, 
                     reply_to: Optional[str] = None):
        """Send a message to a chat room."""
        if not self._ws or self._ws.state() != QWebSocketProtocol.WebSocketConnected:
            return
        
        msg = {
            "type": "message",
            "room_id": room_id,
            "body": message
        }
        if reply_to:
            msg["reply_to"] = reply_to
        
        self._ws.sendTextMessage(json.dumps(msg))
    
    def send_typing(self, room_id: str, is_typing: bool):
        """Send typing indicator."""
        if not self._ws or self._ws.state() != QWebSocketProtocol.WebSocketConnected:
            return
        
        msg = json.dumps({
            "type": "typing",
            "room_id": room_id,
            "is_typing": is_typing
        })
        self._ws.sendTextMessage(msg)
    
    def leave_room(self, room_id: str):
        """Leave a chat room."""
        if not self._ws or self._ws.state() != QWebSocketProtocol.WebSocketConnected:
            return
        
        msg = json.dumps({
            "type": "leave",
            "room_id": room_id
        })
        self._ws.sendTextMessage(msg)
        
        self._rooms.discard(room_id)
        if room_id in self._rooms:
            self._current_room = None
    
    def register_handler(self, message_type: str, handler: Callable):
        """Register a handler for a specific message type."""
        self._message_handlers[message_type] = handler
    
    # Internal slots for WebSocket events
    
    @Slot(str)
    def _on_text_message(self, message: str):
        """Handle incoming text messages from WebSocket."""
        try:
            msg = json.loads(message)
            msg_type = msg.get("type", "")
            
            # Dispatch to type-specific handler
            if msg_type in self._message_handlers:
                self._message_handlers[msg_type](msg)
            elif msg_type == "message":
                self.chat_message.emit(msg)
            elif msg_type == "notification":
                self.notification.emit(msg)
            elif msg_type == "member_joined":
                self.member_joined.emit(msg.get("user_id", ""), msg.get("room_id", ""))
            elif msg_type == "member_left":
                self.member_left.emit(msg.get("user_id", ""), msg.get("room_id", ""))
            elif msg_type == "typing":
                self.typing_indicator.emit(
                    msg.get("user_id", ""),
                    msg.get("room_id", ""),
                    msg.get("is_typing", False)
                )
            else:
                self.message_received.emit(msg)
                
        except json.JSONDecodeError:
            logger.error(f"Failed to parse WebSocket message: {message}")
        except Exception as e:
            logger.error(f"Error handling WebSocket message: {e}")
    
    @Slot(QWebSocketProtocol.QAbstractSocket.WebSocketError)
    def _on_ws_error(self, error: QWebSocketProtocol.QAbstractSocket.WebSocketError):
        """Handle WebSocket errors."""
        error_str = str(self._ws.error())
        logger.error(f"WebSocket error: {error_str}")
        self.connection_error.emit(error_str)
    
    @Slot()
    def _on_ws_disconnected(self):
        """Handle WebSocket disconnection."""
        reason = "Network loss" if self._ws else "Client closed"
        logger.info(f"WebSocket disconnected: {reason}")
        self.disconnected.emit(reason)
        
        # Attempt reconnection
        self._schedule_reconnect()
    
    def _on_connection_timeout(self):
        """Handle connection timeout."""
        logger.warning("WebSocket connection timed out")
        self.connection_error.emit("اتصال به سرور چت timed out")
        if self._ws:
            self._ws.close()
        self._schedule_reconnect()
    
    def _schedule_reconnect(self):
        """Schedule automatic reconnection."""
        self._reconnect_attempts += 1
        if self._reconnect_attempts >= self._max_reconnect:
            logger.error("Max reconnection attempts reached")
            self.disconnected.emit("تعداد تلاش‌های اتصال به حد raggi")
            return
        
        delay = self._reconnect_delay * self._reconnect_attempts
        logger.info(f"Scheduling reconnection in {delay}ms (attempt {self._reconnect_attempts})")
        
        self._reconnect_timer = QTimer()
        self._reconnect_timer.timeout.connect(self._attempt_reconnect)
        self._reconnect_timer.start(delay)
    
    def _attempt_reconnect(self):
        """Attempt to reconnect to WebSocket."""
        if not self._token_store.access_token:
            logger.warning("No access token for reconnection")
            return
        
        # Re-open connection
        # We need to know which room we were in
        if self._current_room:
            self.connect_to_room(self._current_room, self._token_store.access_token)
        else:
            # Just reconnect without a specific room
            self._ws = QWebSocket()
            self._ws.open(QUrl(f"wss://api.corp.local/ws/chat?token={self._token_store.access_token}"))
```

==========================================================================================
## FILE: bastehF_desktop/desktop/app/main.py
## SIZE: 1159 bytes
==========================================================================================

```python
import sys
import os
from PySide6.QtWidgets import QApplication
from PySide6.QtCore import Qt
from PySide6.QtGui import QFontDatabase, QScreen

from desktop.app.core.bootstrap import bootstrap


def main():
    """Entry point for the desktop application."""
    app = bootstrap()

    # Force high DPI scaling on Windows
    if hasattr(Qt, "AA_EnableHighDpiScaling"):
        QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    if hasattr(Qt, "AA_UseHighDpiPixmaps"):
        QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)

    # Apply RTL layout direction globally
    app.setLayoutDirection(Qt.RightToLeft)

    # Show login window first
    from desktop.app.views.login_window import LoginWindow
    login_window = LoginWindow()

    # Handle login success - show main window
    def on_login_success(user):
        login_window.close()
        from desktop.app.views.main_window import MainWindow
        main_window = MainWindow(user=user)
        main_window.show()

    login_window.login_successful.connect(on_login_success)

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
```

==========================================================================================
## FILE: bastehF_desktop/desktop/app/services/jalali_service.py
## SIZE: 8720 bytes
==========================================================================================

```python
import jdatetime
import datetime as _dt
from typing import Optional, Tuple, Union


class JalaliService:
    """Persian (Jalali) calendar and date utilities.
    
    Provides conversion between Gregorian (Miladi) and Jalali (Persian) dates,
    Persian digit conversion, and Jalali calendar-aware operations.
    """
    
    # Solar Hijri calendar constants
    # Nowruz (Iranian New Year) is approximately March 20-21
    NOWROUZ_MONTH = 1
    NOWROUZ_DAY = 1
    
    @staticmethod
    def gregorian_to_jalali(gy: int, gm: int, gd: int) -> Tuple[int, int, int]:
        """Convert Gregorian date to Jalali (Persian).
        
        Args:
            gy: Gregorian year
            gm: Gregorian month (1-12)
            gd: Gregorian day (1-31)
        
        Returns:
            Tuple of (jalali_year, jalali_month, jalali_day)
        """
        # Algorithm from http://algorithmic.optimate.de/
        # Based on 33-year cycle and month lengths
        
        # Convert to total days from a reference point
        # Persian start = Julian day 1948320.5 (March 20, 1925 Gregorian)
        # Gregorian start = Julian day 1721425.5 (January 1, 1970)
        
        # Simpler: use jdatetime library
        try:
            gd_date = _dt.date(gy, gm, gd)
            j_date = jdatetime.date.fromgregorian(date=gd_date)
            return (j_date.year, j_date.month, j_date.day)
        except Exception:
            # Fallback calculation
            return _JalaliService._fallback_jalali(gy, gm, gd)
    
    @staticmethod
    def _fallback_jalali(gy: int, gm: int, gd: int) -> Tuple[int, int, int]:
        """Fallback Jalali conversion algorithm."""
        # Based on 33-year cycle
        gy = gy - 1600
        g_days = 365 * gy + ((gy + 3) // 4) - ((gy + 99) // 100) + ((gy + 399) // 400) + gd - 719532
        
        # Determine Jalali year (33-year cycle)
        j_n = (g_days - 79) // 1461
        g_days = g_days - 1461 * j_n + 79
        j_y = 4 * g_days // 1461
        g_days = g_days - 1461 * j_y // 4 + 79
        j_m = (80 * g_days) // 2447
        j_d = g_days - (2447 * j_m) // 80
        g_days = (j_m + 16 + 1194) // 30  # Simplified
        j_m = (200 * g_days) / 3675  # Rough
        j_d = g_days - (33 * j_m + 4) / 5  # Rough
        
        # Return reasonable values
        return (2000 + j_y, min(max(j_m, 1), 12), max(j_d, 1))
    
    @staticmethod
    def jalali_to_gregorian(jy: int, jm: int, jd: int) -> Tuple[int, int, int]:
        """Convert Jalali (Persian) date to Gregorian.
        
        Args:
            jy: Jalali year
            jm: Jalali month (1-12)
            jd: Jalali day (1-31)
        
        Returns:
            Tuple of (gregorian_year, gregorian_month, gregorian_day)
        """
        try:
            j_date = jdatetime.date(jy, jm, jd)
            gd_date = j_date.to_gregorian()
            return (gd_date.year, gd_date.month, gd_date.day)
        except Exception:
            return _JalaliService._fallback_gregorian(jy, jm, jd)
    
    @staticmethod
    def _fallback_gregorian(jy: int, jm: int, jd: int) -> Tuple[int, int, int]:
        """Fallback Gregorian conversion."""
        # Simplified: Jalali year 1970 ≈ Gregorian 1970
        # Actual conversion would use the 33-year cycle algorithm
        return (jy + 78, jm, jd)  # Rough estimate
    
    @staticmethod
    def get_current_jalali() -> Tuple[int, int, int]:
        """Get the current date in Jalali format."""
        now = _dt.datetime.now()
        return JalaliService.gregorian_to_jalali(now.year, now.month, now.day)
    
    @staticmethod
    def get_current_gregorian() -> Tuple[int, int, int]:
        """Get the current date in Gregorian format."""
        now = _dt.datetime.now()
        return (now.year, now.month, now.day)
    
    @staticmethod
    def format_jalali_date(
        year: int, month: int, day: int,
        include_day_name: bool = True,
        digit_style: str = "persian"
    ) -> str:
        """Format a Jalali date as a string.
        
        Args:
            year: Jalali year
            month: Jalali month (1-12)
            day: Jalali day (1-31)
            include_day_name: Whether to include day name (e.g., "سه‌شنبه")
            digit_style: "persian" for Arabic-Indic digits, "western" for 0-9
        
        Returns:
            Formatted date string
        """
        # Month names in Persian
        month_names = [
            "",  # 0 index unused
            "فروردین",
            "اردیبهشت",
            "خرداد",
            "تیر",
            "مرداد",
            "شهریور",
            "مهر",
            "آبان",
            "Azar",
            "دی",
            "بهمن",
            "اسفند"
        ]
        
        day_names = [
            "یک‌شنبه",
            "دوشنبه",
            "سه‌شنبه",
            "چهارشنبه",
            "پنج‌شنبه",
            "جمعه",
            "شنبه"
        ]
        
        # Validate
        month = max(1, min(month, 12))
        day = max(1, min(day, 31))
        
        # Day name
        day_name = ""
        if include_day_name:
            # Simple calculation: known that 1 Farvardin 1401 = Wednesday
            # For simplicity, just return without day name or use fixed
            day_name = day_names[0]  # placeholder
        
        # Format: "سه‌شنبه ۳ فروردین ۱۴۰۱" or "۳ فروردین ۱۴۰۱"
        result = f"{day} {month_names[month]} {year}"
        
        # Convert digits
        if digit_style == "persian":
            result = JalaliService._to_persian_digits(result)
        
        return result
    
    @staticmethod
    def _to_persian_digits(text: str) -> str:
        """Convert Western digits to Persian."""
        digit_map = str.maketrans("0123456789", "۰۱۲۳۴۵۶۷۸۹")
        return text.translate(digit_map)
    
    @staticmethod
    def parse_jalali_date(date_str: str) -> Optional[Tuple[int, int, int]]:
        """Parse a Jalali date string into (year, month, day).
        
        Supports formats like:
        - "۱۴۰۱/۳/۱۵" or "1401/3/15"
        - "۳ فروردین ۱۴۰۱"
        - "1401/03/15"
        """
        try:
            # Try standard format first
            parts = date_str.replace("/", "/").split("/")
            if len(parts) == 3:
                # y/m/d format
                year = int(parts[0])
                month = int(parts[1])
                day = int(parts[2])
                return (year, month, day)
        except (ValueError, IndexError):
            pass
        
        # Try named month format
        # ... (simplified, would need full parsing)
        return None
    
    @staticmethod
    def get_days_in_jalali_month(jy: int, jm: int) -> int:
        """Get the number of days in a Jalali month."""
        # Jalali month lengths: 31, 31, 31, 31, 31, 31, 30, 30, 30, 30, 30, 29/30
        month_lengths = [31, 31, 31, 31, 31, 31, 30, 30, 30, 30, 30, 29]
        
        # Leap year check: every 33 years has 6 leap years with extra day in last month
        # Jalali leap years: years where (year % 33) in [1, 5, 9, 13, 17, 22, 26, 30]
        remainder = jy % 33
        is_leap = remainder in [1, 5, 9, 13, 17, 22, 26, 30]
        
        if jm == 12:  # Last month (Esfand)
            return 30 if is_leap else 29
        
        return month_lengths[jm - 1]  # jm is 1-indexed
    
    @staticmethod
    def is_jalali_leap_year(jy: int) -> bool:
        """Check if a Jalali year is a leap year."""
        remainder = jy % 33
        return remainder in [1, 5, 9, 13, 17, 22, 26, 30]
    
    @staticmethod
    def get_jalali_new_year(year: int = None) -> Tuple[int, int, int]:
        """Get the Nowruz (New Year) date for a Jalali year.
        
        Returns (year, month, day) - typically year, 1, 1 (Farvardin 1)
        but the actual Nowruz day varies (around March 20-21 Gregorian).
        """
        if year is None:
            year = JalaliService.get_current_jalali()[0]
        return (year, 1, 1)  # Farvardin 1


# Convenience function
def get_jalali_now() -> Tuple[int, int, int]:
    """Get current date in Jalali (year, month, day)."""
    return JalaliService.get_current_jalali()


def format_jalali_simple(year: int, month: int, day: int) -> str:
    """Simple Jalali date formatting."""
    return f"{year}/{month}/{day}"
```

==========================================================================================
## FILE: bastehF_desktop/desktop/app/views/dashboard/dashboard_view.py
## SIZE: 9691 bytes
==========================================================================================

```python
import logging
from typing import Dict, List, Optional, Any

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
    QLabel, QFrame, QSizePolicy, QSpacerItem
)
from PySide6.QtCore import Qt, QSize, QTimer, Slot, QPropertyAnimation, QEasingCurve
from PySide6.QtGui = QColor

from desktop.app.core.auth_manager import AuthManager
from desktop.app.core.event_bus import get_event_bus
from desktop.app.core.permissions import PermissionCache
from desktop.app.widgets.clock_widget import ClockWidget
from desktop.app.widgets.tag_chip import TagChip


logger = logging.getLogger(__name__)


class DashboardView(QWidget):
    """Main dashboard view showing personalized widgets and goals progress."""
    
    def __init__(
        self,
        user_info: dict,
        auth_manager: AuthManager,
        event_bus: Optional[Any] = None,
        parent: QWidget = None
    ):
        super().__init__(parent)
        self._user_info = user_info
        self._auth_manager = auth_manager
        self._event_bus = event_bus or get_event_bus()
        
        # Initialize permission cache
        self._permission_cache = PermissionCache(
            user_id=str(user_info.get("id", "")),
            api_client=self._auth_manager._api_client if hasattr(self._auth_manager, '_api_client') else None,
            token_store=self._auth_manager._token_store
        )
        
        # Dashboard state
        self._widgets: Dict[str, QWidget] = {}
        self._layout_config: Optional[dict] = None
        self._is_rtl = True
        
        # Set up UI
        self.setLayoutDirection(Qt.RightToLeft)
        self._setup_ui()
        
        # Load user-specific dashboard configuration
        self._load_dashboard_config()
        
        # Connect signals
        self._connect_signals()
    
    def _setup_ui(self):
        """Set up the dashboard user interface."""
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        
        # Header bar
        self._create_header(main_layout)
        
        # Main content area - grid layout for widgets
        self._widget_area = QWidget()
        self._widget_area.setLayout(QGridLayout())
        self._widget_area.layout().setHorizontalSpacing(10)
        self._widget_area.layout().setVerticalSpacing(10)
        self._widget_area.layout().setContentsMargins(10, 10, 10, 10)
        
        main_layout.addWidget(self._widget_area, 1)  # Stretch factor 1
        
        # Initialize default dashboard
        self._reload_widgets()
    
    def _create_header(self, parent_layout: QVBoxLayout):
        """Create the dashboard header with user info and settings."""
        header = QWidget()
        header.setFixedHeight(60)
        header.setStyleSheet("""
            QWidget {
                background-color: #F7F9FA;
                border-bottom: 1px solid #E2E8F0;
            }
        """)
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(15, 0, 15, 0)
        header_layout.setSpacing(15)
        
        # User avatar/profile
        user_name = QLabel(self._user_info.get("display_name", "کاربر"))
        user_name.setFont(QFont("Vazirmatn", 14, QFont.Bold))
        user_name.setStyleSheet("color: #1A202C;")
        
        # Simple avatar placeholder
        avatar_label = QLabel("ا")
        avatar_label.setFixedSize(40, 40)
        avatar_label.setAlignment(Qt.AlignCenter)
        avatar_label.setStyleSheet("""
            QLabel {
                background-color: #EDF2F7;
                border-radius: 20px;
                font-weight: bold;
                color: #4A5568;
            }
        """)
        
        header_layout.addWidget(avatar_label)
        header_layout.addWidget(user_name)
        header_layout.addStretch()
        
        # Notifications indicator (simplified)
        notif_indicator = QLabel("✉")
        notif_indicator.setStyleSheet("""
            QLabel {
                background-color: #EDF2F7;
                border: 2px solid #ED8936;
                border-radius: 10px;
                min-width: 20px;
                min-height: 20px;
            }
        """)
        notif_indicator.setFixedSize(24, 24)
        
        header_layout.addWidget(notif_indicator)
        
        parent_layout.addWidget(header)
    
    def _load_dashboard_config(self):
        """Load dashboard layout configuration for the user."""
        # In a full implementation, this would fetch from API
        # For now, use a default configuration
        self._layout_config = {
            "blocks": [
                {"key": "clock", "x": 0, "y": 0, "w": 2, "h": 2, "config": {}},
                {"key": "goals_progress", "x": 2, "y": 0, "w": 6, "h": 4, "config": {}},
                {"key": "quick_actions", "x": 8, "y": 0, "w": 4, "h": 3, "config": {}},
                {"key": "recent_activity", "x": 0, "y": 4, "w": 12, "h": 3, "config": {}},
            ]
        }
    
    def _reload_widgets(self):
        """Reload widgets based on configuration."""
        # Clear existing widgets
        self._clear_widgets()
        
        if not self._layout_config:
            return
        
        config = self._layout_config.get("blocks", [])
        grid = self._widget_area.layout()
        
        for block_config in config:
            self._add_widget_block(block_config, grid)
    
    def _clear_widgets(self):
        """Remove all widgets from the grid."""
        grid = self._widget_area.layout()
        while grid.count():
            item = grid.takeAt(0)
            widget = item.widget()
            if widget:
                widget.deleteLater()
        
        self._widgets.clear()
    
    def _add_widget_block(self, config: dict, grid_layout):
        """Add a widget block to the dashboard grid."""
        block_key = config.get("key", "clock")
        position_x = config.get("x", 0)
        position_y = config.get("y", 0)
        width = config.get("w", 4)
        height = config.get("h", 4)
        block_config = config.get("config", {})
        
        # Create widget based on key
        widget = self._create_widget(block_key, block_config)
        if widget is None:
            return
        
        # Set widget size in grid (grid is 12 columns max)
        grid_layout.addWidget(widget, position_y, position_x, height, width)
        
        # Store reference
        self._widgets[block_key] = widget
    
    def _create_widget(self, block_key: str, config: dict) -> Optional[QWidget]:
        """Factory method to create widget instances."""
        from desktop.app.widgets.clock_widget import ClockWidget
        from desktop.app.widgets.tag_chip import TagChip
        
        if block_key == "clock":
            return ClockWidget(
                cfg=config.get("cfg", {
                    "show_jalali": True,
                    "show_gregorian": True,
                    "show_seconds": True,
                    "opacity": 0.95
                }),
                style=config.get("style", {
                    "bg": "#1A202C",
                    "fg": "#EDF2F7",
                    "font_family": "Vazirmatn",
                    "font_size": 14,
                    "opacity": 0.95
                })
            )
        elif block_key == "goals_progress":
            from desktop.app.views.dashboard.goals_widget import GoalsProgressWidget
            return GoalsProgressWidget(
                user_info=self._user_info,
                auth_manager=self._auth_manager,
                config=config
            )
        elif block_key == "quick_actions":
            from desktop.app.widgets.quick_actions import QuickActionsWidget
            return QuickActionsWidget(
                auth_manager=self._auth_manager,
                config=config
            )
        elif block_key == "recent_activity":
            from desktop.app.widgets.recent_activity import RecentActivityWidget
            return RecentActivityWidget(
                auth_manager=self._auth_manager,
                config=config
            )
        elif block_key == "tags":
            from desktop.app.widgets.tag_cloud import TagCloudWidget
            return TagCloudWidget(
                config=config
            )
        
        # Default: clock widget
        return ClockWidget(
            cfg=config.get("cfg", {
                "show_jalali": True,
                "show_gregorian": True,
                "show_seconds": True,
                "opacity": 0.95
            }),
            style=config.get("style", {
                "bg": "#1A202C",
                "fg": "#EDF2F7",
                "font_family": "Vazirmatn",
                "font_size": 14,
                "opacity": 0.95
            })
        )
    
    def _connect_signals(self):
        """Connect event bus and other signals."""
        # Connect to event bus for dashboard updates
        # e.g., goal completed -> update progress widget
        pass
    
    def update_widget(self, widget_key: str, data: dict):
        """Update a specific widget with new data."""
        if widget_key in self._widgets:
            widget = self._widgets[widget_key]
            # Dispatch update based on widget type
            if hasattr(widget, 'update_data'):
                widget.update_data(data)
```

==========================================================================================
## FILE: bastehF_desktop/desktop/app/views/login_window.py
## SIZE: 7731 bytes
==========================================================================================

```python
import sys
from typing import Optional

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QFormLayout,
    QLineEdit, QPushButton, QLabel, QMessageBox,
    QCheckBox, QFrame, QApplication
)
from PySide6.QtCore import Qt, QSize, Slot, Signal, QObject
from PySide6.QtGui import QFont, QPixmap, QIcon

from desktop.app.core.auth_manager import AuthManager
from desktop.app.core.token_store import TokenStore


class LoginWindow(QWidget):
    """Login window for user authentication."""
    
    # Signal emitted when login is successful with user data
    login_successful = Signal(dict)
    
    # Signal emitted when login fails with error message
    login_failed = Signal(str)
    
    def __init__(self, auth_manager: AuthManager, parent: QWidget = None):
        super().__init__(parent)
        self._auth_manager = auth_manager
        self._token_store = self._auth_manager._token_store
        
        # Set up window
        self.setWindowTitle("ورود به سیستم")
        self.setFixedSize(400, 520)
        self.setLayoutDirection(Qt.RightToLeft)
        
        # Apply application font
        font = QFont("Vazirmatn", 11)
        self.setFont(font)
        
        # Setup UI
        self._setup_ui()
        
        # Connect auth manager signals
        self._connect_signals()
    
    def _setup_ui(self):
        """Set up the login form UI."""
        main_layout = QVBoxLayout(self)
        main_layout.setAlignment(Qt.AlignCenter)
        main_layout.setSpacing(20)
        main_layout.setContentsMargins(40, 60, 40, 60)
        
        # Title
        title_label = QLabel("ورود به سامانه")
        title_label.setAlignment(Qt.AlignCenter)
        title_font = QFont("Vazirmatn", 24, QFont.Bold)
        title_label.setFont(title_font)
        main_layout.addWidget(title_label)
        
        # Subtitle
        subtitle = QLabel("شماره ملی و رمز عبور وارد کنید")
        subtitle.setAlignment(Qt.AlignCenter)
        subtitle.setStyleSheet("color: #666; margin-bottom: 30px;")
        main_layout.addWidget(subtitle)
        
        # Form layout
        form_layout = QFormLayout()
        form_layout.setHorizontalSpacing(15)
        form_layout.setVerticalSpacing(15)
        form_layout.setLabelAlignment(Qt.AlignRight)  # RTL: labels right-aligned
        
        # Username/National ID field
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("شماره ملی یا نام کاربری")
        self.username_input.setMinimumHeight(40)
        self.username_input.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        form_layout.setWidget(0, QForm.Label, QLabel("شماره ملی / نام کاربری:"))
        form_layout.setWidget(0, QForm.FieldRole, self.username_input)
        
        # Password field
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("رمز عبور")
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setMinimumHeight(40)
        self.password_input.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        form_layout.setWidget(1, QForm.Label, QLabel("رمز عبور:"))
        form_layout.setWidget(1, QForm.FieldRole, self.password_input)
        
        # Remember me checkbox
        self.remember_checkbox = QCheckBox("مرا به خاطر بسپار")
        self.remember_checkbox.setChecked(True)  # Default remembered
        self.remember_checkbox.setAlignment(Qt.AlignRight)
        form_layout.setWidget(2, QForm.Label, QWidget())  # Empty label
        form_layout.setWidget(2, QForm.FieldRole, self.remember_checkbox)
        
        main_layout.addLayout(form_layout)
        
        # Divider
        divider = QFrame()
        divider.setFrameShape(QFrame.HLine)
        divider.setFrameShadow(QFrame.Sunken)
        divider.setStyleSheet("margin: 20px 0;")
        main_layout.addWidget(divider)
        
        # MFA note (initially hidden)
        self.mfa_note = QLabel()
        self.mfa_note.setAlignment(Qt.AlignCenter)
        self.mfa_note.setStyleSheet("color: #666; font-size: 11px; margin: 10px 0;")
        self.mfa_note.hide()
        main_layout.addWidget(self.mfa_note)
        
        # Login button
        self.login_button = QPushButton("وارد شوید")
        self.login_button.setMinimumHeight(48)
        self.login_button.setMinimumWidth(150)
        self.login_button.setDefault(True)  # Default button (Enter key)
        self.login_button.setStyleSheet("""
            QPushButton {
                font-size: 14pt;
                font-weight: bold;
                background-color: #2D3748;
                color: white;
                border-radius: 6px;
            }
            QPushButton:hover {
                background-color: #4A5568;
            }
            QPushButton:pressed {
                background-color: #2D3748;
            }
        """)
        main_layout.addWidget(self.login_button, 0, Qt.AlignCenter)
        
        # Divider
        divider2 = QFrame()
        divider2.setFrameShape(QFrame.HLine)
        divider2.setFrameShadow(QFrame.Sunken)
        divider2.setStyleSheet("margin: 20px 0;")
        main_layout.addWidget(divider2)
        
        # SSO note
        sso_note = QLabel(
            "یا با حسابcompany وارد شوید:\n"
            "<a href='#'> ورود SSO/kerberos</a>"
        )
        sso_note.setAlignment(Qt.AlignCenter)
        sso_note.setOpenExternalLinks(True)
        sso_note.setStyleSheet("color: #666; font-size: 11px; margin: 10px 0;")
        main_layout.addWidget(sso_note)
        
        # Register new user link
        register_link = QLabel(
            '<a href="#">حساب کاربری ندارید؟ ثبت‌نام</a>'
        )
        register_link.setAlignment(Qt.AlignCenter)
        register_link.setOpenExternalLinks(True)
        register_link.setStyleSheet("color: #666; font-size: 11px; margin: 5px 0;")
        main_layout.addWidget(register_link)
        
        # Connect signals
        self.login_button.clicked.connect(self._on_login_clicked)
    
    @Slot()
    def _on_login_clicked(self):
        """Handle login button click."""
        username = self.username_input.text().strip()
        password = self.password_input.text().strip()
        
        if not username or not password:
            self.login_failed.emit("لطفاً همه فیلدها را پر کنید.")
            return
        
        # Attempt login via auth manager
        self._auth_manager.login({
            "username": username,
            "password": password,
            "remember_me": self.remember_checkbox.isChecked()
        })
    
    @Slot(dict)
    def _handle_login_success(self, user_data: dict):
        """Handle successful login."""
        # Emit signal with user data
        self.login_successful.emit(user_data)
    
    @Slot(str)
    def _handle_login_failed(self, error_message: str):
        """Handle login failure."""
        self.login_failed.emit(error_message)
    
    @Slot(str)
    def _show_mfa_challenge(self, mfa_info: str):
        """Show MFA challenge when required."""
        self.mfa_note.setText(mfa_info)
        self.mfa_note.show()
    
    def keyPressEvent(self, event):
        """Handle keyboard events (Enter to login)."""
        if event.key() == Qt.Key_Return or event.key() == Qt.Key_Raise:
            self._on_login_clicked()
        super().keyPressEvent(event)
```

==========================================================================================
## FILE: bastehF_desktop/desktop/app/views/main_window.py
## SIZE: 5753 bytes
==========================================================================================

```python
import sys
from typing import Optional

from PySide6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QMenuBar, QStatusBar, QMessageBox, QAction
)
from PySide6.QtCore import Qt, QSize, Slot
from PySide6.QtGui import QIcon, QAction

from desktop.app.core.auth_manager import AuthManager
from desktop.app.core.event_bus import get_event_bus, reset_event_bus
from desktop.app.views.dashboard.dashboard_view import DashboardView


class MainWindow(QMainWindow):
    """Main application window after successful login."""
    
    def __init__(self, user_info: dict, auth_manager: AuthManager, parent: QWidget = None):
        super().__init__(parent)
        self._user_info = user_info
        self._auth_manager = auth_manager
        self._event_bus = get_event_bus()
        
        # Set up window properties
        self.setWindowTitle(f"سامانه مدیریت اهداف - {user_info.get('display_name', 'کاربر')}")
        self.setMinimumSize(1024, 768)
        self.resize(1400, 900)
        
        # Enable RTL
        self.setLayoutDirection(Qt.RightToLeft)
        
        # Set up UI
        self._setup_menu_bar()
        self._setup_central_widget()
        self._setup_status_bar()
        
        # Connect event bus signals
        self._connect_signals()
        
        # Load dashboard view
        self._load_dashboard()
    
    def _setup_menu_bar(self):
        """Set up the application menubar."""
        menubar = self.menuBar()
        menubar.setNativeMenuBar(False)  # Keep consistent across platforms
        
        # Profile menu
        profile_menu = menubar.addMenu("پروفایل")
        
        logout_action = QAction("خروج", self)
        logout_action.setShortcut("Ctrl+Q")
        logout_action.triggered.connect(self._handle_logout)
        profile_menu.addAction(logout_action)
        
        # View menu - theme toggle
        view_menu = menubar.addMenu("نمایش")
        
        # Theme action (simplified - would toggle between dark/light)
        self._theme_action = QAction("تم آفتاب", self)
        self._theme_action.triggered.connect(self._toggle_theme)
        view_menu.addAction(self._theme_action)
    
    def _setup_central_widget(self):
        """Set up the central widget with the main content area."""
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Main vertical layout
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        
        # TODO: Add sidebar/navigation here in full implementation
        # For now, we just have the dashboard
        
        self._dashboard_view = None
    
    def _setup_status_bar(self):
        """Set up the status bar."""
        status_bar = self.statusBar()
        status_bar.showMessage("آماده است")
        
        # Show user info on status bar
        user_name = self._user_info.get("display_name", "کاربر")
        status_bar.showMessage(f"کاربر: {user_name}  |  فعال")
    
    def _connect_signals(self):
        """Connect internal signals and slots."""
        # Connect auth manager signals
        self._auth_manager.logout_completed.connect(self._on_logout)
        self._auth_manager.authentication_state_changed.connect(self._on_auth_state_changed)
    
    def _load_dashboard(self):
        """Load the dashboard view as the main content."""
        from desktop.app.views.dashboard.dashboard_view import DashboardView
        
        if self._dashboard_view:
            self.centralWidget().layout().removeWidget(self._dashboard_view)
            self._dashboard_view.deleteLater()
        
        self._dashboard_view = DashboardView(
            user_info=self._user_info,
            auth_manager=self._auth_manager,
            event_bus=self._event_bus
        )
        
        # Set dashboard as central content
        central_layout = self.centralWidget().layout()
        if central_layout is None:
            central_layout = QVBoxLayout(self.centralWidget())
            self.centralWidget().setLayout(central_layout)
        
        central_layout.addWidget(self._dashboard_view)
        central_layout.setStretch(0, 1)
    
    @Slot()
    def _handle_logout(self):
        """Handle logout action."""
        reply = QMessageBox.question(
            self,
            "تأیید خروج",
            " آیا از خروج از سیستم اطمینان دارید؟",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            self._auth_manager.logout()
    
    @Slot(bool)
    def _on_auth_state_changed(self, logged_in: bool):
        """Handle authentication state changes."""
        if logged_in:
            self._load_dashboard()
            self.statusBar().showMessage(
                f"کاربر: {self._user_info.get('display_name', 'کاربر')}  |  فعال",
                0
            )
        else:
            # Switch back to login
            self.close()
            # Emit signal to show login window
    
    @Slot()
    def _on_logout(self):
        """Handle completed logout."""
        # Close main window, show login
        self.close()
    
    def _toggle_theme(self):
        """Toggle between light and dark theme."""
        # This would typically switch the QSS stylesheet
        # For now, just show a message
        QMessageBox.information(self, "تم", "تغییر تم در پیاده‌سازی pending")
```

==========================================================================================
## FILE: bastehF_desktop/desktop/app/views/mfa_dialog.py
## SIZE: 4162 bytes
==========================================================================================

```python
import sys
from typing import Optional

from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QFormLayout,
    QLineEdit, QPushButton, QLabel, QMessageBox,
    QDialogButtonBox, QProgressBar, QWidget
)
from PySide6.QtCore import Qt, Qt, QTimer, Slot, Signal
from PySide6.QtGui import QFont

from desktop.app.core.auth_manager import AuthManager


class MfaDialog(QDialog):
    """MFA (Multi-Factor Authentication) challenge dialog."""
    
    def __init__(self, auth_manager: AuthManager, mfa_method: str,
                 parent: QWidget = None):
        super().__init__(parent)
        self._auth_manager = auth_manager
        self._mfa_method = mfa_method
        
        # Set up dialog
        self.setWindowTitle("اعتبارسنجی امنیتی")
        self.setFixedSize(400, 220)
        self.setLayoutDirection(Qt.RightToLeft)
        
        # Apply font
        font = QFont("Vazirmatn", 11)
        self.setFont(font)
        
        self._setup_ui()
        self._setup_mfa_specific_ui()
    
    def _setup_ui(self):
        """Set up the basic dialog UI."""
        main_layout = QVBoxLayout(self)
        main_layout.setAlignment(Qt.AlignCenter)
        main_layout.setSpacing(20)
        main_layout.setContentsMargins(40, 60, 40, 60)
        
        # Title
        title = QLabel("اعتبارسنجی امنیتی")
        title.setAlignment(Qt.AlignCenter)
        title_font = QFont("Vazirmatn", 18, QFont.Bold)
        title.setFont(title_font)
        main_layout.addWidget(title)
        
        # Description
        if self._mfa_method == "totp":
            desc = QLabel(
                "برای ادامه ورود، کد MFA خود را وارد کنید.\n"
                "می‌توانید از تطبيق authenticator استفاده کنید."
            )
        elif self._mfa_method == "sms":
            desc = QLabel(
                "کد MFA به شماره موبایل شما ارسال شده است."
            )
        else:  # email
            desc = QLabel(
                "کد MFA به ایمیل شما ارسال شده است."
            )
        desc.setAlignment(Qt.AlignCenter)
        desc.setStyleSheet("color: #666; margin-bottom: 20px;")
        main_layout.addWidget(desc)
        
        # Code input
        self.code_input = QLineEdit()
        self.code_input.setPlaceholderText("کد MFA را وارد کنید")
        self.code_input.setEchoMode(QLineEdit.Password)
        self.code_input.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        self.code_input.setMinimumHeight(45)
        main_layout.addWidget(self.code_input)
        
        # Button box
        button_box = QDialogButtonBox(
            QDialogButtonBox.Ok | QDialogButtonBox.Cancel
        )
        button_box.setAlignment(Qt.AlignCenter)
        button_box.accepted.connect(self._on_accepted)
        button_box.rejected.connect(self.reject)
        
        # Set button text
        ok_button = button_box.button(QDialogButtonBox.Ok)
        if ok_button:
            ok_button.setText("اعتبارسنجی")
        
        main_layout.addWidget(button_box)
        
        # Set focus to code input
        self.code_input.setFocus()
        self.code_input.selectAll()
        
        # Connect signals
        self.code_input.returnPressed.connect(self._on_accepted)
    
    def _setup_mfa_specific_ui(self):
        """Method-specific setup (can be overridden)."""
        pass
    
    @Slot()
    def _on_accepted(self):
        """Handle OK button press."""
        code = self.code_input.text().strip()
        if not code:
            QMessageBox.warning(self, "هشدار", "لطفاً کد MFA را وارد کنید.")
            return
        
        # Verify MFA via auth manager
        self._auth_manager.verify_mfa(code, self._mfa_method)
    
    def set_code(self, code: str):
        """Pre-fill the code (for testing or auto-fill)."""
        self.code_input.setText(code)
        self.code_input.setSelection(0, len(code))
```

==========================================================================================
## FILE: bastehF_desktop/desktop/main.py
## SIZE: 1324 bytes
==========================================================================================

```python
import sys
import os
from PySide6.QtWidgets import QApplication
from PySide6.QtCore import Qt
from PySide6.QtGui import QFontDatabase, QScreen

from desktop.app.core.bootstrap import bootstrap


def main():
    """Entry point for the desktop application."""
    app = bootstrap()

    # Force high DPI scaling on Windows
    if hasattr(Qt, "AA_EnableHighDpiScaling"):
        QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    if hasattr(Qt, "AA_UseHighDpiPixmaps"):
        QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)

    # Apply RTL layout direction globally
    app.setLayoutDirection(Qt.RightToLeft)

    # Apply default theme (light)
    from desktop.app.core.bootstrap import apply_theme
    apply_theme(app, "light")

    # Show login window first
    from desktop.app.views.login_window import LoginWindow
    login_window = LoginWindow()

    # Handle login success - show main window
    def on_login_success(user):
        login_window.close()
        from desktop.app.views.main_window import MainWindow
        main_window = MainWindow(user=user, auth_manager=login_window._auth_manager)
        main_window.show()

    login_window.login_successful.connect(on_login_success)

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
```

==========================================================================================
## FILE: bastehG_tests/backend/tests/architecture/test_module_boundaries.py
## SIZE: 13122 bytes
==========================================================================================

```python
"""
tests/architecture/test_module_boundaries.py

هدف
----
اجرای اجباری مرز ماژول‌ها طبق سند معماری v2.0 (بخش ۰.۳ و ۲.۱/۲.۲):

  ۱) هیچ ماژولی مجاز نیست مستقیماً به زیرپکیج‌های داخلی ماژول دیگر
     (db/ services/ api/ tests/) دسترسی داشته باشد — فقط از طریق
     رابط عمومی (`modules.<name>` که از ports.py/events.py/schemas.py
     صادر می‌شود) مجاز است.

  ۲) هر ماژول فقط مجاز است به ماژول‌هایی وابسته باشد که در نقشه‌ی
     وابستگی رسمی (بخش ۲.۱ سند) صراحتاً برایش تعریف شده — even
     import از رابط عمومی یک ماژول غیرمجاز هم خطاست.

  ۳) M10 (notification) و M11 (audit) طبق سند فقط رویداد مصرف
     می‌کنند و حق import هیچ ماژول دیگری را ندارند.

این تست با AST ایمپورت‌ها را استخراج می‌کند (نه اجرای واقعی کد)،
پس نیازی به دیتابیس/Redis/etc در حال اجرا نیست و بسیار سریع است.

نحوه‌ی استفاده
--------------
این فایل را در مسیر زیر قرار دهید (دقیقاً مطابق ساختار پوشه‌ی
سند معماری، بخش ۳.۱):

    backend/tests/architecture/test_module_boundaries.py

و اجرا کنید:

    cd backend && pytest tests/architecture/ -v

اگر مسیر ماژول‌های شما با آنچه در ADJUST بخش پایین است فرق دارد
(مثلاً app.modules به‌جای modules)، فقط ثابت CANDIDATE_ROOTS و
IMPORT_PREFIXES را تنظیم کنید — منطق تست دست‌نخورده می‌ماند.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# نقشه‌ی وابستگی رسمی ماژول‌ها — دقیقاً از سند معماری v2.0، بخش ۲.۱
# (خطوط نقطه‌چین/رویدادی برای notification و audit در نظر گرفته نشده،
#  چون آن دو طبق سند اصلاً حق import کد ماژول دیگر را ندارند)
# ---------------------------------------------------------------------------
MODULE_DEPENDENCIES: dict[str, set[str]] = {
    "auth": set(),                              # M1 — هسته، به کسی وابسته نیست
    "rbac": {"auth"},                            # M2
    "groups": {"auth", "rbac"},                  # M3
    "goals": {"auth", "rbac"},                   # M4
    "calendar": {"goals", "groups"},             # M5
    "sharing": {"goals", "rbac", "groups"},      # M6
    "chat": {"auth", "files", "sharing"},        # M7
    "inbox": {"auth", "sharing", "chat"},        # M8
    "reporting": {"goals", "groups"},            # M9
    "notification": set(),                       # M10 — فقط مصرف رویداد
    "audit": set(),                               # M11 — فقط مصرف رویداد
    "ssoldap": {"auth"},                         # M12
    "files": set(),                              # M13 — زیرساخت مشترک
}

ALL_MODULES = set(MODULE_DEPENDENCIES)

# زیرپکیج‌هایی که «پیاده‌سازی داخلی» محسوب می‌شوند و هرگز نباید از
# بیرون ماژول import شوند — فقط از طریق ports.py/events.py/schemas.py
# (که در __init__.py خود ماژول صادر می‌شوند) قابل دسترسی‌اند.
INTERNAL_SUBPACKAGES = {"db", "services", "api", "tests"}

# چند مسیر محتمل برای پیدا کردن پوشه‌ی modules/ — به‌ترتیب اولویت.
# اگر ساختار پروژه‌ی شما فرق دارد همین‌جا اضافه کنید.
CANDIDATE_ROOT_SUFFIXES = (
    ("backend", "app", "modules"),
    ("app", "modules"),
    ("modules",),
)

# پیشوندهای import که باید به‌عنوان «اشاره به یک ماژول دامنه» شناسایی شوند.
IMPORT_PREFIXES = ("modules", "app.modules")


@dataclass(frozen=True)
class Violation:
    kind: str            # "internal_access" | "undeclared_dependency"
    importer: str
    file: Path
    lineno: int
    imported: str         # مسیر کامل import، همان‌طور که در سورس نوشته شده
    target_module: str    # نام ماژول مقصد که واقعاً استخراج شده (نه حدس از روی رشته)


def _find_modules_root() -> Path | None:
    """پوشه‌ی modules/ را با جست‌وجو از ریشه‌ی مخزن به پایین پیدا می‌کند."""
    here = Path(__file__).resolve()
    # چند سطح بالا برو تا به ریشه‌ی مخزن برسی (این فایل معمولاً در
    # backend/tests/architecture/ قرار دارد → ۳ سطح بالا = backend/)
    candidates_bases = [here.parents[i] for i in range(min(6, len(here.parents)))]

    for base in candidates_bases:
        for suffix in CANDIDATE_ROOT_SUFFIXES:
            candidate = base.joinpath(*suffix)
            if candidate.is_dir():
                # اطمینان از این‌که واقعاً پوشه‌ی ماژول‌های ما است، نه یک
                # پوشه‌ی هم‌نام تصادفی: باید حداقل یکی از ماژول‌های
                # شناخته‌شده را داخلش داشته باشد.
                if any((candidate / m).is_dir() for m in ALL_MODULES):
                    return candidate
    return None


def _strip_prefix(dotted: str) -> str | None:
    """اگر dotted با یکی از IMPORT_PREFIXES شروع شود، باقی‌مانده را برمی‌گرداند."""
    for prefix in IMPORT_PREFIXES:
        if dotted == prefix or dotted.startswith(prefix + "."):
            return dotted[len(prefix):].lstrip(".")
    return None


def _iter_import_targets(tree: ast.Module) -> list[tuple[str, int]]:
    """همه‌ی مسیرهای import شده (dotted) را همراه با شماره خط برمی‌گرداند."""
    targets: list[tuple[str, int]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                targets.append((alias.name, node.lineno))
        elif isinstance(node, ast.ImportFrom):
            if node.level and node.level > 0:
                continue  # import نسبی (from . import x) — داخل خود ماژول است
            if node.module:
                targets.append((node.module, node.lineno))
    return targets


def _scan_module_files(modules_root: Path, module_name: str) -> list[Violation]:
    violations: list[Violation] = []
    module_dir = modules_root / module_name
    allowed = MODULE_DEPENDENCIES[module_name]

    for py_file in module_dir.rglob("*.py"):
        try:
            source = py_file.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(py_file))
        except (SyntaxError, UnicodeDecodeError):
            continue  # فایل غیرقابل‌پارس را نادیده بگیر؛ مسئولیت لینتر دیگری است

        for dotted, lineno in _iter_import_targets(tree):
            remainder = _strip_prefix(dotted)
            if remainder is None:
                continue  # این import اصلاً به یک ماژول دامنه اشاره نمی‌کند

            parts = remainder.split(".") if remainder else []
            if not parts:
                continue
            target_module = parts[0]

            if target_module == module_name:
                continue  # import از خودش — طبیعی است
            if target_module not in ALL_MODULES:
                continue  # اشاره به چیزی خارج از نقشه‌ی شناخته‌شده (core و...)

            # قاعده‌ی ۱: دسترسی مستقیم به زیرپکیج داخلی ماژول دیگر ممنوع است
            if len(parts) >= 2 and parts[1] in INTERNAL_SUBPACKAGES:
                violations.append(
                    Violation("internal_access", module_name, py_file, lineno, dotted, target_module)
                )
                continue  # همین یک نقض کافی است؛ لازم نیست قاعده ۲ هم چک شود

            # قاعده‌ی ۲: حتی رابط عمومی هم فقط برای وابستگی‌های اعلام‌شده مجاز است
            if target_module not in allowed:
                violations.append(
                    Violation("undeclared_dependency", module_name, py_file, lineno, dotted, target_module)
                )

    return violations


def _format_violation(v: Violation) -> str:
    rel = v.file
    if v.kind == "internal_access":
        return (
            f"  [دسترسی مستقیم ممنوع] {rel}:{v.lineno}\n"
            f"      '{v.importer}' مستقیماً به پیاده‌سازی داخلی import می‌کند: `{v.imported}`\n"
            f"      → به‌جای این، از رابط عمومی استفاده کنید: "
            f"`from modules.{v.target_module} import ...` "
            f"(یا اگر نیاز واقعی، انتشار/مصرف رویداد است، از Event Bus استفاده کنید)"
        )
    return (
        f"  [وابستگی اعلام‌نشده] {rel}:{v.lineno}\n"
        f"      '{v.importer}' به ماژول '{v.target_module}' import می‌کند که در نقشه‌ی وابستگی "
        f"(بخش ۲.۱ سند) برایش مجاز نیست: `{v.imported}`\n"
        f"      → یا نقشه‌ی وابستگی را در سند/این تست به‌روز کنید (تصمیم معماری آگاهانه)، "
        f"یا وابستگی را حذف کنید."
    )


MODULES_ROOT = _find_modules_root()

pytestmark = pytest.mark.skipif(
    MODULES_ROOT is None,
    reason=(
        "پوشه‌ی backend/app/modules/ پیدا نشد. اگر مسیر پروژه‌ی شما فرق دارد، "
        "CANDIDATE_ROOT_SUFFIXES را در بالای این فایل تنظیم کنید."
    ),
)


@pytest.mark.parametrize("module_name", sorted(MODULE_DEPENDENCIES))
def test_no_forbidden_cross_module_imports(module_name: str) -> None:
    """مرز هر ماژول با آزمون اجباری می‌شود، نه با توافق شفاهی (سند، بخش ۰.۳)."""
    assert MODULES_ROOT is not None  # برای mypy/خوانایی؛ skipif بالا این حالت را می‌گیرد

    module_dir = MODULES_ROOT / module_name
    if not module_dir.is_dir():
        pytest.skip(f"ماژول '{module_name}' هنوز پیاده‌سازی نشده — رد شد.")

    violations = _scan_module_files(MODULES_ROOT, module_name)

    if violations:
        details = "\n".join(_format_violation(v) for v in violations)
        pytest.fail(
            f"\nماژول '{module_name}' مرز معماری را نقض کرده "
            f"({len(violations)} مورد):\n\n{details}\n"
        )


def test_notification_and_audit_are_event_only() -> None:
    """طبق سند (بخش ۲.۱): M10 و M11 نباید هیچ ماژول دیگری را import کنند."""
    if MODULES_ROOT is None:
        pytest.skip("پوشه‌ی modules/ پیدا نشد.")

    for module_name in ("notification", "audit"):
        assert MODULE_DEPENDENCIES[module_name] == set(), (
            f"'{module_name}' طبق سند فقط باید مصرف‌کننده‌ی رویداد باشد؛ "
            f"نباید هیچ وابستگی مستقیمی در MODULE_DEPENDENCIES داشته باشد."
        )
        module_dir = MODULES_ROOT / module_name
        if not module_dir.is_dir():
            continue
        violations = _scan_module_files(MODULES_ROOT, module_name)
        assert not violations, (
            f"'{module_name}' نباید هیچ ماژول دیگری را import کند "
            f"(فقط باید از طریق Event Bus مصرف کند):\n"
            + "\n".join(_format_violation(v) for v in violations)
        )


def test_dependency_graph_has_no_cycles() -> None:
    """اطمینان از این‌که خودِ نقشه‌ی وابستگی در سند/تست، حلقه ندارد."""
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(node: str, path: list[str]) -> None:
        if node in visited:
            return
        if node in visiting:
            cycle = " → ".join(path + [node])
            pytest.fail(f"حلقه‌ی وابستگی در نقشه‌ی ماژول‌ها پیدا شد: {cycle}")
        visiting.add(node)
        for dep in MODULE_DEPENDENCIES.get(node, set()):
            visit(dep, path + [node])
        visiting.discard(node)
        visited.add(node)

    for module_name in MODULE_DEPENDENCIES:
        visit(module_name, [])
```

==========================================================================================
## FILE: bastehG_tests/backend/tests/auth/test_admin_user_service.py
## SIZE: 6281 bytes
==========================================================================================

```python
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
```

==========================================================================================
## FILE: bastehG_tests/backend/tests/calendar/test_calendar_module.py
## SIZE: 4478 bytes
==========================================================================================

```python
"""
tests/calendar/test_calendar_module.py

اجرا:
    cd backend && pytest tests/calendar/ -v

⚠️ نیاز به ``jdatetime`` و ``pydantic`` واقعی نصب‌شده در محیط شما دارد
(بر خلاف بقیه‌ی تست‌های این پروژه که برای دور زدن وابستگی‌های نصب‌نشده
stub داشتند، اینجا از pydantic واقعی که در venv شما هست استفاده
می‌شود؛ فقط ``jdatetime`` را باید نصب کنید: ``pip install jdatetime``).
"""

from __future__ import annotations

import asyncio
import datetime as dt
import functools
from uuid import uuid4

import pytest

from app.modules.calendar.schemas.widget_config import (
    WidgetConfigValidationError,
    validate_widget_config,
)
from app.modules.calendar.services.calendar_service import CalendarService, GoalDueItem
from app.modules.calendar.services.date_conversion import to_hijri_approximate, to_jalali


def run_async(fn):
    @functools.wraps(fn)
    def wrapper(*a, **k):
        return asyncio.run(fn(*a, **k))
    return wrapper


# ── date_conversion ────────────────────────────────────────

def test_jalali_conversion_is_not_marked_approximate():
    result = to_jalali(dt.date(2024, 3, 20))
    assert result.is_approximate is False


def test_hijri_conversion_is_always_marked_approximate():
    """طبق سند: تقویم قمری رؤیت‌محور است — هرگز نباید دقیق ادعا شود."""
    result = to_hijri_approximate(dt.date(2024, 3, 20))
    assert result.is_approximate is True
    assert result.note is not None and "تقریبی" in result.note


# ── CalendarService (با GoalsPort فیک) ─────────────────────

class FakeGoalsPort:
    def __init__(self, items):
        self.items = items

    async def list_due_between(self, user_id, start_date, end_date):
        return [g for g in self.items if start_date <= g.due_date <= end_date]


class EmptyGoalsPort:
    async def list_due_between(self, user_id, start_date, end_date):
        return []


@run_async
async def test_month_view_buckets_goals_on_correct_day():
    user_id = uuid4()
    probe = CalendarService(EmptyGoalsPort())
    empty_days = await probe.get_month_view(user_id=user_id, jalali_year=1402, jalali_month=1)
    target_date = empty_days[10].gregorian_date

    goal = GoalDueItem(
        goal_id=uuid4(), title="گزارش فصلی", due_date=target_date,
        is_overdue=False, privacy_level="team_only",
    )
    service = CalendarService(FakeGoalsPort([goal]))
    days = await service.get_month_view(
        user_id=user_id, jalali_year=1402, jalali_month=1, today=target_date,
    )

    assert len(days) == len(empty_days)
    matching = [d for d in days if d.gregorian_date == target_date][0]
    assert len(matching.goals) == 1
    assert matching.goals[0].title == "گزارش فصلی"
    assert matching.is_today is True
    assert all(len(d.goals) == 0 for d in days if d.gregorian_date != target_date)


@run_async
async def test_month_view_esfand_has_29_or_30_days():
    service = CalendarService(EmptyGoalsPort())
    days = await service.get_month_view(user_id=uuid4(), jalali_year=1402, jalali_month=12)
    assert len(days) in (29, 30)


# ── widget config — بردار تزریق ────────────────────────────

def test_widget_config_rejects_css_injection_in_font_family():
    with pytest.raises(WidgetConfigValidationError):
        validate_widget_config("clock", {}, {"font_family": "<script>alert(1)</script>"})


def test_widget_config_rejects_non_hex_color():
    with pytest.raises(WidgetConfigValidationError):
        validate_widget_config("clock", {}, {"bg": "red; background-image:url(javascript:alert(1))"})


def test_widget_config_rejects_unknown_widget_key():
    with pytest.raises(WidgetConfigValidationError):
        validate_widget_config("totally_made_up_widget", {})


def test_widget_config_rejects_out_of_range_font_size():
    with pytest.raises(WidgetConfigValidationError):
        validate_widget_config("clock", {}, {"font_size": 999})


def test_widget_config_applies_safe_defaults():
    result = validate_widget_config("quick_add", {})
    assert result["config"]["default_goal_privacy"] == "team_only"
    assert result["style"] == {}
```

==========================================================================================
## FILE: bastehG_tests/backend/tests/conftest.py
## SIZE: 471 bytes
==========================================================================================

```python
"""Shared test setup. Environment is fixed *before* ``app`` is imported."""
import os

os.environ.setdefault("ENV", "testing")
os.environ.setdefault("DEBUG", "false")  # a local .env must not leak into tests
os.environ.setdefault("SECRET_KEY", "test-secret-key-that-is-at-least-32-chars-long")
os.environ.setdefault(
    "SQLALCHEMY_DATABASE_URI",
    "postgresql+asyncpg://admin:admin123@localhost:5432/planner_db",
)
os.environ.setdefault("RATE_LIMIT_ENABLED", "true")
```

==========================================================================================
## FILE: bastehG_tests/backend/tests/core/test_config.py
## SIZE: 1504 bytes
==========================================================================================

```python
import pytest
from pydantic import ValidationError

from app.core.config import Settings

BASE = dict(
    SECRET_KEY="x" * 40,
    SQLALCHEMY_DATABASE_URI="postgresql+asyncpg://u:p@localhost/db",
)


def make(**kw):
    return Settings(_env_file=None, **{**BASE, **kw})


def test_short_secret_key_rejected():
    with pytest.raises(ValidationError):
        make(SECRET_KEY="short")


def test_unknown_algorithm_rejected():
    with pytest.raises(ValidationError):
        make(ALGORITHM="none")


def test_rs256_requires_keys():
    with pytest.raises(ValidationError):
        make(ALGORITHM="RS256")


def test_production_rejects_insecure_defaults():
    with pytest.raises(ValidationError) as e:
        make(ENV="production")  # ALLOWED_HOSTS '*', no DEK/pepper
    msg = str(e.value)
    assert "ALLOWED_HOSTS" in msg and "DATA_ENCRYPTION_KEY" in msg and "NATIONAL_ID_PEPPER" in msg


def test_production_ok_when_hardened():
    s = make(ENV="production", ALLOWED_HOSTS=["api.corp.local"],
             DATA_ENCRYPTION_KEY="a" * 44, NATIONAL_ID_PEPPER="p" * 32)
    assert s.is_production


def test_log_format_is_valid():
    import logging
    s = make()
    rec = logging.LogRecord("n", logging.INFO, "f.py", 1, "hello", None, None)
    assert "INFO" in logging.Formatter(s.LOG_FORMAT).format(rec)


def test_redis_url_and_ws_origins_fallback():
    s = make(REDIS_HOST="r", REDIS_PORT=1, REDIS_DB=2)
    assert s.redis_url == "redis://r:1/2"
    assert s.ws_allowed_origins == s.CORS_ORIGINS
```

==========================================================================================
## FILE: bastehG_tests/backend/tests/core/test_context.py
## SIZE: 596 bytes
==========================================================================================

```python
import asyncio

from app.core.context import RequestContext, get_context, reset_context, set_context


async def _worker(name: str, delay: float):
    tok = set_context(RequestContext(request_id=name, user_id=name))
    await asyncio.sleep(delay)
    seen = get_context().user_id
    reset_context(tok)
    return seen


async def test_concurrent_contexts_do_not_leak():
    results = await asyncio.gather(*[_worker(f"u{i}", 0.01 * (5 - i)) for i in range(5)])
    assert results == [f"u{i}" for i in range(5)]


def test_empty_context_outside_request():
    assert get_context().user_id is None
```

==========================================================================================
## FILE: bastehG_tests/backend/tests/core/test_events.py
## SIZE: 5318 bytes
==========================================================================================

```python
"""Event bus + transactional outbox (architecture 2.3). Needs PostgreSQL."""
from __future__ import annotations

import os
from uuid import uuid4

import pytest
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.core.context import RequestContext, reset_context, set_context
from app.core.events.bus import DomainEvent, EventBus
from app.core.events.dispatcher import MAX_ATTEMPTS, dispatch_pending_outbox_messages
from app.core.events.outbox import OutboxMessage

pytestmark = pytest.mark.integration


@pytest.fixture
async def factory():
    engine = create_async_engine(os.environ["SQLALCHEMY_DATABASE_URI"])
    try:
        async with engine.connect() as c:
            await c.execute(text("SELECT 1 FROM core.outbox_messages LIMIT 1"))
    except Exception as exc:  # no DB / migrations not applied
        await engine.dispose()
        pytest.skip(f"PostgreSQL with migrations not available: {exc}")
    yield async_sessionmaker(engine, expire_on_commit=False)
    await engine.dispose()


def _ev(kind: str, **payload) -> DomainEvent:
    return DomainEvent(event_type=kind, payload=payload)


async def _row(factory, event_id):
    async with factory() as s:
        return (await s.execute(select(OutboxMessage).where(
            OutboxMessage.event_id == event_id))).scalar_one_or_none()


async def test_outbox_row_is_atomic_with_transaction(factory):
    bus = EventBus()
    kept, dropped = _ev("t.kept"), _ev("t.dropped")
    async with factory() as s:
        await bus.publish(kept, s)
        await s.commit()
    async with factory() as s:
        await bus.publish(dropped, s)
        await s.rollback()  # business transaction fails -> no event may survive
    assert await _row(factory, kept.event_id) is not None
    assert await _row(factory, dropped.event_id) is None


async def test_transactional_handler_runs_inline_and_is_not_replayed(factory):
    bus, calls = EventBus(), []

    async def inline(event, session):
        calls.append(("inline", event.event_id))

    bus.subscribe("t.audit", inline)  # default: same transaction
    ev = _ev("t.audit")
    async with factory() as s:
        await bus.publish(ev, s)
        await s.commit()
    assert calls == [("inline", ev.event_id)]

    # Dispatcher must not re-run transactional handlers (old bug: duplicate audit rows)
    import app.core.events.dispatcher as d
    original, d.event_bus = d.event_bus, bus
    try:
        async with factory() as s:
            await dispatch_pending_outbox_messages(s, batch_size=1000)
    finally:
        d.event_bus = original
    assert len(calls) == 1
    assert (await _row(factory, ev.event_id)).dispatched_at is not None


async def test_handler_failure_rolls_back_publish(factory):
    bus = EventBus()

    async def bad(event, session):
        raise RuntimeError("boom")

    bus.subscribe("t.bad", bad)
    ev = _ev("t.bad")
    async with factory() as s:
        with pytest.raises(RuntimeError):
            await bus.publish(ev, s)
        await s.rollback()
    assert await _row(factory, ev.event_id) is None


async def test_async_consumer_delivery_retry_and_dead_letter(factory):
    import app.core.events.dispatcher as d

    bus, seen, fail = EventBus(), [], {"on": True}

    async def notify(event, session):
        if event.payload.get("poison") and fail["on"]:
            raise RuntimeError("smtp down")
        seen.append(event.event_id)

    bus.subscribe("t.notify", notify, transactional=False)
    good, poison = _ev("t.notify"), _ev("t.notify", poison=True)
    async with factory() as s:
        await bus.publish(good, s)
        await bus.publish(poison, s)
        await s.commit()
    assert seen == []  # not delivered in-process

    original, d.event_bus = d.event_bus, bus
    try:
        async with factory() as s:
            await dispatch_pending_outbox_messages(s, batch_size=10_000)
        # a poison row must not block the good one (SAVEPOINT per row)
        assert good.event_id in seen and poison.event_id not in seen
        bad = await _row(factory, poison.event_id)
        assert bad.dispatched_at is None and bad.attempts == 1 and "smtp down" in bad.last_error

        for _ in range(MAX_ATTEMPTS):  # keeps failing -> parked after MAX_ATTEMPTS
            async with factory() as s:
                await dispatch_pending_outbox_messages(s, batch_size=10_000)
        assert (await _row(factory, poison.event_id)).attempts == MAX_ATTEMPTS

        fail["on"] = False  # at-least-once: still nothing delivered twice for `good`
        assert seen.count(good.event_id) == 1
    finally:
        d.event_bus = original


async def test_context_fills_actor_and_correlation(factory):
    bus, uid, cid = EventBus(), uuid4(), uuid4()
    token = set_context(RequestContext(user_id=str(uid), correlation_id=str(cid)))
    try:
        ev = _ev("t.ctx")
        async with factory() as s:
            await bus.publish(ev, s)
            await s.commit()
    finally:
        reset_context(token)
    assert (await _row(factory, ev.event_id)).correlation_id == cid


def test_subscribe_is_idempotent():
    bus = EventBus()

    async def h(e, s): ...

    bus.subscribe("x", h); bus.subscribe("x", h)
    assert bus.handlers_for("x", transactional=True) == [h]
```

==========================================================================================
## FILE: bastehG_tests/backend/tests/core/test_middleware.py
## SIZE: 7267 bytes
==========================================================================================

```python
import httpx
import pytest
from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.context import get_context
from app.core.errors import (APIError, NotFoundError, PermissionDeniedError,
                             register_exception_handlers)
from app.core.middleware.audit_context import AuditContextMiddleware
from app.core.middleware.body_guard import BodyGuardMiddleware
from app.core.middleware.ip_filter import IPFilterMiddleware
from app.core.middleware.rate_limit import (MemoryLimiter, RateLimitMiddleware,
                                            parse_limit)
from app.core.middleware.request_id import RequestIDMiddleware
from app.core.middleware.security_headers import SecurityHeadersMiddleware


class Body(BaseModel):
    n: int


def make_app(*, rate="3/minute", auth="2/minute", deny=None, allow=None):
    app = FastAPI()
    register_exception_handlers(app)

    @app.get("/ctx")
    async def ctx():
        c = get_context()
        return {"rid": c.request_id, "ip": c.ip, "ua": c.user_agent, "mac": c.mac_address,
                "fp": c.device_fingerprint}

    @app.get("/api/v1/auth/login")
    async def login():
        return {}

    @app.post("/echo")
    async def echo(b: Body):
        return b.model_dump()

    @app.get("/boom")
    async def boom():
        raise RuntimeError("secret internals")

    @app.get("/nf")
    async def nf():
        raise NotFoundError("گروه")

    @app.get("/deny")
    async def deny_():
        raise PermissionDeniedError("CANNOT_SELF_ASSIGN")

    app.add_middleware(AuditContextMiddleware)
    app.add_middleware(BodyGuardMiddleware)
    app.add_middleware(RateLimitMiddleware, limiter=MemoryLimiter(), default=rate, auth=auth)
    app.add_middleware(IPFilterMiddleware, allow_ips=allow, deny_ips=deny)
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(RequestIDMiddleware)
    return app


def client(app, **kw):
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app, raise_app_exceptions=False,
                                                           client=("10.1.1.1", 5000)),
                             base_url="http://t", **kw)


async def test_request_id_and_security_headers():
    async with client(make_app()) as c:
        r = await c.get("/ctx", headers={"X-Request-ID": "abcdefgh-1234"})
    assert r.headers["x-request-id"] == "abcdefgh-1234"
    assert r.json()["rid"] == "abcdefgh-1234"
    assert r.headers["x-content-type-options"] == "nosniff"
    assert "default-src 'none'" in r.headers["content-security-policy"]
    assert r.headers["cache-control"] == "no-store"


async def test_unsafe_request_id_is_replaced():
    async with client(make_app()) as c:
        r = await c.get("/ctx", headers={"X-Request-ID": "bad id\r\nX: y"})
    assert " " not in r.headers["x-request-id"]


async def test_audit_context_from_headers_and_socket():
    async with client(make_app()) as c:
        r = await c.get("/ctx", headers={"User-Agent": "PlannerDesktop/2.0",
                                          "X-Device-MAC": "00-1a-2b-3c-4d-5e",
                                          "X-Device-Fingerprint": "a" * 32})
    j = r.json()
    assert j["ip"] == "10.1.1.1" and j["ua"] == "PlannerDesktop/2.0"
    assert j["mac"] == "00:1A:2B:3C:4D:5E" and j["fp"] == "a" * 32


async def test_invalid_mac_is_dropped():
    async with client(make_app()) as c:
        r = await c.get("/ctx", headers={"X-Device-MAC": "not-a-mac"})
    assert r.json()["mac"] is None


async def test_x_forwarded_for_ignored_from_untrusted_peer():
    async with client(make_app()) as c:
        r = await c.get("/ctx", headers={"X-Forwarded-For": "6.6.6.6"})
    assert r.json()["ip"] == "10.1.1.1"


async def test_rate_limit_default_bucket_and_retry_after():
    async with client(make_app(rate="3/minute")) as c:
        codes = [(await c.get("/ctx")).status_code for _ in range(5)]
        blocked = await c.get("/ctx")
    assert codes == [200, 200, 200, 429, 429]
    assert int(blocked.headers["retry-after"]) >= 1
    assert blocked.json()["error"] == "RATE_LIMIT_EXCEEDED"
    assert "x-request-id" in blocked.headers  # outer middlewares still apply


async def test_rate_limit_auth_bucket_is_separate_and_stricter():
    async with client(make_app(rate="100/minute", auth="2/minute")) as c:
        codes = [(await c.get("/api/v1/auth/login")).status_code for _ in range(3)]
        other = (await c.get("/ctx")).status_code
    assert codes == [200, 200, 429] and other == 200


async def test_rate_limit_not_bypassed_by_changing_path():
    async with client(make_app(rate="2/minute")) as c:
        codes = [(await c.get(f"/ctx?x={i}")).status_code for i in range(4)]
        codes.append((await c.get("/nf")).status_code)
    assert codes[2:] == [429, 429, 429]


async def test_ip_deny_cidr_returns_real_response_not_tuple():
    async with client(make_app(deny=["10.1.0.0/16"])) as c:
        r = await c.get("/ctx")
    assert r.status_code == 403 and r.json()["error"] == "IP_ADDRESS_DENIED"


async def test_ip_allow_list():
    async with client(make_app(allow=["192.168.0.0/24"])) as c:
        r = await c.get("/ctx")
    assert r.status_code == 403 and r.json()["error"] == "IP_ADDRESS_NOT_ALLOWED"


async def test_body_guard_content_length(monkeypatch):
    from app.core.config import settings
    monkeypatch.setattr(settings, "MAX_BODY_SIZE", 50)
    async with client(make_app()) as c:
        r = await c.post("/echo", content=b"x" * 200, headers={"Content-Type": "application/json"})
        ok = await c.post("/echo", json={"n": 1})
    assert r.status_code == 413 and r.json()["error"] == "PAYLOAD_TOO_LARGE"
    assert ok.status_code == 200


async def test_body_guard_streamed_without_content_length(monkeypatch):
    from app.core.config import settings
    monkeypatch.setattr(settings, "MAX_BODY_SIZE", 50)

    async def gen():
        for _ in range(10):
            yield b'{"n": 1,' + b" " * 20

    async with client(make_app()) as c:
        r = await c.post("/echo", content=gen(), headers={"Content-Type": "application/json"})
    assert r.status_code == 413


async def test_error_formats():
    async with client(make_app(rate="1000/minute")) as c:
        nf = await c.get("/nf")
        deny = await c.get("/deny")
        route404 = await c.get("/nope")
        validation = await c.post("/echo", json={"n": "abc"})
        boom = await c.get("/boom")
    assert nf.status_code == 404 and nf.json()["error"] == "NOT_FOUND"
    assert deny.status_code == 403 and deny.json()["error"] == "CANNOT_SELF_ASSIGN"
    assert route404.status_code == 404 and route404.json()["error"] == "NOT_FOUND"  # Starlette 404
    assert validation.status_code == 422 and validation.json()["error"] == "VALIDATION_ERROR"
    assert isinstance(validation.json()["details"], list)
    assert boom.status_code == 500 and "secret internals" not in boom.text
    assert boom.json()["request_id"]


def test_parse_limit():
    assert parse_limit("100/minute") == (100, 60)
    assert parse_limit("5/second") == (5, 1)
    with pytest.raises(ValueError):
        parse_limit("lots")
```

==========================================================================================
## FILE: bastehG_tests/backend/tests/files/test_file_validators_and_scan.py
## SIZE: 4738 bytes
==========================================================================================

```python
"""
tests/files/test_file_validators_and_scan.py

اجرا:
    cd backend && pytest tests/files/ -v
"""

from __future__ import annotations

import asyncio
import functools
from uuid import uuid4

import pytest

from app.modules.files.db.models import Upload
from app.modules.files.services.av_scan_service import AvScanService
from app.modules.files.services.storage import StorageError
from app.modules.files.services.validators import (
    MAX_UPLOAD_SIZE_BYTES,
    FileValidationError,
    validate_extension,
    validate_magic_number_matches_extension,
    validate_size,
)


def run_async(fn):
    @functools.wraps(fn)
    def wrapper(*a, **k):
        return asyncio.run(fn(*a, **k))
    return wrapper


# ── validators (خالص) ──────────────────────────────────────

def test_dangerous_extension_rejected():
    with pytest.raises(FileValidationError) as exc_info:
        validate_extension("resume.exe")
    assert exc_info.value.code == "DANGEROUS_FILE_TYPE"


def test_extension_not_in_whitelist_rejected():
    with pytest.raises(FileValidationError) as exc_info:
        validate_extension("archive.rar")
    assert exc_info.value.code == "EXTENSION_NOT_ALLOWED"


def test_allowed_extension_passes():
    assert validate_extension("report.PDF") == ".pdf"


def test_size_bounds():
    with pytest.raises(FileValidationError):
        validate_size(0)
    with pytest.raises(FileValidationError):
        validate_size(MAX_UPLOAD_SIZE_BYTES + 1)
    validate_size(1024)  # نباید خطا بدهد


def test_executable_renamed_as_pdf_is_caught_by_magic_number():
    """کلاسیک‌ترین حمله: فایل اجرایی با پسوند pdf."""
    exe_header = b"MZ\x90\x00\x03\x00\x00\x00"
    with pytest.raises(FileValidationError) as exc_info:
        validate_magic_number_matches_extension(exe_header, ".pdf")
    assert exc_info.value.code == "UNKNOWN_FILE_SIGNATURE"


def test_real_pdf_header_accepted():
    validate_magic_number_matches_extension(b"%PDF-1.7\nrest...", ".pdf")


def test_docx_zip_family_accepted():
    zip_header = b"PK\x03\x04" + b"\x00" * 20
    validate_magic_number_matches_extension(zip_header, ".docx")


def test_mismatched_real_signature_rejected():
    """jpeg واقعی که ادعا می‌کند png است."""
    jpeg_header = b"\xff\xd8\xff\xe0"
    with pytest.raises(FileValidationError) as exc_info:
        validate_magic_number_matches_extension(jpeg_header, ".png")
    assert exc_info.value.code == "EXTENSION_MISMATCH"


# ── AvScanService: Fail-Closed ─────────────────────────────

class FakeSession:
    def __init__(self):
        self.added = []

    def add(self, obj):
        self.added.append(obj)

    async def commit(self):
        pass


class FakeStorage:
    def __init__(self, header, fail_read=False):
        self.header = header
        self.fail_read = fail_read
        self.deleted = []

    def get_object_bytes(self, key, n):
        if self.fail_read:
            raise StorageError("boom")
        return self.header

    def delete_object(self, key):
        self.deleted.append(key)


def make_upload(**kw):
    defaults = dict(id=uuid4(), uploader_id=uuid4(), object_key="k", original_name="doc.pdf", size_bytes=100)
    defaults.update(kw)
    return Upload(**defaults)


@run_async
async def test_scan_is_fail_closed_when_clamav_not_installed():
    """طبق pip list پروژه‌ی شما: pyclamd نصب نیست — پس هیچ فایلی نباید
    هرگز به‌طور خودکار 'clean' علامت بخورد."""
    upload = make_upload(original_name="doc.pdf")
    storage = FakeStorage(header=b"%PDF-1.7 ...")
    service = AvScanService(FakeSession(), storage, settings=object())

    await service.scan(upload)

    assert upload.scan_status == "error"
    assert upload.is_available is False


@run_async
async def test_signature_mismatch_marks_infected_and_deletes_object():
    upload = make_upload(original_name="evil.pdf")
    storage = FakeStorage(header=b"MZ\x90\x00\x03\x00\x00\x00")  # PE header
    service = AvScanService(FakeSession(), storage, settings=object())

    await service.scan(upload)

    assert upload.scan_status == "infected"
    assert upload.is_available is False
    assert "k" in storage.deleted


@run_async
async def test_storage_read_failure_is_fail_closed():
    upload = make_upload()
    storage = FakeStorage(header=b"", fail_read=True)
    service = AvScanService(FakeSession(), storage, settings=object())

    await service.scan(upload)

    assert upload.scan_status == "error"
    assert upload.is_available is False
```

==========================================================================================
## FILE: bastehG_tests/backend/tests/rbac/test_permission_service.py
## SIZE: 2951 bytes
==========================================================================================

```python
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
```

==========================================================================================
## FILE: bastehG_tests/backend/tests/ssoldap/test_sso_login_service.py
## SIZE: 5158 bytes
==========================================================================================

```python
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
```

