# PART 1/12 of GAP PACK

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
