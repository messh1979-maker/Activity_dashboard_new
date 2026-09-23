# PART 2/12 of GAP PACK

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
