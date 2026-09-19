"""
Auth Module API Routes
Architecture Reference: Sections 5.2, 5.3, 6.2-6.5, 7.1, 11.2-11.3
Endpoints: /api/v1/auth
"""

from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Body, Path, status
from fastapi.responses import JSONResponse

from app.core.dependencies import (
    get_db_session, get_current_user, get_auth_service, 
    get_mfa_service, get_rate_limit_check
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
    request: MFAVerifyRequest,
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session),
    auth_service: AuthService = Depends(get_auth_service)
):
    """Verify MFA code."""
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
    async with db_session() as session:
        try:
            result = await auth_service.enroll_mfa(user_id, secret="temp")
            return {"status": "enrolled", "qr_code": result.get("qr_url"), "secret": result.get("secret")}
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
    async with db_session() as session:
        try:
            result = await auth_service.enroll_mfa(user_id, secret=code)
            return {"status": "enrollment_confirmed", "message": "MFA ثبت شد"}
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