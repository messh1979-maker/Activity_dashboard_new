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