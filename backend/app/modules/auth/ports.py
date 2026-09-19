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