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