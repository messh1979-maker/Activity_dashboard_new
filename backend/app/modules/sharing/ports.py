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