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