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