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