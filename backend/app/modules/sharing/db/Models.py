import uuid
from uuid import UUID
from datetime import datetime
from sqlalchemy import func

from sqlalchemy import (
    Column, String, Integer, Boolean, DateTime,
    ForeignKey, Table, UniqueConstraint, Index
)
from sqlalchemy.orm import relationship

from app.core.db.base import AuditMixin, BaseModel


# --- Shares Table ---

class Shares(BaseModel, AuditMixin):
    """Share entity for ACL and permission sharing."""
    
    __tablename__ = "shares"
    __table_args__ = (
        UniqueConstraint("share_code", name="uq_share_code"),
        Index("ix_shares_entity", "entity_type", "entity_id"),
        Index("ix_shares_recipient", "recipient_id"),
    )
    
    # Primary key inherited
    share_code = Column(
        String(32),
        unique=True,
        nullable=False,
        index=True
    )
    # Unique code for recipient access (time-limited)
    
    entity_type = Column(String(32), nullable=False)
    # 'goal' | 'task' | 'group' | 'document'
    
    entity_id = Column(String(36), nullable=False, index=True)
    # ID of the shared entity
    
    recipient_id = Column(String(36), nullable=False, index=True)
    # ID of the user who received the share
    
    granted_by = Column(String(36), nullable=True)
    # ID of who granted the share
    
    permission_level = Column(
        String(16),
        nullable=False,
        default="read",
        comment="read | write | manage"
    )
    
    allow_comment = Column(Boolean, nullable=False, default=False)
    
    expires_at = Column(DateTime(timezone=True), nullable=True)
    # Expiration time for the share
    
    granted_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    # granter = relationship("Users", foreign_keys=[granted_by])


# --- ACL View ---

class ACLView(BaseModel, AuditMixin):
    """ACL view for an entity."""
    
    __tablename__ = "acl_views"
    __table_args__ = (
        UniqueConstraint("entity_id", "viewer_id", name="uq_acl_view"),
    )
    
    # Primary key components
    entity_id = Column(
        String(36),
        nullable=False,
        index=True
    )
    viewer_id = Column(
        String(36),
        nullable=False,
        index=True
    )
    
    effective_permission = Column(
        String(16),
        nullable=False,
        default="read",
        comment="read | write | manage"
    )
    
    is_denied = Column(Boolean, nullable=False, default=False)
    granted_at = Column(DateTime(timezone=True), server_default=func.now())
    expires_at = Column(DateTime(timezone=True), nullable=True)
    
    # Relationships
    # entity = relationship("Shares", foreign_keys=[entity_id])


# --- Export all ---
__all__ = ["Shares", "ACLView"]