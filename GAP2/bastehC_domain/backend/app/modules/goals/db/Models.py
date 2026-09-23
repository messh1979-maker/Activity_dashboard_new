import uuid
from typing import Dict
from uuid import UUID
from datetime import datetime
from sqlalchemy import (
    Column, String, Integer, DateTime, Boolean, Text,
    ForeignKey, CheckConstraint, UniqueConstraint, Index, Table
)
from sqlalchemy.sql import func

from app.core.db.base import BaseModel, AuditMixin


# --- Goals Table ---

class Goals(BaseModel, AuditMixin):
    """Goal entity with privacy-aware fields."""
    
    __tablename__ = "goals"
    __table_args__ = (
        CheckConstraint("progress_pct >= 0 AND progress_pct <= 100"),
        {},
    )
    
    # Primary key inherited from BaseModel (UUID)
    
    # Goal identity
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    
    # Ownership & Privacy
    owner_id = Column(
        String(36),  # UUID as string
        nullable=False,
        index=True
    )
    privacy_level = Column(
        String(20), 
        nullable=False,
        default="team_only",
        comment="fully_private | team_only | selected | fully_transparent"
    )
    
    # Progress tracking
    progress_pct = Column(
        Integer, 
        nullable=False,
        server_default="0",
        comment="0-100"
    )
    
    # Timeline
    status = Column(
        String(16), 
        nullable=False,
        server_default="active",
        comment="active | completed | archived"
    )
    start_date = Column(DateTime(timezone=True), nullable=True)
    due_date = Column(DateTime(timezone=True), nullable=True)
    
    # Timestamps (inherited from BaseModel)
    # created_at, updated_at, deleted_at, version, created_by, updated_by
    
    # Relationships (lazy loading)
    # tags = relationship("GoalTags", back_populates="goal", cascade="all, delete-orphan")
    # tasks = relationship("Tasks", back_populates="goal", cascade="all, delete-orphan")
    
    def is_visible_to(self, viewer_id: UUID, privacy_level: str) -> bool:
        """Check if goal is visible to a viewer based on privacy settings."""
        if privacy_level == "fully_transparent":
            return True
        elif privacy_level == "team_only":
            # Team members can see - determined by ACL
            return True  # simplified
        elif privacy_level == "selected":
            # Only specific viewers allowed
            return False  # determined by privacy_exceptions
        elif privacy_level == "fully_private":
            # Only owner can see
            return False  # determined by owner check
        return False
    
    def get_privacy_decision(self, owner_id: UUID, viewer_id: UUID) -> dict:
        """Get privacy decision for a viewer."""
        # This would query groups.privacy_settings and groups.privacy_exceptions
        # For now, simplified logic
        is_owner = owner_id == viewer_id
        
        if is_owner:
            return {"level": "full", "redaction": None}
        else:
            # Check privacy level from goal
            level = self.privacy_level
            if level == "fully_private":
                return {"level": "hidden", "redaction": "full_content"}
            elif level == "team_only":
                # Would check if viewer is team member
                return {"level": "aggregate_only", "redaction": "status_only"}
            elif level == "selected":
                # Would check privacy_exceptions
                return {"level": "hidden", "redaction": "full_content"}
            elif level == "fully_transparent":
                return {"level": "full", "redaction": None}
        
        return {"level": "hidden", "redaction": "full_content"}


# --- Tasks Table ---

class Tasks(BaseModel, AuditMixin):
    """Task entity linked to a goal."""
    
    __tablename__ = "tasks"
    __table_args__ = (
        UniqueConstraint("goal_id", "title", name="uq_goal_task_title"),
    )
    
    # Primary key inherited
    goal_id = Column(
        String(36),  # UUID
        ForeignKey("goals.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    
    # Task identity
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    
    # Assignment
    assignee_id = Column(
        String(36),
        ForeignKey("auth.users.id"),
        nullable=True,
        index=True
    )
    owner_id = Column(
        String(36),
        nullable=False,
        comment="Goal owner who created the task"
    )
    
    # Task tracking
    privacy_level = Column(
        String(20),
        nullable=False,
        default="team_only",
        comment="inherited from goal or overridden"
    )
    status = Column(
        String(16),
        nullable=False,
        server_default="pending",
        comment="pending | in_progress | completed | deferred"
    )
    priority = Column(
        String(16),
        nullable=False,
        server_default="normal",
        comment="normal | high | low"
    )
    progress_pct = Column(
        Integer,
        nullable=False,
        server_default="0",
        comment="0-100 for task progress"
    )
    
    # Timeline
    due_date = Column(DateTime(timezone=True), nullable=True)
    
    # Timestamps inherited
    # created_at, updated_at, deleted_at, version, created_by, updated_by
    
    # Relationships
    # goal = relationship("Goals", back_populates="tasks")
    # assignee = relationship("Users", foreign_keys=[assignee_id])
    
    def is_visible_to(self, viewer_id: UUID, goal_privacy: str) -> bool:
        """Check if task is visible to viewer based on privacy."""
        # Tasks inherit privacy from goal, with possible overrides
        if goal_privacy == "fully_transparent":
            return True
        elif goal_privacy == "fully_private" and viewer_id != self.owner_id:
            return False
        elif goal_privacy == "team_only":
            # Team members can see basic info
            return True  # simplified - would check ACL
        elif goal_privacy == "selected":
            # Would check privacy_exceptions
            return False  # simplified
        return False
    
    def get_privacy_decision(self, goal_privacy: str, viewer_id: UUID) -> dict:
        """Get privacy decision for task viewer."""
        is_owner = viewer_id is not None and hasattr(self, 'owner_id') and self.owner_id == viewer_id
        
        if is_owner:
            return {"level": "full", "redaction": None}
        
        if goal_privacy == "fully_private":
            return {"level": "hidden", "redaction": "full_content"}
        elif goal_privacy == "team_only":
            return {"level": "aggregate_only", "redaction": "status_and_progress"}
        elif goal_privacy == "selected":
            return {"level": "hidden", "redaction": "full_content"}
        elif goal_privacy == "fully_transparent":
            return {"level": "full", "redaction": None}
        
        return {"level": "hidden", "redaction": "full_content"}


# --- Tags Table ---

class Tags(BaseModel, AuditMixin):
    """Tag entity for multi-goal labeling."""
    
    __tablename__ = "tags"
    __table_args__ = (
        UniqueConstraint("name", name="uq_tag_name"),
    )
    
    # Primary key inherited
    name = Column(String(64), nullable=False, unique=True)
    color = Column(
        String(7),
        nullable=False,
        default="#3B82F6",
        comment="#RRGGBB format"
    )
    
    # Timestamps inherited
    # created_at, updated_at, deleted_at, version, created_by, updated_by
    
    # Relationships
    # goal_tags = relationship("GoalTags", back_populates="tag", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<Tag name='{self.name}' color='{self.color}'>"


# --- Goal-Tag Junction Table ---

class GoalTags(BaseModel, AuditMixin):
    """Junction table for many-to-many Goal-Tag relationship."""
    
    __tablename__ = "goal_tags"
    __table_args__ = (
        UniqueConstraint("goal_id", "tag_id", name="uq_goal_tag"),
    )
    
    # Primary key inherited
    goal_id = Column(
        String(36),
        ForeignKey("goals.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    tag_id = Column(
        String(36),
        ForeignKey("tags.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    
    # Composite primary key (goal_id, tag_id)
    
    # Relationships
    # goal = relationship("Goals", back_populates="goal_tags")
    # tag = relationship("Tags", back_populates="goal_tags")