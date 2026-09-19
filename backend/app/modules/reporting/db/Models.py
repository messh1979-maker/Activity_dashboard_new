import uuid
from uuid import UUID
from datetime import datetime
from sqlalchemy import func

from sqlalchemy import (
    Column, String, Integer, Boolean, DateTime,
    ForeignKey, Text, JSON, UniqueConstraint, Index
)
from sqlalchemy.orm import relationship

from app.core.db.base import AuditMixin, BaseModel


# --- Dashboard Layouts ---

class DashboardLayouts(BaseModel, AuditMixin):
    """Dashboard layout configurations."""
    
    __tablename__ = "dashboard_layouts"
    __table_args__ = (
        UniqueConstraint("user_id", "view_mode", "is_default", name="uq_layout_default"),
        Index("ix_layouts_user", "user_id"),
    )
    
    # Primary key inherited
    user_id = Column(
        String(36),
        ForeignKey("auth.users.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    name = Column(String(64), nullable=False)
    view_mode = Column(
        String(16),
        nullable=False,
        default="daily",
        comment="daily | weekly | monthly"
    )
    is_default = Column(Boolean, nullable=False, default=False)
    schema_version = Column(Integer, nullable=False, default=1)
    
    # Blocks stored as JSON
    blocks = Column(JSON, nullable=False, default="[]")
    
    # Timestamps inherited from AuditMixin
    
    # Relationships
    # user = relationship("Users", foreign_keys=[user_id])
    # settings = relationship("UserDashboardSettings", back_populates="layout")


# --- User Dashboard Settings ---

class UserDashboardSettings(BaseModel, AuditMixin):
    """User-specific dashboard settings."""
    
    __tablename__ = "user_dashboard_settings"
    __table_args__ = (
        UniqueConstraint("layout_id", "block_key", name="uq_layout_block"),
        Index("ix_settings_layout", "layout_id"),
    )
    
    # Primary key components
    id = Column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4())
    )
    layout_id = Column(
        String(36),
        ForeignKey("dashboard_layouts.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    block_key = Column(String(48), nullable=False)
    is_visible = Column(Boolean, nullable=False, default=True)
    position_x = Column(Integer, nullable=False)
    position_y = Column(Integer, nullable=False)
    width = Column(Integer, nullable=False)
    height = Column(Integer, nullable=False)
    is_collapsed = Column(Boolean, nullable=False, default=False)
    config = Column(JSON, nullable=False, default="{}")
    updated_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Unique constraint: one setting per block per layout
    __table_args__ += (
        UniqueConstraint("layout_id", "block_key", name="uq_layout_block"),
    )
    
    # Relationships
    # layout = relationship("DashboardLayouts", back_populates="settings")


# --- User Widget Settings ---

class UserWidgetSettings(BaseModel, AuditMixin):
    """Per-widget settings (clock, etc.)."""
    
    __tablename__ = "user_widget_settings"
    __table_args__ = (
        UniqueConstraint("user_id", "widget_key", "platform", name="uq_widget_user_platform"),
        Index("ix_widgets_user", "user_id"),
    )
    
    # Primary key components
    id = Column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4())
    )
    user_id = Column(
        String(36),
        ForeignKey("auth.users.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    widget_key = Column(String(48), nullable=False)
    platform = Column(
        String(16),
        nullable=False,
        default="all",
        comment="desktop | web | all"
    )
    is_visible = Column(Boolean, nullable=False, default=True)
    position_x = Column(Integer, nullable=False)
    position_y = Column(Integer, nullable=False)
    width = Column(Integer, nullable=False)
    height = Column(Integer, nullable=False)
    z_index = Column(Integer, nullable=False, default=10)
    style = Column(JSON, nullable=False, default="{}")  # {bg, fg, font_family, font_size, opacity}
    config = Column(JSON, nullable=False, default="{}")  # widget-specific
    updated_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Unique constraint
    __table_args__ += (
        UniqueConstraint("user_id", "widget_key", "platform", name="uq_widget_user_platform"),
    )
    
    # Relationships
    # user = relationship("Users", foreign_keys=[user_id])


# --- Export/Import ---

class ReportExports(BaseModel, AuditMixin):
    """Report export records."""
    
    __tablename__ = "report_exports"
    __table_args__ = (
        Index("ix_exports_user", "user_id"),
    )
    
    id = Column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4())
    )
    user_id = Column(
        String(36),
        ForeignKey("auth.users.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    schema_version = Column(Integer, nullable=False)
    layout_id = Column(String(36), nullable=True)
    name = Column(String(64), nullable=True)
    view_mode = Column(String(16), nullable=True)
    blocks = Column(JSON, nullable=False, default="[]")
    exported_at = Column(DateTime(timezone=True), server_default=func.now())


# --- Export all ---
__all__ = [
    "DashboardLayouts", "UserDashboardSettings", "UserWidgetSettings",
    "ReportExports"
]