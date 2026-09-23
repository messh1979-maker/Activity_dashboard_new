from typing import Protocol, Optional, List, Tuple, Dict, Any
from uuid import UUID
from datetime import datetime
from pydantic import BaseModel, Field


# --- Dashboard Layout ---

class LayoutBlock(BaseModel):
    """Single block in a dashboard layout."""
    block_key: str
    position_x: int = Field(ge=0, le=11)
    position_y: int = Field(ge=0, le=200)
    width: int = Field(ge=1, le=12)
    height: int = Field(ge=1, le=20)
    is_visible: bool = True
    config: dict = Field(default_factory=dict)


class DashboardLayout(BaseModel):
    """Complete dashboard layout."""
    id: UUID
    user_id: UUID
    name: str
    view_mode: str = "daily"  # daily | weekly | monthly
    is_default: bool = False
    schema_version: int = 1
    blocks: List[LayoutBlock]
    created_at: datetime
    updated_at: datetime


# --- User Dashboard Settings ---

class UserDashboardSettings(BaseModel):
    """User-specific dashboard settings."""
    id: UUID
    user_id: UUID
    layout_id: UUID
    block_key: str
    is_visible: bool = True
    position_x: int = Field(ge=0, le=11)
    position_y: int = Field(ge=0, le=200)
    width: int = Field(ge=1, le=12)
    height: int = Field(ge=1, le=20)
    is_collapsed: bool = False
    config: dict = Field(default_factory=dict)
    updated_at: datetime


# --- User Widget Settings ---

class UserWidgetSettings(BaseModel):
    """Per-widget settings (clock, etc.)."""
    id: UUID
    user_id: UUID
    widget_key: str  # clock | quick_add | mini_calendar
    platform: str = "all"  # desktop | web | all
    is_visible: bool = True
    position_x: int = Field(ge=0)
    position_y: int = Field(ge=0)
    width: int = Field(ge=160, le=640)
    height: int = Field(ge=80, le=400)
    z_index: int = Field(default=10)
    style: dict = Field(default_factory=dict)  # {bg, fg, font_family, font_size, opacity}
    config: dict = Field(default_factory=dict)  # widget-specific config


# --- Dashboard Data ---

class DashboardData(BaseModel):
    """Complete dashboard data response."""
    layout: DashboardLayout
    widgets: Dict[str, UserWidgetSettings]
    visible_sections: dict


# --- Report Export/Import ---

class ReportExport(BaseModel):
    """Report export format."""
    schema_version: int
    layout: DashboardLayout
    widgets: List[UserWidgetSettings]


class ReportImport(BaseModel):
    """Report import format."""
    schema_version: int
    name: str
    view_mode: str
    blocks: List[LayoutBlock]


# --- Section Types ---

class SectionType(BaseModel):
    """Dashboard section types."""
    key: str
    label: str
    description: str
    default_blocks: List[str]


# Export all
__all__ = [
    "LayoutBlock", "DashboardLayout", "UserDashboardSettings",
    "UserWidgetSettings", "DashboardData", "ReportExport", "ReportImport",
    "SectionType"
]