from typing import Protocol, Optional, List, Tuple, Dict, Any
from uuid import UUID
from datetime import datetime
from pydantic import BaseModel, Field


# --- Goal Read Model Protocol ---
# Defines what other modules can see about a goal (interface contract)

class GoalReadModel(Protocol):
    """Her ماژول دیگری فقط این را می‌بیند. تغییر امضای این متدها = تغییر Schuster."""
    
    id: UUID
    title: str
    description: Optional[str]
    owner_id: UUID
    privacy_level: str  # fully_private | team_only | selected | fully_transparent
    progress_pct: int  # 0-100
    status: str  # active | completed | archived
    start_date: Optional[datetime]
    due_date: Optional[datetime]
    created_at: datetime
    updated_at: datetime


# --- Goal Schemas ---

class GoalCreate(BaseModel):
    """Create goal request."""
    title: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=1000)
    privacy_level: str = Field(default="team_only", pattern="^(fully_private|team_only|selected|fully_transparent)$")
    start_date: Optional[str] = Field(None, pattern="^\\d{4}-\\d{2}-\\d{2}$")
    due_date: Optional[str] = Field(None, pattern="^\\d{4}-\\d{2}-\\d{2}$")


class GoalUpdate(BaseModel):
    """Update goal request."""
    title: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=1000)
    privacy_level: Optional[str] = Field(None, pattern="^(fully_private|team_only|selected|fully_transparent)$")
    status: Optional[str] = Field(None, pattern="^(active|completed|archived)$")
    start_date: Optional[str] = Field(None, pattern="^\\d{4}-\\d{2}-\\d{2}$")
    due_date: Optional[str] = Field(None, pattern="^\\d{4}-\\d{2}-\\d{2}$")


class GoalProgressUpdate(BaseModel):
    """Update goal progress."""
    progress_pct: int = Field(..., ge=0, le=100)
    notes: Optional[str] = Field(None, max_length=500)


class GoalFilter(BaseModel):
    """Filter goals query."""
    privacy: Optional[str] = Field(None, pattern="^(fully_private|team_only|selected|fully_transparent)$")
    status: Optional[str] = Field(None, pattern="^(active|completed|archived)$")
    owner: Optional[UUID] = Field(None)
    tag: Optional[str] = Field(None)


class GoalDashboardData(BaseModel):
    """Goal dashboard data with privacy applied."""
    goal: dict
    owner: dict
    tasks: List[dict]
    privacy_applied: bool
    redaction: str  # "full" | "aggregate_only" | "hidden"


# --- Task Schemas ---

class TaskCreate(BaseModel):
    """Create task request."""
    title: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=1000)
    priority: str = Field(default="normal", pattern="^(normal|high|low)$")
    due_date: Optional[str] = Field(None, pattern="^\\d{4}-\\d{2}-\\d{2}$")


class TaskUpdate(BaseModel):
    """Update task request."""
    title: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=1000)
    status: Optional[str] = Field(None, pattern="^(pending|in_progress|completed|deferred)$")
    priority: Optional[str] = Field(None, pattern="^(normal|high|low)$")
    due_date: Optional[str] = Field(None, pattern="^\\d{4}-\\d{2}-\\d{2}$")


class TaskFilter(BaseModel):
    """Filter tasks query."""
    status: Optional[str] = Field(None, pattern="^(pending|in_progress|completed|deferred)$")
    assignee: Optional[UUID] = Field(None)
    priority: Optional[str] = Field(None)


# --- Tag Schemas ---

class TagCreate(BaseModel):
    """Create tag request."""
    name: str = Field(..., min_length=1, max_length=64, unique=True)
    color: str = Field(default="#3B82F6", pattern="^#([A-Fa-f0-9]{6}|[A-Fa-f0-9]{3})$")


class TagUpdate(BaseModel):
    """Update tag request."""
    name: Optional[str] = Field(None, min_length=1, max_length=64)
    color: Optional[str] = Field(None, pattern="^#([A-Fa-f0-9]{6}|[A-Fa-f0-9]{3})$")


# --- Export/Import ---

class GoalExport(BaseModel):
    """Goal export format."""
    id: UUID
    title: str
    description: Optional[str]
    progress_pct: int
    status: str
    tags: List[str]
    created_at: datetime


# Export all
__all__ = [
    "GoalReadModel", "GoalCreate", "GoalUpdate", "GoalProgressUpdate",
    "GoalFilter", "GoalDashboardData", "TaskCreate", "TaskUpdate",
    "TaskFilter", "TagCreate", "TagUpdate", "GoalExport"
]