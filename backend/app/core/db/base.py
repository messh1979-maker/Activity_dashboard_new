import uuid
from datetime import datetime
from typing import TypeVar, Generic, Optional, List
from sqlalchemy import (
    Column, Integer, String, DateTime, Boolean, Text, 
    JSON, func, Index, CheckConstraint
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import declared_attr
from sqlalchemy.sql import expression

Base = declarative_base()


# Type variable for generic models
M = TypeVar("M", bound="BaseModel")


class BaseModel(Base):
    """Base model with common fields for all tables."""
    
    __abstract__ = True
    
    # UUID primary key
    id = Column(
        String(36), 
        primary_key=True, 
        default=lambda: str(uuid.uuid4()),
        unique=True
    )
    
    # Soft delete support
    deleted_at = Column(DateTime(timezone=True), nullable=True)
    
    # Timestamps
    created_at = Column(
        DateTime(timezone=True), 
        nullable=False, 
        default=func.now()
    )
    updated_at = Column(
        DateTime(timezone=True), 
        nullable=False, 
        default=func.now(),
        onupdate=func.now()
    )
    
    # Version for optimistic locking
    version = Column(Integer, nullable=False, server_default="1")
    
    # Soft delete check
    __table_args__ = (
        CheckConstraint("deleted_at IS NULL OR deleted_at > created_at"),
    )
    
    def soft_delete(self):
        """Mark record as deleted instead of hard delete."""
        self.deleted_at = datetime.utcnow()
    
    def is_deleted(self) -> bool:
        """Check if record is soft-deleted."""
        return self.deleted_at is not None
    
    def to_dict(self, exclude: Optional[List[str]] = None) -> dict:
        """Convert model to dict, excluding sensitive fields."""
        data = {}
        for column in self.__table__.columns:
            name = column.name
            if exclude and name in exclude:
                continue
            value = getattr(self, name, None)
            if isinstance(value, datetime):
                value = value.isoformat()
            elif value is None:
                value = None
            data[name] = value
        return data
    
    def update_timestamp(self):
        """Update the updated_at timestamp."""
        self.updated_at = datetime.utcnow()


# Mixin for audit tracking
class AuditMixin:
    """Mixin that adds audit fields to a model."""
    
    __abstract__ = True
    
    created_by = Column(String(100), nullable=True)
    updated_by = Column(String(100), nullable=True)
    
    def set_audit_fields(self, user_id: str | None = None):
        """Set audit fields for the current user."""
        self.created_by = user_id
        self.updated_by = user_id


# Database utilities
class DatabaseUtils:
    """Utility functions for database operations."""
    
    @staticmethod
    def generate_uuid() -> str:
        """Generate a string UUID."""
        return str(uuid.uuid4())
    
    @staticmethod
    def current_timestamp() -> datetime:
        """Get current UTC timestamp."""
        return datetime.utcnow()
    
    @staticmethod
    def paginate_query(query, page: int = 1, size: int = 20):
        """Apply pagination to a query."""
        if page < 1:
            page = 1
        if size < 1 or size > 1000:
            size = 20
        offset = (page - 1) * size
        return query.offset(offset).limit(size)
    
    @staticmethod
    def search_vector(columns: list) -> str:
        """Generate GIN search vector string."""
        # This is a placeholder - actual implementation depends on columns
        return func.tsvector(" || ".join([f"coalesce({c}::text, '')" for c in columns]))


# Export base and utilities
__all__ = ["BaseModel", "AuditMixin", "DatabaseUtils", "Base"]