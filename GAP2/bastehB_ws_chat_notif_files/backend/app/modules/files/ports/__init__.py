"""File storage ports — request/response Pydantic schemas (real DDL).

Architecture Reference: Sections 8.2, 11.1 (files.uploads / scan_queue /
access_logs).  The DDL lives in ``chat_schema.sql`` (files.uploads) plus
``files_schema.sql`` (scan_queue, access_logs, composite indexes).
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional, Literal
from uuid import UUID

from pydantic import BaseModel, Field


# --- Upload lifecycle ---

class PresignUpload(BaseModel):
    """Request a presigned upload URL / local upload path."""
    context_type: Literal["chat", "task_attachment", "avatar", "goal"]
    context_id: Optional[UUID] = None
    original_name: str = Field(..., max_length=255)
    mime_declared: Optional[str] = None
    size_bytes: int = Field(..., gt=0, le=52_428_800)


class PresignResponse(BaseModel):
    """Data returned to the caller so it can PUT the file bytes."""
    upload_id: UUID
    object_key: str
    upload_url: str        # local ``PUT /api/v1/files/upload/{upload_id}``
    expires_in: int
    max_size: int


class UploadFinalize(BaseModel):
    """Finalize a completed upload (trigger AV scan, mark available)."""
    sha256: Optional[str] = None  # client-provided hash for verification


class DownloadRequest(BaseModel):
    """Optional scope used by the download endpoint."""
    ip_address: Optional[str] = None


# --- Row-level responses ---

class _UploadBase(BaseModel):
    id: UUID
    uploader_id: UUID
    context_type: str
    context_id: Optional[UUID]
    original_name: str
    object_key: str
    mime_declared: Optional[str] = None
    mime_detected: Optional[str] = None
    size_bytes: int
    sha256: Optional[str] = None
    scan_status: str
    scanned_at: Optional[datetime] = None
    is_available: bool
    created_at: datetime
    expires_at: Optional[datetime] = None


class UploadResponse(_UploadBase):
    """Full upload row."""
    pass


class UploadListItem(BaseModel):
    """Lightweight row for list views."""
    id: UUID
    original_name: str
    mime_declared: Optional[str] = None
    size_bytes: int
    scan_status: str
    is_available: bool
    created_at: datetime


class AccessLogResponse(BaseModel):
    id: int
    upload_id: UUID
    ip_address: Optional[str] = None
    user_id: Optional[UUID] = None
    accessed_at: datetime
    action: str


__all__ = [
    "PresignUpload", "PresignResponse", "UploadFinalize",
    "UploadResponse", "UploadListItem", "AccessLogResponse",
]