"""Notification module API routes (real DDL, M10)."""

from __future__ import annotations

from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, Body, Query, Path, Request
from fastapi.responses import JSONResponse

from app.core.dependencies import get_db_session, get_current_user
from app.core.errors import APIError, NotFoundError
from app.modules.notification.ports import (
    NotificationCreate, NotificationResponse, PreferencesUpdate,
    PreferencesResponse, NotificationCount,
)
from app.modules.notification.services.notification_service import NotificationService


router = APIRouter(prefix="/notifications", tags=["Notifications"])


@router.get("", response_model=dict)
async def list_notifications(
    request: Request,
    user_id: UUID = Depends(get_current_user),
    limit: int = Query(50, ge=1, le=200),
    unread_only: bool = Query(False),
    db_session=Depends(get_db_session),
):
    """List the caller's notifications, newest first."""
    async with db_session() as session:
        try:
            svc = NotificationService(session)
            items = await svc.list_for_user(user_id, limit, unread_only)
            return {"status": "success", "data": items,
                    "count": len(items)}
        except APIError as e:
            return JSONResponse(status_code=e.status_code,
                                content={"error": e.error_code,
                                         "message": e.message,
                                         "success": False})


@router.get("/unread-count", response_model=dict)
async def unread_count(
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session),
):
    """Return count of unread notifications."""
    async with db_session() as session:
        try:
            svc = NotificationService(session)
            count = await svc.unread_count(user_id)
            return {"status": "success", "data": {"unread": count}}
        except APIError as e:
            return JSONResponse(status_code=e.status_code,
                                content={"error": e.error_code,
                                         "message": e.message,
                                         "success": False})


@router.patch("/{notification_id}/read", response_model=dict)
async def mark_read(
    notification_id: UUID = Path(...),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session),
):
    """Mark a single notification as read."""
    async with db_session() as session:
        try:
            svc = NotificationService(session)
            result = await svc.mark_read(user_id, notification_id)
            return {"status": "success", "data": {"id": str(result.id),
                                                  "is_read": result.is_read}}
        except NotFoundError:
            return JSONResponse(status_code=404,
                                content={"error": "NOT_FOUND",
                                         "message": "اعلان یافت نشد.",
                                         "success": False})


@router.patch("/read-all", response_model=dict)
async def mark_all_read(
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session),
):
    """Mark all of the caller's notifications as read."""
    async with db_session() as session:
        try:
            svc = NotificationService(session)
            updated = await svc.mark_all_read(user_id)
            return {"status": "success", "data": {"updated": updated}}
        except APIError as e:
            return JSONResponse(status_code=e.status_code,
                                content={"error": e.error_code,
                                         "message": e.message,
                                         "success": False})


@router.get("/preferences", response_model=dict)
async def get_preferences(
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session),
):
    """Return the caller's notification preferences."""
    async with db_session() as session:
        try:
            svc = NotificationService(session)
            prefs = await svc.get_preferences(user_id)
            return {"status": "success", "data": prefs}
        except APIError as e:
            return JSONResponse(status_code=e.status_code,
                                content={"error": e.error_code,
                                         "message": e.message,
                                         "success": False})


@router.put("/preferences", response_model=dict)
async def update_preferences(
    patch: PreferencesUpdate,
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session),
):
    """Update the caller's notification preferences."""
    async with db_session() as session:
        try:
            svc = NotificationService(session)
            prefs = await svc.update_preferences(user_id,
                                                 patch.model_dump(exclude_unset=True))
            return {"status": "success", "data": prefs}
        except APIError as e:
            return JSONResponse(status_code=e.status_code,
                                content={"error": e.error_code,
                                         "message": e.message,
                                         "success": False})