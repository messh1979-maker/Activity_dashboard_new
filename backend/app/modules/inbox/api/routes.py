from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, Body, Path, Query
from fastapi.responses import JSONResponse

from app.core.dependencies import get_db_session, get_current_user
from app.core.errors import APIError, NotFoundError
from app.modules.inbox.ports import (
    InboxItemCreate, InboxItemUpdate, InboxItemResponse,
    OutboxItemCreate, ReceiptState, InboxExport
)
from app.modules.inbox.services.inbox_service import InboxService
from app.modules.inbox.db.Models import InboxItems, Receipts, OutboxItems
from app.core.database import async_session_context


router = APIRouter(prefix="/inbox", tags=["Inbox"])


@router.get("/outbox", response_model=dict)
async def list_outbox(
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """List outbox items for a user.

    NOTE: defined BEFORE /{user_id} so "outbox" is not parsed as a UUID.
    """
    async with db_session() as session:
        try:
            service = InboxService(session)
            items = await service.list_outbox(user_id)
            return {
                "status": "success",
                "data": {"items": items}
            }
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.post("/", response_model=dict)
async def create_inbox_item(
    request: InboxItemCreate,
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Create an inbox item."""
    async with db_session() as session:
        try:
            service = InboxService(session)
            result = await service.create_item(
                sender_id=user_id,
                recipient_id=request.recipient_id,
                item_type=request.item_type,
                entity_type=request.entity_type,
                entity_id=str(request.entity_id) if request.entity_id else None,
                title=request.title,
                message=request.message,
                priority=request.priority,
                due_at=request.due_at,
                expires_at=request.expires_at
            )
            return {
                "status": "item_created",
                "item_id": str(result.id),
                "action_state": result.action_state,
                "receipt_state": result.receipt_state
            }
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.get("/{user_id}", response_model=dict)
async def list_inbox(
    user_id: UUID = Path(...),
    state: Optional[str] = Query(None),
    db_session=Depends(get_db_session)
):
    """List inbox items for a user."""
    async with db_session() as session:
        try:
            service = InboxService(session)
            items = await service.list_items(user_id, state)
            return {
                "status": "success",
                "data": {"items": items}
            }
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.post("/{item_id}/act", response_model=dict)
async def act_on_item(
    item_id: UUID = Path(...),
    action: str = Body(...),
    note: Optional[str] = Body(None),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Act on an inbox item (accept, reject, defer)."""
    async with db_session() as session:
        try:
            service = InboxService(session)
            result = await service.act_on_item(item_id, action, note, user_id)
            return {
                "status": "item_acted",
                "item_id": str(item_id),
                "action_state": result.action_state,
                "receipt_state": result.receipt_state,
                "acted_at": result.acted_at.isoformat() if result.acted_at else None,
                "note": result.note
            }
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.post("/{item_id}/read", response_model=dict)
async def mark_read(
    item_id: UUID = Path(...),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Mark inbox item as read."""
    async with db_session() as session:
        try:
            service = InboxService(session)
            result = await service.mark_read(item_id, user_id)
            return {
                "status": "item_marked_read",
                "receipt_state": result.receipt_state
            }
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )