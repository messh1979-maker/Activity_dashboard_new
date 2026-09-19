"""
Chat Module API Routes
Architecture Reference: Sections 8.1, 8.2, 8.3
Endpoints: /api/v1/chat
"""

from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends, Query, Body, Path
from fastapi.responses import JSONResponse

from app.core.dependencies import (
    get_db_session, get_current_user, get_chat_service
)
from app.core.errors import APIError, NotFoundError, PrivacyHiddenError
from app.core.database import async_session_context
from app.modules.chat.ports import (
    RoomCreate, RoomUpdate, MessageCreate, MessageResponse,
    MemberCreate, ChatExport
)
from app.modules.chat.services.chat_service import ChatService
from app.modules.chat.db.Models import Rooms, RoomMembers, Messages


router = APIRouter(prefix="/chat", tags=["Chat"])


@router.post("/rooms", response_model=dict)
async def create_room(
    request: RoomCreate,
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Create a new chat room."""
    async with db_session() as session:
        try:
            service = ChatService(session)
            room = await service.create_room(
                title=request.title,
                linked_type=request.linked_type,
                linked_id=request.linked_id,
                owner_id=user_id
            )
            return {"status": "room_created", "room_id": str(room.id)}
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.get("/rooms", response_model=dict)
async def list_rooms(
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """List chat rooms."""
    async with db_session() as session:
        try:
            service = ChatService(session)
            rooms = await service.list_rooms(user_id)
            return {
                "status": "success",
                "data": {"rooms": rooms}
            }
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.get("/rooms/{room_id}", response_model=dict)
async def get_room(
    room_id: UUID = Path(...),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Get a single chat room."""
    async with db_session() as session:
        try:
            service = ChatService(session)
            room = await service.get_room(room_id, user_id)
            
            if not room:
                return JSONResponse(
                    status_code=404,
                    content={"error": "ROOM_NOT_FOUND", "message": "اتاق یافت نشد.", "success": False}
                )
            
            return {
                "status": "success",
                "data": room
            }
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.post("/rooms/{room_id}/members", response_model=dict)
async def add_room_member(
    room_id: UUID = Path(...),
    user_id: UUID = Body(...),
    role: str = Body("member"),
    user_adding_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Add member to chat room."""
    async with db_session() as session:
        try:
            service = ChatService(session)
            result = await service.add_member(room_id, user_id, role, user_adding_id)
            return {"status": "member_added", "result": result}
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.post("/{room_id}/messages", response_model=dict)
async def send_message(
    room_id: UUID = Path(...),
    request: MessageCreate = Body(...),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Send a chat message."""
    async with db_session() as session:
        try:
            service = ChatService(session)
            message = await service.send_message(room_id, request.body, user_id)
            return {
                "status": "message_sent",
                "message_id": str(message.id),
                "message": {
                    "id": str(message.id),
                    "room_id": str(message.room_id),
                    "sender_id": str(message.sender_id),
                    "body": message.body,
                    "created_at": message.created_at.isoformat(),
                    "message_type": message.message_type,
                }
            }
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.get("/{room_id}/messages", response_model=dict)
async def get_messages(
    room_id: UUID = Path(...),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Get chat messages."""
    async with db_session() as session:
        try:
            service = ChatService(session)
            messages = await service.get_messages(room_id, user_id)
            return {
                "status": "success",
                "data": {"messages": messages}
            }
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.post("/rooms/{room_id}/archive", response_model=dict)
async def archive_room(
    room_id: UUID = Path(...),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Archive a chat room."""
    async with db_session() as session:
        try:
            service = ChatService(session)
            result = await service.archive_room(room_id, user_id)
            return {"status": "room_archived", "result": result}
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )