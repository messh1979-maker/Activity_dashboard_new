"""
Groups Module API Routes
Architecture Reference: Sections 4.4, 7.2, 7.3, 11.2
Endpoints: /api/v1/groups
"""

from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Body, Path
from fastapi.responses import JSONResponse

from app.core.dependencies import (
    get_db_session, get_current_user, get_groups_service
)
from app.core.errors import APIError, NotFoundError, PrivacyHiddenError
from app.core.database import async_session_context
from app.modules.groups.ports import (
    GroupCreate, GroupUpdate, GroupMember, GroupPrivacySettings,
    PrivacyLevel, GroupFilter
)
from app.modules.groups.services.groups_service import GroupsService


router = APIRouter(prefix="/groups", tags=["Groups"])


@router.post("/", response_model=dict)
async def create_group(
    request: GroupCreate,
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Create a new group."""
    async with db_session() as session:
        try:
            service = GroupsService(session)
            group = await service.create_group(
                title=request.name,
                description=request.description,
                owner_id=user_id,
                privacy_level=request.privacy_level,
                parent_id=request.parent_id
            )
            return {"status": "group_created", "group_id": str(group.id)}
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.get("/", response_model=dict)
async def list_groups(
    privacy: Optional[str] = Query(None),
    is_active: Optional[bool] = Query(True),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """List groups with filtering."""
    async with db_session() as session:
        try:
            service = GroupsService(session)
            groups, total = await service.list_groups(
                privacy=privacy,
                is_active=is_active,
                viewer_id=user_id
            )
            return {
                "status": "success",
                "data": {
                    "groups": groups,
                    "total": total
                }
            }
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.get("/{group_id}", response_model=dict)
async def get_group(
    group_id: UUID = Path(...),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Get a single group with privacy applied."""
    async with db_session() as session:
        try:
            service = GroupsService(session)
            group_data = await service.get_group_with_privacy(group_id, user_id)
            
            if not group_data:
                return JSONResponse(
                    status_code=404,
                    content={"error": "GROUP_NOT_FOUND", "message": " گروه یافت نشد.", "success": False}
                )
            
            return {
                "status": "success",
                "data": group_data
            }
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.patch("/{group_id}", response_model=dict)
async def update_group(
    group_id: UUID = Path(...),
    request: GroupUpdate = Body(...),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Update a group."""
    async with db_session() as session:
        try:
            service = GroupsService(session)
            group = await service.update_group(group_id, request, user_id)
            return {"status": "group_updated", "group_id": str(group.id)}
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.post("/{group_id}/members", response_model=dict)
async def add_group_member(
    group_id: UUID = Path(...),
    user_id: UUID = Body(...),  # user to add
    is_manager: bool = Body(False),
    user_adding_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Add a member to a group."""
    async with db_session() as session:
        try:
            service = GroupsService(session)
            result = await service.add_member(group_id, user_id, is_manager, user_adding_id)
            return {"status": "member_added", "result": result}
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.get("/{group_id}/members", response_model=dict)
async def list_group_members(
    group_id: UUID = Path(...),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """List group members."""
    async with db_session() as session:
        try:
            service = GroupsService(session)
            members = await service.list_members(group_id, user_id)
            return {
                "status": "success",
                "data": {"members": members}
            }
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.patch("/{group_id}/members/{member_id}", response_model=dict)
async def update_member_role(
    group_id: UUID = Path(...),
    member_id: UUID = Path(...),
    is_manager: bool = Body(...),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Update member role (manager promotion/demotion)."""
    async with db_session() as session:
        try:
            service = GroupsService(session)
            result = await service.update_member_role(group_id, member_id, is_manager, user_id)
            return {"status": "member_updated", "result": result}
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.post("/{group_id}/privacy", response_model=dict)
async def set_group_privacy(
    group_id: UUID = Path(...),
    privacy_level: str = Body(...),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Set group privacy level."""
    async with db_session() as session:
        try:
            service = GroupsService(session)
            result = await service.set_privacy(group_id, privacy_level, user_id)
            return {"status": "privacy_set", "result": result}
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.post("/{group_id}/privacy/exceptions", response_model=dict)
async def add_privacy_exception(
    group_id: UUID = Path(...),
    viewer_id: UUID = Body(...),
    can_comment: bool = Body(False),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Add privacy exception for 'selected' level."""
    async with db_session() as session:
        try:
            service = GroupsService(session)
            result = await service.add_exception(group_id, viewer_id, can_comment, user_id)
            return {"status": "exception_added", "result": result}
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.get("/{group_id}/dashboard", response_model=dict)
async def group_dashboard(
    group_id: UUID = Path(...),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Get group dashboard data with privacy."""
    async with db_session() as session:
        try:
            service = GroupsService(session)
            dashboard = await service.get_dashboard(group_id, user_id)
            return {
                "status": "success",
                "data": dashboard
            }
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )