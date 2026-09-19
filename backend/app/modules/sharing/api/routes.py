"""
Sharing Module API Routes
Architecture Reference: Sections 4.6, 8.2, 11.1
Endpoints: /api/v1/sharing
"""

from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, Body, Path
from fastapi.responses import JSONResponse

from app.core.dependencies import (
    get_db_session, get_current_user, get_sharing_service
)
from app.core.errors import APIError, NotFoundError
from app.core.database import async_session_context
from app.modules.sharing.ports import (
    ShareCreate, ShareUpdate, ShareResponse, ACLOptions,
    PermissionCheck, ShareExport
)
from app.modules.sharing.services.sharing_service import SharingService


router = APIRouter(prefix="/sharing", tags=["Sharing"])


@router.post("/", response_model=dict)
async def create_share(
    request: ShareCreate,
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Create a share/permission for an entity."""
    async with db_session() as session:
        try:
            service = SharingService(session)
            result = await service.create_share(
                entity_type=request.entity_type,
                entity_id=request.entity_id,
                recipient_id=request.recipient_id,
                permission_level=request.permission_level,
                allow_comment=request.allow_comment,
                granted_by=user_id
            )
            return {"status": "share_created", "share_code": result.share_code}
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.get("/entity/{entity_type}/{entity_id}", response_model=dict)
async def get_entity_shares(
    entity_type: str = Path(...),
    entity_id: UUID = Path(...),
    viewer_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Get all shares for an entity."""
    async with db_session() as session:
        try:
            service = SharingService(session)
            shares = await service.get_entity_shares(entity_type, entity_id, viewer_id)
            return {
                "status": "success",
                "data": {"shares": shares}
            }
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.post("/check", response_model=dict)
async def check_permission(
    entity_type: str = Body(...),
    entity_id: UUID = Body(...),
    user_id: UUID = Body(...),
    required_level: str = Body(...),
    viewer_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Check if a user has required permission on an entity."""
    async with db_session() as session:
        try:
            service = SharingService(session)
            result = await service.check_permission(
                entity_type, entity_id, user_id, required_level, viewer_id
            )
            return {
                "status": "success",
                "data": {
                    "has_permission": result.has_permission,
                    "permission_level": result.permission_level,
                    "source": result.source
                }
            }
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.post("/revoke", response_model=dict)
async def revoke_share(
    share_code: str = Body(...),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Revoke a share."""
    async with db_session() as session:
        try:
            service = SharingService(session)
            result = await service.revoke_share(share_code, user_id)
            return {"status": "share_revoked", "result": result}
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )