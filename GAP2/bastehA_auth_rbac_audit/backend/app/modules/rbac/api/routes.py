"""
RBAC Module API Routes
Architecture Reference: Sections 7.1, 7.3, 7.4, 11.1
Endpoints: /api/v1/rbac
"""

from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Body, Path
from fastapi.responses import JSONResponse

from app.core.dependencies import (
    get_db_session, get_current_user, get_rbac_service
)
from app.core.errors import APIError, NotFoundError
from app.core.database import async_session_context
from app.modules.rbac.ports import (
    PermissionCreate, PermissionUpdate, RoleCreate, RoleUpdate,
    UserRoleAssignment, AssignRoleRequest, RevokeRoleRequest,
    RBACDecision
)
from app.modules.rbac.services.rbac_service import RBACService
from app.modules.rbac.db.Models import Permissions, Roles, RolePermissions, UserRoles


router = APIRouter(prefix="/rbac", tags=["RBAC"])


@router.post("/permissions", response_model=dict)
async def create_permission(
    request: PermissionCreate,
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Create a new permission."""
    async with db_session() as session:
        try:
            service = RBACService(session)
            permission = await service.create_permission(request)
            return {"status": "permission_created", "permission_code": permission.code}
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.get("/permissions", response_model=dict)
async def list_permissions(
    module: Optional[str] = Query(None),
    action: Optional[str] = Query(None),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """List permissions, optionally filtered."""
    async with db_session() as session:
        try:
            service = RBACService(session)
            permissions = await service.list_permissions(
                module=module, action=action, viewer_id=user_id
            )
            return {
                "status": "success",
                "data": {"permissions": permissions}
            }
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.post("/roles", response_model=dict)
async def create_role(
    request: RoleCreate,
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Create a new role."""
    async with db_session() as session:
        try:
            service = RBACService(session)
            role = await service.create_role(request)
            return {"status": "role_created", "role_code": role.code}
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.get("/roles", response_model=dict)
async def list_roles(
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """List all roles."""
    async with db_session() as session:
        try:
            service = RBACService(session)
            roles = await service.list_roles(viewer_id=user_id)
            return {
                "status": "success",
                "data": {"roles": roles}
            }
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.post("/assign", response_model=dict)
async def assign_role(
    request: AssignRoleRequest,
    user_id: UUID = Depends(get_current_user),
    actor_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Assign a role to a user."""
    async with db_session() as session:
        try:
            service = RBACService(session)
            target = request.target_user_id or user_id
            payload = request.model_dump(exclude={"target_user_id"})
            result = await service.assign_role(
                actor_id=actor_id, target_user_id=target, **payload
            )
            return {"status": "role_assigned", "result": result}
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.post("/revoke", response_model=dict)
async def revoke_role(
    request: RevokeRoleRequest,
    user_id: UUID = Depends(get_current_user),
    actor_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Revoke a role from a user."""
    async with db_session() as session:
        try:
            service = RBACService(session)
            target = request.target_user_id or user_id
            payload = request.model_dump(exclude={"target_user_id"})
            result = await service.revoke_role(
                actor_id=actor_id, target_user_id=target, **payload
            )
            return {"status": "role_revoked", "result": result}
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.get("/user/{user_id}/roles", response_model=dict)
async def get_user_roles(
    user_id: UUID = Path(...),
    viewer_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Get roles for a specific user."""
    async with db_session() as session:
        try:
            service = RBACService(session)
            roles = await service.get_user_roles(user_id, viewer_id)
            return {
                "status": "success",
                "data": {"roles": roles}
            }
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )