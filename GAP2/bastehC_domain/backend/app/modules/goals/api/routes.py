"""
Goals Module API Routes
Architecture Reference: Sections 4.5, 9.10, 12.12
Endpoints: /api/v1/goals
"""

from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Body, Path
from fastapi.responses import JSONResponse

from app.core.dependencies import (
    get_db_session, get_current_user, get_goals_service
)
from app.core.errors import APIError, NotFoundError, PrivacyHiddenError
from app.core.database import async_session_context
from app.modules.goals.ports import (
    GoalCreate, GoalUpdate, GoalProgressUpdate, GoalFilter,
    TaskCreate, TaskUpdate, TaskFilter, TagCreate, TagUpdate,
    GoalDashboardData
)
from app.modules.goals.services.goals_service import GoalsService


router = APIRouter(prefix="/goals", tags=["Goals"])


@router.post("/", response_model=dict)
async def create_goal(
    request: GoalCreate,
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Create a new goal."""
    async with db_session() as session:
        try:
            service = GoalsService(session)
            goal = await service.create_goal(
                title=request.title,
                description=request.description,
                owner_id=user_id,
                privacy_level=request.privacy_level
            )
            return {"status": "goal_created", "goal_id": str(goal.id)}
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.get("/", response_model=dict)
async def list_goals(
    privacy: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    owner: Optional[UUID] = Query(None),
    tag: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """List goals with filtering."""
    async with db_session() as session:
        try:
            service = GoalsService(session)
            goals, total = await service.list_goals(
                privacy=privacy,
                status=status,
                owner_id=owner,
                tag=tag,
                page=page,
                page_size=size,
                viewer_id=user_id
            )
            return {
                "status": "success",
                "data": {
                    "goals": goals,
                    "total": total,
                    "page": page,
                    "page_size": size
                }
            }
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.get("/{goal_id}", response_model=dict)
async def get_goal(
    goal_id: UUID = Path(...),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Get a single goal with privacy applied."""
    async with db_session() as session:
        try:
            service = GoalsService(session)
            goal_data = await service.get_goal_with_privacy(goal_id, user_id)
            
            if not goal_data:
                return JSONResponse(
                    status_code=404,
                    content={"error": "GOAL_NOT_FOUND", "message": "اهداف یافت نشد.", "success": False}
                )
            
            return {
                "status": "success",
                "data": goal_data
            }
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.patch("/{goal_id}", response_model=dict)
async def update_goal(
    goal_id: UUID = Path(...),
    request: GoalUpdate = Body(...),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Update a goal."""
    async with db_session() as session:
        try:
            service = GoalsService(session)
            goal = await service.update_goal(goal_id, request, user_id)
            return {"status": "goal_updated", "goal_id": str(goal.id)}
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.post("/{goal_id}/progress", response_model=dict)
async def update_progress(
    goal_id: UUID = Path(...),
    request: GoalProgressUpdate = Body(...),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Update goal progress."""
    async with db_session() as session:
        try:
            service = GoalsService(session)
            goal = await service.update_progress(goal_id, request.progress_pct, user_id)
            return {
                "status": "progress_updated",
                "goal_id": str(goal.id),
                "progress_pct": goal.progress_pct
            }
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.post("/{goal_id}/tasks", response_model=dict)
async def create_task(
    goal_id: UUID = Path(...),
    request: TaskCreate = Body(...),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Create a task under a goal."""
    async with db_session() as session:
        try:
            service = GoalsService(session)
            task = await service.create_task(goal_id, request, user_id)
            return {"status": "task_created", "task_id": str(task.id)}
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.get("/{goal_id}/tasks", response_model=dict)
async def list_tasks(
    goal_id: UUID = Path(...),
    status: Optional[str] = Query(None),
    assignee: Optional[UUID] = Query(None),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """List tasks for a goal with privacy."""
    async with db_session() as session:
        try:
            service = GoalsService(session)
            tasks, total = await service.list_tasks(
                goal_id=goal_id,
                status=status,
                assignee_id=assignee,
                viewer_id=user_id
            )
            return {
                "status": "success",
                "data": {
                    "tasks": tasks,
                    "total": total
                }
            }
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.post("/{goal_id}/tags", response_model=dict)
async def add_tag_to_goal(
    goal_id: UUID = Path(...),
    tag_name: str = Body(...),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Add a tag to a goal."""
    async with db_session() as session:
        try:
            service = GoalsService(session)
            result = await service.add_tag(goal_id, tag_name, user_id)
            return {"status": "tag_added", "tag_name": tag_name}
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.get("/{goal_id}/dashboard", response_model=dict)
async def goal_dashboard(
    goal_id: UUID = Path(...),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Get goal dashboard data with privacy applied."""
    async with db_session() as session:
        try:
            service = GoalsService(session)
            dashboard_data = await service.get_dashboard_data(goal_id, user_id)
            return {
                "status": "success",
                "data": dashboard_data
            }
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )