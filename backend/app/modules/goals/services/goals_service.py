from typing import Optional, List, Tuple, Dict, Any
from uuid import UUID
from datetime import datetime

from sqlalchemy import select, func, delete, insert
from sqlalchemy.orm import Session

from app.core.db.base import BaseModel
from app.modules.goals.db.Models import Goals, Tasks, Tags, GoalTags
from app.modules.goals.ports import (
    GoalCreate, GoalUpdate, GoalProgressUpdate, GoalFilter,
    TaskCreate, TaskUpdate, TaskFilter, TagCreate, TagUpdate,
    GoalDashboardData
)
from app.core.errors import APIError, NotFoundError, PrivacyHiddenError


class GoalsService:
    """Service layer for Goals module operations."""
    
    def __init__(self, session: Session):
        self.session = session
    
    # --- Goal CRUD ---
    
    async def create_goal(
        self, title: str, description: Optional[str],
        owner_id: UUID, privacy_level: str
    ) -> Goals:
        """Create a new goal."""
        # Validate privacy level
        valid_levels = {"fully_private", "team_only", "selected", "fully_transparent"}
        if privacy_level not in valid_levels:
            raise APIError(
                error_code="INVALID_PRIVACY_LEVEL",
                message=f"سطح حریم خصوصی نامعتبر است. مقادیر مجاز: {valid_levels}"
            )
        
        goal = Goals(
            title=title,
            description=description,
            owner_id=owner_id,
            privacy_level=privacy_level,
            progress_pct=0,
            status="active",
        )
        
        self.session.add(goal)
        await self.session.flush()  # Get ID without committing
        return goal
    
    async def list_goals(
        self, privacy: Optional[str], status: Optional[str],
        owner_id: Optional[UUID], tag: Optional[str],
        page: int, page_size: int,
        viewer_id: UUID
    ) -> Tuple[List[dict], int]:
        """List goals with filtering and privacy applied."""
        
        # Base query
        query = select(Goals)
        
        # Apply filters
        if privacy:
            query = query.where(Goals.privacy_level == privacy)
        if status:
            query = query.where(Goals.status == status)
        if owner_id:
            query = query.where(Goals.owner_id == str(owner_id))
        
        # Count total before privacy filtering
        count_query = select(func.count()).select_from(Goals)
        if privacy:
            count_query = count_query.where(Goals.privacy_level == privacy)
        if status:
            count_query = count_query.where(Goals.status == status)
        if owner_id:
            count_query = count_query.where(Goals.owner_id == str(owner_id))
        
        total = (await self.session.execute(count_query)).scalar()
        
        # Apply pagination
        query = query.offset((page - 1) * page_size).limit(page_size)
        results = (await self.session.execute(query)).scalars().all()
        
        # Apply privacy to each goal
        goals_data = []
        for goal in results:
            decision = goal.get_privacy_decision(
                owner_id=goal.owner_id,
                viewer_id=viewer_id
            )
            
            if decision["level"] == "hidden":
                # Don't include hidden goals in list, or include with redaction
                continue  # or include with redaction
            
            goals_data.append({
                "id": str(goal.id),
                "title": goal.title,
                "description": goal.description,
                "progress_pct": goal.progress_pct,
                "status": goal.status,
                "privacy_level": goal.privacy_level,
                "privacy_applied": decision["level"] != "full",
                "redaction": decision["redaction"]
            })
        
        return goals_data, total
    
    async def get_goal_with_privacy(
        self, goal_id: UUID, viewer_id: UUID
    ) -> Optional[dict]:
        """Get goal with privacy decision applied."""
        result = await self.session.execute(
            select(Goals).where(Goals.id == str(goal_id))
        )
        goal = result.scalar_one_or_none()
        
        if not goal:
            return None
        
        # Check if user has permission to view
        # RBAC check would go here
        
        # Get privacy decision
        decision = goal.get_privacy_decision(
            owner_id=goal.owner_id,
            viewer_id=viewer_id
        )
        
        if decision["level"] == "hidden":
            raise PrivacyHiddenError()
        
        # Build dashboard data
        tasks_result = await self.session.execute(
            select(Tasks).where(Tasks.goal_id == str(goal_id))
        )
        tasks = tasks_result.scalars().all()
        
        tasks_data = []
        for task in tasks:
            task_decision = task.get_privacy_decision(
                goal_privacy=goal.privacy_level,
                viewer_id=viewer_id
            )
            
            if task_decision["level"] == "hidden":
                tasks_data.append({
                    "id": str(task.id),
                    "title": "—",  # Hidden
                    "status": task.status,
                    "progress_pct": task.progress_pct,
                    "privacy_applied": True
                })
            else:
                tasks_data.append({
                    "id": str(task.id),
                    "title": task.title,
                    "status": task.status,
                    "progress_pct": task.progress_pct,
                    "privacy_applied": False
                })
        
        # Get owner info (simplified)
        owner_decision = goal.get_privacy_decision(
            owner_id=goal.owner_id,
            viewer_id=viewer_id
        )
        
        return {
            "goal": {
                "id": str(goal.id),
                "title": goal.title,
                "description": goal.description,
                "progress_pct": goal.progress_pct,
                "status": goal.status,
                "privacy_level": goal.privacy_level,
            },
            "owner": {
                "id": str(goal.owner_id),
                "display_name": "owner",  # Would fetch user details
                "privacy_level": goal.privacy_level,
            },
            "tasks": tasks_data,
            "privacy_applied": decision["level"] != "full",
            "redaction": decision["redaction"]
        }
    
    async def update_goal(
        self, goal_id: UUID, request: GoalUpdate, user_id: UUID
    ) -> Goals:
        """Update a goal."""
        result = await self.session.execute(
            select(Goals).where(Goals.id == str(goal_id))
        )
        goal = result.scalar_one_or_none()
        
        if not goal:
            raise NotFoundError("goal")
        
        # Check ownership/permissions
        if goal.owner_id != user_id:
            raise APIError(
                error_code="PERMISSION_DENIED",
                message="شما اجازه ویرایش این هدف را ندارید.",
                status_code=403
            )
        
        # Update fields
        if request.title is not None:
            goal.title = request.title
        if request.description is not None:
            goal.description = request.description
        if request.privacy_level is not None:
            goal.privacy_level = request.privacy_level
        if request.status is not None:
            goal.status = request.status
        if request.start_date is not None:
            goal.start_date = request.start_date
        if request.end_date is not None:  # Note: should be due_date
            goal.due_date = request.due_date
        
        goal.update_timestamp()
        await self.session.flush()
        return goal
    
    # --- Task CRUD ---
    
    async def create_task(
        self, goal_id: UUID, request: TaskCreate, user_id: UUID
    ) -> Tasks:
        """Create a new task under a goal."""
        # Verify goal exists and user has permission
        result = await self.session.execute(
            select(Goals).where(Goals.id == str(goal_id))
        )
        goal = result.scalar_one_or_none()
        
        if not goal:
            raise APIError(
                error_code="GOAL_NOT_FOUND",
                message="اهداف یافت نشد.",
                status_code=404
            )
        
        # Check permission (simplified - owner can always create)
        if goal.owner_id != user_id:
            raise APIError(
                error_code="PERMISSION_DENIED",
                message="شما اجازه ساخت تسک این هدف را ندارید.",
                status_code=403
            )
        
        task = Tasks(
            goal_id=goal_id,
            title=request.title,
            description=request.description,
            owner_id=user_id,
            assignee_id=request.assignee_id,
            privacy_level=goal.privacy_level,
            status="pending",
            priority=request.priority or "normal",
        )
        
        self.session.add(task)
        await self.session.flush()
        return task
    
    async def list_tasks(
        self, goal_id: UUID, status: Optional[str],
        assignee_id: Optional[UUID],
        viewer_id: UUID
    ) -> Tuple[List[dict], int]:
        """List tasks for a goal with privacy."""
        query = select(Tasks).where(Tasks.goal_id == str(goal_id))
        
        if status:
            query = query.where(Tasks.status == status)
        
        results = (await self.session.execute(query)).scalars().all()
        
        tasks_data = []
        for task in results:
            decision = task.get_privacy_decision(
                goal_privacy=goal.privacy_level,
                viewer_id=viewer_id
            )
            
            if decision["level"] == "hidden":
                tasks_data.append({
                    "id": str(task.id),
                    "title": "—",
                    "status": task.status,
                    "progress_pct": task.progress_pct,
                    "privacy_applied": True
                })
            else:
                tasks_data.append({
                    "id": str(task.id),
                    "title": task.title,
                    "status": task.status,
                    "progress_pct": task.progress_pct,
                    "privacy_applied": False
                })
        
        return tasks_data, len(tasks_data)
    
    # --- Tag Operations ---
    
    async def add_tag(self, goal_id: UUID, tag_name: str, user_id: UUID) -> dict:
        """Add a tag to a goal."""
        # Verify goal exists and user is owner
        result = await self.session.execute(
            select(Goals).where(Goals.id == str(goal_id))
        )
        goal = result.scalar_one_or_none()
        
        if not goal:
            raise APIError(
                error_code="GOAL_NOT_FOUND",
                message="اهداف یافت نشد.",
                status_code=404
            )
        
        if goal.owner_id != user_id:
            raise APIError(
                error_code="PERMISSION_DENIED",
                message="شما اجازه افزودن تگ این هدف را ندارید.",
                status_code=403
            )
        
        # Check if tag exists, create if not
        tag_result = await self.session.execute(
            select(Tags).where(Tags.name == tag_name)
        )
        tag = tag_result.scalar_one_or_none()
        
        if not tag:
            tag = Tags(name=tag_name)
            self.session.add(tag)
            await self.session.flush()
        
        # Check if already associated
        junction_result = await self.session.execute(
            select(GoalTags).where(
                (GoalTags.goal_id == str(goal_id)) & 
                (GoalTags.tag_id == str(tag.id))
            )
        )
        existing = junction_result.scalar_one_or_none()
        
        if existing:
            return {"status": "already_exists", "tag_name": tag_name}
        
        # Create junction
        junction = GoalTags(goal_id=str(goal_id), tag_id=str(tag.id))
        self.session.add(junction)
        await self.session.flush()
        
        return {"status": "added", "tag_name": tag_name}