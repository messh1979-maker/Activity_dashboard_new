from typing import Optional, List, Tuple, Dict, Any
from uuid import UUID
from datetime import datetime

from sqlalchemy import select, func, delete, insert, update
from sqlalchemy.orm import Session

from app.core.errors import APIError, NotFoundError, PrivacyHiddenError
from app.modules.groups.ports import (
    GroupCreate, GroupUpdate, GroupMember, GroupPrivacySettings,
    PrivacyLevel, GroupFilter, GroupExport
)
from app.modules.groups.db.Models import Groups, GroupMembers, PrivacyExceptions


class GroupsService:
    """Service layer for Groups module operations."""
    
    def __init__(self, session: Session):
        self.session = session
    
    # --- Group CRUD ---
    
    async def create_group(
        self, name: str, description: Optional[str],
        owner_id: UUID, privacy_level: str,
        parent_id: Optional[UUID] = None
    ) -> Groups:
        """Create a new group."""
        # Validate privacy level
        valid_levels = {"fully_private", "team_only", "selected", "fully_transparent"}
        if privacy_level not in valid_levels:
            raise APIError(
                error_code="INVALID_PRIVACY_LEVEL",
                message=f"سطح حریم خصوصی نامعتبر است.",
                status_code=400
            )
        
        # Validate parent if provided
        if parent_id:
            result = await self.session.execute(
                select(Groups).where(Groups.id == str(parent_id))
            )
            parent = result.scalar_one_or_none()
            if not parent:
                raise APIError(
                    error_code="GROUP_NOT_FOUND",
                    message=" گروه والد یافت نشد.",
                    status_code=404
                )
            if not parent.is_active:
                raise APIError(
                    error_code="GROUP_INACTIVE",
                   message=" گروه غیرفعال است.",
                    status_code=400
                )
        
        # Check ownership permission
        result = await self.session.execute(
            select(Groups).where(Groups.owner_id == str(owner_id))
        )
        # Simplified - owner can always create
        
        group = Groups(
            title=name,
            description=description,
            owner_id=owner_id,
            privacy_level=privacy_level,
            is_active=True,
        )
        
        # Set path for hierarchical structure
        if parent_id:
            parent_result = await self.session.execute(
                select(Groups).where(Groups.id == str(parent_id))
            )
            parent = parent_result.scalar_one_or_none()
            if parent and parent.path:
                # LTREE path: parent.path + '.' + new id segment
                group.path = f"{parent.path}.{uuid.uuid4()}"
            else:
                group.path = str(uuid.uuid4())
        else:
            group.path = str(uuid.uuid4())
        
        self.session.add(group)
        await self.session.flush()
        return group
    
    async def list_groups(
        self, privacy: Optional[str], is_active: bool,
        viewer_id: UUID
    ) -> Tuple[List[dict], int]:
        """List groups with filtering and privacy applied."""
        
        # Base query
        query = select(Groups)
        count_query = select(func.count()).select_from(Groups)
        
        # Apply filters
        if privacy:
            query = query.where(Groups.privacy_level == privacy)
            count_query = count_query.where(Groups.privacy_level == privacy)
        if is_active is not None:
            query = query.where(Groups.is_active == is_active)
            count_query = count_query.where(Groups.is_active == is_active)
        
        # Count total
        total = (await self.session.execute(count_query)).scalar()
        
        # Execute query
        results = (await self.session.execute(query)).scalars().all()
        
        # Apply privacy to each group
        groups_data = []
        for group in results:
            # Check if viewer can see this group
            # Simplified: all active groups visible to authenticated users
            # Real implementation would check privacy levels
            
            groups_data.append({
                "id": str(group.id),
                "name": group.title,
                "description": group.description,
                "privacy_level": group.privacy_level,
                "is_active": group.is_active,
                "member_count": 0,  # Would query members
                "owner_id": str(group.owner_id),
            })
        
        return groups_data, total
    
    async def get_group_with_privacy(
        self, group_id: UUID, viewer_id: UUID
    ) -> Optional[dict]:
        """Get group with privacy decision."""
        result = await self.session.execute(
            select(Groups).where(Groups.id == str(group_id))
        )
        group = result.scalar_one_or_none()
        
        if not group:
            return None
        
        # Privacy decision logic
        is_owner = group.owner_id == viewer_id
        
        if is_owner:
            level = "full"
            redaction = None
        elif group.privacy_level == "fully_private":
            level = "hidden"
            redaction = "full_content"
        elif group.privacy_level == "team_only":
            # Would check if viewer is team member
            level = "aggregate_only"
            redaction = "status_only"
        elif group.privacy_level == "selected":
            # Would check privacy exceptions
            level = "hidden"
            redaction = "full_content"
        elif group.privacy_level == "fully_transparent":
            level = "full"
            redaction = None
        else:
            level = "hidden"
            redaction = "full_content"
        
        if level == "hidden":
            raise PrivacyHiddenError()
        
        # Get member count
        member_result = await self.session.execute(
            select(func.count()).select_from(GroupMembers).where(
                GroupMembers.group_id == str(group.id),
                GroupMembers.is_active == True
            )
        )
        member_count = member_result.scalar() or 0
        
        return {
            "group": {
                "id": str(group.id),
                "name": group.title,
                "description": group.description,
                "privacy_level": group.privacy_level,
                "is_active": group.is_active,
                "path": group.path or "",
            },
            "owner": {
                "id": str(group.owner_id),
                "display_name": "owner",  # Would fetch user details
            },
            "member_count": member_count,
            "privacy_applied": level != "full",
            "redaction": redaction
        }
    
    async def update_group(
        self, group_id: UUID, request: GroupUpdate, user_id: UUID
    ) -> Groups:
        """Update a group."""
        result = await self.session.execute(
            select(Groups).where(Groups.id == str(group_id))
        )
        group = result.scalar_one_or_none()
        
        if not group:
            raise NotFoundError("group")
        
        # Check ownership
        if group.owner_id != user_id:
            raise APIError(
                error_code="PERMISSION_DENIED",
                message="شما اجازه ویرایش این گروه را ندارید.",
                status_code=403
            )
        
        # Update fields
        if request.name is not None:
            group.title = request.name
        if request.description is not None:
            group.description = request.description
        if request.privacy_level is not None:
            # Validate new privacy level
            valid_levels = {"fully_private", "team_only", "selected", "fully_transparent"}
            if request.privacy_level not in valid_levels:
                raise APIError(
                    error_code="INVALID_PRIVACY_LEVEL",
                    message="سطح حریم خصوصی نامعتبر.",
                    status_code=400
                )
            group.privacy_level = request.privacy_level
        
        group.update_timestamp()
        await self.session.flush()
        return group
    
    # --- Member Management ---
    
    async def add_member(
        self, group_id: UUID, user_id: UUID, is_manager: bool,
        added_by: UUID
    ) -> dict:
        """Add a member to a group."""
        # Verify group exists and user is owner
        result = await self.session.execute(
            select(Groups).where(Groups.id == str(group_id))
        )
        group = result.scalar_one_or_none()
        
        if not group:
            raise APIError(
                error_code="GROUP_NOT_FOUND",
                message="اهداف یافت نشد.",
                status_code=404
            )
        
        if group.owner_id != added_by:
            raise APIError(
                error_code="PERMISSION_DENIED",
                message="شما اجازه افزودن.member این گروه را ندارید.",
                status_code=403
            )
        
        # Check if user already a member
        existing_result = await self.session.execute(
            select(GroupMembers).where(
                (GroupMembers.group_id == str(group_id)) &
                (GroupMembers.user_id == str(user_id))
            )
        )
        if existing_result.scalar_one_or_none():
            return {"status": "already_member", "message": "کاربر déjà عضو گروه است."}
        
        # Add member
        member = GroupMembers(
            group_id=str(group_id),
            user_id=str(user_id),
            is_manager=is_manager,
            source="manual",
        )
        
        self.session.add(member)
        await self.session.flush()
        
        return {"status": "added", "member_id": str(member.id)}
    
    async def list_members(
        self, group_id: UUID, viewer_id: UUID
    ) -> List[dict]:
        """List group members."""
        query = select(GroupMembers).where(GroupMembers.group_id == str(group_id))
        results = (await self.session.execute(query)).scalars().all()
        
        members = []
        for member in results:
            members.append({
                "user_id": str(member.user_id),
                "is_manager": member.is_manager,
                "joined_at": member.joined_at.isoformat() if member.joined_at else None,
            })
        
        return members
    
    # --- Privacy Exceptions ---
    
    async def set_privacy(
        self, group_id: UUID, privacy_level: str, user_id: UUID
    ) -> dict:
        """Set group privacy level."""
        # Verify group exists and user is owner
        result = await self.session.execute(
            select(Groups).where(Groups.id == str(group_id))
        )
        group = result.scalar_one_or_none()
        
        if not group:
            raise APIError(
                error_code="GROUP_NOT_FOUND",
                message=" گروه یافت نشد.",
                status_code=404
            )
        
        if group.owner_id != user_id:
            raise APIError(
                error_code="PERMISSION_DENIED",
                message="شما اجازه تغییر حریم خصوصی این گروه را ندارید.",
                status_code=403
            )
        
        # Validate privacy level
        valid_levels = {"fully_private", "team_only", "selected", "fully_transparent"}
        if privacy_level not in valid_levels:
            raise APIError(
                error_code="INVALID_PRIVACY_LEVEL",
                message="سطح حریم خصوصی نامعتبر.",
                status_code=400
            )
        
        group.privacy_level = privacy_level
        await self.session.flush()
        
        return {"status": "privacy_updated", "privacy_level": privacy_level}
    
    async def add_exception(
        self, group_id: UUID, viewer_id: UUID, can_comment: bool,
        set_by: UUID
    ) -> dict:
        """Add privacy exception for 'selected' level."""
        # Verify group exists and user is owner
        result = await self.session.execute(
            select(Groups).where(Groups.id == str(group_id))
        )
        group = result.scalar_one_or_none()
        
        if not group:
            raise APIError(
                error_code="GROUP_NOT_FOUND",
                message=" گروه یافت نشد.",
                status_code=404
            )
        
        if group.owner_id != set_by:
            raise APIError(
                error_code="PERMISSION_DENIED",
                message="شما اجازه افزودن exemption این گروه را ندارید.",
                status_code=403
            )
        
        # Check if exception already exists
        existing_result = await self.session.execute(
            select(PrivacyExceptions).where(
                (PrivacyExceptions.group_id == str(group_id)) &
                (PrivacyExceptions.viewer_id == str(viewer_id))
            )
        )
        if existing_result.scalar_one_or_none():
            return {"status": "already_exists", "message": " exemption déjà وجود دارد."}
        
        # Create exception
        exception = PrivacyExceptions(
            group_id=str(group_id),
            owner_id=str(set_by),
            viewer_id=str(viewer_id),
            can_comment=can_comment,
        )
        
        self.session.add(exception)
        await self.session.flush()
        
        return {"status": "added", "exception_id": str(exception.id)}