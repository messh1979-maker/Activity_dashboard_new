from typing import Optional, List, Tuple, Dict, Any
from uuid import UUID
from datetime import datetime

from sqlalchemy import select, func, delete, insert
from sqlalchemy.orm import Session

from app.core.errors import APIError, NotFoundError
from app.modules.sharing.ports import (
    ShareCreate, ShareUpdate, ShareResponse, ACLOptions,
    PermissionCheck, ShareExport
)
from app.modules.sharing.db.Models import Shares, ACLView


class SharingService:
    """Service layer for Sharing module operations."""
    
    def __init__(self, session: Session):
        self.session = session
    
    # --- Share Operations ---
    
    async def create_share(
        self, entity_type: str, entity_id: UUID,
        recipient_id: UUID, permission_level: str,
        allow_comment: bool, granted_by: UUID
    ) -> ShareResponse:
        """Create a new share."""
        # Validate permission level
        valid_levels = {"read", "write", "manage"}
        if permission_level not in valid_levels:
            raise APIError(
                error_code="INVALID_PERMISSION_LEVEL",
                message="سطح دسترسی نامعتبر.",
                status_code=400
            )
        
        # Generate share code
        share_code = uuid.uuid4().hex[:16].upper()
        
        # Check if entity exists (simplified - would check entity_type)
        # In real implementation, check based on entity_type
        
        # Check if recipient exists
        result = await self.session.execute(
            select(Shares).where(Shares.recipient_id == str(recipient_id))
        )
        # Simplified - would check user exists
        
        # Create share
        share = Shares(
            share_code=share_code,
            entity_type=entity_type,
            entity_id=str(entity_id),
            recipient_id=str(recipient_id),
            granted_by=str(granted_by),
            permission_level=permission_level,
            allow_comment=allow_comment,
        )
        
        self.session.add(share)
        await self.session.flush()
        
        return ShareResponse(
            id=share.id,
            share_code=share.share_code,
            entity_type=entity_type,
            entity_id=entity_id,
            recipient_id=recipient_id,
            permission_level=permission_level,
            granted_at=share.granted_at,
            allow_comment=share.allow_comment,
            recipient={"id": str(recipient_id)}  # Limited info
        )
    
    async def get_entity_shares(
        self, entity_type: str, entity_id: UUID,
        viewer_id: UUID
    ) -> List[dict]:
        """Get all shares for an entity."""
        query = select(Shares).where(
            (Shares.entity_type == entity_type) &
            (Shares.entity_id == str(entity_id))
        )
        results = (await self.session.execute(query)).scalars().all()
        
        shares = []
        for share in results:
            shares.append({
                "id": str(share.id),
                "share_code": share.share_code,
                "entity_type": entity_type,
                "entity_id": entity_id,
                "recipient_id": share.recipient_id,
                "permission_level": share.permission_level,
                "granted_at": share.granted_at.isoformat() if share.granted_at else None,
                "allow_comment": share.allow_comment,
            })
        
        return shares
    
    # --- Permission Check ---
    
    async def check_permission(
        self, entity_type: str, entity_id: UUID,
        user_id: UUID, required_level: str,
        viewer_id: UUID
    ) -> PermissionCheck:
        """Check if a user has required permission on an entity."""
        # Validate permission level
        valid_levels = {"read", "write", "manage"}
        if required_level not in valid_levels:
            raise APIError(
                error_code="INVALID_PERMISSION_LEVEL",
                message="سطح دسترسی_required_level نامعتبر.",
                status_code=400
            )
        
        # Check direct share
        result = await self.session.execute(
            select(Shares).where(
                (Shares.entity_type == entity_type) &
                (Shares.entity_id == str(entity_id)) &
                (Shares.recipient_id == str(user_id)) &
                (Shares.permission_level == required_level) &
                (Shares.expires_at.is_(None) | (Shares.expires_at > func.now()))
            )
        )
        direct_share = result.scalar_one_or_none()
        
        # Check if user is owner (simplified)
        is_owner = True  # Would check entity ownership
        
        # Determine permission level and source
        if is_owner:
            return PermissionCheck(
                user_id=user_id,
                has_permission=True,
                permission_level=required_level,
                source="direct"
            )
        
        if direct_share:
            return PermissionCheck(
                user_id=user_id,
                has_permission=True,
                permission_level=direct_share.permission_level,
                source="direct"
            )
        
        # Check inherited permissions (from groups)
        # Would query group memberships
        
        return PermissionCheck(
            user_id=user_id,
            has_permission=False,
            permission_level=required_level,
            source="denied"
        )
    
    # --- Revoke Share ---
    
    async def revoke_share(self, share_code: str, revoked_by: UUID) -> dict:
        """Revoke a share by code."""
        result = await self.session.execute(
            select(Shares).where(Shares.share_code == share_code)
        )
        share = result.scalar_one_or_none()
        
        if not share:
            raise APIError(
                error_code="SHARE_NOT_FOUND",
                message="share_code یافت نشد.",
                status_code=404
            )
        
        # Check permission to revoke (simplified - owner can revoke)
        can_revoke = True  # Would check permissions
        
        if not can_revoke:
            raise APIError(
                error_code="PERMISSION_DENIED",
                message="شما اجازه لغو این share را ندارید.",
                status_code=403
            )
        
        await self.session.execute(
            delete(Shares).where(Shares.share_code == share_code)
        )
        await self.session.flush()
        
        return {"status": "revoked", "share_code": share_code}