"""
Inbox State Machine Implementation
Architecture Reference: Sections 9.1, 9.2
State Machine: pending -> accepted/rejected/deferred/expired
Read Receipt: sent -> seen -> acted
"""

from uuid import UUID
from datetime import datetime, timedelta
from typing import Dict, Optional, Literal
from sqlalchemy import select, func, update, delete
from sqlalchemy.orm import Session

from app.core.errors import APIError, NotFoundError
from app.modules.inbox.ports import (
    InboxItemCreate, InboxItemUpdate, InboxItemResponse,
    OutboxItemCreate, ReceiptState, INBOX_ITEM_TYPES
)
from app.modules.inbox.db.Models import InboxItems, Receipts, OutboxItems


class InboxStateMachine:
    """Manages inbox item state transitions and read receipts."""
    
    def __init__(self, session: Session):
        self.session = session
    
    # --- Item Creation ---
    
    async def create_item(self, sender_id: UUID, recipient_id: UUID,
                         item_type: str, entity_type: Optional[str],
                         entity_id: Optional[UUID], title: str,
                         message: Optional[str], priority: str,
                         due_at: Optional[datetime], expires_at: Optional[datetime]
                         ) -> InboxItems:
        """Create a new inbox item with initial state."""
        # Validate item type
        valid_types = [t.value for t in INBOX_ITEM_TYPES]
        if item_type not in valid_types:
            raise APIError(
                error_code="INVALID_ITEM_TYPE",
                message="نوع آیتم نامعتبر.",
                status_code=400
            )
        
        # Create inbox item
        item = InboxItems(
            sender_id=str(sender_id),
            recipient_id=str(recipient_id),
            item_type=item_type,
            entity_type=entity_type,
            entity_id=str(entity_id) if entity_id else None,
            title=title,
            message=message,
            priority=priority,
            action_state="pending",
            receipt_state="sent",
            due_at=due_at,
            expires_at=expires_at,
        )
        
        self.session.add(item)
        await self.session.flush()
        
        # Create read receipt
        receipt = Receipts(
            item_id=str(item.id),
            user_id=str(recipient_id),
            state="sent",
        )
        
        self.session.add(receipt)
        await self.session.flush()
        
        return item
    
    # --- Listing ---

    async def list_items(self, user_id: UUID, state: Optional[str] = None) -> list:
        """List inbox items for a recipient, optionally filtered by action state."""
        query = select(InboxItems).where(InboxItems.recipient_id == str(user_id))
        if state:
            query = query.where(InboxItems.action_state == state)
        result = await self.session.execute(query)
        return result.scalars().all()

    async def list_outbox(self, user_id: UUID) -> list:
        """List outbox items sent by a user."""
        result = await self.session.execute(
            select(OutboxItems).where(OutboxItems.sender_id == str(user_id))
        )
        return result.scalars().all()

    # --- Item Acting ---
    
    async def act_on_item(self, item_id: UUID, action: Literal["accepted", "rejected", "deferred"],
                         actor_id: UUID, note: Optional[str] = None) -> dict:
        """Handle item action (accept, reject, defer)."""
        # Verify item exists and user is recipient
        result = await self.session.execute(
            select(InboxItems).where(InboxItems.id == str(item_id))
        )
        item = result.scalar_one_or_none()
        
        if not item:
            raise APIError(
                error_code="ITEM_NOT_FOUND",
                message="آیتم یافت نشد.",
                status_code=404
            )
        
        if item.recipient_id != str(actor_id):
            raise APIError(
                error_code="PERMISSION_DENIED",
                message="شما اجازه عملکرد بر این آیتم را ندارید.",
                status_code=403
            )
        
        # Handle action
        now = datetime.utcnow()
        
        if action == "accepted":
            item.action_state = "accepted"
            item.receipt_state = "acted"
            item.acted_at = now
        elif action == "rejected":
            item.action_state = "rejected"
            item.receipt_state = "acted"
            item.acted_at = now
        elif action == "deferred":
            # Set defer_until to 48 hours from now or specified time
            item.action_state = "deferred"
            item.defer_until = now + timedelta(hours=48)  # Could be configurable
            item.receipt_state = "acted"
            item.acted_at = now
        else:
            raise APIError(
                error_code="INVALID_ACTION",
                message="عملیات نامعتبر.",
                status_code=400
            )
        
        # Add note if provided
        if note:
            item.response_note = note
        
        await self.session.flush()
        
        # Update receipt
        receipt_result = await self.session.execute(
            select(Receipts).where(Receipts.item_id == str(item_id))
        )
        receipt = receipt_result.scalar_one_or_none()
        
        if not receipt:
            receipt = Receipts(
                item_id=str(item.id),
                user_id=str(actor_id),
                state="acted",
                acted_at=now,
            )
            self.session.add(receipt)
        else:
            receipt.state = "acted"
            receipt.acted_at = now
            if note:
                receipt.note = note
        
        await self.session.flush()
        
        return {
            "action_state": item.action_state,
            "receipt_state": receipt.state,
            "acted_at": item.acted_at.isoformat() if item.acted_at else None,
            "note": item.response_note
        }
    
    # --- Read Receipt ---
    
    async def mark_read(self, item_id: UUID, reader_id: UUID) -> dict:
        """Mark inbox item as read."""
        # Verify item exists and user is recipient
        result = await self.session.execute(
            select(InboxItems).where(InboxItems.id == str(item_id))
        )
        item = result.scalar_one_or_none()
        
        if not item:
            raise APIError(
                error_code="ITEM_NOT_FOUND",
                message="آیتم یافت نشد.",
                status_code=404
            )
        
        if item.recipient_id != str(reader_id):
            raise APIError(
                error_code="PERMISSION_DENIED",
                message="شما اجازه خواندن این آیتم را ندارید.",
                status_code=403
            )
        
        # Update receipt
        receipt_result = await self.session.execute(
            select(Receipts).where(Receipts.item_id == str(item_id))
        )
        receipt = receipt_result.scalar_one_or_none()
        
        if not receipt:
            receipt = Receipts(
                item_id=str(item.id),
                user_id=str(reader_id),
                state="seen",
            )
            self.session.add(receipt)
        else:
            receipt.state = "seen"
        
        await self.session.flush()
        
        return {"receipt_state": receipt.state}
    
    # --- Outbox ---
    
    async def create_outbox(self, sender_id: UUID, recipient_id: UUID,
                           item_type: str, entity_type: Optional[str],
                           entity_id: Optional[UUID], title: str,
                           message: Optional[str]) -> OutboxItems:
        """Create outbox item (sent item)."""
        item = OutboxItems(
            sender_id=str(sender_id),
            recipient_id=str(recipient_id),
            item_type=item_type,
            entity_type=entity_type,
            entity_id=str(entity_id) if entity_id else None,
            title=title,
            message=message,
            read_receipt=False,
        )
        
        self.session.add(item)
        await self.session.flush()
        
        return item
    
    # --- Expiry Handling ---
    
    async def check_expiries(self) -> dict:
        """Check and process expired items."""
        now = datetime.utcnow()
        
        # Find expired pending items
        expired_items = await self.session.execute(
            select(InboxItems).where(
                InboxItems.action_state == "pending",
                InboxItems.expires_at < now
            )
        )
        
        expired_list = expired_items.scalars().all()
        
        for item in expired_list:
            item.action_state = "expired"
            item.receipt_state = "acted"
            item.acted_at = now
        
        await self.session.flush()
        
        return {
            "expired_count": len(expired_list),
            "processed": True
        }


# Name used by the API layer (routes import ``InboxService``).
InboxService = InboxStateMachine