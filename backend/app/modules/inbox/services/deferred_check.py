"""
Inbox Deferred State Timeout Check
Architecture Reference: Section 9.1 - State Machine
Handles transition of deferred items back to pending when defer_until <= now.
"""

import asyncio
from typing import Dict
from datetime import datetime
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.modules.inbox.db.Models import InboxItems


async def check_deferred_timeout() -> dict:
    """Check and process deferred items that should return to pending state.
    
    Architecture 9.1: deferred -> pending when defer_until <= now
    
    Returns:
        dict with processing results
    """
    from app.core.database import engine
    
    now = datetime.utcnow()
    
    async with engine.begin() as conn:
        # Find deferred items where defer_until <= now
        result = await conn.execute(
            select(InboxItems).where(
                InboxItems.action_state == "deferred",
                InboxItems.defer_until <= now
            )
        )
        
        deferred_items = result.scalars().all()
        
        processed = 0
        for item in deferred_items:
            # Transition: deferred -> pending
            item.action_state = "pending"
            # Clear defer_until since it's now active again
            item.defer_until = None
            # Reset receipt state to sent (will be updated when recipient acts)
            # Note: receipt state should remain as acted or reset based on business logic
            
            processed += 1
        
        if processed > 0:
            await conn.commit()
        
        return {
            "transitioned_count": processed,
            "from_state": "deferred",
            "to_state": "pending",
            "processed_at": now.isoformat(),
            "success": True
        }


async def check_all_expiries() -> dict:
    """Check all inbox item expiries (combined check for expires and deferred timeouts)."""
    from app.core.database import engine
    
    now = datetime.utcnow()
    results = {}
    
    async with engine.begin() as conn:
        # Check expired items
        result = await conn.execute(
            select(InboxItems).where(
                InboxItems.expires_at < now,
                InboxItems.action_state == "pending"
            )
        )
        expired = result.scalars().all()
        
        for item in expired:
            item.action_state = "expired"
        
        # Check deferred timeouts
        result = await conn.execute(
            select(InboxItems).where(
                InboxItems.action_state == "deferred",
                InboxItems.defer_until <= now
            )
        )
        deferred = result.scalars().all()
        
        for item in deferred:
            item.action_state = "pending"
            item.defer_until = None
    
    await conn.commit()
    
    return {
        "expired_count": len(expired),
        "deferred_transitioned": len(deferred),
        "processed_at": now.isoformat(),
        "success": True
    }