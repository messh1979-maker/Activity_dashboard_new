"""Notification module API routes (stub)."""
from fastapi import APIRouter

router = APIRouter(prefix="/notifications", tags=["Notifications"])


@router.get("", response_model=dict)
async def list_notifications():
    """List notifications (stub — returns empty until M10 is implemented)."""
    return {"status": "success", "data": []}
