"""Calendar module API routes (stub)."""
from fastapi import APIRouter

router = APIRouter(prefix="/calendar", tags=["Calendar"])


@router.get("/events", response_model=dict)
async def list_events():
    """List calendar events (stub — returns empty until M5 is implemented)."""
    return {"status": "success", "data": [], "message": "Calendar module stub"}
