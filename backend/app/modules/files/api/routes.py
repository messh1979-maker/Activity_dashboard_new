"""File storage module API routes (stub)."""
from fastapi import APIRouter

router = APIRouter(prefix="/files", tags=["Files"])


@router.post("/presign", response_model=dict)
async def presign_upload():
    """Generate a presigned upload URL (stub — M13 not yet implemented)."""
    return {"status": "unavailable", "message": "Files module stub"}
