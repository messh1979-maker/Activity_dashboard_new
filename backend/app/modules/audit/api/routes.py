"""Audit module API routes (stub)."""
from fastapi import APIRouter

router = APIRouter(prefix="/audit", tags=["Audit"])


@router.get("/logs", response_model=dict)
async def list_audit_logs():
    """List audit logs (stub — returns empty until M11 routes land)."""
    return {"status": "success", "data": []}


@router.get("/integrity-check", response_model=dict)
async def integrity_check():
    """Verify audit hash-chain integrity."""
    try:
        from app.audit.integrity import check_audit_integrity

        return await check_audit_integrity()
    except Exception as exc:  # pragma: no cover - defensive
        return {"status": "unavailable", "message": str(exc)}
