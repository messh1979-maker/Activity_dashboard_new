"""SSO/LDAP module API routes (stub)."""
from fastapi import APIRouter

router = APIRouter(prefix="/sso", tags=["SSO/LDAP"])


@router.get("/negotiate", response_model=dict)
async def sso_negotiate():
    """Initiate SSO negotiation (stub — M12 not yet implemented)."""
    return {"status": "unavailable", "message": "SSO module stub"}
