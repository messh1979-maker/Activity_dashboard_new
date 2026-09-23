"""Auth module public interface."""
from fastapi import APIRouter

from app.modules.auth.api.routes import router as auth_router
from app.modules.auth.api.admin_routes import router as admin_users_router

router = APIRouter()
router.include_router(auth_router)
router.include_router(admin_users_router)

__all__ = ["router"]