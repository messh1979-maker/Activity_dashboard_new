"""Reporting module public interface."""
from app.modules.reporting.api.routes import router
from app.modules.reporting.api.dashboard import dashboard_router

router.include_router(dashboard_router)

__all__ = ["router"]
