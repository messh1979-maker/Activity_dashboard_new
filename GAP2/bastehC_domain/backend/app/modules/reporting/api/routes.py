"""
Reporting Module API Routes
Architecture Reference: Sections 10.1, 10.2, 10.3
Endpoints: /api/v1/reporting
"""

from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, Body, Path
from fastapi.responses import JSONResponse

from app.core.dependencies import (
    get_db_session, get_current_user, get_reporting_service
)
from app.core.errors import APIError, NotFoundError
from app.core.database import async_session_context
from app.modules.reporting.ports import (
    LayoutBlock, DashboardLayout, UserDashboardSettings,
    UserWidgetSettings, DashboardData, ReportExport, ReportImport
)
from app.modules.reporting.services.reporting_service import ReportingService
from app.modules.reporting.db.Models import DashboardLayouts, UserDashboardSettings, UserWidgetSettings, ReportExports


router = APIRouter(prefix="/reporting", tags=["Reporting"])


@router.post("/layouts", response_model=dict)
async def save_layout(
    layout_data: dict,
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Save dashboard layout."""
    async with db_session() as session:
        try:
            service = ReportingService(session)
            layout_id = await service.save_layout(user_id, layout_data)
            return {"status": "layout_saved", "layout_id": str(layout_id)}
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.get("/layouts/{layout_id}", response_model=dict)
async def get_layout(
    layout_id: UUID = Path(...),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Get a dashboard layout."""
    async with db_session() as session:
        try:
            service = ReportingService(session)
            layout = await service.get_layout(layout_id, user_id)
            return {"status": "success", "data": layout}
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.get("/layouts", response_model=dict)
async def list_layouts(
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """List user's dashboard layouts."""
    async with db_session() as session:
        try:
            service = ReportingService(session)
            layouts = await service.list_layouts(user_id)
            return {"status": "success", "data": {"layouts": layouts}}
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.post("/layouts/import", response_model=dict)
async def import_layout(
    import_data: dict,
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Import dashboard layout from JSON."""
    async with db_session() as session:
        try:
            service = ReportingService(session)
            result = await service.import_layout(user_id, import_data)
            return {"status": "layout_imported", "result": result}
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.post("/widgets/settings", response_model=dict)
async def save_widget_settings(
    settings_data: dict,
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Save widget settings."""
    async with db_session() as session:
        try:
            service = ReportingService(session)
            result = await service.save_widget_settings(user_id, settings_data)
            return {"status": "widgets_saved", "result": result}
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.get("/widgets/settings", response_model=dict)
async def get_widget_settings(
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Get widget settings."""
    async with db_session() as session:
        try:
            service = ReportingService(session)
            settings = await service.get_widget_settings(user_id)
            return {"status": "success", "data": {"widgets": settings}}
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )


@router.post("/widgets/settings/reset", response_model=dict)
async def reset_widget_settings(
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session)
):
    """Reset widget settings to default."""
    async with db_session() as session:
        try:
            service = ReportingService(session)
            result = await service.reset_widget_settings(user_id)
            return {"status": "widgets_reset", "result": result}
        except APIError as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.error_code, "message": e.message, "success": False}
            )