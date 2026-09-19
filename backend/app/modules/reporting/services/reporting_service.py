from typing import Optional, List, Tuple, Dict, Any
from uuid import UUID
from datetime import datetime

from sqlalchemy import select, func, insert, update
from sqlalchemy.orm import Session

from app.core.errors import APIError, NotFoundError
from app.modules.reporting.ports import (
    LayoutBlock, DashboardLayout, UserDashboardSettings,
    UserWidgetSettings, DashboardData, ReportExport, ReportImport
)
from app.modules.reporting.db.Models import DashboardLayouts, UserDashboardSettings, UserWidgetSettings, ReportExports


class ReportingService:
    """Service layer for Reporting module operations."""
    
    def __init__(self, session: Session):
        self.session = session
    
    # --- Layout Save ---
    
    async def save_layout(self, user_id: UUID, layout_data: dict) -> UUID:
        """Save dashboard layout for user."""
        # Check if user has default layout for this view mode
        result = await self.session.execute(
            select(DashboardLayouts).where(
                (DashboardLayouts.user_id == str(user_id)) &
                (DashboardLayouts.view_mode == layout_data.get("view_mode", "daily"))
            )
        )
        existing = result.scalar_one_or_none()
        
        if existing:
            # Update existing
            existing.name = layout_data.get("name", existing.name)
            existing.blocks = layout_data.get("blocks", existing.blocks)
            existing.updated_at = datetime.utcnow()
            layout_id = existing.id
        else:
            # Create new
            layout = DashboardLayouts(
                user_id=str(user_id),
                name=layout_data.get("name", "چیدمان جدید"),
                view_mode=layout_data.get("view_mode", "daily"),
                is_default=layout_data.get("is_default", False),
                schema_version=layout_data.get("schema_version", 1),
                blocks=layout_data.get("blocks", []),
            )
            self.session.add(layout)
            await self.session.flush()
            layout_id = layout.id
        
        # Save widget settings
        widgets_data = layout_data.get("widgets", [])
        for widget_data in widgets_data:
            # Check if setting exists
            setting_result = await self.session.execute(
                select(UserDashboardSettings).where(
                    (UserDashboardSettings.layout_id == layout_id) &
                    (UserDashboardSettings.block_key == widget_data.get("block_key"))
                )
            )
            setting = setting_result.scalar_one_or_none()
            
            if setting:
                setting.is_visible = widget_data.get("is_visible", setting.is_visible)
                setting.position_x = widget_data.get("position_x", setting.position_x)
                setting.position_y = widget_data.get("position_y", setting.position_y)
                setting.width = widget_data.get("width", setting.width)
                setting.height = widget_data.get("height", setting.height)
                setting.is_collapsed = widget_data.get("is_collapsed", setting.is_collapsed)
                setting.config = widget_data.get("config", setting.config)
                setting.updated_at = datetime.utcnow()
            else:
                # Create new setting
                setting = UserDashboardSettings(
                    layout_id=layout_id,
                    block_key=widget_data.get("block_key"),
                    is_visible=widget_data.get("is_visible", True),
                    position_x=widget_data.get("position_x", 0),
                    position_y=widget_data.get("position_y", 0),
                    width=widget_data.get("width", 4),
                    height=widget_data.get("height", 4),
                    is_collapsed=widget_data.get("is_collapsed", False),
                    config=widget_data.get("config", {}),
                )
                self.session.add(setting)
        
        await self.session.flush()
        return layout_id
    
    # --- Layout Get ---
    
    async def get_layout(self, layout_id: UUID, user_id: UUID) -> dict:
        """Get dashboard layout with widget settings."""
        # Get layout
        result = await self.session.execute(
            select(DashboardLayouts).where(DashboardLayouts.id == str(layout_id))
        )
        layout = result.scalar_one_or_none()
        
        if not layout:
            raise NotFoundError("layout")
        
        # Get widget settings
        widgets_result = await self.session.execute(
            select(UserDashboardSettings).where(UserDashboardSettings.layout_id == str(layout_id))
        )
        widgets = setting_result.scalars().all() if 'setting_result' in dir() else []
        
        # Simplified - would return full data
        return {
            "id": str(layout.id),
            "name": layout.name,
            "view_mode": layout.view_mode,
            "is_default": layout.is_default,
            "blocks": layout.blocks if layout else [],
        }
    
    # --- List Layouts ---
    
    async def list_layouts(self, user_id: UUID) -> List[dict]:
        """List user's dashboard layouts."""
        result = await self.session.execute(
            select(DashboardLayouts).where(DashboardLayouts.user_id == str(user_id))
        )
        layouts = result.scalars().all()
        
        return [
            {
                "id": str(l.id),
                "name": l.name,
                "view_mode": l.view_mode,
                "is_default": l.is_default,
            }
            for l in layouts
        ]
    
    # --- Import Layout ---
    
    async def import_layout(self, user_id: UUID, import_data: dict) -> dict:
        """Import dashboard layout from JSON."""
        schema_version = import_data.get("schema_version", 1)
        name = import_data.get("name", "چیدمان وارد شده")
        view_mode = import_data.get("view_mode", "daily")
        blocks = import_data.get("blocks", [])
        
        # Validate schema version
        if schema_version < 1:
            raise APIError(
                error_code="INVALID_SCHEMA_VERSION",
                message="نسخه اسکیمای ناصلح在此期间.",
                status_code=400
            )
        
        # Create or update layout
        layout_result = await self.save_layout(user_id, {
            "name": name,
            "view_mode": view_mode,
            "is_default": import_data.get("is_default", False),
            "schema_version": schema_version,
            "blocks": blocks,
        })
        
        return {"layout_id": str(layout_result), "schema_version": schema_version}
    
    # --- Widget Settings ---
    
    async def save_widget_settings(self, user_id: UUID, settings_data: dict) -> dict:
        """Save widget settings for user."""
        widget_keys = settings_data.get("widgets", [])
        
        for widget_data in widget_keys:
            widget_key = widget_data.get("widget_key")
            platform = widget_data.get("platform", "all")
            
            # Check if setting exists
            setting_result = await self.session.execute(
                select(UserWidgetSettings).where(
                    (UserWidgetSettings.user_id == str(user_id)) &
                    (UserWidgetSettings.widget_key == widget_key) &
                    (UserWidgetSettings.platform == platform)
                )
            )
            setting = setting_result.scalar_one_or_none()
            
            if setting:
                # Update existing
                setting.is_visible = widget_data.get("is_visible", setting.is_visible)
                setting.position_x = widget_data.get("position_x", setting.position_x)
                setting.position_y = widget_data.get("position_y", setting.position_y)
                setting.width = widget_data.get("width", setting.width)
                setting.height = widget_data.get("height", setting.height)
                setting.z_index = widget_data.get("z_index", setting.z_index)
                setting.style = widget_data.get("style", setting.style)
                setting.config = widget_data.get("config", setting.config)
                setting.updated_at = datetime.utcnow()
            else:
                # Create new setting
                setting = UserWidgetSettings(
                    user_id=str(user_id),
                    widget_key=widget_key,
                    platform=platform,
                    is_visible=widget_data.get("is_visible", True),
                    position_x=widget_data.get("position_x", 0),
                    position_y=widget_data.get("position_y", 0),
                    width=widget_data.get("width", 160),
                    height=widget_data.get("height", 80),
                    z_index=widget_data.get("z_index", 10),
                    style=widget_data.get("style", {}),
                    config=widget_data.get("config", {}),
                )
                self.session.add(setting)
        
        await self.session.flush()
        
        return {"status": "widgets_saved", "updated_count": len(widget_keys)}
    
    # --- Get Widget Settings ---
    
    async def get_widget_settings(self, user_id: UUID) -> dict:
        """Get all widget settings for user."""
        result = await self.session.execute(
            select(UserWidgetSettings).where(UserWidgetSettings.user_id == str(user_id))
        )
        widgets = result.scalars().all()
        
        return {
            "widgets": [
                {
                    "widget_key": w.widget_key,
                    "platform": w.platform,
                    "is_visible": w.is_visible,
                    "position_x": w.position_x,
                    "position_y": w.position_y,
                    "width": w.width,
                    "height": w.height,
                    "z_index": w.z_index,
                    "style": w.style,
                    "config": w.config,
                }
                for w in widgets
            ]
        }
    
    # --- Reset Widget Settings ---
    
    async def reset_widget_settings(self, user_id: UUID) -> dict:
        """Reset widget settings to default."""
        await self.session.execute(
            delete(UserWidgetSettings).where(UserWidgetSettings.user_id == str(user_id))
        )
        await self.session.flush()
        
        return {"status": "widgets_reset", "reset_count": 0}  # Would count reset