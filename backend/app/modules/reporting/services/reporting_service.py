"""Reporting service — raw SQL against the real DDL (schema ``reporting``).

Architecture Reference: Sections 10.1, 10.2, 10.3.
Note: dashboard blocks live in ``reporting.user_dashboard_settings``
(layout JSON blocks == block_key settings), not on the layout row.
The unique layout index is PARTIAL (``WHERE is_default``), so upserts
are manual SELECT -> INSERT/UPDATE.
"""
import json
from typing import Optional, List
from types import SimpleNamespace
from uuid import UUID
from datetime import datetime

from sqlalchemy import text

from app.core.errors import APIError, NotFoundError


def _iso(v):
    return v.isoformat() if isinstance(v, datetime) else v


class ReportingService:
    """Service layer for Reporting module operations (real DDL)."""

    def __init__(self, session):
        self.session = session

    async def save_layout(self, user_id: UUID, layout_data: dict) -> UUID:
        """Save dashboard layout for user (upsert by view_mode)."""
        view_mode = layout_data.get("view_mode", "daily")
        name = layout_data.get("name", "چیدمان جدید")
        schema_version = layout_data.get("schema_version", 1)
        is_default = layout_data.get("is_default", False)

        existing = (await self.session.execute(text("""
            SELECT id FROM reporting.dashboard_layouts
             WHERE user_id = :uid AND view_mode = :vm
             ORDER BY is_default DESC, updated_at DESC LIMIT 1
        """), {"uid": str(user_id), "vm": view_mode})).mappings().first()
        if existing:
            await self.session.execute(text("""
                UPDATE reporting.dashboard_layouts
                   SET name = :name, is_default = :def, schema_version = :sv,
                       updated_at = now()
                 WHERE id = :lid
            """), {"lid": str(existing["id"]), "name": name,
                   "def": bool(is_default), "sv": schema_version})
            layout_id = existing["id"]
        else:
            row = (await self.session.execute(text("""
                INSERT INTO reporting.dashboard_layouts
                    (user_id, name, view_mode, is_default, schema_version)
                VALUES (:uid, :name, :vm, :def, :sv)
                RETURNING id
            """), {"uid": str(user_id), "name": name, "vm": view_mode,
                   "def": bool(is_default), "sv": schema_version})).mappings().first()
            layout_id = row["id"]

        # Store widget/block placement in user_dashboard_settings
        blocks = layout_data.get("blocks", [])
        if layout_data.get("widgets"):
            blocks = layout_data["widgets"]
        for b in blocks:
            bkey = b.get("block_key") or b.get("key")
            if not bkey:
                continue
            await self.session.execute(text("""
                INSERT INTO reporting.user_dashboard_settings
                    (user_id, layout_id, block_key, is_visible,
                     position_x, position_y, width, height, is_collapsed, config)
                VALUES (:uid, :lid, :key, :vis, :x, :y, :w, :h, :col, CAST(:cfg AS jsonb))
                ON CONFLICT (layout_id, block_key)
                DO UPDATE SET is_visible = EXCLUDED.is_visible,
                              position_x = EXCLUDED.position_x,
                              position_y = EXCLUDED.position_y,
                              width = EXCLUDED.width,
                              height = EXCLUDED.height,
                              is_collapsed = EXCLUDED.is_collapsed,
                              config = EXCLUDED.config,
                              updated_at = now()
            """), {
                "uid": str(user_id), "lid": str(layout_id), "key": bkey,
                "vis": bool(b.get("is_visible", True)),
                "x": int(b.get("position_x", b.get("x", 0))),
                "y": int(b.get("position_y", b.get("y", 0))),
                "w": int(b.get("width", b.get("w", 4))),
                "h": int(b.get("height", b.get("h", 4))),
                "col": bool(b.get("is_collapsed", False)),
                "cfg": json.dumps(b.get("config") or {}),
            })
        await self.session.commit()
        return layout_id

    async def get_layout(self, layout_id: UUID, user_id: UUID) -> dict:
        """Get dashboard layout with widget settings."""
        row = (await self.session.execute(text("""
            SELECT id, name, view_mode, is_default, schema_version, created_at, updated_at
              FROM reporting.dashboard_layouts WHERE id = :lid AND user_id = :uid
        """), {"lid": str(layout_id), "uid": str(user_id)})).mappings().first()
        if not row:
            raise NotFoundError("layout")
        blocks = (await self.session.execute(text("""
            SELECT block_key, is_visible, position_x, position_y, width, height,
                   is_collapsed, config
              FROM reporting.user_dashboard_settings
             WHERE layout_id = :lid ORDER BY position_y, position_x
        """), {"lid": str(layout_id)})).mappings().all()
        return {
            "id": str(row["id"]),
            "name": row["name"],
            "view_mode": row["view_mode"],
            "is_default": row["is_default"],
            "schema_version": row["schema_version"],
            "blocks": [dict(b) for b in blocks],
        }

    async def list_layouts(self, user_id: UUID) -> List[dict]:
        """List user's dashboard layouts."""
        rows = (await self.session.execute(text("""
            SELECT id, name, view_mode, is_default
              FROM reporting.dashboard_layouts WHERE user_id = :uid
             ORDER BY created_at DESC
        """), {"uid": str(user_id)})).mappings().all()
        return [{"id": str(r["id"]), "name": r["name"],
                 "view_mode": r["view_mode"], "is_default": r["is_default"]}
                for r in rows]

    async def import_layout(self, user_id: UUID, import_data: dict) -> dict:
        """Import dashboard layout from JSON."""
        schema_version = import_data.get("schema_version", 1)
        if schema_version < 1:
            raise APIError(error_code="INVALID_SCHEMA_VERSION",
                           message="نسخه اسکیمای ناصحیح است.", status_code=400)
        layout_id = await self.save_layout(user_id, {
            "name": import_data.get("name", "چیدمان وارد شده"),
            "view_mode": import_data.get("view_mode", "daily"),
            "is_default": import_data.get("is_default", False),
            "schema_version": schema_version,
            "blocks": import_data.get("blocks", []),
        })
        return {"layout_id": str(layout_id), "schema_version": schema_version}

    async def save_widget_settings(self, user_id: UUID, settings_data: dict) -> dict:
        """Save widget settings for user."""
        widgets = settings_data.get("widgets", [])
        for w in widgets:
            wkey = w.get("widget_key") or w.get("key")
            if not wkey:
                continue
            platform = w.get("platform", "all")
            await self.session.execute(text("""
                INSERT INTO reporting.user_widget_settings
                    (user_id, widget_key, platform, is_visible,
                     position_x, position_y, width, height, z_index, style, config)
                VALUES (:uid, :key, :plat, :vis, :x, :y, :w, :h, :z, CAST(:style AS jsonb), CAST(:cfg AS jsonb))
                ON CONFLICT (user_id, widget_key, platform)
                DO UPDATE SET is_visible = EXCLUDED.is_visible,
                              position_x = EXCLUDED.position_x,
                              position_y = EXCLUDED.position_y,
                              width = EXCLUDED.width,
                              height = EXCLUDED.height,
                              z_index = EXCLUDED.z_index,
                              style = EXCLUDED.style,
                              config = EXCLUDED.config,
                              updated_at = now()
            """), {
                "uid": str(user_id), "key": wkey, "plat": platform,
                "vis": bool(w.get("is_visible", True)),
                "x": int(w.get("position_x", 0)),
                "y": int(w.get("position_y", 0)),
                "w": int(w.get("width", 160)),
                "h": int(w.get("height", 80)),
                "z": int(w.get("z_index", 10)),
                "style": json.dumps(w.get("style") or {}),
                "cfg": json.dumps(w.get("config") or {}),
            })
        return {"status": "widgets_saved", "updated_count": len(widgets)}

    async def get_widget_settings(self, user_id: UUID) -> dict:
        """Get all widget settings for user."""
        rows = (await self.session.execute(text("""
            SELECT widget_key, platform, is_visible, position_x, position_y,
                   width, height, z_index, style, config
              FROM reporting.user_widget_settings WHERE user_id = :uid
             ORDER BY position_y, position_x
        """), {"uid": str(user_id)})).mappings().all()
        return {"widgets": [dict(r) for r in rows]}

    async def reset_widget_settings(self, user_id: UUID) -> dict:
        """Reset widget settings to default."""
        result = await self.session.execute(text(
            "DELETE FROM reporting.user_widget_settings WHERE user_id = :uid"),
            {"uid": str(user_id)})
        count = result.rowcount or 0
        await self.session.commit()
        return {"status": "widgets_reset", "reset_count": count}