"""Notification service — real DDL (M10).

Raw SQL against schema ``notification``: notifications, preferences, log.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Optional
from uuid import UUID
from types import SimpleNamespace

from sqlalchemy import text

from app.core.errors import APIError, NotFoundError


def _iso(v) -> Optional[str]:
    return v.isoformat() if isinstance(v, datetime) else v


def _row_serialize(r) -> dict:
    d = dict(r)
    for k, v in list(d.items()):
        if v is not None and isinstance(v, datetime):
            d[k] = _iso(v)
        elif isinstance(v, (dict, list)):
            d[k] = json.dumps(v, ensure_ascii=False)
    return d


class NotificationStateMachine:
    """Manages notifications, delivery log and user preferences."""

    def __init__(self, session):
        self.session = session

    # --- Create / list ---

    async def create(self, spec: dict) -> SimpleNamespace:
        """Persist a notification with default priority."""
        row = (await self.session.execute(text("""
            INSERT INTO notification.notifications (
                user_id, type, title, message, data,
                is_read, action_url, action_text,
                related_entity_type, related_entity_id,
                priority, expires_at
            )
            VALUES (:uid, :type, :title, :msg, :data,
                    FALSE, :aurl, :atext,
                    :rtype, :rid,
                    :prio, :exp)
            RETURNING id, created_at, is_read
        """), {
            "uid": str(spec["user_id"]),
            "type": spec["type"],
            "title": spec["title"],
            "msg": spec.get("message"),
            "data": json.dumps(spec.get("data")) if spec.get("data") else None,
            "aurl": spec.get("action_url"),
            "atext": spec.get("action_text"),
            "rtype": spec.get("related_entity_type"),
            "rid": str(spec["related_entity_id"]) if spec.get("related_entity_id") else None,
            "prio": spec.get("priority", "normal"),
            "exp": spec.get("expires_at"),
        })).mappings().first()
        await self.session.commit()
        return SimpleNamespace(id=row["id"], created_at=_iso(row["created_at"]),
                               is_read=row["is_read"])

    async def list_for_user(self, user_id: UUID, limit: int = 50,
                            unread_only: bool = False) -> list[dict]:
        """List recent notifications, newest first."""
        conds, params = ["user_id = :uid"], {"uid": str(user_id)}
        if unread_only:
            conds.append("is_read = FALSE")
        rows = (await self.session.execute(text(f"""
            SELECT id, type, title, message, data, is_read,
                   action_url, action_text, priority, created_at, read_at
              FROM notification.notifications
             WHERE {" AND ".join(conds)}
             ORDER BY created_at DESC
             LIMIT {int(limit)}
        """), params)).mappings().all()
        return [_row_serialize(r) for r in rows]

    async def unread_count(self, user_id: UUID) -> int:
        row = (await self.session.execute(text("""
            SELECT count(*) AS n FROM notification.notifications
             WHERE user_id = :uid AND is_read = FALSE
        """), {"uid": str(user_id)})).mappings().first()
        return row["n"] or 0

    async def mark_read(self, user_id: UUID, notification_id: UUID) -> SimpleNamespace:
        row = (await self.session.execute(text("""
            UPDATE notification.notifications
               SET is_read = TRUE, read_at = now()
             WHERE id = :nid AND user_id = :uid
          RETURNING id, is_read, read_at
        """), {"nid": str(notification_id), "uid": str(user_id)})).mappings().first()
        await self.session.commit()
        if not row:
            raise NotFoundError(resource="notification")
        return SimpleNamespace(id=row["id"], is_read=row["is_read"],
                               read_at=_iso(row["read_at"]))

    async def mark_all_read(self, user_id: UUID) -> int:
        result = (await self.session.execute(text("""
            UPDATE notification.notifications
               SET is_read = TRUE, read_at = now()
             WHERE user_id = :uid AND is_read = FALSE
        """), {"uid": str(user_id)}))
        await self.session.commit()
        return result.rowcount

    # --- Preferences ---

    async def get_preferences(self, user_id: UUID) -> dict:
        row = (await self.session.execute(text("""
            SELECT user_id, email_enabled, push_enabled, inbox_enabled,
                   types, quiet_hours_start, quiet_hours_end
              FROM notification.preferences WHERE user_id = :uid
        """), {"uid": str(user_id)})).mappings().first()
        if not row:
            await self._ensure_preferences(user_id)
            row = (await self.session.execute(text("""
                SELECT user_id, email_enabled, push_enabled, inbox_enabled,
                       types, quiet_hours_start, quiet_hours_end
                  FROM notification.preferences WHERE user_id = :uid
            """), {"uid": str(user_id)})).mappings().first()
        return _row_serialize(row)

    async def _ensure_preferences(self, user_id: UUID) -> None:
        await self.session.execute(text("""
            INSERT INTO notification.preferences (user_id, email_enabled,
                push_enabled, inbox_enabled, types)
            VALUES (:uid, TRUE, TRUE, TRUE,
                    '{"all": true}'::jsonb)
            ON CONFLICT (user_id) DO NOTHING
        """), {"uid": str(user_id)})
        await self.session.commit()

    async def update_preferences(self, user_id: UUID, patch: dict) -> dict:
        from app.modules.notification.ports import PreferencesUpdate
        valid = PreferencesUpdate(**patch)
        upserts = []
        params: dict = {"uid": str(user_id)}
        fields = [("email_enabled", "email_enabled"), ("push_enabled", "push_enabled"),
                  ("inbox_enabled", "inbox_enabled"), ("quiet_hours_start", "qhs"),
                  ("quiet_hours_end", "qhe")]
        for col, key in fields:
            val = getattr(valid, col)
            if val is not None:
                upserts.append(f"{col} = :{key}")
                params[key] = val
        if valid.types is not None:
            upserts.append("types = :types")
            params["types"] = json.dumps(valid.types, ensure_ascii=False)
        await self._ensure_preferences(user_id)
        if upserts:
            upserts.append("updated_at = now()")
            await self.session.execute(text(f"""
                UPDATE notification.preferences
                   SET {" , ".join(upserts)}
                 WHERE user_id = :uid
            """), params)
            await self.session.commit()
        return await self.get_preferences(user_id)

    # --- Delivery log ---

    async def log_delivery(self, user_id: UUID, notification_id: UUID,
                           action: str, ip: Optional[str] = None,
                           ua: Optional[str] = None) -> None:
        await self.session.execute(text("""
            INSERT INTO notification.log (user_id, action, notification_id,
                                          ip_address, user_agent)
            VALUES (:uid, :act, :nid, :ip, :ua)
        """), {"uid": str(user_id), "act": action, "nid": str(notification_id),
               "ip": ip, "ua": ua})
        await self.session.commit()


NotificationService = NotificationStateMachine