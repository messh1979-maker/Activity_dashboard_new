"""Sharing service — raw SQL against the real DDL (schema ``sharing``).

Architecture Reference: Sections 4.6, 8.2, 11.1.
Note: the DDL has no ``share_code`` column; the share ``id`` is used as
the public code (routes keep the ``share_code`` interface).
"""
from typing import Optional, List
from types import SimpleNamespace
from uuid import UUID
from datetime import datetime

from sqlalchemy import text

from app.core.errors import APIError, NotFoundError

VALID_LEVELS = {"read", "write", "manage"}


def _iso(v):
    return v.isoformat() if isinstance(v, datetime) else v


class SharingService:
    """Service layer for Sharing module operations (real DDL)."""

    def __init__(self, session):
        self.session = session

    async def create_share(self, entity_type: str, entity_id: UUID,
                           recipient_id: UUID, permission_level: str,
                           allow_comment: bool, granted_by: UUID) -> SimpleNamespace:
        """Create a new share."""
        if permission_level not in VALID_LEVELS:
            raise APIError(error_code="INVALID_PERMISSION_LEVEL",
                           message="سطح دسترسی نامعتبر.", status_code=400)
        # sharing.shares has no unique constraint on the triple; upsert manually.
        existing = (await self.session.execute(text("""
            SELECT id FROM sharing.shares
             WHERE entity_type = :etype AND entity_id = :eid
               AND recipient_id = :rid AND revoked_at IS NULL
        """), {"etype": entity_type, "eid": str(entity_id),
               "rid": str(recipient_id)})).mappings().first()
        if existing:
            id_ = existing["id"]
            await self.session.execute(text("""
                UPDATE sharing.shares
                   SET permission_level = :lvl, allow_comment = :can,
                       granted_by = :by, granted_at = now(),
                       revoked_at = NULL, revoked_reason = NULL
                 WHERE id = :id
            """), {"id": str(id_), "lvl": permission_level,
                   "can": bool(allow_comment), "by": str(granted_by)})
        else:
            row = (await self.session.execute(text("""
                INSERT INTO sharing.shares (entity_type, entity_id, recipient_id,
                                            granted_by, permission_level, allow_comment)
                VALUES (:etype, :eid, :rid, :by, :lvl, :can)
                RETURNING id
            """), {
                "etype": entity_type, "eid": str(entity_id),
                "rid": str(recipient_id), "by": str(granted_by),
                "lvl": permission_level, "can": bool(allow_comment),
            })).mappings().first()
            id_ = row["id"]
        await self.session.commit()
        return SimpleNamespace(share_code=str(id_))

    async def get_entity_shares(self, entity_type: str, entity_id: UUID,
                                viewer_id: UUID) -> List[dict]:
        """Get all shares for an entity."""
        rows = (await self.session.execute(text("""
            SELECT id, entity_type, entity_id, recipient_id, permission_level,
                   allow_comment, granted_at, expires_at
              FROM sharing.shares
             WHERE entity_type = :etype AND entity_id = :eid
               AND revoked_at IS NULL
             ORDER BY granted_at DESC
        """), {"etype": entity_type, "eid": str(entity_id)})).mappings().all()
        return [{
            "id": str(r["id"]),
            "share_code": str(r["id"]),
            "entity_type": entity_type,
            "entity_id": str(entity_id),
            "recipient_id": str(r["recipient_id"]),
            "recipient": {"id": str(r["recipient_id"])},
            "permission_level": r["permission_level"],
            "granted_at": _iso(r["granted_at"]),
            "expires_at": _iso(r["expires_at"]) if r["expires_at"] else None,
            "allow_comment": r["allow_comment"],
        } for r in rows]

    async def check_permission(self, entity_type: str, entity_id: UUID,
                               user_id: UUID, required_level: str,
                               viewer_id: UUID) -> SimpleNamespace:
        """Check if a user has required permission on an entity."""
        if required_level not in VALID_LEVELS:
            raise APIError(error_code="INVALID_PERMISSION_LEVEL",
                           message="سطح دسترسی نامعتبر.", status_code=400)
        row = (await self.session.execute(text("""
            SELECT permission_level FROM sharing.effective_permissions
             WHERE entity_type = :etype AND entity_id = :eid
               AND recipient_id = :uid
        """), {"etype": entity_type, "eid": str(entity_id),
               "uid": str(user_id)})).mappings().first()
        if row:
            return SimpleNamespace(user_id=user_id, has_permission=True,
                                   permission_level=row["permission_level"],
                                   source="direct")
        return SimpleNamespace(user_id=user_id, has_permission=False,
                               permission_level=required_level, source="denied")

    async def revoke_share(self, share_code: str, revoked_by: UUID) -> dict:
        """Revoke a share by its id (used as the share code)."""
        row = (await self.session.execute(text("""
            UPDATE sharing.shares
               SET revoked_at = now(), revoked_reason = 'revoked'
             WHERE id = :sid AND revoked_at IS NULL
            RETURNING id
        """), {"sid": share_code})).mappings().first()
        if not row:
            raise APIError(error_code="SHARE_NOT_FOUND",
                           message="اشتراک یافت نشد.", status_code=404)
        await self.session.commit()
        return {"status": "revoked", "share_code": share_code}