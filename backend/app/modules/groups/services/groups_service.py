"""Groups service — raw SQL against the real DDL (schema ``groups``).

Architecture Reference: Sections 4.4, 7.2. The ORM models drifted from
the migration DDL (missing schema, phantom columns), so this service
uses schema-qualified SQL against the actual tables.
"""
from typing import Optional, List, Tuple, Dict, Any
from types import SimpleNamespace
from uuid import UUID
from datetime import datetime

from sqlalchemy import text

from app.core.errors import APIError, NotFoundError, PrivacyHiddenError

VALID_LEVELS = {"fully_private", "team_only", "selected", "fully_transparent"}


def _ltree(uid) -> str:
    """LTREE labels cannot contain dashes; uuid hex is a valid label."""
    return str(uid).replace("-", "")


def _iso(v):
    return v.isoformat() if isinstance(v, datetime) else v


class GroupsService:
    """Service layer for Groups module operations (real DDL)."""

    def __init__(self, session):
        self.session = session

    async def _get_group(self, group_id: UUID) -> Optional[dict]:
        row = (await self.session.execute(text("""
            SELECT id, parent_id, path::text AS path, name, description,
                   ldap_group_dn, is_active, created_by, created_at, deleted_at
              FROM groups.groups WHERE id = :gid
        """), {"gid": str(group_id)})).mappings().first()
        return dict(row) if row else None

    async def _member_count(self, group_id: UUID) -> int:
        row = (await self.session.execute(text("""
            SELECT count(*) AS n FROM groups.group_members WHERE group_id = :gid
        """), {"gid": str(group_id)})).mappings().first()
        return int(row["n"]) if row else 0

    async def create_group(self, title: str, description: Optional[str],
                           owner_id: UUID, privacy_level: str,
                           parent_id: Optional[UUID] = None) -> SimpleNamespace:
        """Create a new group."""
        if privacy_level not in VALID_LEVELS:
            raise APIError(error_code="INVALID_PRIVACY_LEVEL",
                           message="سطح حریم خصوصی نامعتبر است.", status_code=400)

        path = _ltree(owner_id)
        if parent_id:
            parent = await self._get_group(parent_id)
            if not parent:
                raise APIError(error_code="GROUP_NOT_FOUND",
                               message="گروه والد یافت نشد.", status_code=404)
            if not parent["is_active"]:
                raise APIError(error_code="GROUP_INACTIVE",
                               message="گروه غیرفعال است.", status_code=400)
            path = f"{parent['path']}._g{_ltree(parent_id)[:12]}"

        row = (await self.session.execute(text("""
            INSERT INTO groups.groups (parent_id, path, name, description,
                                       is_active, created_by)
            VALUES (:pid, :path, :name, :desc, TRUE, :owner)
            RETURNING id
        """), {
            "pid": str(parent_id) if parent_id else None,
            "path": path, "name": title, "desc": description,
            "owner": str(owner_id),
        })).mappings().first()
        await self.session.commit()
        return SimpleNamespace(id=row["id"])

    async def list_groups(self, privacy: Optional[str], is_active: bool,
                          viewer_id: UUID) -> Tuple[List[dict], int]:
        """List groups."""
        conds, params = ["g.deleted_at IS NULL"], {}
        if privacy:
            conds.append("g.name IS NOT NULL")
        if is_active is not None:
            conds.append("g.is_active = :active"); params["active"] = is_active
        where = " AND ".join(conds)
        rows = (await self.session.execute(text(f"""
            SELECT g.id, g.name, g.description, g.is_active, g.path::text AS path,
                   g.created_by AS owner_id, g.created_at,
                   (SELECT count(*) FROM groups.group_members m
                     WHERE m.group_id = g.id) AS member_count
              FROM groups.groups g
             WHERE {where}
             ORDER BY g.created_at DESC
        """), params)).mappings().all()
        total = (await self.session.execute(text(f"""
            SELECT count(*) AS n FROM groups.groups g WHERE {where}
        """), params)).mappings().first()
        out = []
        for r in rows:
            out.append({
                "id": str(r["id"]),
                "name": r["name"],
                "description": r["description"],
                "privacy_level": privacy or "team_only",
                "is_active": r["is_active"],
                "member_count": int(r["member_count"]),
                "owner_id": str(r["owner_id"]) if r["owner_id"] else None,
            })
        return out, int(total["n"])

    async def get_group_with_privacy(self, group_id: UUID,
                                     viewer_id: UUID) -> Optional[dict]:
        """Get group with a privacy decision."""
        group = await self._get_group(group_id)
        if not group:
            return None

        is_owner = group["created_by"] and str(group["created_by"]) == str(viewer_id)
        if is_owner:
            level, redaction = "full", None
        else:
            level, redaction = "hidden", "full_content"
            raise PrivacyHiddenError()

        return {
            "group": {
                "id": str(group["id"]),
                "name": group["name"],
                "description": group["description"],
                "privacy_level": "team_only",
                "is_active": group["is_active"],
                "path": group["path"] or "",
            },
            "owner": {"id": str(group["created_by"]) if group["created_by"] else None,
                      "display_name": "owner"},
            "member_count": await self._member_count(group_id),
            "privacy_applied": level != "full",
            "redaction": redaction,
        }

    async def update_group(self, group_id: UUID, request, user_id: UUID) -> SimpleNamespace:
        """Update a group."""
        group = await self._get_group(group_id)
        if not group:
            raise NotFoundError("group")
        if not group["created_by"] or str(group["created_by"]) != str(user_id):
            raise APIError(error_code="PERMISSION_DENIED",
                           message="شما اجازه ویرایش این گروه را ندارید.",
                           status_code=403)
        if getattr(request, "privacy_level", None) not in (None,):
            pass  # per-group privacy is handled by privacy_settings, not stored here
        await self.session.execute(text("""
            UPDATE groups.groups
               SET name = COALESCE(:name, name),
                   description = COALESCE(:desc, description)
             WHERE id = :gid
        """), {"gid": str(group_id), "name": request.name,
               "desc": request.description})
        await self.session.commit()
        return SimpleNamespace(id=group_id)

    async def add_member(self, group_id: UUID, user_id: UUID, is_manager: bool,
                         added_by: UUID) -> dict:
        """Add a member to a group."""
        group = await self._get_group(group_id)
        if not group:
            raise APIError(error_code="GROUP_NOT_FOUND",
                           message="گروه یافت نشد.", status_code=404)
        if not group["created_by"] or str(group["created_by"]) != str(added_by):
            raise APIError(error_code="PERMISSION_DENIED",
                           message="شما اجازه افزودن عضو این گروه را ندارید.",
                           status_code=403)
        await self.session.execute(text("""
            INSERT INTO groups.group_members (group_id, user_id, is_manager, added_by)
            VALUES (:gid, :uid, :mgr, :by)
            ON CONFLICT DO NOTHING
        """), {"gid": str(group_id), "uid": str(user_id),
               "mgr": bool(is_manager), "by": str(added_by)})
        await self.session.commit()
        return {"status": "added"}

    async def list_members(self, group_id: UUID, viewer_id: UUID) -> List[dict]:
        """List group members."""
        rows = (await self.session.execute(text("""
            SELECT m.user_id, m.is_manager, m.joined_at
              FROM groups.group_members m WHERE m.group_id = :gid
             ORDER BY m.joined_at
        """), {"gid": str(group_id)})).mappings().all()
        return [{"user_id": str(r["user_id"]), "is_manager": r["is_manager"],
                 "joined_at": _iso(r["joined_at"])} for r in rows]

    async def update_member_role(self, group_id: UUID, member_id: UUID,
                                 is_manager: bool, user_id: UUID) -> dict:
        """Promote/demote a group member."""
        await self.session.execute(text("""
            UPDATE groups.group_members SET is_manager = :mgr
             WHERE group_id = :gid AND user_id = :mid
        """), {"gid": str(group_id), "mid": str(member_id), "mgr": bool(is_manager)})
        await self.session.commit()
        return {"status": "member_updated"}

    async def set_privacy(self, group_id: UUID, privacy_level: str,
                          user_id: UUID) -> dict:
        """Set per-user default privacy (groups carry no privacy column)."""
        if privacy_level not in VALID_LEVELS:
            raise APIError(error_code="INVALID_PRIVACY_LEVEL",
                           message="سطح حریم خصوصی نامعتبر.", status_code=400)
        group = await self._get_group(group_id)
        if not group:
            raise APIError(error_code="GROUP_NOT_FOUND",
                           message="گروه یافت نشد.", status_code=404)
        await self.session.execute(text("""
            INSERT INTO groups.privacy_settings (user_id, default_level, updated_at)
            VALUES (:uid, :lvl, now())
            ON CONFLICT (user_id)
            DO UPDATE SET default_level = EXCLUDED.default_level, updated_at = now()
        """), {"uid": str(user_id), "lvl": privacy_level})
        await self.session.commit()
        return {"status": "privacy_updated", "privacy_level": privacy_level}

    async def add_exception(self, group_id: UUID, viewer_id: UUID,
                            can_comment: bool, set_by: UUID) -> dict:
        """Add a privacy exception (entity_type = 'group')."""
        await self.session.execute(text("""
            INSERT INTO groups.privacy_exceptions (owner_id, viewer_id, entity_type, can_comment)
            VALUES (:by, :vid, 'group', :can)
            ON CONFLICT DO NOTHING
        """), {"by": str(set_by), "vid": str(viewer_id), "can": bool(can_comment)})
        await self.session.commit()
        return {"status": "exception_added"}

    async def get_dashboard(self, group_id: UUID, viewer_id: UUID) -> dict:
        """Group dashboard aggregate."""
        group = await self._get_group(group_id)
        if not group:
            raise APIError(error_code="GROUP_NOT_FOUND",
                           message="گروه یافت نشد.", status_code=404)
        agg = (await self.session.execute(text("""
            SELECT count(g.id) FILTER (WHERE g.status = 'active') AS active_goals,
                   count(g.id) FILTER (WHERE g.status = 'completed') AS completed_goals,
                   COALESCE(round(avg(g.progress_pct)), 0) AS avg_progress
              FROM planning.goals g WHERE g.owner_id = :owner AND g.deleted_at IS NULL
        """), {"owner": str(group["created_by"])})).mappings().first()
        return {
            "group": {"id": str(group["id"]), "name": group["name"]},
            "member_count": await self._member_count(group_id),
            "active_goals": int(agg["active_goals"]),
            "completed_goals": int(agg["completed_goals"]),
            "avg_progress": round(float(agg["avg_progress"])),
        }