"""RBAC service — raw SQL against the real DDL (schema ``rbac``).

Architecture Reference: Sections 2, 7.1, 7.4.
The ORM models drifted from the migration DDL (missing schema, extra
columns, wrong PK types), so this service uses schema-qualified SQL,
the same proven pattern as the reporting dashboard endpoints.
"""
from typing import List, Optional
from types import SimpleNamespace
from uuid import UUID

from sqlalchemy import text

from app.core.errors import APIError


class RBACService:
    """Service layer for RBAC module operations."""

    def __init__(self, session):
        self.session = session

    # --- Permissions ---

    async def create_permission(self, request) -> SimpleNamespace:
        """Create a new permission."""
        row = (await self.session.execute(text("""
            INSERT INTO rbac.permissions (code, module, action, title_fa, is_dangerous)
            VALUES (:code, :module, :action, :title_fa, :dangerous)
            ON CONFLICT (code) DO NOTHING
            RETURNING id, code, module, action, title_fa, is_dangerous
        """), {
            "code": request.code, "module": request.module,
            "action": request.action, "title_fa": request.title_fa,
            "dangerous": bool(request.is_dangerous),
        })).mappings().first()
        if row is None:
            raise APIError(error_code="PERMISSION_EXISTS",
                           message="این دسترسی قبلاً ثبت شده است.", status_code=409)
        await self.session.commit()
        return SimpleNamespace(**dict(row))

    async def list_permissions(self, module: Optional[str] = None,
                               action: Optional[str] = None,
                               viewer_id: Optional[UUID] = None) -> List[dict]:
        """List permissions, optionally filtered."""
        conds, params = [], {}
        if module:
            conds.append("module = :module"); params["module"] = module
        if action:
            conds.append("action = :action"); params["action"] = action
        where = ("WHERE " + " AND ".join(conds)) if conds else ""
        rows = (await self.session.execute(text(f"""
            SELECT id, code, module, action, title_fa, is_dangerous
              FROM rbac.permissions {where} ORDER BY module, action
        """), params)).mappings().all()
        return [dict(r) for r in rows]

    # --- Roles ---

    async def create_role(self, request) -> SimpleNamespace:
        """Create a new role."""
        row = (await self.session.execute(text("""
            INSERT INTO rbac.roles (code, title_fa, level, is_system, description)
            VALUES (:code, :title_fa, :level, :is_system, :description)
            ON CONFLICT (code) DO NOTHING
            RETURNING id, code, title_fa, level, is_system, description
        """), {
            "code": request.code, "title_fa": request.title_fa,
            "level": request.level, "is_system": bool(request.is_system),
            "description": request.description,
        })).mappings().first()
        if row is None:
            raise APIError(error_code="ROLE_EXISTS",
                           message="این نقش قبلاً ثبت شده است.", status_code=409)
        await self.session.commit()
        return SimpleNamespace(**dict(row))

    async def list_roles(self, viewer_id: Optional[UUID] = None) -> List[dict]:
        """List all roles."""
        rows = (await self.session.execute(text("""
            SELECT id, code, title_fa, level, is_system, description
              FROM rbac.roles ORDER BY level DESC, code
        """))).mappings().all()
        return [dict(r) for r in rows]

    # --- Assignments (with anti-escalation guards per ADR/7.4) ---

    async def _max_level(self, user_id: UUID) -> int:
        row = (await self.session.execute(text("""
            SELECT COALESCE(MAX(r.level), 0) AS m
              FROM rbac.user_roles ur JOIN rbac.roles r ON r.id = ur.role_id
             WHERE ur.user_id = :uid
               AND (ur.expires_at IS NULL OR ur.expires_at > now())
        """), {"uid": str(user_id)})).mappings().first()
        return int(row["m"] if row else 0)

    async def assign_role(self, actor_id: UUID, target_user_id: UUID,
                          role_id: int, scope_type: str = "global",
                          scope_id: Optional[UUID] = None, **_) -> dict:
        """Assign a role to a user (guards: no self-assign, no equal/higher)."""
        if str(target_user_id) == str(actor_id):
            raise APIError(error_code="CANNOT_SELF_ASSIGN",
                           message="نمی‌توان به خود نقش داد.", status_code=403)
        role = (await self.session.execute(text(
            "SELECT id, code, level FROM rbac.roles WHERE id = :rid"),
            {"rid": role_id})).mappings().first()
        if role is None:
            raise APIError(error_code="ROLE_NOT_FOUND",
                           message="نقش یافت نشد.", status_code=404)
        actor_max = await self._max_level(actor_id)
        # Bootstrap: a user with no roles yet may assign only level-1 roles.
        if actor_max > 0 and int(role["level"]) >= actor_max:
            raise APIError(error_code="CANNOT_GRANT_EQUAL_OR_HIGHER_ROLE",
                           message="نمی‌توان نقش هم‌سطح یا بالاتر از خود اعطا کرد.",
                           status_code=403)
        if scope_type == "group" and scope_id is not None:
            mgr = (await self.session.execute(text("""
                SELECT 1 FROM groups.group_members
                 WHERE group_id = :gid AND user_id = :uid AND is_manager
            """), {"gid": str(scope_id), "uid": str(actor_id)})).first()
            if mgr is None:
                raise APIError(error_code="NOT_GROUP_MANAGER",
                               message="مدیر این گروه نیستید.", status_code=403)
        await self.session.execute(text("""
            INSERT INTO rbac.user_roles (user_id, role_id, scope_type, scope_id, granted_by, source)
            VALUES (:uid, :rid, :scope, :sid, :by, 'manual')
            ON CONFLICT DO NOTHING
        """), {
            "uid": str(target_user_id), "rid": role_id, "scope": scope_type,
            "sid": str(scope_id) if scope_id else None, "by": str(actor_id),
        })
        await self.session.commit()
        return {"role_id": role_id, "role_code": role["code"],
                "target_user_id": str(target_user_id)}

    async def revoke_role(self, actor_id: UUID, target_user_id: UUID,
                          role_id: int, scope_type: str = "global", **_) -> dict:
        """Revoke a role from a user."""
        await self.session.execute(text("""
            DELETE FROM rbac.user_roles
             WHERE user_id = :uid AND role_id = :rid AND scope_type = :scope
        """), {"uid": str(target_user_id), "rid": role_id, "scope": scope_type})
        await self.session.commit()
        return {"role_id": role_id, "target_user_id": str(target_user_id)}

    async def get_user_roles(self, user_id: UUID,
                             viewer_id: Optional[UUID] = None) -> List[dict]:
        """Get roles for a specific user."""
        rows = (await self.session.execute(text("""
            SELECT r.id, r.code, r.title_fa, r.level,
                   ur.scope_type, ur.scope_id::text AS scope_id,
                   ur.granted_at, ur.expires_at, ur.source
              FROM rbac.user_roles ur JOIN rbac.roles r ON r.id = ur.role_id
             WHERE ur.user_id = :uid
               AND (ur.expires_at IS NULL OR ur.expires_at > now())
             ORDER BY r.level DESC
        """), {"uid": str(user_id)})).mappings().all()
        out = []
        for r in rows:
            d = dict(r)
            for k in ("granted_at", "expires_at"):
                if d.get(k) is not None:
                    d[k] = d[k].isoformat()
            out.append(d)
        return out

    async def effective_permissions(self, user_id: UUID) -> List[str]:
        """Flat permission codes for a user (used by the policy engine)."""
        rows = (await self.session.execute(text("""
            SELECT DISTINCT p.code
              FROM rbac.user_roles ur
              JOIN rbac.role_permissions rp ON rp.role_id = ur.role_id
              JOIN rbac.permissions p ON p.id = rp.permission_id
             WHERE ur.user_id = :uid
               AND (ur.expires_at IS NULL OR ur.expires_at > now())
        """), {"uid": str(user_id)})).mappings().all()
        return [r["code"] for r in rows]
