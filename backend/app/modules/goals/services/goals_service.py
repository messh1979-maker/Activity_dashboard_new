"""Goals service — raw SQL against the real DDL (schema ``planning``).

Architecture Reference: Sections 4.5, 9.10.
"""
from typing import Optional, List, Tuple
from types import SimpleNamespace
from uuid import UUID
from datetime import datetime

from sqlalchemy import text

from app.core.errors import APIError, NotFoundError, PrivacyHiddenError

VALID_LEVELS = {"fully_private", "team_only", "selected", "fully_transparent"}
VALID_STATUS = {"active", "completed", "archived"}


def _iso(v):
    return v.isoformat() if isinstance(v, datetime) else v


class GoalsService:
    """Service layer for Goals module operations (real DDL)."""

    def __init__(self, session):
        self.session = session

    async def _get_goal(self, goal_id: UUID) -> Optional[dict]:
        row = (await self.session.execute(text("""
            SELECT id, title, description, owner_id, privacy_level::text AS privacy_level,
                   progress_pct, start_date, due_date, status, created_at, updated_at
              FROM planning.goals WHERE id = :gid AND deleted_at IS NULL
        """), {"gid": str(goal_id)})).mappings().first()
        return dict(row) if row else None

    @staticmethod
    def _decision(goal: dict, viewer_id: UUID) -> tuple:
        is_owner = str(goal["owner_id"]) == str(viewer_id)
        if is_owner or goal["privacy_level"] == "fully_transparent":
            return "full", None
        if goal["privacy_level"] == "fully_private":
            return "hidden", "full_content"
        return "aggregate_only", "status_only"

    async def create_goal(self, title: str, description: Optional[str],
                          owner_id: UUID, privacy_level: str) -> SimpleNamespace:
        """Create a new goal."""
        if privacy_level not in VALID_LEVELS:
            raise APIError(error_code="INVALID_PRIVACY_LEVEL",
                           message=f"سطح حریم خصوصی نامعتبر است. مقادیر مجاز: {VALID_LEVELS}",
                           status_code=400)
        row = (await self.session.execute(text("""
            INSERT INTO planning.goals (title, description, owner_id, privacy_level,
                                        progress_pct, status)
            VALUES (:title, :desc, :owner, :lvl, 0, 'active')
            RETURNING id, progress_pct, status
        """), {"title": title, "desc": description, "owner": str(owner_id),
               "lvl": privacy_level})).mappings().first()
        await self.session.commit()
        return SimpleNamespace(**dict(row))

    async def list_goals(self, privacy: Optional[str], status: Optional[str],
                         owner_id: Optional[UUID], tag: Optional[str],
                         page: int, page_size: int,
                         viewer_id: UUID) -> Tuple[List[dict], int]:
        """List goals with filtering."""
        conds, params = ["g.deleted_at IS NULL"], {}
        if privacy:
            conds.append("g.privacy_level::text = :prv"); params["prv"] = privacy
        if status:
            conds.append("g.status = :st"); params["st"] = status
        if owner_id:
            conds.append("g.owner_id = :oid"); params["oid"] = str(owner_id)
        if tag:
            conds.append("""EXISTS (SELECT 1 FROM planning.goal_tags gt
                           JOIN planning.tags t ON t.id = gt.tag_id
                           WHERE gt.goal_id = g.id AND t.name = :tag)""")
            params["tag"] = tag
        where = " AND ".join(conds)
        rows = (await self.session.execute(text(f"""
            SELECT g.id, g.title, g.description, g.owner_id,
                   g.privacy_level::text AS privacy_level, g.progress_pct,
                   g.status, g.start_date, g.due_date, g.created_at
              FROM planning.goals g
             WHERE {where}
             ORDER BY g.created_at DESC
             LIMIT :size OFFSET :off
        """), {**params, "size": page_size, "off": (page - 1) * page_size})).mappings().all()
        cnt = (await self.session.execute(text(
            f"SELECT count(*) AS n FROM planning.goals g WHERE {where}"), params)).mappings().first()

        out = []
        for r in rows:
            g = dict(r)
            decision = self._decision(g, viewer_id)
            if decision[0] == "hidden":
                continue
            out.append({
                "id": str(g["id"]),
                "title": g["title"],
                "description": g["description"],
                "progress_pct": g["progress_pct"],
                "status": g["status"],
                "privacy_level": g["privacy_level"],
                "owner_id": str(g["owner_id"]),
                "privacy_applied": decision[0] != "full",
                "redaction": decision[1],
            })
        return out, int(cnt["n"])

    async def get_goal_with_privacy(self, goal_id: UUID,
                                    viewer_id: UUID) -> Optional[dict]:
        """Get goal with privacy decision applied."""
        goal = await self._get_goal(goal_id)
        if not goal:
            return None
        decision = self._decision(goal, viewer_id)
        if decision[0] == "hidden":
            raise PrivacyHiddenError()

        task_rows = (await self.session.execute(text("""
            SELECT id, title, status, progress_pct, privacy_level::text AS privacy_level
              FROM planning.tasks WHERE goal_id = :gid AND deleted_at IS NULL
             ORDER BY created_at
        """), {"gid": str(goal_id)})).mappings().all()
        tasks = [{
            "id": str(t["id"]),
            "title": t["title"],
            "status": t["status"],
            "progress_pct": t["progress_pct"],
            "privacy_applied": decision[0] != "full",
        } for t in task_rows]

        return {
            "goal": {
                "id": str(goal["id"]),
                "title": goal["title"],
                "description": goal["description"],
                "progress_pct": goal["progress_pct"],
                "status": goal["status"],
                "privacy_level": goal["privacy_level"],
            },
            "owner": {"id": str(goal["owner_id"]), "display_name": "owner",
                      "privacy_level": goal["privacy_level"]},
            "tasks": tasks,
            "privacy_applied": decision[0] != "full",
            "redaction": decision[1],
        }

    async def update_goal(self, goal_id: UUID, request, user_id: UUID) -> SimpleNamespace:
        """Update a goal."""
        goal = await self._get_goal(goal_id)
        if not goal:
            raise NotFoundError("goal")
        if str(goal["owner_id"]) != str(user_id):
            raise APIError(error_code="PERMISSION_DENIED",
                           message="شما اجازه ویرایش این هدف را ندارید.",
                           status_code=403)
        if request.privacy_level and request.privacy_level not in VALID_LEVELS:
            raise APIError(error_code="INVALID_PRIVACY_LEVEL",
                           message="سطح حریم خصوصی نامعتبر است.", status_code=400)
        await self.session.execute(text("""
            UPDATE planning.goals
               SET title = COALESCE(:title, title),
                   description = COALESCE(:desc, description),
                   privacy_level = COALESCE(CAST(:lvl AS privacy_level), privacy_level),
                   status = COALESCE(:st, status),
                   start_date = COALESCE(:sd, start_date),
                   due_date = COALESCE(:dd, due_date),
                   updated_at = now()
             WHERE id = :gid
        """), {
            "gid": str(goal_id), "title": request.title,
            "desc": request.description, "lvl": request.privacy_level,
            "st": request.status, "sd": request.start_date,
            "dd": request.due_date,
        })
        await self.session.commit()
        return SimpleNamespace(id=goal_id)

    async def update_progress(self, goal_id: UUID, progress_pct: int,
                              user_id: UUID) -> SimpleNamespace:
        """Update goal progress."""
        goal = await self._get_goal(goal_id)
        if not goal:
            raise NotFoundError("goal")
        if str(goal["owner_id"]) != str(user_id):
            raise APIError(error_code="PERMISSION_DENIED",
                           message="شما اجازه ویرایش این هدف را ندارید.",
                           status_code=403)
        row = (await self.session.execute(text("""
            UPDATE planning.goals
               SET progress_pct = :pct, updated_at = now()
             WHERE id = :gid RETURNING id, progress_pct
        """), {"gid": str(goal_id), "pct": int(progress_pct)})).mappings().first()
        await self.session.commit()
        return SimpleNamespace(**dict(row))

    async def create_task(self, goal_id: UUID, request, user_id: UUID) -> SimpleNamespace:
        """Create a new task under a goal."""
        goal = await self._get_goal(goal_id)
        if not goal:
            raise APIError(error_code="GOAL_NOT_FOUND",
                           message="هدف یافت نشد.", status_code=404)
        if str(goal["owner_id"]) != str(user_id):
            raise APIError(error_code="PERMISSION_DENIED",
                           message="شما اجازه ساخت تسک این هدف را ندارید.",
                           status_code=403)
        row = (await self.session.execute(text("""
            INSERT INTO planning.tasks (goal_id, title, description, owner_id,
                                        assignee_id, privacy_level, status,
                                        priority, due_date, progress_pct)
            VALUES (:gid, :title, :desc, :owner, :assignee,
                    :lvl, 'pending', :pr, :dd, 0)
            RETURNING id
        """), {
            "gid": str(goal_id), "title": request.title,
            "desc": getattr(request, "description", None),
            "owner": str(user_id),
            "assignee": str(request.assignee_id) if getattr(request, "assignee_id", None) else None,
            "lvl": goal["privacy_level"],
            "pr": getattr(request, "priority", None) or "normal",
            "dd": getattr(request, "due_date", None),
        })).mappings().first()
        await self.session.commit()
        return SimpleNamespace(id=row["id"])

    async def list_tasks(self, goal_id: UUID, status: Optional[str],
                         assignee_id: Optional[UUID],
                         viewer_id: UUID) -> Tuple[List[dict], int]:
        """List tasks for a goal with privacy."""
        goal = await self._get_goal(goal_id)
        goal_privacy = goal["privacy_level"] if goal else "team_only"
        conds, params = ["t.goal_id = :gid", "t.deleted_at IS NULL"], {"gid": str(goal_id)}
        if status:
            conds.append("t.status = :st"); params["st"] = status
        if assignee_id:
            conds.append("t.assignee_id = :aid"); params["aid"] = str(assignee_id)
        where = " AND ".join(conds)
        rows = (await self.session.execute(text(f"""
            SELECT t.id, t.title, t.status, t.priority, t.progress_pct,
                   t.due_date, t.privacy_level::text AS privacy_level
              FROM planning.tasks t WHERE {where} ORDER BY t.created_at
        """), params)).mappings().all()
        private = goal_privacy == "fully_private" and str(goal["owner_id"]) != str(viewer_id)
        out = [{
            "id": str(t["id"]),
            "title": "—" if private else t["title"],
            "status": t["status"],
            "priority": t["priority"],
            "progress_pct": t["progress_pct"],
            "privacy_applied": private,
        } for t in rows]
        return out, len(out)

    async def add_tag(self, goal_id: UUID, tag_name: str, user_id: UUID) -> dict:
        """Add a tag to a goal."""
        goal = await self._get_goal(goal_id)
        if not goal:
            raise APIError(error_code="GOAL_NOT_FOUND",
                           message="هدف یافت نشد.", status_code=404)
        if str(goal["owner_id"]) != str(user_id):
            raise APIError(error_code="PERMISSION_DENIED",
                           message="شما اجازه افزودن تگ این هدف را ندارید.",
                           status_code=403)
        tag = (await self.session.execute(text("""
            INSERT INTO planning.tags (name, color)
            VALUES (:name, '#3B82F6')
            ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name
            RETURNING id
        """), {"name": tag_name})).mappings().first()
        await self.session.execute(text("""
            INSERT INTO planning.goal_tags (goal_id, tag_id)
            VALUES (:gid, :tid) ON CONFLICT DO NOTHING
        """), {"gid": str(goal_id), "tid": tag["id"]})
        await self.session.commit()
        return {"status": "added", "tag_name": tag_name}

    async def get_dashboard_data(self, goal_id: UUID, user_id: UUID) -> dict:
        """Goal dashboard data with privacy applied."""
        goal = await self._get_goal(goal_id)
        if not goal:
            raise APIError(error_code="GOAL_NOT_FOUND",
                           message="هدف یافت نشد.", status_code=404)
        decision = self._decision(goal, user_id)
        row = (await self.session.execute(text("""
            SELECT count(*) AS total,
                   count(*) FILTER (WHERE t.status = 'completed') AS done,
                   count(*) FILTER (WHERE t.status = 'in_progress') AS doing
              FROM planning.tasks t
             WHERE t.goal_id = :gid AND t.deleted_at IS NULL
        """), {"gid": str(goal_id)})).mappings().first()
        return {
            "goal": {"id": str(goal["id"]), "title": goal["title"]},
            "progress_pct": goal["progress_pct"],
            "tasks_total": int(row["total"]),
            "tasks_done": int(row["done"]),
            "tasks_in_progress": int(row["doing"]),
            "status": goal["status"],
            "privacy_applied": decision[0] != "full",
        }