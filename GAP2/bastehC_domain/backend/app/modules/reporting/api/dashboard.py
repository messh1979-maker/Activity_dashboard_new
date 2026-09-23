"""Dashboard read/composite endpoints (raw SQL, schema-qualified).

Rationale: ORM models in app/modules/*/db/Models.py drifted from the
alembic DDL (missing schema + columns), so every module service currently
500s on real queries. Rather than rewriting six model files, the dashboard
reads the architecture-compliant tables directly with qualified names.
Each widget query is independent -- one failing table never breaks the
whole summary.
"""

from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, Body
from fastapi.responses import JSONResponse
from sqlalchemy import text

from app.core.dependencies import get_db_session, get_current_user
from app.core.errors import APIError


dashboard_router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


def _rows(result):
    return [dict(r._mapping) for r in result]


def _iso(row: dict) -> dict:
    for k, v in list(row.items()):
        if hasattr(v, "isoformat"):
            row[k] = v.isoformat()
        elif not isinstance(v, (str, int, float, bool, type(None))):
            row[k] = str(v)
    return row


async def _fetch(session, sql: str, params: dict):
    try:
        result = await session.execute(text(sql), params)
        return [_iso(r) for r in _rows(result)]
    except Exception:
        return None  # widget-level degradation, never 500 the dashboard


@dashboard_router.get("/summary", response_model=dict)
async def dashboard_summary(
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session),
):
    """One call powering the whole dashboard page."""
    async with db_session() as session:
        p = {"uid": str(user_id)}

        goals = await _fetch(session, """
            SELECT id::text AS id, title, description, status,
                   progress_pct, due_date, created_at
              FROM planning.goals
             WHERE owner_id = :uid AND deleted_at IS NULL
             ORDER BY created_at DESC LIMIT 10
        """, p) or []

        goal_counts = await _fetch(session, """
            SELECT status, COUNT(*)::int AS n
              FROM planning.goals
             WHERE owner_id = :uid AND deleted_at IS NULL
             GROUP BY status
        """, p) or []

        tasks = await _fetch(session, """
            SELECT t.id::text AS id, t.title, t.status, t.priority,
                   t.due_date, g.title AS goal_title
              FROM planning.tasks t
              LEFT JOIN planning.goals g ON g.id = t.goal_id
             WHERE (t.owner_id = :uid OR t.assignee_id = :uid)
               AND t.deleted_at IS NULL AND t.status IN ('pending','in_progress')
             ORDER BY t.created_at DESC LIMIT 10
        """, p) or []

        inbox = await _fetch(session, """
            SELECT i.id::text AS id, i.title, i.message, i.item_type,
                   i.priority, i.action_state, i.created_at,
                   u.display_name AS sender_name
              FROM inbox.items i
              LEFT JOIN auth.users u ON u.id = i.sender_id
             WHERE i.recipient_id = :uid AND i.action_state = 'pending'
             ORDER BY i.created_at DESC LIMIT 10
        """, p) or []

        inbox_pending = await _fetch(session, """
            SELECT COUNT(*)::int AS n FROM inbox.items
             WHERE recipient_id = :uid AND action_state = 'pending'
        """, p)
        pending_n = (inbox_pending or [{"n": 0}])[0]["n"]

        groups = await _fetch(session, """
            SELECT g.id::text AS id, g.name, gm.is_manager
              FROM groups.groups g
              JOIN groups.group_members gm ON gm.group_id = g.id
             WHERE gm.user_id = :uid AND g.deleted_at IS NULL AND g.is_active
             ORDER BY g.name LIMIT 20
        """, p) or []

        rooms = await _fetch(session, """
            SELECT r.id::text AS id, r.title, r.linked_type
              FROM chat.rooms r
              JOIN chat.room_members m ON m.room_id = r.id
             WHERE m.user_id = :uid AND m.left_at IS NULL
               AND r.deleted_at IS NULL AND NOT r.is_archived
             ORDER BY r.created_at DESC LIMIT 10
        """, p)
        if rooms is None:  # older DDL without left_at? degrade gracefully
            rooms = []

        stats = {
            "goals_active": sum(r["n"] for r in goal_counts if r["status"] == "active"),
            "goals_completed": sum(r["n"] for r in goal_counts if r["status"] == "completed"),
            "goals_total": sum(r["n"] for r in goal_counts),
            "tasks_open": len(tasks),
            "inbox_pending": pending_n,
            "groups_count": len(groups),
            "rooms_count": len(rooms),
        }

        return {
            "status": "success",
            "data": {
                "stats": stats,
                "recent_goals": goals,
                "open_tasks": tasks,
                "pending_inbox": inbox,
                "my_groups": groups,
                "my_rooms": rooms,
            },
        }


@dashboard_router.get("/goals", response_model=dict)
async def dashboard_goals(
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session),
):
    async with db_session() as session:
        goals = await _fetch(session, """
            SELECT id::text AS id, title, description, status,
                   progress_pct, due_date, created_at
              FROM planning.goals
             WHERE owner_id = :uid AND deleted_at IS NULL
             ORDER BY created_at DESC LIMIT 50
        """, {"uid": str(user_id)}) or []
        return {"status": "success", "data": goals}


@dashboard_router.post("/goals", response_model=dict, status_code=201)
async def dashboard_create_goal(
    payload: dict = Body(...),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session),
):
    title = (payload.get("title") or "").strip()
    if not title:
        return JSONResponse(status_code=400, content={
            "error": "TITLE_REQUIRED",
            "message": "عنوان هدف الزامی است.",
            "success": False,
        })
    async with db_session() as session:
        try:
            result = await session.execute(text("""
                INSERT INTO planning.goals
                    (owner_id, title, description, due_date, status, progress_pct)
                VALUES (:uid, :title, :desc, :due, 'active', 0)
                RETURNING id::text AS id
            """), {
                "uid": str(user_id),
                "title": title[:255],
                "desc": (payload.get("description") or None),
                "due": payload.get("due_date") or None,
            })
            new_id = result.scalar_one()
            await session.commit()
            return {"status": "success", "data": {"id": new_id}}
        except APIError as e:
            return JSONResponse(status_code=e.status_code, content={
                "error": e.error_code, "message": e.message, "success": False})
        except Exception:
            await session.rollback()
            return JSONResponse(status_code=500, content={
                "error": "CREATE_FAILED",
                "message": "ایجاد هدف ناموفق بود.",
                "success": False,
            })


@dashboard_router.post("/inbox/{item_id}/act", response_model=dict)
async def dashboard_inbox_act(
    item_id: UUID,
    payload: dict = Body(...),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session),
):
    action = (payload.get("action") or "").strip().lower()
    if action not in ("accepted", "rejected", "deferred"):
        return JSONResponse(status_code=400, content={
            "error": "INVALID_ACTION",
            "message": "عمل باید accepted/rejected/deferred باشد.",
            "success": False,
        })
    async with db_session() as session:
        try:
            result = await session.execute(text("""
                UPDATE inbox.items
                   SET action_state = CAST(:action AS inbox.item_action),
                       receipt_state = 'acted',
                       acted_at = now(),
                       response_note = :note,
                       defer_until = CASE WHEN :action = 'deferred'
                                          THEN COALESCE(:defer, now() + interval '3 days')
                                          ELSE defer_until END,
                       seen_at = COALESCE(seen_at, now())
                 WHERE id = :iid AND recipient_id = :uid
                   AND action_state = 'pending'
                RETURNING id::text AS id
            """), {
                "action": action,
                "note": payload.get("note"),
                "defer": payload.get("defer_until"),
                "iid": str(item_id),
                "uid": str(user_id),
            })
            row = result.mappings().first()
            if row is None:
                return JSONResponse(status_code=404, content={
                    "error": "NOT_FOUND",
                    "message": "آیتم یافت نشد یا قبلاً تعیین تکلیف شده.",
                    "success": False,
                })
            await session.commit()
            return {"status": "success",
                    "data": {"id": row["id"], "action_state": action}}
        except Exception:
            await session.rollback()
            return JSONResponse(status_code=500, content={
                "error": "ACT_FAILED",
                "message": "ثبت تصمیم ناموفق بود.",
                "success": False,
            })
