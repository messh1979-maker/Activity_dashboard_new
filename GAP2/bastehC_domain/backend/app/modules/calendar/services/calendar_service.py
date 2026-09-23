"""Calendar service — real DDL (M5).

Raw SQL against schema ``calendar``: events, attendees, notes.
Mirrors the inbox pattern (raw ``sa.text``, ``SimpleNamespace``,
``_row_serialize``) so the ORM drift between code and the DDL
is handled consistently.
"""

from __future__ import annotations

from datetime import datetime, timedelta
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
    return d


class CalendarStateMachine:
    """Manages calendar events, attendees and notes (real DDL)."""

    def __init__(self, session):
        self.session = session

    async def create_event(self, owner_id: UUID, payload: dict) -> SimpleNamespace:
        """Insert a new event and return its identity + state."""
        row = (await self.session.execute(text("""
            INSERT INTO calendar.events (
                title, description, owner_id, privacy_level,
                start_time, end_time, all_day, recurrence_rule, status
            )
            VALUES (:title, :desc, :owner, :privacy, :start, :end,
                    :all_day, :recur, :status)
            RETURNING id, title, status, created_at
        """), {
            "title": payload["title"],
            "desc": payload.get("description"),
            "owner": str(owner_id),
            "privacy": payload.get("privacy_level", "team_only"),
            "start": payload["start_time"],
            "end": payload["end_time"],
            "all_day": payload.get("all_day", False),
            "recur": payload.get("recurrence_rule"),
            "status": payload.get("status", "active"),
        })).mappings().first()
        await self.session.commit()
        return SimpleNamespace(
            id=row["id"], title=row["title"], status=row["status"],
            created_at=_iso(row["created_at"]),
        )

    async def list_events(self, user_id: UUID,
                          date_from: Optional[datetime] = None,
                          date_to: Optional[datetime] = None,
                          status: Optional[str] = None) -> list[dict]:
        """List events the user owns or attends, with safe filtering."""
        conds = ["(e.owner_id = :uid OR EXISTS (SELECT 1 FROM calendar.attendees a WHERE a.event_id = e.id AND a.user_id = :uid))"]
        params: dict = {"uid": str(user_id)}
        if date_from:
            conds.append("e.start_time >= :from")
            params["from"] = date_from
        if date_to:
            conds.append("e.end_time <= :to")
            params["to"] = date_to
        if status:
            conds.append("e.status::text = :st")
            params["st"] = status

        rows = (await self.session.execute(text(f"""
            SELECT e.id, e.title, e.description, e.owner_id, e.privacy_level,
                   e.start_time, e.end_time, e.all_day, e.recurrence_rule,
                   e.status, e.created_at, e.updated_at, e.deleted_at
              FROM calendar.events e
             WHERE {" AND ".join(conds)}
             ORDER BY e.start_time ASC
        """), params)).mappings().all()
        return [_row_serialize(r) for r in rows]

    async def get_event(self, event_id: UUID,
                        user_id: UUID) -> dict:
        """Fetch a single event with its attendees and note count."""
        row = (await self.session.execute(text("""
            SELECT e.id, e.title, e.description, e.owner_id, e.privacy_level,
                   e.start_time, e.end_time, e.all_day, e.recurrence_rule,
                   e.status, e.created_at, e.updated_at, e.deleted_at
              FROM calendar.events e
             WHERE e.id = :eid AND (e.owner_id = :uid OR EXISTS (
                SELECT 1 FROM calendar.attendees a WHERE a.event_id = e.id AND a.user_id = :uid
             ))
        """), {"eid": str(event_id), "uid": str(user_id)})).mappings().first()
        if not row:
            raise NotFoundError(resource="calendar event")
        event = _row_serialize(row)

        attendees = (await self.session.execute(text("""
            SELECT a.user_id, a.response_status, a.notified_at, a.rsvp
              FROM calendar.attendees a WHERE a.event_id = :eid
        """), {"eid": str(event_id)})).mappings().all()
        event["attendees"] = [
            {"user_id": str(a["user_id"]), "response_status": a["response_status"],
             "notified_at": _iso(a["notified_at"]), "rsvp": a["rsvp"]}
            for a in attendees
        ]
        note_row = (await self.session.execute(text("""
            SELECT count(*) AS n FROM calendar.notes WHERE event_id = :eid
        """), {"eid": str(event_id)})).mappings().first()
        event["notes_count"] = note_row["n"] or 0
        return event

    async def update_event(self, event_id: UUID, user_id: UUID,
                           patch: dict) -> SimpleNamespace:
        """Patch event fields; returns updated identity."""
        set_parts, params = [], {"eid": str(event_id), "uid": str(user_id)}
        for col, key in (("title", "title"), ("description", "description"),
                         ("privacy_level", "privacy"), ("start_time", "start"),
                         ("end_time", "end"), ("all_day", "all_day"),
                         ("recurrence_rule", "recur"), ("status", "st")):
            if key in patch and patch[key] is not None:
                set_parts.append(f"{col} = :{key}")
                params[key] = patch[key]
        if not set_parts:
            raise APIError(error_code="NO_CHANGE",
                           message="هیچ فیلدی برای بروزرسانی داده نشد.",
                           status_code=400)
        set_parts.append("updated_at = now()")
        result = (await self.session.execute(text(f"""
            UPDATE calendar.events
               SET {" , ".join(set_parts)}
             WHERE id = :eid AND owner_id = :uid
         RETURNING id, title, status, updated_at
        """), params)).mappings().first()
        await self.session.commit()
        if not result:
            raise NotFoundError(resource="calendar event")
        return SimpleNamespace(id=result["id"], title=result["title"],
                               status=result["status"],
                               updated_at=_iso(result["updated_at"]))

    async def delete_event(self, event_id: UUID, user_id: UUID) -> SimpleNamespace:
        """Soft-delete an event (sets deleted_at)."""
        result = (await self.session.execute(text("""
            UPDATE calendar.events SET deleted_at = now()
             WHERE id = :eid AND owner_id = :uid
         RETURNING id
        """), {"eid": str(event_id), "uid": str(user_id)})).mappings().first()
        await self.session.commit()
        if not result:
            raise NotFoundError(resource="calendar event")
        return SimpleNamespace(id=result["id"])

    # --- Attendees ---

    async def add_attendee(self, event_id: UUID, user_id: UUID) -> SimpleNamespace:
        """Add attendee to an event (UPSERT)."""
        row = (await self.session.execute(text("""
            INSERT INTO calendar.attendees (event_id, user_id)
            VALUES (:eid, :uid)
            ON CONFLICT (event_id, user_id) DO NOTHING
            RETURNING event_id, user_id, response_status, rsvp
        """), {"eid": str(event_id), "uid": str(user_id)})).mappings().first()
        await self.session.commit()
        if not row:
            row = (await self.session.execute(text("""
                SELECT event_id, user_id, response_status, rsvp
                  FROM calendar.attendees
                 WHERE event_id = :eid AND user_id = :uid
            """), {"eid": str(event_id), "uid": str(user_id)})).mappings().first()
        return SimpleNamespace(event_id=row["event_id"],
                               user_id=row["user_id"],
                               response_status=row["response_status"],
                               rsvp=row["rsvp"])

    async def list_attendees(self, event_id: UUID) -> list[dict]:
        """List all attendees for an event."""
        rows = (await self.session.execute(text("""
            SELECT a.user_id, a.response_status, a.notified_at, a.rsvp
              FROM calendar.attendees a WHERE a.event_id = :eid
        """), {"eid": str(event_id)})).mappings().all()
        return [{"user_id": str(a["user_id"]), "response_status": a["response_status"],
                 "notified_at": _iso(a["notified_at"]), "rsvp": a["rsvp"]} for a in rows]

    async def set_response(self, event_id: UUID, user_id: UUID,
                           status: str) -> SimpleNamespace:
        """RSVP an attendee (pending/accepted/declined/tentative)."""
        valid = {"pending", "accepted", "declined", "tentative"}
        if status not in valid:
            raise APIError(error_code="INVALID_RESPONSE",
                           message="وضعیت پاسخ نامعتبر.", status_code=400)
        result = (await self.session.execute(text("""
            UPDATE calendar.attendees SET response_status = :st, notified_at = now()
             WHERE event_id = :eid AND user_id = :uid
         RETURNING event_id, user_id, response_status
        """), {"st": status, "eid": str(event_id), "uid": str(user_id)})).mappings().first()
        await self.session.commit()
        if not result:
            raise NotFoundError(resource="calendar attendee")
        return SimpleNamespace(event_id=result["event_id"],
                               user_id=result["user_id"],
                               response_status=result["response_status"])

    # --- Notes ---

    async def add_note(self, event_id: UUID, author_id: UUID,
                       content: str) -> SimpleNamespace:
        """Append a note to an event."""
        row = (await self.session.execute(text("""
            INSERT INTO calendar.notes (event_id, author_id, content)
            VALUES (:eid, :aid, :content)
            RETURNING id, content, created_at
        """), {"eid": str(event_id), "aid": str(author_id),
              "content": content})).mappings().first()
        await self.session.commit()
        return SimpleNamespace(id=row["id"], content=row["content"],
                               created_at=_iso(row["created_at"]))


CalendarService = CalendarStateMachine