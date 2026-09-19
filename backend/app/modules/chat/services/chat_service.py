"""Chat service — raw SQL against the real DDL (schema ``chat``).

Architecture Reference: Sections 8.1, 8.2, 8.3.
"""
from typing import Optional, List
from types import SimpleNamespace
from uuid import UUID
from datetime import datetime

from sqlalchemy import text

from app.core.errors import APIError, NotFoundError


def _iso(v):
    return v.isoformat() if isinstance(v, datetime) else v


class ChatService:
    """Service layer for Chat module operations (real DDL)."""

    def __init__(self, session):
        self.session = session

    async def _member_of(self, room_id: UUID, user_id: UUID) -> bool:
        row = (await self.session.execute(text("""
            SELECT 1 FROM chat.room_members
             WHERE room_id = :rid AND user_id = :uid AND left_at IS NULL
        """), {"rid": str(room_id), "uid": str(user_id)})).first()
        return row is not None

    async def create_room(self, title: str, linked_type: Optional[str],
                          linked_id: Optional[UUID], owner_id: UUID) -> SimpleNamespace:
        """Create a new chat room."""
        row = (await self.session.execute(text("""
            INSERT INTO chat.rooms (title, linked_type, linked_id, owner_id,
                                    is_archived, retention_days)
            VALUES (:title, :ltype, :lid, :owner, FALSE, 30)
            RETURNING id, title, owner_id, is_archived
        """), {"title": title, "ltype": linked_type,
               "lid": str(linked_id) if linked_id else None,
               "owner": str(owner_id)})).mappings().first()
        # Add room creator as an owner member
        await self.session.execute(text("""
            INSERT INTO chat.room_members (room_id, user_id, role)
            VALUES (:rid, :uid, 'owner')
            ON CONFLICT DO NOTHING
        """), {"rid": row["id"], "uid": str(owner_id)})
        await self.session.commit()
        return SimpleNamespace(id=row["id"], title=row["title"],
                               owner_id=row["owner_id"], is_archived=row["is_archived"])

    async def list_rooms(self, user_id: UUID) -> List[dict]:
        """List rooms user is member of."""
        rows = (await self.session.execute(text("""
            SELECT r.id, r.title, r.is_archived, r.owner_id, r.linked_type, r.linked_id,
                   (SELECT count(*) FROM chat.room_members m
                     WHERE m.room_id = r.id AND m.left_at IS NULL) AS member_count
              FROM chat.rooms r
              JOIN chat.room_members m ON m.room_id = r.id
             WHERE m.user_id = :uid AND m.left_at IS NULL
               AND r.is_archived = FALSE
             ORDER BY r.created_at DESC
        """), {"uid": str(user_id)})).mappings().all()
        return [{
            "id": str(r["id"]),
            "title": r["title"],
            "is_archived": r["is_archived"],
            "member_count": int(r["member_count"]),
            "owner_id": str(r["owner_id"]),
            "linked_type": r["linked_type"],
            "linked_id": str(r["linked_id"]) if r["linked_id"] else None,
        } for r in rows]

    async def get_room(self, room_id: UUID, user_id: UUID) -> Optional[dict]:
        """Get room with membership check."""
        row = (await self.session.execute(text("""
            SELECT id, title, owner_id, is_archived, linked_type, linked_id,
                   retention_days, created_at
              FROM chat.rooms WHERE id = :rid
        """), {"rid": str(room_id)})).mappings().first()
        if not row:
            return None
        if not await self._member_of(room_id, user_id):
            return None
        cnt = (await self.session.execute(text("""
            SELECT count(*) AS n FROM chat.room_members
             WHERE room_id = :rid AND left_at IS NULL
        """), {"rid": str(room_id)})).mappings().first()
        return {
            "id": str(row["id"]),
            "title": row["title"],
            "description": None,
            "is_archived": row["is_archived"],
            "member_count": int(cnt["n"]),
            "owner_id": str(row["owner_id"]),
            "linked_type": row["linked_type"],
            "linked_id": str(row["linked_id"]) if row["linked_id"] else None,
        }

    async def add_member(self, room_id: UUID, user_id: UUID, role: str,
                         added_by: UUID) -> dict:
        """Add member to room."""
        room = (await self.session.execute(text(
            "SELECT 1 FROM chat.rooms WHERE id = :rid"),
            {"rid": str(room_id)})).first()
        if not room:
            raise APIError(error_code="ROOM_NOT_FOUND",
                           message="اتاق یافت نشد.", status_code=404)
        await self.session.execute(text("""
            INSERT INTO chat.room_members (room_id, user_id, role, joined_at)
            VALUES (:rid, :uid, :role, now())
            ON CONFLICT (room_id, user_id)
            DO UPDATE SET left_at = NULL, role = EXCLUDED.role
        """), {"rid": str(room_id), "uid": str(user_id), "role": role})
        await self.session.commit()
        return {"status": "added", "room_id": str(room_id), "user_id": str(user_id)}

    async def send_message(self, room_id: UUID, body: str,
                           sender_id: UUID) -> SimpleNamespace:
        """Send a chat message."""
        room = (await self.session.execute(text("""
            SELECT is_archived, owner_id FROM chat.rooms WHERE id = :rid
        """), {"rid": str(room_id)})).mappings().first()
        if not room:
            raise APIError(error_code="ROOM_NOT_FOUND",
                           message="اتاق یافت نشد.", status_code=404)
        if room["is_archived"] and str(room["owner_id"]) != str(sender_id):
            raise APIError(error_code="ROOM_ARCHIVED",
                           message="اتاق آرشیو شده است.", status_code=403)
        if not await self._member_of(room_id, sender_id):
            raise APIError(error_code="NOT_MEMBER",
                           message="شما عضو این اتاق نیستید.", status_code=403)
        if len(body) > 4000:
            raise APIError(error_code="MESSAGE_TOO_LONG",
                           message="متن پیام بیش از حد مجاز است.", status_code=400)
        row = (await self.session.execute(text("""
            INSERT INTO chat.messages (room_id, sender_id, body, message_type, is_edited)
            VALUES (:rid, :uid, :body, 'text', FALSE)
            RETURNING id, room_id, sender_id, body, created_at, message_type, is_edited
        """), {"rid": str(room_id), "uid": str(sender_id), "body": body})).mappings().first()
        await self.session.commit()
        return SimpleNamespace(**dict(row))

    async def get_messages(self, room_id: UUID, viewer_id: UUID) -> List[dict]:
        """Get messages for a room."""
        if not await self._member_of(room_id, viewer_id):
            return []
        rows = (await self.session.execute(text("""
            SELECT id, room_id, sender_id, body, message_type, is_edited,
                   is_edited AS edited, created_at
              FROM chat.messages
             WHERE room_id = :rid AND deleted_at IS NULL
             ORDER BY created_at ASC
             LIMIT 200
        """), {"rid": str(room_id)})).mappings().all()
        return [{
            "id": str(m["id"]),
            "room_id": str(m["room_id"]),
            "sender_id": str(m["sender_id"]),
            "body": m["body"],
            "sender_name": "user",
            "created_at": _iso(m["created_at"]),
            "message_type": m["message_type"],
            "is_edited": m["is_edited"],
        } for m in rows]

    async def archive_room(self, room_id: UUID, archived_by: UUID) -> dict:
        """Archive a chat room."""
        room = (await self.session.execute(text("""
            SELECT owner_id FROM chat.rooms WHERE id = :rid
        """), {"rid": str(room_id)})).mappings().first()
        if not room:
            raise APIError(error_code="ROOM_NOT_FOUND",
                           message="اتاق یافت نشد.", status_code=404)
        if str(room["owner_id"]) != str(archived_by):
            raise APIError(error_code="PERMISSION_DENIED",
                           message="شما اجازه آرشیو این اتاق را ندارید.", status_code=403)
        await self.session.execute(text("""
            UPDATE chat.rooms SET is_archived = TRUE, archived_at = now()
             WHERE id = :rid
        """), {"rid": str(room_id)})
        await self.session.commit()
        return {"status": "archived"}