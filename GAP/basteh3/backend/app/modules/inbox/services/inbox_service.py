"""
Inbox State Machine Implementation (real DDL).

Architecture Reference: Sections 9.1, 9.2, 11.1.
State Machine: pending -> accepted/rejected/deferred/expired
Read Receipt: sent -> seen -> acted

Raw SQL against schema ``inbox``; the ORM models drifted from the DDL.
"""

from uuid import UUID
from datetime import datetime, timedelta
from typing import Optional, Literal
from types import SimpleNamespace

from sqlalchemy import text

from app.core.errors import APIError, NotFoundError
from app.modules.inbox.ports import INBOX_ITEM_TYPES


def _iso(v):
    return v.isoformat() if isinstance(v, datetime) else v


def _row_serialize(r) -> dict:
    d = dict(r)
    for k in (k for k in d if d[k] is not None):
        if isinstance(d[k], datetime):
            d[k] = _iso(d[k])
    return d


class InboxStateMachine:
    """Manages inbox item state transitions and read receipts (real DDL)."""

    def __init__(self, session):
        self.session = session

    async def create_item(self, sender_id: UUID, recipient_id: UUID,
                          item_type: str, entity_type: Optional[str],
                          entity_id: Optional[UUID], title: str,
                          message: Optional[str], priority: str,
                          due_at: Optional[datetime], expires_at: Optional[datetime]
                          ) -> SimpleNamespace:
        """Create a new inbox item with initial state."""
        valid_types = [t.value for t in INBOX_ITEM_TYPES]
        if item_type not in valid_types:
            raise APIError(error_code="INVALID_ITEM_TYPE",
                           message="نوع آیتم نامعتبر.", status_code=400)
        row = (await self.session.execute(text("""
            INSERT INTO inbox.items (sender_id, recipient_id, item_type,
                                     entity_type, entity_id, title, message,
                                     priority, action_state, receipt_state,
                                     due_at, expires_at)
            VALUES (:sid, :rid, :itype, :etype, :eid, :title, :msg,
                    :prio, 'pending', 'sent', :due, :exp)
            RETURNING id, action_state, receipt_state
        """), {
            "sid": str(sender_id), "rid": str(recipient_id),
            "itype": item_type, "etype": entity_type,
            "eid": str(entity_id) if entity_id else None,
            "title": title, "msg": message, "prio": priority,
            "due": due_at, "exp": expires_at,
        })).mappings().first()
        await self.session.execute(text("""
            INSERT INTO inbox.receipts (item_id, user_id, state)
            VALUES (:iid, :uid, 'sent')
        """), {"iid": row["id"], "uid": str(recipient_id)})
        await self.session.commit()
        return SimpleNamespace(id=row["id"], action_state=row["action_state"],
                               receipt_state=row["receipt_state"])

    async def list_items(self, user_id: UUID, state: Optional[str] = None) -> list:
        """List inbox items for a recipient."""
        conds, params = ["recipient_id = :uid"], {"uid": str(user_id)}
        if state:
            conds.append("action_state::text = :st"); params["st"] = state
        rows = (await self.session.execute(text(f"""
            SELECT id, sender_id, recipient_id, item_type, entity_type,
                   entity_id, title, message, priority,
                   action_state::text AS action_state, receipt_state::text AS receipt_state,
                   seen_at, acted_at, defer_until, response_note, due_at, expires_at, created_at
              FROM inbox.items WHERE {" AND ".join(conds)}
             ORDER BY created_at DESC
        """), params)).mappings().all()
        return [_row_serialize(r) for r in rows]

    async def list_outbox(self, user_id: UUID) -> list:
        """List outbox items sent by a user."""
        rows = (await self.session.execute(text("""
            SELECT id, sender_id, recipient_id, item_type, entity_type,
                   entity_id, title, message, read_receipt, created_at,
                   recipient_acknowledged_at, recipient_acknowledged_note
              FROM inbox.outbox WHERE sender_id = :uid
             ORDER BY created_at DESC
        """), {"uid": str(user_id)})).mappings().all()
        return [_row_serialize(r) for r in rows]

    async def act_on_item(self, item_id: UUID, action: Literal["accepted", "rejected", "deferred"],
                          note: Optional[str], actor_id: UUID) -> SimpleNamespace:
        """Handle item action (accept, reject, defer)."""
        item = (await self.session.execute(text("""
            SELECT id, recipient_id, action_state::text AS action_state FROM inbox.items
             WHERE id = :iid
        """), {"iid": str(item_id)})).mappings().first()
        if not item:
            raise APIError(error_code="ITEM_NOT_FOUND",
                           message="آیتم یافت نشد.", status_code=404)
        if str(item["recipient_id"]) != str(actor_id):
            raise APIError(error_code="PERMISSION_DENIED",
                           message="شما اجازه عملکرد بر این آیتم را ندارید.",
                           status_code=403)
        now = datetime.utcnow()
        valid = {"accepted", "rejected", "deferred"}
        if action not in valid:
            raise APIError(error_code="INVALID_ACTION",
                           message="عملیات نامعتبر.", status_code=400)
        new_state = action
        defer_until = (now + timedelta(hours=48)) if action == "deferred" else None
        await self.session.execute(text("""
            UPDATE inbox.items
               SET action_state = :st, receipt_state = 'acted',
                   acted_at = now(), defer_until = :defer, response_note = :note
             WHERE id = :iid
        """), {"st": new_state, "defer": defer_until, "note": note,
               "iid": str(item_id)})
        await self.session.execute(text("""
            INSERT INTO inbox.receipts (item_id, user_id, state, acted_at, note)
            VALUES (:iid, :uid, 'acted', now(), :note)
            ON CONFLICT DO NOTHING
        """), {"iid": str(item_id), "uid": str(actor_id), "note": note})
        await self.session.commit()
        return SimpleNamespace(action_state=new_state, receipt_state="acted",
                               acted_at=now, note=note)

    async def mark_read(self, item_id: UUID, reader_id: UUID) -> SimpleNamespace:
        """Mark inbox item as read."""
        item = (await self.session.execute(text("""
            SELECT recipient_id FROM inbox.items WHERE id = :iid
        """), {"iid": str(item_id)})).mappings().first()
        if not item:
            raise APIError(error_code="ITEM_NOT_FOUND",
                           message="آیتم یافت نشد.", status_code=404)
        if str(item["recipient_id"]) != str(reader_id):
            raise APIError(error_code="PERMISSION_DENIED",
                           message="شما اجازه خواندن این آیتم را ندارید.",
                           status_code=403)
        await self.session.execute(text("""
            UPDATE inbox.items SET receipt_state = 'seen', seen_at = now()
             WHERE id = :iid
        """), {"iid": str(item_id)})
        await self.session.execute(text("""
            INSERT INTO inbox.receipts (item_id, user_id, state, seen_at)
            VALUES (:iid, :uid, 'seen', now())
            ON CONFLICT DO NOTHING
        """), {"iid": str(item_id), "uid": str(reader_id)})
        await self.session.commit()
        return SimpleNamespace(receipt_state="seen")

    async def create_outbox(self, sender_id: UUID, recipient_id: UUID,
                            item_type: str, entity_type: Optional[str],
                            entity_id: Optional[UUID], title: str,
                            message: Optional[str]) -> SimpleNamespace:
        """Create outbox item (sent item)."""
        row = (await self.session.execute(text("""
            INSERT INTO inbox.outbox (sender_id, recipient_id, item_type,
                                      entity_type, entity_id, title, message, read_receipt)
            VALUES (:sid, :rid, :itype, :etype, :eid, :title, :msg, FALSE)
            RETURNING id
        """), {
            "sid": str(sender_id), "rid": str(recipient_id),
            "itype": item_type, "etype": entity_type,
            "eid": str(entity_id) if entity_id else None,
            "title": title, "msg": message,
        })).mappings().first()
        await self.session.commit()
        return SimpleNamespace(id=row["id"])

    async def check_expiries(self) -> dict:
        """Check and process expired items."""
        result = await self.session.execute(text("""
            UPDATE inbox.items SET action_state = 'expired', receipt_state = 'acted',
                                   acted_at = now()
             WHERE action_state = 'pending' AND expires_at IS NOT NULL AND expires_at < now()
            RETURNING id
        """))
        expired = result.rowcount or 0
        await self.session.commit()
        return {"expired_count": expired, "processed": True}


# Name used by the API layer (routes import ``InboxService``).
InboxService = InboxStateMachine