"""Calendar module API routes (real DDL, M5).

CRUD for events/attendees/notes backed by ``calendar.events``,
``calendar.attendees`` and ``calendar.notes``.  This is the tested
implementation (the S3/newer patch that required `api/deps.py` is not
wired, mirrors other modules).
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, Body, Path, Query
from fastapi.responses import JSONResponse

from app.core.dependencies import get_db_session, get_current_user
from app.core.errors import APIError, NotFoundError
from app.modules.calendar.ports import (
    EventCreate, EventUpdate, AttendeeLink, NoteCreate,
)
from app.modules.calendar.services.calendar_service import CalendarService
from sqlalchemy import text

router = APIRouter(prefix="/calendar", tags=["calendar"])


@router.get("/events", response_model=dict)
async def list_events(
    user_id: UUID = Depends(get_current_user),
    date_from: Optional[datetime] = Query(None),
    date_to: Optional[datetime] = Query(None),
    status: Optional[str] = Query(None),
    db_session=Depends(get_db_session),
):
    """List events owned by or attended by the caller."""
    async with db_session() as session:
        try:
            svc = CalendarService(session)
            items = await svc.list_events(user_id, date_from, date_to, status)
            return {"status": "success", "data": items, "count": len(items)}
        except APIError as e:
            return JSONResponse(status_code=e.status_code,
                                content={"error": e.error_code,
                                         "message": e.message,
                                         "success": False})


@router.post("/events", response_model=dict)
async def create_event(
    payload: EventCreate,
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session),
):
    """Create a new calendar event."""
    async with db_session() as session:
        try:
            svc = CalendarService(session)
            result = await svc.create_event(user_id, payload.model_dump())
            return {"status": "event_created", "event_id": str(result.id),
                    "event_status": result.status}
        except APIError as e:
            return JSONResponse(status_code=e.status_code,
                                content={"error": e.error_code,
                                         "message": e.message,
                                         "success": False})


@router.get("/events/{event_id}", response_model=dict)
async def get_event(
    event_id: UUID = Path(...),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session),
):
    """Fetch a single event including attendees and note count."""
    async with db_session() as session:
        try:
            svc = CalendarService(session)
            event = await svc.get_event(event_id, user_id)
            return {"status": "success", "data": event}
        except (APIError, NotFoundError) as e:
            return JSONResponse(status_code=e.status_code,
                                content={"error": e.error_code,
                                         "message": e.message,
                                         "success": False})


@router.patch("/events/{event_id}", response_model=dict)
async def update_event(
    event_id: UUID = Path(...),
    patch: EventUpdate = Body(...),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session),
):
    """Patch an event the caller owns."""
    async with db_session() as session:
        try:
            svc = CalendarService(session)
            result = await svc.update_event(event_id, user_id,
                                             patch.model_dump(exclude_unset=True))
            return {"status": "event_updated", "event_id": str(result.id)}
        except (APIError, NotFoundError) as e:
            return JSONResponse(status_code=e.status_code,
                                content={"error": e.error_code,
                                         "message": e.message,
                                         "success": False})


@router.delete("/events/{event_id}", response_model=dict)
async def delete_event(
    event_id: UUID = Path(...),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session),
):
    """Soft-delete an event."""
    async with db_session() as session:
        try:
            svc = CalendarService(session)
            await svc.delete_event(event_id, user_id)
            return {"status": "event_deleted", "event_id": str(event_id)}
        except (APIError, NotFoundError) as e:
            return JSONResponse(status_code=e.status_code,
                                content={"error": e.error_code,
                                         "message": e.message,
                                         "success": False})


@router.post("/events/{event_id}/attendees", response_model=dict)
async def add_attendee(
    event_id: UUID = Path(...),
    link: AttendeeLink = Body(...),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session),
):
    """Add an attendee (or refresh their RSVP)."""
    async with db_session() as session:
        try:
            svc = CalendarService(session)
            a = await svc.add_attendee(event_id, link.user_id)
            return {"status": "attendee_added",
                    "event_id": str(a.event_id),
                    "user_id": str(a.user_id),
                    "response_status": a.response_status}
        except APIError as e:
            return JSONResponse(status_code=e.status_code,
                                content={"error": e.error_code,
                                         "message": e.message,
                                         "success": False})


@router.get("/events/{event_id}/attendees", response_model=dict)
async def list_attendees(
    event_id: UUID = Path(...),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session),
):
    """List attendees of an event."""
    async with db_session() as session:
        try:
            svc = CalendarService(session)
            attendees = await svc.list_attendees(event_id)
            return {"status": "success", "data": attendees}
        except APIError as e:
            return JSONResponse(status_code=e.status_code,
                                content={"error": e.error_code,
                                         "message": e.message,
                                         "success": False})


@router.put("/events/{event_id}/attendees/{attendee_user_id}/response",
            response_model=dict)
async def set_response(
    event_id: UUID = Path(...),
    attendee_user_id: UUID = Path(...),
    status: str = Body(..., embed=True),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session),
):
    """Record an attendee's RSVP response."""
    async with db_session() as session:
        try:
            svc = CalendarService(session)
            result = await svc.set_response(event_id, attendee_user_id, status)
            return {"status": "response_set",
                    "response_status": result.response_status}
        except (APIError, NotFoundError) as e:
            return JSONResponse(status_code=e.status_code,
                                content={"error": e.error_code,
                                         "message": e.message,
                                         "success": False})


@router.post("/events/{event_id}/notes", response_model=dict)
async def add_note(
    event_id: UUID = Path(...),
    note: NoteCreate = Body(...),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session),
):
    """Append a note to an event."""
    async with db_session() as session:
        try:
            svc = CalendarService(session)
            result = await svc.add_note(event_id, user_id, note.content)
            return {"status": "note_added", "note_id": str(result.id)}
        except APIError as e:
            return JSONResponse(status_code=e.status_code,
                                content={"error": e.error_code,
                                         "message": e.message,
                                         "success": False})


@router.get("/events/{event_id}/notes", response_model=dict)
async def list_notes(
    event_id: UUID = Path(...),
    user_id: UUID = Depends(get_current_user),
    db_session=Depends(get_db_session),
):
    """List notes for an event."""
    async with db_session() as session:
        try:
            svc = CalendarService(session)
            rows = (await session.execute(text("""
                SELECT n.id, n.event_id, n.author_id, n.content, n.created_at, n.updated_at
                  FROM calendar.notes n WHERE n.event_id = :eid
            """), {"eid": str(event_id)})).mappings().all()
            notes = [{"id": str(r["id"]), "event_id": str(r["event_id"]),
                      "author_id": str(r["author_id"]), "content": r["content"],
                      "created_at": r["created_at"].isoformat() if r["created_at"] else None,
                      "updated_at": r["updated_at"].isoformat() if r["updated_at"] else None}
                     for r in rows]
            return {"status": "success", "data": notes}
        except APIError as e:
            return JSONResponse(status_code=e.status_code,
                                content={"error": e.error_code,
                                         "message": e.message,
                                         "success": False})