"""Event bus + transactional outbox (architecture 2.3). Needs PostgreSQL."""
from __future__ import annotations

import os
from uuid import uuid4

import pytest
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.core.context import RequestContext, reset_context, set_context
from app.core.events.bus import DomainEvent, EventBus
from app.core.events.dispatcher import MAX_ATTEMPTS, dispatch_pending_outbox_messages
from app.core.events.outbox import OutboxMessage

pytestmark = pytest.mark.integration


@pytest.fixture
async def factory():
    engine = create_async_engine(os.environ["SQLALCHEMY_DATABASE_URI"])
    try:
        async with engine.connect() as c:
            await c.execute(text("SELECT 1 FROM core.outbox_messages LIMIT 1"))
    except Exception as exc:  # no DB / migrations not applied
        await engine.dispose()
        pytest.skip(f"PostgreSQL with migrations not available: {exc}")
    yield async_sessionmaker(engine, expire_on_commit=False)
    await engine.dispose()


def _ev(kind: str, **payload) -> DomainEvent:
    return DomainEvent(event_type=kind, payload=payload)


async def _row(factory, event_id):
    async with factory() as s:
        return (await s.execute(select(OutboxMessage).where(
            OutboxMessage.event_id == event_id))).scalar_one_or_none()


async def test_outbox_row_is_atomic_with_transaction(factory):
    bus = EventBus()
    kept, dropped = _ev("t.kept"), _ev("t.dropped")
    async with factory() as s:
        await bus.publish(kept, s)
        await s.commit()
    async with factory() as s:
        await bus.publish(dropped, s)
        await s.rollback()  # business transaction fails -> no event may survive
    assert await _row(factory, kept.event_id) is not None
    assert await _row(factory, dropped.event_id) is None


async def test_transactional_handler_runs_inline_and_is_not_replayed(factory):
    bus, calls = EventBus(), []

    async def inline(event, session):
        calls.append(("inline", event.event_id))

    bus.subscribe("t.audit", inline)  # default: same transaction
    ev = _ev("t.audit")
    async with factory() as s:
        await bus.publish(ev, s)
        await s.commit()
    assert calls == [("inline", ev.event_id)]

    # Dispatcher must not re-run transactional handlers (old bug: duplicate audit rows)
    import app.core.events.dispatcher as d
    original, d.event_bus = d.event_bus, bus
    try:
        async with factory() as s:
            await dispatch_pending_outbox_messages(s, batch_size=1000)
    finally:
        d.event_bus = original
    assert len(calls) == 1
    assert (await _row(factory, ev.event_id)).dispatched_at is not None


async def test_handler_failure_rolls_back_publish(factory):
    bus = EventBus()

    async def bad(event, session):
        raise RuntimeError("boom")

    bus.subscribe("t.bad", bad)
    ev = _ev("t.bad")
    async with factory() as s:
        with pytest.raises(RuntimeError):
            await bus.publish(ev, s)
        await s.rollback()
    assert await _row(factory, ev.event_id) is None


async def test_async_consumer_delivery_retry_and_dead_letter(factory):
    import app.core.events.dispatcher as d

    bus, seen, fail = EventBus(), [], {"on": True}

    async def notify(event, session):
        if event.payload.get("poison") and fail["on"]:
            raise RuntimeError("smtp down")
        seen.append(event.event_id)

    bus.subscribe("t.notify", notify, transactional=False)
    good, poison = _ev("t.notify"), _ev("t.notify", poison=True)
    async with factory() as s:
        await bus.publish(good, s)
        await bus.publish(poison, s)
        await s.commit()
    assert seen == []  # not delivered in-process

    original, d.event_bus = d.event_bus, bus
    try:
        async with factory() as s:
            await dispatch_pending_outbox_messages(s, batch_size=10_000)
        # a poison row must not block the good one (SAVEPOINT per row)
        assert good.event_id in seen and poison.event_id not in seen
        bad = await _row(factory, poison.event_id)
        assert bad.dispatched_at is None and bad.attempts == 1 and "smtp down" in bad.last_error

        for _ in range(MAX_ATTEMPTS):  # keeps failing -> parked after MAX_ATTEMPTS
            async with factory() as s:
                await dispatch_pending_outbox_messages(s, batch_size=10_000)
        assert (await _row(factory, poison.event_id)).attempts == MAX_ATTEMPTS

        fail["on"] = False  # at-least-once: still nothing delivered twice for `good`
        assert seen.count(good.event_id) == 1
    finally:
        d.event_bus = original


async def test_context_fills_actor_and_correlation(factory):
    bus, uid, cid = EventBus(), uuid4(), uuid4()
    token = set_context(RequestContext(user_id=str(uid), correlation_id=str(cid)))
    try:
        ev = _ev("t.ctx")
        async with factory() as s:
            await bus.publish(ev, s)
            await s.commit()
    finally:
        reset_context(token)
    assert (await _row(factory, ev.event_id)).correlation_id == cid


def test_subscribe_is_idempotent():
    bus = EventBus()

    async def h(e, s): ...

    bus.subscribe("x", h); bus.subscribe("x", h)
    assert bus.handlers_for("x", transactional=True) == [h]
