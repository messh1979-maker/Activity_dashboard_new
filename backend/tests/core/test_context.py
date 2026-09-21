import asyncio

from app.core.context import RequestContext, get_context, reset_context, set_context


async def _worker(name: str, delay: float):
    tok = set_context(RequestContext(request_id=name, user_id=name))
    await asyncio.sleep(delay)
    seen = get_context().user_id
    reset_context(tok)
    return seen


async def test_concurrent_contexts_do_not_leak():
    results = await asyncio.gather(*[_worker(f"u{i}", 0.01 * (5 - i)) for i in range(5)])
    assert results == [f"u{i}" for i in range(5)]


def test_empty_context_outside_request():
    assert get_context().user_id is None
