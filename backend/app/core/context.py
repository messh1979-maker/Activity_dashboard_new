"""Per-request context (architecture 3.1: ``core/context.py``).

Uses :mod:`contextvars`, so concurrent requests/tasks never see each other's
values. (The old implementation stored a single module-level global, which
leaks user/IP/MAC between simultaneous requests - and audit rows are built
from this data.)
"""
from __future__ import annotations

from contextvars import ContextVar, Token
from dataclasses import asdict, dataclass, field
from typing import Any, Optional
from uuid import uuid4


@dataclass
class RequestContext:
    request_id: str = field(default_factory=lambda: str(uuid4()))
    correlation_id: Optional[str] = None
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    ip: Optional[str] = None
    user_agent: Optional[str] = None
    mac_address: Optional[str] = None
    mac_verified: bool = False
    device_fingerprint: Optional[str] = None
    path: Optional[str] = None
    method: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


_ctx: ContextVar[Optional[RequestContext]] = ContextVar("request_ctx", default=None)


def set_context(ctx: RequestContext) -> Token:
    return _ctx.set(ctx)


def reset_context(token: Token) -> None:
    _ctx.reset(token)


def get_context() -> RequestContext:
    """Current context, or an empty one outside a request (workers, tests)."""
    return _ctx.get() or RequestContext()


def bind_user(user_id: Any, session_id: Any = None) -> None:
    """Called after authentication so later audit rows carry the actor."""
    ctx = _ctx.get()
    if ctx is not None:
        ctx.user_id = str(user_id) if user_id is not None else None
        if session_id is not None:
            ctx.session_id = str(session_id)
