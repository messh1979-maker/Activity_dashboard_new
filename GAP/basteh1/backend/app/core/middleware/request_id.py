"""Creates the per-request context and the ``X-Request-ID`` header."""
from __future__ import annotations

import re
from uuid import uuid4

from starlette.datastructures import Headers, MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.context import RequestContext, reset_context, set_context

_SAFE_ID = re.compile(r"^[A-Za-z0-9\-_.]{8,64}$")


class RequestIDMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return
        incoming = Headers(scope=scope).get("x-request-id", "")
        # Accept a client id only if it is short/safe (log-injection guard).
        request_id = incoming if _SAFE_ID.match(incoming) else str(uuid4())
        ctx = RequestContext(request_id=request_id, path=scope.get("path"),
                             method=scope.get("method"))
        scope.setdefault("state", {})["request_id"] = request_id
        token = set_context(ctx)

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                MutableHeaders(scope=message)["X-Request-ID"] = request_id
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            reset_context(token)
