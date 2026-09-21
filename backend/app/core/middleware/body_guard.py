"""Request body size guard (architecture 3.1 ``body_guard``).

Checks ``Content-Length`` up front and also counts streamed bytes, so
chunked uploads cannot bypass the limit. Upload endpoints (``/files``) use
``MAX_UPLOAD_SIZE`` instead of the small JSON limit.
"""
from __future__ import annotations

from starlette.datastructures import Headers
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.config import settings
from app.core.middleware._http import send_error

_UPLOAD_PREFIXES = ("/api/v1/files",)


class _TooLarge(Exception):
    pass


class BodyGuardMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope["method"] in ("GET", "HEAD", "OPTIONS"):
            await self.app(scope, receive, send)
            return
        limit = (settings.MAX_UPLOAD_SIZE
                 if scope.get("path", "").startswith(_UPLOAD_PREFIXES)
                 else settings.MAX_BODY_SIZE)
        declared = Headers(scope=scope).get("content-length")
        if declared is not None:
            try:
                too_big = int(declared) > limit
            except ValueError:
                too_big = True
            if too_big:
                await send_error(scope, receive, send, status=413,
                                 code="PAYLOAD_TOO_LARGE",
                                 message="حجم درخواست بیش از حد مجاز است.")
                return

        received = 0
        exceeded = False
        started = False

        async def counting_receive() -> Message:
            nonlocal received, exceeded
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > limit:
                    exceeded = True
                    raise _TooLarge()
            return message

        async def tracking_send(message: Message) -> None:
            nonlocal started
            if exceeded:
                # FastAPI wraps any body-read exception into its own 400; once the
                # limit was crossed that response is wrong, so swallow it and let
                # the 413 below win.
                return
            if message["type"] == "http.response.start":
                started = True
            await send(message)

        try:
            await self.app(scope, counting_receive, tracking_send)
        except _TooLarge:
            pass
        if exceeded and not started:
            await send_error(scope, receive, send, status=413,
                             code="PAYLOAD_TOO_LARGE",
                             message="حجم درخواست بیش از حد مجاز است.")
