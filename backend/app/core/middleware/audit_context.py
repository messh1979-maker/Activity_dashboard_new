"""Fills network/device identity into the request context (architecture 3.1).

The identity that ends up in audit rows always comes from here (headers /
socket), never from a request body. ``mac_verified`` stays False until the
device-binding step validates the HMAC signature (ADR-08: MAC is a forensic
signal, not a security control).
"""
from __future__ import annotations

import re

from starlette.datastructures import Headers
from starlette.types import ASGIApp, Receive, Scope, Send

from app.core.context import get_context
from app.core.middleware._http import client_ip

_MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$")
_FP_RE = re.compile(r"^[A-Za-z0-9+/=_\-]{16,255}$")


class AuditContextMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] in ("http", "websocket"):
            h = Headers(scope=scope)
            ctx = get_context()
            ctx.ip = client_ip(scope)
            ctx.user_agent = (h.get("user-agent") or "")[:512] or None
            mac = h.get("x-device-mac")
            if mac and _MAC_RE.match(mac):
                ctx.mac_address = mac.upper().replace("-", ":")
            fp = h.get("x-device-fingerprint")
            if fp and _FP_RE.match(fp):
                ctx.device_fingerprint = fp
            ctx.correlation_id = h.get("x-correlation-id") or ctx.request_id
        await self.app(scope, receive, send)
