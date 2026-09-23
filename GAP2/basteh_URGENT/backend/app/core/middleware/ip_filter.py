"""IP allow / deny lists (CIDR aware). Deny wins over allow."""
from __future__ import annotations

from starlette.types import ASGIApp, Receive, Scope, Send

from app.core.middleware._http import client_ip, ip_in, parse_networks, send_error


class IPFilterMiddleware:
    def __init__(self, app: ASGIApp, allow_ips: list[str] | None = None,
                 deny_ips: list[str] | None = None) -> None:
        self.app = app
        self.allow = parse_networks(allow_ips or [])
        self.deny = parse_networks(deny_ips or [])

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ("http", "websocket") or not (self.allow or self.deny):
            await self.app(scope, receive, send)
            return
        ip = client_ip(scope)
        if self.deny and ip_in(ip, self.deny):
            await self._reject(scope, receive, send, "IP_ADDRESS_DENIED",
                               "آدرس IP شما مسدود شده است.")
            return
        if self.allow and not ip_in(ip, self.allow):
            await self._reject(scope, receive, send, "IP_ADDRESS_NOT_ALLOWED",
                               "دسترسی از این آدرس IP مجاز نیست.")
            return
        await self.app(scope, receive, send)

    @staticmethod
    async def _reject(scope, receive, send, code, message) -> None:
        if scope["type"] == "websocket":
            await send({"type": "websocket.close", "code": 4403})
            return
        await send_error(scope, receive, send, status=403, code=code, message=message)
