"""Small helpers shared by the pure-ASGI middlewares."""
from __future__ import annotations

import ipaddress
from typing import Iterable, Optional

from starlette.datastructures import Headers
from starlette.responses import JSONResponse
from starlette.types import Receive, Scope, Send

from app.core.config import settings
from app.core.context import get_context


async def send_error(
    scope: Scope, receive: Receive, send: Send, *, status: int, code: str,
    message: str, headers: Optional[dict[str, str]] = None,
) -> None:
    """Send the platform-wide error body (same shape as ``core.errors``)."""
    body = {"error": code, "message": message, "success": False,
            "request_id": get_context().request_id}
    await JSONResponse(body, status_code=status, headers=headers)(scope, receive, send)


def parse_networks(values: Iterable[str]):
    nets = []
    for v in values:
        try:
            nets.append(ipaddress.ip_network(v.strip(), strict=False))
        except ValueError:
            continue
    return nets


def ip_in(ip: str, networks) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in n for n in networks)


def client_ip(scope: Scope) -> str:
    """Peer address; ``X-Forwarded-For`` is honoured only from TRUSTED_PROXIES.

    Trusting the header unconditionally lets any client spoof its IP and
    bypass rate limiting / IP rules / audit attribution.
    """
    peer = (scope.get("client") or ("unknown", 0))[0]
    if settings.TRUSTED_PROXIES and ip_in(peer, parse_networks(settings.TRUSTED_PROXIES)):
        xff = Headers(scope=scope).get("x-forwarded-for")
        if xff:
            # right-most entry that is not itself a trusted proxy
            nets = parse_networks(settings.TRUSTED_PROXIES)
            for hop in reversed([h.strip() for h in xff.split(",") if h.strip()]):
                if not ip_in(hop, nets):
                    return hop
    return peer
