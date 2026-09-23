"""Security primitives for WebSocket/device binding (architecture 1.2).

Mirrors the Windows desktop client's device fingerprint + HMAC scheme so a
WebSocket handshake can be tied to a known device, reusing the same
``SECRET_KEY`` domain.
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Optional
from uuid import UUID

from app.core.config import settings


def get_device_fingerprint(
    user_agent: Optional[str] = None,
    ip: Optional[str] = None,
    mac: Optional[str] = None,
    salt: Optional[str] = None,
) -> str:
    """Stable per-device fingerprint from the available client hints.

    Missing components are skipped so fingerprints stay stable for clients
    that do not disclose them.  The digest is truncated (16 bytes) to keep
    stored fingerprints compact.
    """
    parts: list[str] = []
    if salt:
        parts.append(salt)
    if mac:
        parts.append(mac.strip().lower())
    if user_agent:
        parts.append(user_agent.strip())
    if ip:
        parts.append(ip.strip())
    if not parts:
        # Deterministic fallback so a missing fingerprint never crashes auth.
        parts.append("unknown-device")
    raw = "|".join(parts).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:32]


def verify_hmac_signature(
    signature: str,
    *,
    user_id,
    endpoint: str,
    payload: Optional[str] = None,
) -> bool:
    """Verify an HMAC-SHA256 device signature (constant-time compare).

    The signature should be computed by the client as
    ``HMAC_SHA256(secret_key, f"{user_id}|{endpoint}|{payload}")``.  A
    missing signature or key is a hard reject.
    """
    if not signature or not settings.SECRET_KEY:
        return False
    message = "|".join([str(user_id), endpoint, payload or ""]).encode("utf-8")
    expected = hmac.new(
        settings.SECRET_KEY.encode("utf-8"), message, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(signature.strip().lower(), expected.lower())


def hmac_sign(user_id, endpoint: str, payload: Optional[str] = None) -> str:
    """Helper used where the *server* must mint a signature (e.g. callbacks)."""
    message = "|".join([str(user_id), endpoint, payload or ""]).encode("utf-8")
    return hmac.new(
        settings.SECRET_KEY.encode("utf-8"), message, hashlib.sha256
    ).hexdigest()