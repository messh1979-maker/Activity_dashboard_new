"""MFA service (RFC 6238 TOTP implementation, stdlib only).

The auth flow (auth_service + api/routes) always referenced these methods
while this file was a bootstrap stub — so enabling MFA on a user would
crash at login/verify/enroll time. This is the real implementation:

  - generate_mfa_token(user_id) -> short-lived signed "challenge" token
    returned by login() when the user has a second factor enabled.
  - verify_token(token, method, user_id) -> verifies a TOTP code (or a
    hashed recovery code) against the stored, AES-GCM-encrypted secret.
  - enroll(user_id, secret) -> generates + stores an encrypted TOTP secret
    (and 10 one-time recovery codes); when called again with the 6-digit
    confirmation code it enables the second factor.

No third-party OTP library is required (pyotp/qrcode are not installed);
the client renders the returned ``otpauth://`` URI itself.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from uuid import UUID

from jose import jwt as jose_jwt

from app.core.config import settings
from app.core.errors import APIError

_JWT_ALGORITHM = settings.ALGORITHM if settings.ALGORITHM in ("HS256", "HS384", "HS512") else "HS256"
_MFA_CHALLENGE_LIFETIME = 300  # seconds (5 minutes)
_TOTP_STEP = 30
_TOTP_DIGITS = 6
_TOTP_WINDOW = 1  # +/- 30s to tolerate clock skew
_TOTP_HASH = hashlib.sha1
_RECOVERY_CODE_COUNT = 10


# --- RFC 6238 helpers (pure stdlib) ---

def _base32_decode(value: str) -> bytes:
    padded = value.upper().strip().replace(" ", "")
    padded += "=" * ((8 - len(padded) % 8) % 8)
    return base64.b32decode(padded, casefold=True)


def _totp_at(secret_bytes: bytes, timestamp: int) -> str:
    """Return the 6-digit TOTP code for ``timestamp`` (RFC 6238 / 4226)."""
    counter = struct.pack(">Q", timestamp // _TOTP_STEP)
    digest = hmac.new(secret_bytes, counter, _TOTP_HASH).digest()
    offset = digest[-1] & 0x0F
    code = (struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF) % (10 ** _TOTP_DIGITS)
    return f"{code:0{_TOTP_DIGITS}d}"


def _generate_secret() -> str:
    """Random 20-byte base32 secret (160-bit, RFC 6238 recommendation)."""
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def _totp_secret_match(stored_secret: bytes, code: str, now: Optional[int] = None) -> bool:
    """Check ``code`` against the current +/- window of TOTP codes."""
    now = int(time.time()) if now is None else now
    return any(
        hmac.compare_digest(code, _totp_at(stored_secret, now + delta * _TOTP_STEP))
        for delta in range(-_TOTP_WINDOW, _TOTP_WINDOW + 1)
    )


def _encrypt_secret(secret_b32: str) -> tuple:
    """AES-GCM encrypt a TOTP secret; returns (ciphertext, nonce)."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    nonce = secrets.token_bytes(12)
    key = hashlib.sha256(settings.SECRET_KEY.encode()).digest()
    ciphertext = AESGCM(key).encrypt(nonce, secret_b32.encode(), None)
    return ciphertext, nonce


def _decrypt_secret(ciphertext: bytes, nonce: bytes) -> str:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    key = hashlib.sha256(settings.SECRET_KEY.encode()).digest()
    return AESGCM(key).decrypt(nonce, ciphertext, None).decode()


class MFAService:
    """Multi-factor authentication helper (real TOTP + recovery codes)."""

    def __init__(self):
        pass

    def generate_mfa_token(self, user_id: UUID) -> str:
        """Return a short-lived signed challenge token for the login flow."""
        now = datetime.utcnow()
        return jose_jwt.encode(
            {
                "sub": str(user_id),
                "purpose": "mfa",
                "jti": secrets.token_urlsafe(12),
                "exp": now + timedelta(seconds=_MFA_CHALLENGE_LIFETIME),
            },
            settings.SECRET_KEY,
            algorithm=_JWT_ALGORITHM,
        )

    async def verify_token(self, mfa_token: str, mfa_method: str, user_id: UUID) -> bool:
        """Verify a TOTP code (or recovery code) for ``user_id``.

        ``mfa_token`` is the 6-digit code entered by the user (the
        challenge token from ``generate_mfa_token`` identifies the login
        at the route layer; it is separate from this field).
        """
        from app.core.database import async_session_context

        async with async_session_context() as session:
            from sqlalchemy import select
            from app.modules.auth.db.models import Users

            result = await session.execute(select(Users).where(Users.id == user_id))
            user = result.scalar_one_or_none()
            if user is None:
                return False

            if mfa_method == "recovery":
                return await self._verify_recovery_code(session, user_id, mfa_token)

            # TOTP (fallback default when method is unspecified/totp)
            if mfa_method not in ("totp", ""):
                return False
            if not (user.mfa_secret_enc and user.mfa_secret_nonce):
                return False
            secret = _decrypt_secret(user.mfa_secret_enc, user.mfa_secret_nonce)
            return _totp_secret_match(_base32_decode(secret), mfa_token.strip())

    async def enable_totp(self, user_id: UUID, secret_b32: str) -> bool:
        """Persist a (already validated) TOTP secret and mark MFA enabled."""
        from app.core.database import async_session_context
        from sqlalchemy import select
        from app.modules.auth.db.models import Users

        async with async_session_context() as session:
            result = await session.execute(select(Users).where(Users.id == user_id))
            user = result.scalar_one_or_none()
            if user is None:
                return False
            ciphertext, nonce = _encrypt_secret(secret_b32)
            user.mfa_secret_enc = ciphertext
            user.mfa_secret_nonce = nonce
            user.mfa_enabled = True
            user.mfa_method = "totp"
            user.mfa_enrolled_at = datetime.utcnow()
            await session.commit()
            return True

    async def enroll(self, user_id: UUID, secret: str) -> dict:
        """Create or confirm TOTP enrollment.

        ``secret`` == "temp" (or empty): the *create* step — a new secret is
        generated and stored encrypted, plus recovery codes are issued.
        ``secret`` == a 6-digit code: the *confirm* step — verify the code
        against the stored secret and only then enable the factor.
        """
        if not secret or secret == "temp":
            return await self._create_enrollment(user_id)

        # Confirm step
        from app.core.database import async_session_context
        from sqlalchemy import select
        from app.modules.auth.db.models import Users

        async with async_session_context() as session:
            result = await session.execute(select(Users).where(Users.id == user_id))
            user = result.scalar_one_or_none()
            if user is None:
                raise APIError(error_code="USER_NOT_FOUND", message="کاربر یافت نشد.", status_code=404)
            if not (user.mfa_secret_enc and user.mfa_secret_nonce):
                raise APIError(error_code="MFA_NOT_INITIATED", message="ابتدا مرحله‌ی ساخت رمز MFA انجام شود.", status_code=400)
            stored = _decrypt_secret(user.mfa_secret_enc, user.mfa_secret_nonce)
            if not _totp_secret_match(_base32_decode(stored), secret.strip()):
                raise APIError(error_code="MFA_INVALID", message="کد MFA نامعتبر است.", status_code=400)
            user.mfa_enabled = True
            user.mfa_method = "totp"
            user.mfa_enrolled_at = datetime.utcnow()
            await session.commit()
            return {"status": "enrollment_confirmed", "mfa_method": "totp", "mfa_enabled": True}

    async def _create_enrollment(self, user_id: UUID) -> dict:
        """Generate a fresh secret, store it encrypted and return the QR data."""
        from app.core.database import async_session_context
        from sqlalchemy import select
        from app.modules.auth.db.models import Users

        secret_b32 = _generate_secret()
        ciphertext, nonce = _encrypt_secret(secret_b32)
        recovery_codes: List[str] = []

        async with async_session_context() as session:
            result = await session.execute(select(Users).where(Users.id == user_id))
            user = result.scalar_one_or_none()
            if user is None:
                raise APIError(error_code="USER_NOT_FOUND", message="کاربر یافت نشد.", status_code=404)

            user.mfa_secret_enc = ciphertext
            user.mfa_secret_nonce = nonce
            user.mfa_method = "totp"
            user.mfa_enrolled_at = datetime.utcnow()

            # Issue fresh recovery codes (hashed, one-time use).
            from app.modules.auth.db.models import MFARecoveryCodes
            from sqlalchemy import delete

            await session.execute(delete(MFARecoveryCodes).where(MFARecoveryCodes.user_id == user_id))
            for _ in range(_RECOVERY_CODE_COUNT):
                code = _format_recovery_code()
                recovery_codes.append(code)
                session.add(
                    MFARecoveryCodes(
                        user_id=user_id,
                        code_hash=hashlib.sha256(code.encode()).hexdigest(),
                    )
                )
            await session.commit()

        username = user.username if user is not None else str(user_id)
        otpauth = (
            f"otpauth://totp/{_urlsafe(username)}?secret={secret_b32}"
            f"&issuer={_urlsafe(settings.APP_NAME or 'Planner Enterprise')}&digits={_TOTP_DIGITS}"
            f"&period={_TOTP_STEP}"
        )
        return {
            "status": "enrolled",
            "secret": secret_b32,
            "qr_url": otpauth,
            "recovery_codes": recovery_codes,
            "mfa_enabled": False,
            "message": "رمز یک‌بارمصرف (TOTP) ساخته شد؛ برای فعال‌سازی کد ۶ رقمی را تأیید کنید.",
        }

    async def _verify_recovery_code(self, session, user_id: UUID, code: str) -> bool:
        """Validate + consume a hashed recovery code."""
        from sqlalchemy import select, update
        from app.modules.auth.db.models import MFARecoveryCodes

        code_hash = hashlib.sha256(code.strip().encode()).hexdigest()
        result = await session.execute(
            select(MFARecoveryCodes).where(
                MFARecoveryCodes.user_id == user_id,
                MFARecoveryCodes.code_hash == code_hash,
                MFARecoveryCodes.used_at.is_(None),
            )
        )
        row = result.scalar_one_or_none()
        if row is None:
            return False
        row.used_at = datetime.utcnow()
        await session.execute(
            update(MFARecoveryCodes)
            .where(MFARecoveryCodes.id == row.id)
            .values(used_at=datetime.utcnow())
        )
        await session.commit()
        return True


def _format_recovery_code() -> str:
    """8 groups of 8 base32-ish chars, e.g. ``ABCD-EFGH-IJKL-MNOP``."""
    block = base64.b32encode(secrets.token_bytes(10)).decode().rstrip("=")
    return "-".join(block[i : i + 4] for i in range(0, len(block), 4))


def _urlsafe(value: str) -> str:
    return value.replace(" ", "_").replace("%", "_")


__all__ = ["MFAService", "_totp_at", "_generate_secret"]