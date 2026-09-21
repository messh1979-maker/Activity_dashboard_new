import hashlib
import secrets
import base64
from typing import Optional, Tuple, Dict, Any
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

from passlib.context import CryptContext
from fastapi import HTTPException, status

from app.core.config import settings
from app.core.errors import APIError, AuthenticationError, MFARequiredError
from app.core.events.bus import event_bus
from app.modules.auth import events as auth_events
from app.modules.auth.ports import (
    LoginRequest, MFAVerifyRequest, RegisterRequest, TokenResponse,
    DeviceRegisterRequest, DeviceTrustRequest, PasswordChangeRequest,
    PasswordForgotRequest, AuditLogEntry
)


# Password hashing context
pwd_context = CryptContext(
    schemes=["argon2"],
    argon2__time_cost=3,
    deprecated="auto",
)


class AuthService:
    """Core authentication service implementing the logic for user login, 
    registration, MFA, and device management."""
    
    def __init__(self, user_repo, device_repo, mfa_service):
        self.user_repo = user_repo
        self.device_repo = device_repo
        self.mfa_service = mfa_service
    
    # --- Registration ---
    
    async def register(self, request: RegisterRequest) -> dict:
        """Register a new user with national ID."""
        
        # Validate national ID format (10 digits with check digit)
        if not self._validate_national_id(request.national_id):
            raise APIError(
                error_code="INVALID_NATIONAL_ID",
                message="فرمت کد ملی صحیح نیست.",
                status_code=status.HTTP_400_BAD_REQUEST
            )
        
        # Check if user already exists
        existing = await self.user_repo.get_by_national_id(request.national_id)
        if existing:
            raise APIError(
                error_code="USER_EXISTS",
                message="کاربری با این کد ملی قبلاً ثبت شده است.",
                status_code=status.HTTP_409_CONFLICT
            )
        
        # Check username availability
        existing_username = await self.user_repo.get_by_username(request.username)
        if existing_username:
            raise APIError(
                error_code="USERNAME_EXISTS",
                message="این نام کاربری قبلاً استفاده شده است.",
                status_code=status.HTTP_409_CONFLICT
            )
        
        # Hash password
        password_hash = pwd_context.hash(request.password)
        
        # Create user (national ID stored encrypted + hashed for lookup)
        from app.modules.auth.db.models import Users
        from app.modules.auth.db.repositories import national_id_hash
        nid_enc, nid_nonce = self._encrypt_national_id(request.national_id)
        user = Users(
            username=request.username,
            national_id_enc=nid_enc,
            national_id_nonce=nid_nonce,
            national_id_hash=national_id_hash(request.national_id),
            national_id_last4=request.national_id[-4:],
            password_hash=password_hash,
            display_name=request.display_name,
            auth_mode="local",
            is_active=True,
        )
        # Transient (non-column) attributes used by the read model below
        user.national_id = request.national_id
        
        await self.user_repo.add(user)
        await self.user_repo.commit()
        
        # Create initial device entry
        await self.device_repo.create_initial_device(user.id)
        
        # Publish domain event — audit (and anything else that subscribes,
        # e.g. notification for a welcome email) reacts without auth ever
        # importing their internal tables (ADR-02 / section 2.3).
        await self._publish_event(
            auth_events.AUTH_USER_REGISTERED,
            actor_id=user.id,
            payload={"username": user.username},
        )
        
        return {"status": "success", "user_id": str(user.id)}
    
    # --- Login ---
    
    async def login(self, request: LoginRequest) -> Tuple[dict, Optional[str]]:
        """Authenticate user and return tokens.
        
        Returns:
            Tuple of (token_response, mfa_required_flag)
        """
        
        # Find user by identifier (username or national ID)
        user = await self.user_repo.get_by_identifier(request.identifier)
        if not user:
            await self._publish_event(
                auth_events.AUTH_LOGIN_FAILED,
                payload={"identifier": request.identifier, "reason": "user_not_found"},
            )
            # Generic error to avoid leaking whether user exists
            raise AuthenticationError(
                message="اطلاعات ورود نادرست است."
            )
        
        # Check if account is active
        if not user.is_active:
            await self._publish_event(
                auth_events.AUTH_LOGIN_FAILED,
                actor_id=user.id,
                payload={"identifier": request.identifier, "reason": "account_inactive"},
            )
            raise AuthenticationError(
                message="حساب کاربری فعال نیست."
            )
        
        # Verify password
        if not pwd_context.verify(request.password, user.password_hash):
            # Increment failed login counter
            user.failed_login_count += 1
            # Lock account if too many failures
            if user.failed_login_count >= 5:
                user.locked_until = datetime.utcnow() + timedelta(minutes=30)
            await self.user_repo.commit()
            await self._publish_event(
                auth_events.AUTH_LOGIN_FAILED,
                actor_id=user.id,
                payload={
                    "identifier": request.identifier,
                    "reason": "wrong_password",
                    "failed_login_count": user.failed_login_count,
                },
            )
            raise AuthenticationError(
                message="اطلاعات ورود نادرست است."
            )
        
        # Reset failed login counter on success
        user.failed_login_count = 0
        user.locked_until = None
        await self.user_repo.commit()
        
        # Check MFA status
        mfa_required = bool(user.mfa_enabled) and not getattr(
            user, "is_trusted_device", False
        )
        
        if mfa_required:
            # Generate MFA token (short-lived)
            mfa_token = self.mfa_service.generate_mfa_token(user.id)
            return {
                "mfa_required": True,
                "mfa_token": mfa_token,
                "mfa_method": user.mfa_method,
                "expires_in": 300  # 5 minutes
            }, True
        
        # No MFA needed — login is fully successful right here.
        # NOTE: if MFA *is* required, the success event is published once
        # verify_mfa() actually confirms the second factor (see below) —
        # publishing it here too would record a "succeeded" login for an
        # attempt that hasn't cleared MFA yet.
        await self._publish_event(
            auth_events.AUTH_LOGIN_SUCCEEDED,
            actor_id=user.id,
            payload={"identifier": request.identifier, "mfa_used": "none"},
        )
        return await self._generate_tokens(user), False
    
    # --- Token Generation ---
    
    async def _generate_tokens(self, user) -> dict:
        """Generate access and refresh tokens for a user."""
        from jose import jwt  # PyJWT

        # Bump FIRST so the freshly issued access token carries the new
        # version; bumping after encoding instantly revokes the new token.
        user.token_version += 1
        await self.user_repo.commit()

        # Access token (HS256 + exp claim; python-jose has no expires_at kwarg)
        access_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = jwt.encode(
            {
                "sub": str(user.id),
                "username": user.username,
                "roles": getattr(user, "roles", []) or [],
                "permissions": getattr(user, "permissions", []) or [],
                "privacy_level": getattr(user, "privacy_level", None) or "team_only",
                "token_version": user.token_version,
                "type": "access",
                "exp": datetime.utcnow() + access_expires,
            },
            settings.SECRET_KEY,
            algorithm=settings.ALGORITHM,
        )
        
        # Refresh token
        refresh_token = secrets.token_urlsafe(32)
        # Store hash of refresh token
        refresh_token_hash = hashlib.sha256(refresh_token.encode()).hexdigest()
        
        # Store in sessions table
        from app.modules.auth.db.models import Sessions
        session = Sessions(
            user_id=user.id,
            refresh_hash=refresh_token_hash,
            family_id=getattr(user, "family_id", None) or uuid4(),
            auth_method=user.auth_mode,
            mfa_satisfied=bool(user.mfa_enabled),
            expires_at=datetime.utcnow() + timedelta(
                days=settings.REFRESH_TOKEN_EXPIRE_DAYS
            ),
        )
        await self.user_repo.add(session)
        await self.user_repo.commit()

        # Get user read model for response
        user_read = self._get_user_read_model(user)
        
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "Bearer",
            "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            "user": user_read,
        }
    
    # --- MFA ---
    
    async def verify_mfa(self, mfa_token: str, mfa_method: str, user_id: UUID) -> bool:
        """Verify MFA token."""
        verified = await self.mfa_service.verify_token(mfa_token, mfa_method, user_id)
        if verified:
            # This is the actual "login succeeded" moment for an MFA-gated
            # login — the plain login() above only got this far because
            # mfa_required was True, so it deliberately did not publish
            # AUTH_LOGIN_SUCCEEDED itself.
            await self._publish_event(
                auth_events.AUTH_LOGIN_SUCCEEDED,
                actor_id=user_id,
                payload={"mfa_used": mfa_method},
            )
        else:
            await self._publish_event(
                auth_events.AUTH_LOGIN_FAILED,
                actor_id=user_id,
                payload={"reason": "mfa_invalid", "mfa_method": mfa_method},
            )
        return verified
    
    async def enroll_mfa(self, user_id: UUID, secret: str) -> dict:
        """Enroll TOTP MFA for a user."""
        return await self.mfa_service.enroll(user_id, secret)
    
    # --- Device Management ---
    
    async def register_device(self, request: DeviceRegisterRequest, user_id: UUID) -> dict:
        """Register a new device for a user."""
        # Generate HMAC key for this device
        hmac_key = secrets.token_bytes(32)
        
        from app.modules.auth.db.models import UserDevices
        device = UserDevices(
            user_id=user_id,
            device_fingerprint=request.device_fingerprint,
            mac_address=request.mac_address,
            mac_source=request.mac_source,
            platform=request.platform,
            device_label=request.device_label,
            os_info=request.os_info,
            hmac_key_enc=self._encrypt_hmac_key(hmac_key),
            is_trusted=False,
        )
        await self.device_repo.add(device)
        await self.user_repo.commit()

        await self._publish_event(
            auth_events.AUTH_DEVICE_REGISTERED,
            actor_id=user_id,
            payload={
                "device_id": str(device.id),
                "platform": request.platform,
                "device_label": request.device_label,
            },
        )
        
        return {
            "device_id": str(device.id),
            "hmac_key": base64.b64encode(hmac_key).decode(),  # Only sent once
            "is_trusted": False,
            "requires_mfa_to_trust": True,
        }
    
    async def trust_device(self, device_id: UUID, mfa_satisfied: bool, user_id: UUID) -> dict:
        """Mark device as trusted (requires MFA)."""
        from app.modules.auth.db.models import UserDevices
        device = await self.device_repo.get(device_id)
        if device.user_id != user_id:
            raise APIError(
                error_code="DEVICE_NOT_FOUND",
                message="دستگاه یافت نشد.",
                status_code=status.HTTP_404_NOT_FOUND
            )
        
        device.is_trusted = True
        device.trusted_at = datetime.utcnow()
        device.trusted_by_mfa = mfa_satisfied
        await self.user_repo.commit()

        await self._publish_event(
            auth_events.AUTH_DEVICE_TRUSTED,
            actor_id=user_id,
            payload={"device_id": str(device_id), "mfa_satisfied": mfa_satisfied},
        )
        
        return {"status": "device_trusted"}
    
    # --- Password Management ---
    
    async def change_password(self, user_id: UUID, request: PasswordChangeRequest) -> dict:
        """Change user password."""
        user = await self.user_repo.get(user_id)
        if not user:
            raise APIError(
                error_code="USER_NOT_FOUND",
                message="کاربر یافت نشد.",
                status_code=status.HTTP_404_NOT_FOUND
            )
        
        # Verify current password
        if not pwd_context.verify(request.current_password, user.password_hash):
            raise APIError(
                error_code="INVALID_PASSWORD",
                message="رمز فعلی صحیح نیست.",
                status_code=status.HTTP_400_BAD_REQUEST
            )
        
        # Hash new password
        new_hash = pwd_context.hash(request.new_password)
        user.password_hash = new_hash
        user.password_changed_at = datetime.utcnow()
        user.must_change_password = False
        await self.user_repo.commit()
        
        # Invalidate all sessions (force re-login)
        user.token_version += 1
        await self.user_repo.commit()
        
        await self._publish_event(
            auth_events.AUTH_PASSWORD_CHANGED,
            actor_id=user_id,
            payload={},
        )
        
        return {"status": "password_changed"}
    
    # --- Password Reset ---
    
    async def forgot_password(self, request: PasswordForgotRequest) -> dict:
        """Start password reset process."""
        user = await self.user_repo.get_by_identifier(request.identifier)
        if not user:
            # Don't reveal if user exists - security through obscurity
            return {"status": "sent"}  # Always say sent for security
        
        # Generate reset token
        reset_token = secrets.token_urlsafe(32)
        reset_token_hash = hashlib.sha256(reset_token.encode()).hexdigest()
        
        # Store in user record
        user.password_reset_token = reset_token_hash
        user.password_reset_expires = datetime.utcnow() + timedelta(hours=24)
        await self.user_repo.commit()
        
        # In real implementation: send email with reset link
        # For now, just return that process started
        return {"status": "reset_initiated", "expires_in_hours": 24}
    
    # --- Profile / Session / Devices ---

    async def get_profile(self, user_id: UUID) -> dict:
        """Current user profile + effective roles/permissions."""
        user = await self.user_repo.get(user_id)
        if not user:
            raise APIError(
                error_code="USER_NOT_FOUND",
                message="کاربر یافت نشد.",
                status_code=status.HTTP_404_NOT_FOUND,
            )
        profile = self._get_user_read_model(user)
        profile["id"] = str(profile["id"])
        return profile

    async def logout(self, user_id: UUID) -> dict:
        """Revoke all sessions for the user (bump token_version)."""
        user = await self.user_repo.get(user_id)
        if not user:
            raise APIError(
                error_code="USER_NOT_FOUND",
                message="کاربر یافت نشد.",
                status_code=status.HTTP_404_NOT_FOUND,
            )
        user.token_version += 1
        await self.user_repo.commit()
        await self._publish_event(auth_events.AUTH_LOGOUT, actor_id=user_id, payload={})
        return {"status": "logged_out"}

    async def list_devices(self, user_id: UUID) -> list:
        """List known devices with masked MAC addresses."""
        from sqlalchemy import select

        from app.modules.auth.db.models import UserDevices

        result = await self.user_repo.session.execute(
            select(UserDevices).where(UserDevices.user_id == user_id)
        )
        devices = result.scalars().all()
        items = []
        for d in devices:
            mac = d.mac_address or ""
            masked = (
                f"{mac[:5]}**:**:**:{mac[-2:]}"
                if len(mac) == 17 else None
            )
            items.append({
                "id": str(d.id),
                "device_label": d.device_label,
                "platform": d.platform,
                "mac_address_masked": masked,
                "is_trusted": d.is_trusted,
                "last_seen_at": d.last_seen_at.isoformat() if d.last_seen_at else None,
                "last_ip": str(d.last_ip) if d.last_ip else None,
            })
        return items

    async def _generate_tokens_by_id(self, user_id: UUID) -> dict:
        """Generate fresh tokens for a user ID (used by /refresh)."""
        user = await self.user_repo.get(user_id)
        if not user or not user.is_active:
            raise APIError(
                error_code="USER_NOT_FOUND",
                message="کاربر یافت نشد.",
                status_code=status.HTTP_404_NOT_FOUND,
            )
        return await self._generate_tokens(user)

    async def refresh_session(self, refresh_token: str, db_session=None) -> dict:
        """Validate an opaque refresh token and rotate the session.

        The refresh token is stored as SHA-256 in ``auth.sessions``. We look
        it up, reject revoked/expired sessions, revoke the old session and
        issue fresh tokens. Returns the new ``{status, tokens, user}``-shaped
        response expected by the frontend auth client.
        """
        from sqlalchemy import select
        from app.modules.auth.db.models import Sessions

        session = self.user_repo.session
        if session is None:
            raise APIError(
                error_code="SESSION_ERROR",
                message="نشست قابل استفاده نیست.",
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        refresh_hash = hashlib.sha256(refresh_token.encode()).hexdigest()

        result = await session.execute(
            select(Sessions).where(Sessions.refresh_hash == refresh_hash)
        )
        s = result.scalar_one_or_none()
        if s is None:
            raise APIError(
                error_code="TOKEN_INVALID",
                message="توکن یافت نشد.",
                status_code=status.HTTP_401_UNAUTHORIZED,
            )
        if s.revoked_at is not None:
            raise APIError(
                error_code="TOKEN_REVOKED",
                message="نشست باطل شده است.",
                status_code=status.HTTP_401_UNAUTHORIZED,
            )
        # NOTE: timestamptz columns come back timezone-aware from asyncpg,
        # so compare against an aware "now" (naive utcnow() would TypeError).
        now_utc = datetime.now(timezone.utc)
        expires_at = s.expires_at
        if expires_at is not None:
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)
            if expires_at < now_utc:
                raise APIError(
                    error_code="TOKEN_EXPIRED",
                    message="نشست منقضی شده است.",
                    status_code=status.HTTP_401_UNAUTHORIZED,
                )

        # Revoke the old session (rotation).
        s.revoked_at = datetime.utcnow()
        s.revoked_reason = "refresh"

        user = await self.user_repo.get(s.user_id)
        if not user or not user.is_active:
            raise APIError(
                error_code="USER_NOT_FOUND",
                message="کاربر یافت نشد.",
                status_code=status.HTTP_404_NOT_FOUND,
            )

        # Carry the session family forward so rotation stays in one family.
        user.family_id = s.family_id
        new_tokens = await self._generate_tokens(user)
        await self.user_repo.commit()
        return {
            "status": "token_refreshed",
            "tokens": {
                "access_token": new_tokens.get("access_token"),
                "refresh_token": new_tokens.get("refresh_token"),
                "token_type": "Bearer",
                "expires_in": new_tokens.get("expires_in"),
            },
            "user": new_tokens.get("user"),
        }

    # --- Helper methods ---
    
    def _validate_national_id(self, national_id: str) -> bool:
        """Validate Iranian national ID format and checksum."""
        # Remove any separators
        national_id = national_id.strip()
        
        # Must be exactly 10 digits
        if not national_id.isdigit() or len(national_id) != 10:
            return False
        
        # Calculate checksum (official Iranian algorithm)
        digits = [int(d) for d in national_id]
        # Iranian national ID checksum: sum of (digit * position) % 11
        # Positions: 10, 9, 8, 7, 6, 5, 4, 3, 2 (from left to right, excluding check digit)
        weights = [10, 9, 8, 7, 6, 5, 4, 3, 2]
        weighted_sum = sum(d * w for d, w in zip(digits[:9], weights))
        remainder = weighted_sum % 11

        # Official check digit rules:
        # If remainder < 2, the 10th digit must equal remainder;
        # otherwise it must equal (11 - remainder).
        expected_check = remainder if remainder < 2 else 11 - remainder

        return digits[9] == expected_check
    
    def _encrypt_national_id(self, national_id: str) -> tuple:
        """Encrypt national ID with AES-GCM; returns (ciphertext, nonce)."""
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        nonce = secrets.token_bytes(12)  # 96-bit nonce for GCM
        kdf_key = hashlib.sha256(settings.SECRET_KEY.encode()).digest()
        aesgcm = AESGCM(kdf_key)
        return aesgcm.encrypt(nonce, national_id.encode(), None), nonce

    def _encrypt_hmac_key(self, key: bytes) -> bytes:
        """Encrypt HMAC key using AES-GCM with a per-key nonce."""
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        nonce = secrets.token_bytes(12)  # 96-bit nonce for GCM
        # In production, use a key from Vault, not hardcoded
        # Here we use a simplified approach
        kdf_key = hashlib.sha256(settings.SECRET_KEY.encode()).digest()
        aesgcm = AESGCM(kdf_key)
        encrypted = aesgcm.encrypt(nonce, key, None)
        return nonce + encrypted  # prepend nonce
    
    def _decrypt_hmac_key(self, encrypted_key: bytes) -> bytes:
        """Decrypt HMAC key."""
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        kdf_key = hashlib.sha256(settings.SECRET_KEY.encode()).digest()
        nonce = encrypted_key[:12]
        ciphertext = encrypted_key[12:]
        aesgcm = AESGCM(kdf_key)
        return aesgcm.decrypt(nonce, ciphertext, None)
    
    def _get_user_read_model(self, user) -> dict:
        """Convert user model to read model for API responses."""
        from datetime import datetime
        
        # Get masked national ID (last 4 digits)
        national_id = getattr(user, "national_id", None)
        if not national_id:
            national_id = f"*****{user.national_id_last4}" if getattr(
                user, "national_id_last4", None) else "******"
        national_id_masked = (
            f"*****{national_id[-4:]}" if national_id else "******"
        )

        return {
            "id": user.id,
            "username": user.username,
            "display_name": user.display_name,
            "national_id_masked": national_id_masked,
            "is_active": user.is_active,
            "roles": getattr(user, "roles", None) or [],
            "permissions": getattr(user, "permissions", None) or [],
            "privacy_level": getattr(user, "privacy_level", None) or "team_only",
            "auth_mode": user.auth_mode or "local",
            "mfa_enabled": user.mfa_enabled or False,
            "last_login_at": user.last_login_at,
        }
    
    async def _publish_event(
        self, event_type: str, *, payload: dict, actor_id: UUID | None = None
    ) -> None:
        """رویداد دامنه را منتشر می‌کند — جایگزین متد قدیمی ``_audit_log``.

        برخلاف نسخه‌ی قبلی، اینجا هیچ importی به ``app.modules.audit``
        وجود ندارد (نقض مرز ماژول که تست ``test_module_boundaries.py``
        آن را گرفت). به‌جایش یک ``DomainEvent`` روی ``event_bus`` منتشر
        می‌شود؛ ماژول Audit (اگر مشترک شده باشد) و هر ماژول دیگری که به
        این رویداد علاقه دارد (مثلاً Notification برای هشدار «ورود از
        دستگاه جدید» طبق کاتالوگ رویدادهای سند) بدون هیچ وابستگی کدی
        به auth، آن را دریافت می‌کنند.

        TODO(security): وقتی ``core/context.py`` (ContextVar) و
        ``core/middleware/`` واقعی پیاده شدند (بخش ۱.۲ و ۳.۱ سند)،
        ``ip_address`` / ``mac_address`` / ``device_fingerprint`` باید
        از آن‌جا در payload اضافه شوند — نه از پارامترهای متد سرویس
        (که هنوز به این service پاس داده نمی‌شوند).
        """
        from app.core.events.bus import DomainEvent

        event = DomainEvent(event_type=event_type, payload=payload, actor_id=actor_id)
        try:
            await event_bus.publish(event, self.user_repo.session)
            await self.user_repo.commit()
        except Exception:
            # مطابق طراحی bus.py: خطای یک handler بالا می‌آید. این‌جا آن را
            # قورت نمی‌دهیم (برخلاف باگ قبلی) اما هم اجازه نمی‌دهیم شکست
            # انتشار رویداد، کل جریان login/register/... را متوقف کند —
            # چون در نبود Outbox dispatcher واقعی هنوز، این یک تصمیم آگاهانه
            # است، نه بی‌توجهی. اگر می‌خواهید شکست انتشار رویداد باعث شکست
            # کل عملیات شود (مثلاً برای الزامات Compliance)، این except را
            # حذف کنید تا خطا بالا برود.
            import logging
            logging.getLogger("auth.events").exception(
                "failed to publish event_type=%s", event_type
            )
