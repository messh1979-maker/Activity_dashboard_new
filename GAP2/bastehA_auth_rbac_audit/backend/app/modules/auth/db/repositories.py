"""Auth repositories (AsyncSession-backed)."""
import hashlib
from uuid import UUID

from sqlalchemy import func, select

from app.core.config import settings
from app.modules.auth.db.models import UserDevices, Users


def national_id_hash(national_id: str) -> str:
    """HMAC-SHA256 lookup hash for a national ID (matches registration)."""
    return hashlib.sha256(
        f"{national_id}:{settings.SECRET_KEY}".encode()
    ).hexdigest()


class UserRepository:
    """Persistence adapter for users (backed by an async session)."""

    def __init__(self, session):
        self.session = session

    async def get(self, user_id):
        result = await self.session.execute(
            select(Users).where(Users.id == user_id)
        )
        return result.scalar_one_or_none()

    async def get_by_national_id(self, national_id: str):
        result = await self.session.execute(
            select(Users).where(
                Users.national_id_hash == national_id_hash(national_id.strip())
            )
        )
        return result.scalar_one_or_none()

    async def get_by_username(self, username: str):
        result = await self.session.execute(
            select(Users).where(func.lower(Users.username) == username.lower())
        )
        return result.scalar_one_or_none()

    async def get_by_identifier(self, identifier: str):
        identifier = identifier.strip()
        if identifier.isdigit() and len(identifier) == 10:
            user = await self.get_by_national_id(identifier)
            if user:
                return user
        return await self.get_by_username(identifier)

    async def add(self, obj):
        self.session.add(obj)

    async def commit(self):
        await self.session.commit()


class DeviceRepository:
    """Persistence adapter for user devices."""

    def __init__(self, session):
        self.session = session

    async def get(self, device_id):
        result = await self.session.execute(
            select(UserDevices).where(UserDevices.id == device_id)
        )
        return result.scalar_one_or_none()

    async def add(self, obj):
        self.session.add(obj)

    async def create_initial_device(self, user_id: UUID):
        import uuid as uuid_lib

        device = UserDevices(
            user_id=user_id,
            device_fingerprint=f"initial-{uuid_lib.uuid4().hex[:16]}",
            platform="web",
            device_label="Initial device",
            is_trusted=False,
        )
        self.session.add(device)
        await self.session.flush()
        return device


__all__ = ["UserRepository", "DeviceRepository", "national_id_hash"]
