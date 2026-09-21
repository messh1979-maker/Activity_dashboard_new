"""
app/modules/auth/admin_ports.py

اسکیمای request/response بخش «تعریف/مدیریت کاربر» در تنظیمات ادمین —
که در سند فقط برای `/auth/register` (ثبت‌نام خودِ کاربر) و
`/admin/users/bulk-login-mode` (بخش ۱۲.۶) وجود دارد، نه برای
create/list/update/deactivate عمومی. این فایل آن‌ها را اضافه می‌کند.

⚠️ عمداً در فایل جدا (نه داخل ``ports.py`` موجودتان) گذاشته شده، چون
محتوای واقعی ``ports.py`` را ندیده‌ام و نمی‌خواهم چیزی را ناخواسته
پاک کنم. اگر می‌خواهید این‌ها را به ``ports.py`` منتقل کنید، فقط
تعریف‌های زیر را کپی/پیست کنید — چیز دیگری در کد به مسیر فایل وابسته
نیست جز importها در ``admin_user_service.py`` و ``admin_routes.py``.
"""

from __future__ import annotations

from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field


class AdminCreateUserRequest(BaseModel):
    """ادمین مستقیماً کاربر می‌سازد — برخلاف ``/auth/register`` که خودِ
    کاربر با کد ملی ثبت‌نام می‌کند. رمز عبور اولیه توسط ادمین تعیین
    می‌شود و ``must_change_password`` اجباری True است."""

    username: str = Field(min_length=3, max_length=64)
    national_id: str = Field(min_length=10, max_length=10)
    display_name: str = Field(min_length=1, max_length=120)
    initial_password: str = Field(min_length=8)
    role_id: int | None = None  # اختیاری: نقش اولیه (از طریق RoleAssignmentService اعطا می‌شود)


class AdminUpdateUserRequest(BaseModel):
    """همه‌ی فیلدها اختیاری — فقط چیزی که فرستاده شود عوض می‌شود."""

    display_name: str | None = Field(default=None, min_length=1, max_length=120)
    is_active: bool | None = None
    must_change_password: bool | None = None


class AdminUserListItem(BaseModel):
    id: UUID
    username: str
    display_name: str
    national_id_masked: str
    is_active: bool
    auth_mode: str
    mfa_enabled: bool
    last_login_at: str | None = None


class AdminUserListResponse(BaseModel):
    items: list[AdminUserListItem]
    total: int
    limit: int
    offset: int


class BulkLoginModeRequest(BaseModel):
    """طبق بخش ۱۲.۶ سند — تغییر sso_enabled برای گروهی از کاربران."""

    user_ids: list[UUID] = Field(min_length=1, max_length=500)
    sso_enabled: bool
    revoke_sessions: bool = False


class BulkFailure(BaseModel):
    user_id: UUID
    code: Literal["NOT_FOUND", "CANNOT_MODIFY_SELF", "NO_LOCAL_PASSWORD"]


class BulkResult(BaseModel):
    updated: list[UUID]
    failed: list[BulkFailure]
