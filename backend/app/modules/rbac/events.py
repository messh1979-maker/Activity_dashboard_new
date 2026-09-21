"""
app/modules/rbac/events.py

رویدادهایی که ماژول RBAC منتشر می‌کند — طبق کاتالوگ سند (بخش ۲.۴) و
بخش ۱۲.۴ («رویداد rbac.role.assigned کش آن کاربر را فوراً باطل می‌کند»).

مثل auth/events.py: این فقط رشته‌های event_type را صادر می‌کند تا
مصرف‌کننده‌ها (audit، و هر چیزی که بخواهد کش Permission را باطل کند)
بدون import از rbac مشترک شوند.
"""

from __future__ import annotations

RBAC_ROLE_ASSIGNED = "rbac.role.assigned"
RBAC_ROLE_REVOKED = "rbac.role.revoked"
RBAC_ACCESS_DENIED = "rbac.denied"
