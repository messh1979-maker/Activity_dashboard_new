"""
app/modules/auth/events.py

رویدادهایی که ماژول Auth منتشر می‌کند — طبق قرارداد رابط سند
(بخش ۲.۲: هر ماژول رویدادهای خودش را از ``events.py`` صادر می‌کند)
و کاتالوگ رویدادها (بخش ۲.۴).

هیچ ماژول دیگری نباید این فایل را import کند تا از رویداد مطلع شود —
فقط باید با رشته‌ی ``event_type`` (مثل ``AUTH_LOGIN_SUCCEEDED``ی که
همین‌جا صادر شده) در ``event_bus.subscribe(...)`` مشترک شود. صادر کردن
این ثابت‌ها فقط برای جلوگیری از اشتباه تایپی در همین ماژول (auth) است؛
مصرف‌کننده‌ها (مثل audit) باید مقدار رشته را مستقیم بنویسند تا
وابستگی کد به auth ایجاد نشود — دقیقاً همان قاعده‌ای که تست
``test_module_boundaries.py`` اجرا می‌کند.
"""

from __future__ import annotations

# ── کاتالوگ رویدادها (بخش ۲.۴ سند) + رویدادهای اضافه‌ی مورد نیاز کد فعلی
AUTH_USER_REGISTERED = "auth.user.registered"
AUTH_LOGIN_SUCCEEDED = "auth.login.succeeded"
AUTH_LOGIN_FAILED = "auth.login.failed"
AUTH_LOGOUT = "auth.logout"
AUTH_PASSWORD_CHANGED = "auth.password.changed"
AUTH_DEVICE_REGISTERED = "auth.device.registered"
AUTH_DEVICE_TRUSTED = "auth.device.trusted"
