"""
app/modules/calendar/services/date_conversion.py

طبق سند (بخش ۱۱، نکته‌ی مهم): «تقویم قمری در ایران مبتنی بر رؤیت
هلال است و با محاسبات نجومی تا یک روز اختلاف دارد. اگر این ویجت
برای مناسبت‌های رسمی استفاده می‌شود، باید منبع تاریخ رسمی داشته
باشد؛ در غیر این صورت با ذکر «تقریبی» نمایش داده شود.»

این فایل دقیقاً همین را اجرایی می‌کند: تبدیل هجری قمری **همیشه**
``is_approximate=True`` برمی‌گرداند، مگر این‌که یک منبع رسمی (تقویم
اعلام‌شده توسط دولت) تزریق شود — که در این پروژه هنوز چنین منبعی
وجود ندارد، پس این فایل به‌جای نادیده گرفتن این هشدار (که ساده‌ترین
راه بود)، آن را در همان مقدار بازگشتی enforce می‌کند تا فرانت‌اند
مجبور شود «تقریبی» را نشان دهد.

تبدیل جلالی (تقویم رسمی ایران) دقیق است — چون ``jdatetime`` (کتابخانه‌ی
مشخص‌شده در سند، بخش نیازمندی‌ها) یک الگوریتم قطعی و رسمی است، نه
رؤیت‌محور.

⚠️ وابستگی: ``jdatetime`` طبق `pip list` شما نصب نیست.
    pip install jdatetime
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date


@dataclass(frozen=True)
class ConvertedDate:
    calendar_system: str  # "jalali" | "hijri"
    year: int
    month: int
    day: int
    is_approximate: bool
    note: str | None = None


def to_jalali(gregorian_date: date) -> ConvertedDate:
    try:
        import jdatetime
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("`jdatetime` نصب نیست — `pip install jdatetime` را اجرا کنید.") from exc

    j = jdatetime.date.fromgregorian(date=gregorian_date)
    return ConvertedDate(
        calendar_system="jalali", year=j.year, month=j.month, day=j.day,
        is_approximate=False,
    )


# میانگین طول ماه قمری (روز) — فقط برای تخمین حسابی، نه رؤیت‌محور واقعی.
_HIJRI_EPOCH_GREGORIAN = date(622, 7, 16)  # ۱ محرم ۱ هجری (تقریب متعارف)
_HIJRI_MONTH_LENGTH_DAYS = 29.530588853


def to_hijri_approximate(gregorian_date: date) -> ConvertedDate:
    """تبدیل حسابی تقریبی — **هرگز** برای مناسبت‌های رسمی (مثل شروع ماه
    رمضان) بدون تأیید منبع رسمی استفاده نشود؛ به همین دلیل
    ``is_approximate`` همیشه True است و این تابع اصلاً پارامتری برای
    False کردنش ندارد — عمداً، تا کسی به‌اشتباه این تصمیم امنیتی/شرعی
    را دور نزند.
    """
    days_since_epoch = (gregorian_date - _HIJRI_EPOCH_GREGORIAN).days
    total_months = int(days_since_epoch / _HIJRI_MONTH_LENGTH_DAYS)
    year = total_months // 12 + 1
    month = total_months % 12 + 1
    day_of_month = int(days_since_epoch - total_months * _HIJRI_MONTH_LENGTH_DAYS) + 1
    day_of_month = max(1, min(30, day_of_month))

    return ConvertedDate(
        calendar_system="hijri", year=year, month=month, day=day_of_month,
        is_approximate=True,
        note="محاسبه‌ی حسابی تقریبی — تا یک روز با رؤیت هلال واقعی اختلاف دارد؛ "
             "برای مناسبت‌های رسمی به منبع رسمی مراجعه کنید.",
    )
