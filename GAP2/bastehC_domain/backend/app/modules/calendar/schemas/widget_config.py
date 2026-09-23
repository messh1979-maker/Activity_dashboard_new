"""
app/modules/calendar/schemas/widget_config.py

طبق سند (بخش ۴.۷، درست زیر DDL جدول ``reporting.user_widget_settings``):

    «`config` و `style` عمداً JSONB هستند... اما محتوای آن‌ها **در سرور
    با یک اسکیمای Pydantic مخصوص هر widget_key/block_key اعتبارسنجی
    می‌شود**. JSONB به معنای پذیرش هر ورودی نیست — این یک بردار تزریق
    رایج است (ذخیره‌ی `opacity: "<script>"` و رندر مستقیم آن در CSS).»

این فایل دقیقاً همان اسکیمای مفقود را برای سه ویجت calendar-محور
(``mini_calendar``, ``clock``, ``quick_add``) می‌سازد. اگر endpoint
واقعی ذخیره‌ی ``user_widget_settings`` جای دیگری (مثلاً ماژول
``reporting``) است، فقط ``validate_widget_config`` را از همان‌جا
import و صدا بزنید — این فایل به هیچ چیزِ دیگری از reporting وابسته
نیست.
"""

from __future__ import annotations

import re
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

# رنگ باید یا نام رنگ CSS شناخته‌شده باشد یا هگز معتبر — هرگز رشته‌ی آزاد
_HEX_COLOR_RE = re.compile(r"^#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6})$")
_ALLOWED_FONT_FAMILIES = {"system-ui", "Vazirmatn", "IRANSans", "Tahoma", "Arial", "monospace"}


def _validate_color(value: str) -> str:
    if not _HEX_COLOR_RE.match(value):
        raise ValueError(f"رنگ نامعتبر: {value!r} — فقط هگز (#rrggbb) مجاز است.")
    return value


class WidgetStyle(BaseModel):
    """طبق سند: ``style: {bg, fg, font_family, font_size, opacity}`` —
    اما هرکدام اینجا محدود و اعتبارسنجی‌شده‌اند، نه رشته‌ی آزاد."""

    bg: str = "#ffffff"
    fg: str = "#000000"
    font_family: str = "system-ui"
    font_size: int = Field(default=14, ge=8, le=48)
    opacity: float = Field(default=1.0, ge=0.1, le=1.0)

    @field_validator("bg", "fg")
    @classmethod
    def _check_color(cls, v: str) -> str:
        return _validate_color(v)

    @field_validator("font_family")
    @classmethod
    def _check_font(cls, v: str) -> str:
        if v not in _ALLOWED_FONT_FAMILIES:
            raise ValueError(f"font_family باید یکی از {_ALLOWED_FONT_FAMILIES} باشد.")
        return v


class ClockWidgetConfig(BaseModel):
    show_jalali: bool = True
    show_gregorian: bool = False
    show_hijri: bool = False
    time_format: Literal["HH:mm", "HH:mm:ss", "hh:mm a"] = "HH:mm:ss"
    show_seconds: bool = True


class MiniCalendarWidgetConfig(BaseModel):
    show_jalali: bool = True
    show_gregorian: bool = True
    show_hijri: bool = False
    highlight_today: bool = True
    week_start_day: int = Field(default=6, ge=0, le=6)  # ۰=یکشنبه ... ۶=شنبه (طبق تقویم ایران)


class QuickAddWidgetConfig(BaseModel):
    default_goal_privacy: Literal["private", "team_only", "selected", "public"] = "team_only"
    show_recent_goals: bool = True
    max_recent_items: int = Field(default=5, ge=1, le=20)


_CONFIG_SCHEMA_BY_WIDGET_KEY: dict[str, type[BaseModel]] = {
    "clock": ClockWidgetConfig,
    "mini_calendar": MiniCalendarWidgetConfig,
    "quick_add": QuickAddWidgetConfig,
}


class WidgetConfigValidationError(Exception):
    def __init__(self, widget_key: str, errors: Any) -> None:
        self.widget_key = widget_key
        self.errors = errors
        super().__init__(f"invalid config for widget_key={widget_key}: {errors}")


def validate_widget_config(widget_key: str, raw_config: dict, raw_style: dict | None = None) -> dict:
    """قبل از ذخیره در ستون JSONB صدا زده شود — هرگز raw_config/raw_style
    مستقیم در DB نروند.

    برمی‌گرداند: ``{"config": <dict تمیزشده>, "style": <dict تمیزشده>}``
    """
    schema_cls = _CONFIG_SCHEMA_BY_WIDGET_KEY.get(widget_key)
    if schema_cls is None:
        raise WidgetConfigValidationError(widget_key, "unknown widget_key — no schema registered")

    try:
        clean_config = schema_cls(**raw_config).model_dump()
    except Exception as exc:  # pydantic.ValidationError
        raise WidgetConfigValidationError(widget_key, str(exc)) from exc

    clean_style = {}
    if raw_style is not None:
        try:
            clean_style = WidgetStyle(**raw_style).model_dump()
        except Exception as exc:
            raise WidgetConfigValidationError(widget_key, str(exc)) from exc

    return {"config": clean_config, "style": clean_style}
