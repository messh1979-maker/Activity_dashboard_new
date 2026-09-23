"""
tests/calendar/test_calendar_module.py

اجرا:
    cd backend && pytest tests/calendar/ -v

⚠️ نیاز به ``jdatetime`` و ``pydantic`` واقعی نصب‌شده در محیط شما دارد
(بر خلاف بقیه‌ی تست‌های این پروژه که برای دور زدن وابستگی‌های نصب‌نشده
stub داشتند، اینجا از pydantic واقعی که در venv شما هست استفاده
می‌شود؛ فقط ``jdatetime`` را باید نصب کنید: ``pip install jdatetime``).
"""

from __future__ import annotations

import asyncio
import datetime as dt
import functools
from uuid import uuid4

import pytest

from app.modules.calendar.schemas.widget_config import (
    WidgetConfigValidationError,
    validate_widget_config,
)
from app.modules.calendar.services.calendar_service import CalendarService, GoalDueItem
from app.modules.calendar.services.date_conversion import to_hijri_approximate, to_jalali


def run_async(fn):
    @functools.wraps(fn)
    def wrapper(*a, **k):
        return asyncio.run(fn(*a, **k))
    return wrapper


# ── date_conversion ────────────────────────────────────────

def test_jalali_conversion_is_not_marked_approximate():
    result = to_jalali(dt.date(2024, 3, 20))
    assert result.is_approximate is False


def test_hijri_conversion_is_always_marked_approximate():
    """طبق سند: تقویم قمری رؤیت‌محور است — هرگز نباید دقیق ادعا شود."""
    result = to_hijri_approximate(dt.date(2024, 3, 20))
    assert result.is_approximate is True
    assert result.note is not None and "تقریبی" in result.note


# ── CalendarService (با GoalsPort فیک) ─────────────────────

class FakeGoalsPort:
    def __init__(self, items):
        self.items = items

    async def list_due_between(self, user_id, start_date, end_date):
        return [g for g in self.items if start_date <= g.due_date <= end_date]


class EmptyGoalsPort:
    async def list_due_between(self, user_id, start_date, end_date):
        return []


@run_async
async def test_month_view_buckets_goals_on_correct_day():
    user_id = uuid4()
    probe = CalendarService(EmptyGoalsPort())
    empty_days = await probe.get_month_view(user_id=user_id, jalali_year=1402, jalali_month=1)
    target_date = empty_days[10].gregorian_date

    goal = GoalDueItem(
        goal_id=uuid4(), title="گزارش فصلی", due_date=target_date,
        is_overdue=False, privacy_level="team_only",
    )
    service = CalendarService(FakeGoalsPort([goal]))
    days = await service.get_month_view(
        user_id=user_id, jalali_year=1402, jalali_month=1, today=target_date,
    )

    assert len(days) == len(empty_days)
    matching = [d for d in days if d.gregorian_date == target_date][0]
    assert len(matching.goals) == 1
    assert matching.goals[0].title == "گزارش فصلی"
    assert matching.is_today is True
    assert all(len(d.goals) == 0 for d in days if d.gregorian_date != target_date)


@run_async
async def test_month_view_esfand_has_29_or_30_days():
    service = CalendarService(EmptyGoalsPort())
    days = await service.get_month_view(user_id=uuid4(), jalali_year=1402, jalali_month=12)
    assert len(days) in (29, 30)


# ── widget config — بردار تزریق ────────────────────────────

def test_widget_config_rejects_css_injection_in_font_family():
    with pytest.raises(WidgetConfigValidationError):
        validate_widget_config("clock", {}, {"font_family": "<script>alert(1)</script>"})


def test_widget_config_rejects_non_hex_color():
    with pytest.raises(WidgetConfigValidationError):
        validate_widget_config("clock", {}, {"bg": "red; background-image:url(javascript:alert(1))"})


def test_widget_config_rejects_unknown_widget_key():
    with pytest.raises(WidgetConfigValidationError):
        validate_widget_config("totally_made_up_widget", {})


def test_widget_config_rejects_out_of_range_font_size():
    with pytest.raises(WidgetConfigValidationError):
        validate_widget_config("clock", {}, {"font_size": 999})


def test_widget_config_applies_safe_defaults():
    result = validate_widget_config("quick_add", {})
    assert result["config"]["default_goal_privacy"] == "team_only"
    assert result["style"] == {}
