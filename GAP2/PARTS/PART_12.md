# PART 12/12 of GAP PACK

## FILE: bastehG_tests/backend/tests/architecture/test_module_boundaries.py
## SIZE: 13122 bytes
==========================================================================================

```python
"""
tests/architecture/test_module_boundaries.py

هدف
----
اجرای اجباری مرز ماژول‌ها طبق سند معماری v2.0 (بخش ۰.۳ و ۲.۱/۲.۲):

  ۱) هیچ ماژولی مجاز نیست مستقیماً به زیرپکیج‌های داخلی ماژول دیگر
     (db/ services/ api/ tests/) دسترسی داشته باشد — فقط از طریق
     رابط عمومی (`modules.<name>` که از ports.py/events.py/schemas.py
     صادر می‌شود) مجاز است.

  ۲) هر ماژول فقط مجاز است به ماژول‌هایی وابسته باشد که در نقشه‌ی
     وابستگی رسمی (بخش ۲.۱ سند) صراحتاً برایش تعریف شده — even
     import از رابط عمومی یک ماژول غیرمجاز هم خطاست.

  ۳) M10 (notification) و M11 (audit) طبق سند فقط رویداد مصرف
     می‌کنند و حق import هیچ ماژول دیگری را ندارند.

این تست با AST ایمپورت‌ها را استخراج می‌کند (نه اجرای واقعی کد)،
پس نیازی به دیتابیس/Redis/etc در حال اجرا نیست و بسیار سریع است.

نحوه‌ی استفاده
--------------
این فایل را در مسیر زیر قرار دهید (دقیقاً مطابق ساختار پوشه‌ی
سند معماری، بخش ۳.۱):

    backend/tests/architecture/test_module_boundaries.py

و اجرا کنید:

    cd backend && pytest tests/architecture/ -v

اگر مسیر ماژول‌های شما با آنچه در ADJUST بخش پایین است فرق دارد
(مثلاً app.modules به‌جای modules)، فقط ثابت CANDIDATE_ROOTS و
IMPORT_PREFIXES را تنظیم کنید — منطق تست دست‌نخورده می‌ماند.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# نقشه‌ی وابستگی رسمی ماژول‌ها — دقیقاً از سند معماری v2.0، بخش ۲.۱
# (خطوط نقطه‌چین/رویدادی برای notification و audit در نظر گرفته نشده،
#  چون آن دو طبق سند اصلاً حق import کد ماژول دیگر را ندارند)
# ---------------------------------------------------------------------------
MODULE_DEPENDENCIES: dict[str, set[str]] = {
    "auth": set(),                              # M1 — هسته، به کسی وابسته نیست
    "rbac": {"auth"},                            # M2
    "groups": {"auth", "rbac"},                  # M3
    "goals": {"auth", "rbac"},                   # M4
    "calendar": {"goals", "groups"},             # M5
    "sharing": {"goals", "rbac", "groups"},      # M6
    "chat": {"auth", "files", "sharing"},        # M7
    "inbox": {"auth", "sharing", "chat"},        # M8
    "reporting": {"goals", "groups"},            # M9
    "notification": set(),                       # M10 — فقط مصرف رویداد
    "audit": set(),                               # M11 — فقط مصرف رویداد
    "ssoldap": {"auth"},                         # M12
    "files": set(),                              # M13 — زیرساخت مشترک
}

ALL_MODULES = set(MODULE_DEPENDENCIES)

# زیرپکیج‌هایی که «پیاده‌سازی داخلی» محسوب می‌شوند و هرگز نباید از
# بیرون ماژول import شوند — فقط از طریق ports.py/events.py/schemas.py
# (که در __init__.py خود ماژول صادر می‌شوند) قابل دسترسی‌اند.
INTERNAL_SUBPACKAGES = {"db", "services", "api", "tests"}

# چند مسیر محتمل برای پیدا کردن پوشه‌ی modules/ — به‌ترتیب اولویت.
# اگر ساختار پروژه‌ی شما فرق دارد همین‌جا اضافه کنید.
CANDIDATE_ROOT_SUFFIXES = (
    ("backend", "app", "modules"),
    ("app", "modules"),
    ("modules",),
)

# پیشوندهای import که باید به‌عنوان «اشاره به یک ماژول دامنه» شناسایی شوند.
IMPORT_PREFIXES = ("modules", "app.modules")


@dataclass(frozen=True)
class Violation:
    kind: str            # "internal_access" | "undeclared_dependency"
    importer: str
    file: Path
    lineno: int
    imported: str         # مسیر کامل import، همان‌طور که در سورس نوشته شده
    target_module: str    # نام ماژول مقصد که واقعاً استخراج شده (نه حدس از روی رشته)


def _find_modules_root() -> Path | None:
    """پوشه‌ی modules/ را با جست‌وجو از ریشه‌ی مخزن به پایین پیدا می‌کند."""
    here = Path(__file__).resolve()
    # چند سطح بالا برو تا به ریشه‌ی مخزن برسی (این فایل معمولاً در
    # backend/tests/architecture/ قرار دارد → ۳ سطح بالا = backend/)
    candidates_bases = [here.parents[i] for i in range(min(6, len(here.parents)))]

    for base in candidates_bases:
        for suffix in CANDIDATE_ROOT_SUFFIXES:
            candidate = base.joinpath(*suffix)
            if candidate.is_dir():
                # اطمینان از این‌که واقعاً پوشه‌ی ماژول‌های ما است، نه یک
                # پوشه‌ی هم‌نام تصادفی: باید حداقل یکی از ماژول‌های
                # شناخته‌شده را داخلش داشته باشد.
                if any((candidate / m).is_dir() for m in ALL_MODULES):
                    return candidate
    return None


def _strip_prefix(dotted: str) -> str | None:
    """اگر dotted با یکی از IMPORT_PREFIXES شروع شود، باقی‌مانده را برمی‌گرداند."""
    for prefix in IMPORT_PREFIXES:
        if dotted == prefix or dotted.startswith(prefix + "."):
            return dotted[len(prefix):].lstrip(".")
    return None


def _iter_import_targets(tree: ast.Module) -> list[tuple[str, int]]:
    """همه‌ی مسیرهای import شده (dotted) را همراه با شماره خط برمی‌گرداند."""
    targets: list[tuple[str, int]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                targets.append((alias.name, node.lineno))
        elif isinstance(node, ast.ImportFrom):
            if node.level and node.level > 0:
                continue  # import نسبی (from . import x) — داخل خود ماژول است
            if node.module:
                targets.append((node.module, node.lineno))
    return targets


def _scan_module_files(modules_root: Path, module_name: str) -> list[Violation]:
    violations: list[Violation] = []
    module_dir = modules_root / module_name
    allowed = MODULE_DEPENDENCIES[module_name]

    for py_file in module_dir.rglob("*.py"):
        try:
            source = py_file.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(py_file))
        except (SyntaxError, UnicodeDecodeError):
            continue  # فایل غیرقابل‌پارس را نادیده بگیر؛ مسئولیت لینتر دیگری است

        for dotted, lineno in _iter_import_targets(tree):
            remainder = _strip_prefix(dotted)
            if remainder is None:
                continue  # این import اصلاً به یک ماژول دامنه اشاره نمی‌کند

            parts = remainder.split(".") if remainder else []
            if not parts:
                continue
            target_module = parts[0]

            if target_module == module_name:
                continue  # import از خودش — طبیعی است
            if target_module not in ALL_MODULES:
                continue  # اشاره به چیزی خارج از نقشه‌ی شناخته‌شده (core و...)

            # قاعده‌ی ۱: دسترسی مستقیم به زیرپکیج داخلی ماژول دیگر ممنوع است
            if len(parts) >= 2 and parts[1] in INTERNAL_SUBPACKAGES:
                violations.append(
                    Violation("internal_access", module_name, py_file, lineno, dotted, target_module)
                )
                continue  # همین یک نقض کافی است؛ لازم نیست قاعده ۲ هم چک شود

            # قاعده‌ی ۲: حتی رابط عمومی هم فقط برای وابستگی‌های اعلام‌شده مجاز است
            if target_module not in allowed:
                violations.append(
                    Violation("undeclared_dependency", module_name, py_file, lineno, dotted, target_module)
                )

    return violations


def _format_violation(v: Violation) -> str:
    rel = v.file
    if v.kind == "internal_access":
        return (
            f"  [دسترسی مستقیم ممنوع] {rel}:{v.lineno}\n"
            f"      '{v.importer}' مستقیماً به پیاده‌سازی داخلی import می‌کند: `{v.imported}`\n"
            f"      → به‌جای این، از رابط عمومی استفاده کنید: "
            f"`from modules.{v.target_module} import ...` "
            f"(یا اگر نیاز واقعی، انتشار/مصرف رویداد است، از Event Bus استفاده کنید)"
        )
    return (
        f"  [وابستگی اعلام‌نشده] {rel}:{v.lineno}\n"
        f"      '{v.importer}' به ماژول '{v.target_module}' import می‌کند که در نقشه‌ی وابستگی "
        f"(بخش ۲.۱ سند) برایش مجاز نیست: `{v.imported}`\n"
        f"      → یا نقشه‌ی وابستگی را در سند/این تست به‌روز کنید (تصمیم معماری آگاهانه)، "
        f"یا وابستگی را حذف کنید."
    )


MODULES_ROOT = _find_modules_root()

pytestmark = pytest.mark.skipif(
    MODULES_ROOT is None,
    reason=(
        "پوشه‌ی backend/app/modules/ پیدا نشد. اگر مسیر پروژه‌ی شما فرق دارد، "
        "CANDIDATE_ROOT_SUFFIXES را در بالای این فایل تنظیم کنید."
    ),
)


@pytest.mark.parametrize("module_name", sorted(MODULE_DEPENDENCIES))
def test_no_forbidden_cross_module_imports(module_name: str) -> None:
    """مرز هر ماژول با آزمون اجباری می‌شود، نه با توافق شفاهی (سند، بخش ۰.۳)."""
    assert MODULES_ROOT is not None  # برای mypy/خوانایی؛ skipif بالا این حالت را می‌گیرد

    module_dir = MODULES_ROOT / module_name
    if not module_dir.is_dir():
        pytest.skip(f"ماژول '{module_name}' هنوز پیاده‌سازی نشده — رد شد.")

    violations = _scan_module_files(MODULES_ROOT, module_name)

    if violations:
        details = "\n".join(_format_violation(v) for v in violations)
        pytest.fail(
            f"\nماژول '{module_name}' مرز معماری را نقض کرده "
            f"({len(violations)} مورد):\n\n{details}\n"
        )


def test_notification_and_audit_are_event_only() -> None:
    """طبق سند (بخش ۲.۱): M10 و M11 نباید هیچ ماژول دیگری را import کنند."""
    if MODULES_ROOT is None:
        pytest.skip("پوشه‌ی modules/ پیدا نشد.")

    for module_name in ("notification", "audit"):
        assert MODULE_DEPENDENCIES[module_name] == set(), (
            f"'{module_name}' طبق سند فقط باید مصرف‌کننده‌ی رویداد باشد؛ "
            f"نباید هیچ وابستگی مستقیمی در MODULE_DEPENDENCIES داشته باشد."
        )
        module_dir = MODULES_ROOT / module_name
        if not module_dir.is_dir():
            continue
        violations = _scan_module_files(MODULES_ROOT, module_name)
        assert not violations, (
            f"'{module_name}' نباید هیچ ماژول دیگری را import کند "
            f"(فقط باید از طریق Event Bus مصرف کند):\n"
            + "\n".join(_format_violation(v) for v in violations)
        )


def test_dependency_graph_has_no_cycles() -> None:
    """اطمینان از این‌که خودِ نقشه‌ی وابستگی در سند/تست، حلقه ندارد."""
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(node: str, path: list[str]) -> None:
        if node in visited:
            return
        if node in visiting:
            cycle = " → ".join(path + [node])
            pytest.fail(f"حلقه‌ی وابستگی در نقشه‌ی ماژول‌ها پیدا شد: {cycle}")
        visiting.add(node)
        for dep in MODULE_DEPENDENCIES.get(node, set()):
            visit(dep, path + [node])
        visiting.discard(node)
        visited.add(node)

    for module_name in MODULE_DEPENDENCIES:
        visit(module_name, [])
```

==========================================================================================
## FILE: bastehG_tests/backend/tests/auth/test_admin_user_service.py
## SIZE: 6281 bytes
==========================================================================================

```python
"""
tests/auth/test_admin_user_service.py

تست‌های واحد برای AdminUserService — بدون DB واقعی (Fake repo)، هم‌خانواده
با tests/rbac/test_role_assignment_escalation.py (همان الگوی run_async).

اجرا:
    cd backend && pytest tests/auth/test_admin_user_service.py -v
"""

from __future__ import annotations

import asyncio
import functools
from uuid import uuid4

import pytest

from app.core.errors import APIError
from app.modules.auth.admin_ports import (
    AdminCreateUserRequest,
    AdminUpdateUserRequest,
    BulkLoginModeRequest,
)
from app.modules.auth.services.admin_user_service import AdminUserService


def run_async(fn):
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        return asyncio.run(fn(*args, **kwargs))
    return wrapper


class FakeActor:
    def __init__(self, id):
        self.id = id


class FakeUser:
    def __init__(self, id, username, password_hash="hashed:x", auth_mode="local",
                 sso_enabled=False, token_version=0, is_active=True,
                 national_id_last4="1234", display_name="Test",
                 mfa_enabled=False, last_login_at=None):
        self.id = id
        self.username = username
        self.password_hash = password_hash
        self.auth_mode = auth_mode
        self.sso_enabled = sso_enabled
        self.token_version = token_version
        self.is_active = is_active
        self.national_id_last4 = national_id_last4
        self.display_name = display_name
        self.mfa_enabled = mfa_enabled
        self.last_login_at = last_login_at
        self.must_change_password = False


class FakeSession:
    def __init__(self):
        self.added = []

    def add(self, obj):
        self.added.append(obj)


class FakeUserRepo:
    def __init__(self, users=None):
        self._users = {u.id: u for u in (users or [])}
        self.session = FakeSession()
        self.commits = 0

    async def get(self, uid):
        return self._users.get(uid)

    async def get_by_username(self, username):
        return next((u for u in self._users.values() if u.username == username), None)

    async def get_by_national_id(self, nid):
        return None

    async def add(self, user):
        self._users[user.id] = user

    async def commit(self):
        self.commits += 1


# کد ملی معتبر (چک‌سام درست) صرفاً برای تست
VALID_NATIONAL_ID = "0499370899"


@run_async
async def test_create_user_rejects_invalid_national_id():
    admin_id = uuid4()
    repo = FakeUserRepo([FakeUser(id=admin_id, username="admin")])
    svc = AdminUserService(repo)

    with pytest.raises(APIError) as exc_info:
        await svc.create_user(FakeActor(admin_id), AdminCreateUserRequest(
            username="newguy", national_id="1234567890",
            display_name="New Guy", initial_password="longpassword123",
        ))
    assert exc_info.value.error_code == "INVALID_NATIONAL_ID"


@run_async
async def test_create_user_rejects_duplicate_username():
    admin_id = uuid4()
    repo = FakeUserRepo([FakeUser(id=admin_id, username="admin")])
    svc = AdminUserService(repo)
    actor = FakeActor(admin_id)

    await svc.create_user(actor, AdminCreateUserRequest(
        username="newguy", national_id=VALID_NATIONAL_ID,
        display_name="New Guy", initial_password="longpassword123",
    ))

    with pytest.raises(APIError) as exc_info:
        await svc.create_user(actor, AdminCreateUserRequest(
            username="newguy", national_id=VALID_NATIONAL_ID,
            display_name="Someone Else", initial_password="anotherpassword123",
        ))
    assert exc_info.value.error_code == "USERNAME_EXISTS"


@run_async
async def test_cannot_deactivate_self():
    admin_id = uuid4()
    repo = FakeUserRepo([FakeUser(id=admin_id, username="admin")])
    svc = AdminUserService(repo)

    with pytest.raises(APIError) as exc_info:
        await svc.update_user(FakeActor(admin_id), admin_id, AdminUpdateUserRequest(is_active=False))
    assert exc_info.value.error_code == "CANNOT_DEACTIVATE_SELF"


@run_async
async def test_deactivate_other_user_revokes_sessions():
    admin_id, target_id = uuid4(), uuid4()
    target = FakeUser(id=target_id, username="bob")
    repo = FakeUserRepo([FakeUser(id=admin_id, username="admin"), target])
    svc = AdminUserService(repo)

    await svc.update_user(FakeActor(admin_id), target_id, AdminUpdateUserRequest(is_active=False))

    assert target.is_active is False
    assert target.token_version == 1  # نشست‌ها باطل شدند


@run_async
async def test_bulk_login_mode_all_three_failure_kinds_plus_success():
    admin = FakeUser(id=uuid4(), username="admin", auth_mode="local")
    normal_user = FakeUser(id=uuid4(), username="ali", auth_mode="sso")  # هم رمز محلی دارد هم sso
    sso_only_user = FakeUser(id=uuid4(), username="sara", password_hash=None, auth_mode="sso")
    missing_id = uuid4()

    repo = FakeUserRepo([admin, normal_user, sso_only_user])
    svc = AdminUserService(repo)
    actor = FakeActor(admin.id)

    # خاموش‌کردن sso (اجبار به local) برای همه — sso_only_user باید رد شود
    request = BulkLoginModeRequest(
        user_ids=[normal_user.id, sso_only_user.id, missing_id, admin.id],
        sso_enabled=False, revoke_sessions=True,
    )
    result = await svc.bulk_change_login_mode(actor, request)

    assert normal_user.id in result.updated
    assert normal_user.auth_mode == "local"
    assert normal_user.token_version == 1

    failure_codes = {f.code for f in result.failed}
    assert failure_codes == {"NOT_FOUND", "CANNOT_MODIFY_SELF", "NO_LOCAL_PASSWORD"}
    assert sso_only_user.auth_mode == "sso"  # دست‌نخورده ماند


@run_async
async def test_bulk_login_mode_rejects_more_than_500():
    admin = FakeUser(id=uuid4(), username="admin")
    repo = FakeUserRepo([admin])
    svc = AdminUserService(repo)

    class OversizedRequest:
        user_ids = [uuid4() for _ in range(501)]
        sso_enabled = True
        revoke_sessions = False

    with pytest.raises(APIError) as exc_info:
        await svc.bulk_change_login_mode(FakeActor(admin.id), OversizedRequest())
    assert exc_info.value.error_code == "TOO_MANY_USERS"
```

==========================================================================================
## FILE: bastehG_tests/backend/tests/calendar/test_calendar_module.py
## SIZE: 4478 bytes
==========================================================================================

```python
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
```

==========================================================================================
## FILE: bastehG_tests/backend/tests/conftest.py
## SIZE: 471 bytes
==========================================================================================

```python
"""Shared test setup. Environment is fixed *before* ``app`` is imported."""
import os

os.environ.setdefault("ENV", "testing")
os.environ.setdefault("DEBUG", "false")  # a local .env must not leak into tests
os.environ.setdefault("SECRET_KEY", "test-secret-key-that-is-at-least-32-chars-long")
os.environ.setdefault(
    "SQLALCHEMY_DATABASE_URI",
    "postgresql+asyncpg://admin:admin123@localhost:5432/planner_db",
)
os.environ.setdefault("RATE_LIMIT_ENABLED", "true")
```

==========================================================================================
## FILE: bastehG_tests/backend/tests/core/test_config.py
## SIZE: 1504 bytes
==========================================================================================

```python
import pytest
from pydantic import ValidationError

from app.core.config import Settings

BASE = dict(
    SECRET_KEY="x" * 40,
    SQLALCHEMY_DATABASE_URI="postgresql+asyncpg://u:p@localhost/db",
)


def make(**kw):
    return Settings(_env_file=None, **{**BASE, **kw})


def test_short_secret_key_rejected():
    with pytest.raises(ValidationError):
        make(SECRET_KEY="short")


def test_unknown_algorithm_rejected():
    with pytest.raises(ValidationError):
        make(ALGORITHM="none")


def test_rs256_requires_keys():
    with pytest.raises(ValidationError):
        make(ALGORITHM="RS256")


def test_production_rejects_insecure_defaults():
    with pytest.raises(ValidationError) as e:
        make(ENV="production")  # ALLOWED_HOSTS '*', no DEK/pepper
    msg = str(e.value)
    assert "ALLOWED_HOSTS" in msg and "DATA_ENCRYPTION_KEY" in msg and "NATIONAL_ID_PEPPER" in msg


def test_production_ok_when_hardened():
    s = make(ENV="production", ALLOWED_HOSTS=["api.corp.local"],
             DATA_ENCRYPTION_KEY="a" * 44, NATIONAL_ID_PEPPER="p" * 32)
    assert s.is_production


def test_log_format_is_valid():
    import logging
    s = make()
    rec = logging.LogRecord("n", logging.INFO, "f.py", 1, "hello", None, None)
    assert "INFO" in logging.Formatter(s.LOG_FORMAT).format(rec)


def test_redis_url_and_ws_origins_fallback():
    s = make(REDIS_HOST="r", REDIS_PORT=1, REDIS_DB=2)
    assert s.redis_url == "redis://r:1/2"
    assert s.ws_allowed_origins == s.CORS_ORIGINS
```

==========================================================================================
## FILE: bastehG_tests/backend/tests/core/test_context.py
## SIZE: 596 bytes
==========================================================================================

```python
import asyncio

from app.core.context import RequestContext, get_context, reset_context, set_context


async def _worker(name: str, delay: float):
    tok = set_context(RequestContext(request_id=name, user_id=name))
    await asyncio.sleep(delay)
    seen = get_context().user_id
    reset_context(tok)
    return seen


async def test_concurrent_contexts_do_not_leak():
    results = await asyncio.gather(*[_worker(f"u{i}", 0.01 * (5 - i)) for i in range(5)])
    assert results == [f"u{i}" for i in range(5)]


def test_empty_context_outside_request():
    assert get_context().user_id is None
```

==========================================================================================
## FILE: bastehG_tests/backend/tests/core/test_events.py
## SIZE: 5318 bytes
==========================================================================================

```python
"""Event bus + transactional outbox (architecture 2.3). Needs PostgreSQL."""
from __future__ import annotations

import os
from uuid import uuid4

import pytest
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.core.context import RequestContext, reset_context, set_context
from app.core.events.bus import DomainEvent, EventBus
from app.core.events.dispatcher import MAX_ATTEMPTS, dispatch_pending_outbox_messages
from app.core.events.outbox import OutboxMessage

pytestmark = pytest.mark.integration


@pytest.fixture
async def factory():
    engine = create_async_engine(os.environ["SQLALCHEMY_DATABASE_URI"])
    try:
        async with engine.connect() as c:
            await c.execute(text("SELECT 1 FROM core.outbox_messages LIMIT 1"))
    except Exception as exc:  # no DB / migrations not applied
        await engine.dispose()
        pytest.skip(f"PostgreSQL with migrations not available: {exc}")
    yield async_sessionmaker(engine, expire_on_commit=False)
    await engine.dispose()


def _ev(kind: str, **payload) -> DomainEvent:
    return DomainEvent(event_type=kind, payload=payload)


async def _row(factory, event_id):
    async with factory() as s:
        return (await s.execute(select(OutboxMessage).where(
            OutboxMessage.event_id == event_id))).scalar_one_or_none()


async def test_outbox_row_is_atomic_with_transaction(factory):
    bus = EventBus()
    kept, dropped = _ev("t.kept"), _ev("t.dropped")
    async with factory() as s:
        await bus.publish(kept, s)
        await s.commit()
    async with factory() as s:
        await bus.publish(dropped, s)
        await s.rollback()  # business transaction fails -> no event may survive
    assert await _row(factory, kept.event_id) is not None
    assert await _row(factory, dropped.event_id) is None


async def test_transactional_handler_runs_inline_and_is_not_replayed(factory):
    bus, calls = EventBus(), []

    async def inline(event, session):
        calls.append(("inline", event.event_id))

    bus.subscribe("t.audit", inline)  # default: same transaction
    ev = _ev("t.audit")
    async with factory() as s:
        await bus.publish(ev, s)
        await s.commit()
    assert calls == [("inline", ev.event_id)]

    # Dispatcher must not re-run transactional handlers (old bug: duplicate audit rows)
    import app.core.events.dispatcher as d
    original, d.event_bus = d.event_bus, bus
    try:
        async with factory() as s:
            await dispatch_pending_outbox_messages(s, batch_size=1000)
    finally:
        d.event_bus = original
    assert len(calls) == 1
    assert (await _row(factory, ev.event_id)).dispatched_at is not None


async def test_handler_failure_rolls_back_publish(factory):
    bus = EventBus()

    async def bad(event, session):
        raise RuntimeError("boom")

    bus.subscribe("t.bad", bad)
    ev = _ev("t.bad")
    async with factory() as s:
        with pytest.raises(RuntimeError):
            await bus.publish(ev, s)
        await s.rollback()
    assert await _row(factory, ev.event_id) is None


async def test_async_consumer_delivery_retry_and_dead_letter(factory):
    import app.core.events.dispatcher as d

    bus, seen, fail = EventBus(), [], {"on": True}

    async def notify(event, session):
        if event.payload.get("poison") and fail["on"]:
            raise RuntimeError("smtp down")
        seen.append(event.event_id)

    bus.subscribe("t.notify", notify, transactional=False)
    good, poison = _ev("t.notify"), _ev("t.notify", poison=True)
    async with factory() as s:
        await bus.publish(good, s)
        await bus.publish(poison, s)
        await s.commit()
    assert seen == []  # not delivered in-process

    original, d.event_bus = d.event_bus, bus
    try:
        async with factory() as s:
            await dispatch_pending_outbox_messages(s, batch_size=10_000)
        # a poison row must not block the good one (SAVEPOINT per row)
        assert good.event_id in seen and poison.event_id not in seen
        bad = await _row(factory, poison.event_id)
        assert bad.dispatched_at is None and bad.attempts == 1 and "smtp down" in bad.last_error

        for _ in range(MAX_ATTEMPTS):  # keeps failing -> parked after MAX_ATTEMPTS
            async with factory() as s:
                await dispatch_pending_outbox_messages(s, batch_size=10_000)
        assert (await _row(factory, poison.event_id)).attempts == MAX_ATTEMPTS

        fail["on"] = False  # at-least-once: still nothing delivered twice for `good`
        assert seen.count(good.event_id) == 1
    finally:
        d.event_bus = original


async def test_context_fills_actor_and_correlation(factory):
    bus, uid, cid = EventBus(), uuid4(), uuid4()
    token = set_context(RequestContext(user_id=str(uid), correlation_id=str(cid)))
    try:
        ev = _ev("t.ctx")
        async with factory() as s:
            await bus.publish(ev, s)
            await s.commit()
    finally:
        reset_context(token)
    assert (await _row(factory, ev.event_id)).correlation_id == cid


def test_subscribe_is_idempotent():
    bus = EventBus()

    async def h(e, s): ...

    bus.subscribe("x", h); bus.subscribe("x", h)
    assert bus.handlers_for("x", transactional=True) == [h]
```

==========================================================================================
## FILE: bastehG_tests/backend/tests/core/test_middleware.py
## SIZE: 7267 bytes
==========================================================================================

```python
import httpx
import pytest
from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.context import get_context
from app.core.errors import (APIError, NotFoundError, PermissionDeniedError,
                             register_exception_handlers)
from app.core.middleware.audit_context import AuditContextMiddleware
from app.core.middleware.body_guard import BodyGuardMiddleware
from app.core.middleware.ip_filter import IPFilterMiddleware
from app.core.middleware.rate_limit import (MemoryLimiter, RateLimitMiddleware,
                                            parse_limit)
from app.core.middleware.request_id import RequestIDMiddleware
from app.core.middleware.security_headers import SecurityHeadersMiddleware


class Body(BaseModel):
    n: int


def make_app(*, rate="3/minute", auth="2/minute", deny=None, allow=None):
    app = FastAPI()
    register_exception_handlers(app)

    @app.get("/ctx")
    async def ctx():
        c = get_context()
        return {"rid": c.request_id, "ip": c.ip, "ua": c.user_agent, "mac": c.mac_address,
                "fp": c.device_fingerprint}

    @app.get("/api/v1/auth/login")
    async def login():
        return {}

    @app.post("/echo")
    async def echo(b: Body):
        return b.model_dump()

    @app.get("/boom")
    async def boom():
        raise RuntimeError("secret internals")

    @app.get("/nf")
    async def nf():
        raise NotFoundError("گروه")

    @app.get("/deny")
    async def deny_():
        raise PermissionDeniedError("CANNOT_SELF_ASSIGN")

    app.add_middleware(AuditContextMiddleware)
    app.add_middleware(BodyGuardMiddleware)
    app.add_middleware(RateLimitMiddleware, limiter=MemoryLimiter(), default=rate, auth=auth)
    app.add_middleware(IPFilterMiddleware, allow_ips=allow, deny_ips=deny)
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(RequestIDMiddleware)
    return app


def client(app, **kw):
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app, raise_app_exceptions=False,
                                                           client=("10.1.1.1", 5000)),
                             base_url="http://t", **kw)


async def test_request_id_and_security_headers():
    async with client(make_app()) as c:
        r = await c.get("/ctx", headers={"X-Request-ID": "abcdefgh-1234"})
    assert r.headers["x-request-id"] == "abcdefgh-1234"
    assert r.json()["rid"] == "abcdefgh-1234"
    assert r.headers["x-content-type-options"] == "nosniff"
    assert "default-src 'none'" in r.headers["content-security-policy"]
    assert r.headers["cache-control"] == "no-store"


async def test_unsafe_request_id_is_replaced():
    async with client(make_app()) as c:
        r = await c.get("/ctx", headers={"X-Request-ID": "bad id\r\nX: y"})
    assert " " not in r.headers["x-request-id"]


async def test_audit_context_from_headers_and_socket():
    async with client(make_app()) as c:
        r = await c.get("/ctx", headers={"User-Agent": "PlannerDesktop/2.0",
                                          "X-Device-MAC": "00-1a-2b-3c-4d-5e",
                                          "X-Device-Fingerprint": "a" * 32})
    j = r.json()
    assert j["ip"] == "10.1.1.1" and j["ua"] == "PlannerDesktop/2.0"
    assert j["mac"] == "00:1A:2B:3C:4D:5E" and j["fp"] == "a" * 32


async def test_invalid_mac_is_dropped():
    async with client(make_app()) as c:
        r = await c.get("/ctx", headers={"X-Device-MAC": "not-a-mac"})
    assert r.json()["mac"] is None


async def test_x_forwarded_for_ignored_from_untrusted_peer():
    async with client(make_app()) as c:
        r = await c.get("/ctx", headers={"X-Forwarded-For": "6.6.6.6"})
    assert r.json()["ip"] == "10.1.1.1"


async def test_rate_limit_default_bucket_and_retry_after():
    async with client(make_app(rate="3/minute")) as c:
        codes = [(await c.get("/ctx")).status_code for _ in range(5)]
        blocked = await c.get("/ctx")
    assert codes == [200, 200, 200, 429, 429]
    assert int(blocked.headers["retry-after"]) >= 1
    assert blocked.json()["error"] == "RATE_LIMIT_EXCEEDED"
    assert "x-request-id" in blocked.headers  # outer middlewares still apply


async def test_rate_limit_auth_bucket_is_separate_and_stricter():
    async with client(make_app(rate="100/minute", auth="2/minute")) as c:
        codes = [(await c.get("/api/v1/auth/login")).status_code for _ in range(3)]
        other = (await c.get("/ctx")).status_code
    assert codes == [200, 200, 429] and other == 200


async def test_rate_limit_not_bypassed_by_changing_path():
    async with client(make_app(rate="2/minute")) as c:
        codes = [(await c.get(f"/ctx?x={i}")).status_code for i in range(4)]
        codes.append((await c.get("/nf")).status_code)
    assert codes[2:] == [429, 429, 429]


async def test_ip_deny_cidr_returns_real_response_not_tuple():
    async with client(make_app(deny=["10.1.0.0/16"])) as c:
        r = await c.get("/ctx")
    assert r.status_code == 403 and r.json()["error"] == "IP_ADDRESS_DENIED"


async def test_ip_allow_list():
    async with client(make_app(allow=["192.168.0.0/24"])) as c:
        r = await c.get("/ctx")
    assert r.status_code == 403 and r.json()["error"] == "IP_ADDRESS_NOT_ALLOWED"


async def test_body_guard_content_length(monkeypatch):
    from app.core.config import settings
    monkeypatch.setattr(settings, "MAX_BODY_SIZE", 50)
    async with client(make_app()) as c:
        r = await c.post("/echo", content=b"x" * 200, headers={"Content-Type": "application/json"})
        ok = await c.post("/echo", json={"n": 1})
    assert r.status_code == 413 and r.json()["error"] == "PAYLOAD_TOO_LARGE"
    assert ok.status_code == 200


async def test_body_guard_streamed_without_content_length(monkeypatch):
    from app.core.config import settings
    monkeypatch.setattr(settings, "MAX_BODY_SIZE", 50)

    async def gen():
        for _ in range(10):
            yield b'{"n": 1,' + b" " * 20

    async with client(make_app()) as c:
        r = await c.post("/echo", content=gen(), headers={"Content-Type": "application/json"})
    assert r.status_code == 413


async def test_error_formats():
    async with client(make_app(rate="1000/minute")) as c:
        nf = await c.get("/nf")
        deny = await c.get("/deny")
        route404 = await c.get("/nope")
        validation = await c.post("/echo", json={"n": "abc"})
        boom = await c.get("/boom")
    assert nf.status_code == 404 and nf.json()["error"] == "NOT_FOUND"
    assert deny.status_code == 403 and deny.json()["error"] == "CANNOT_SELF_ASSIGN"
    assert route404.status_code == 404 and route404.json()["error"] == "NOT_FOUND"  # Starlette 404
    assert validation.status_code == 422 and validation.json()["error"] == "VALIDATION_ERROR"
    assert isinstance(validation.json()["details"], list)
    assert boom.status_code == 500 and "secret internals" not in boom.text
    assert boom.json()["request_id"]


def test_parse_limit():
    assert parse_limit("100/minute") == (100, 60)
    assert parse_limit("5/second") == (5, 1)
    with pytest.raises(ValueError):
        parse_limit("lots")
```

==========================================================================================
## FILE: bastehG_tests/backend/tests/files/test_file_validators_and_scan.py
## SIZE: 4738 bytes
==========================================================================================

```python
"""
tests/files/test_file_validators_and_scan.py

اجرا:
    cd backend && pytest tests/files/ -v
"""

from __future__ import annotations

import asyncio
import functools
from uuid import uuid4

import pytest

from app.modules.files.db.models import Upload
from app.modules.files.services.av_scan_service import AvScanService
from app.modules.files.services.storage import StorageError
from app.modules.files.services.validators import (
    MAX_UPLOAD_SIZE_BYTES,
    FileValidationError,
    validate_extension,
    validate_magic_number_matches_extension,
    validate_size,
)


def run_async(fn):
    @functools.wraps(fn)
    def wrapper(*a, **k):
        return asyncio.run(fn(*a, **k))
    return wrapper


# ── validators (خالص) ──────────────────────────────────────

def test_dangerous_extension_rejected():
    with pytest.raises(FileValidationError) as exc_info:
        validate_extension("resume.exe")
    assert exc_info.value.code == "DANGEROUS_FILE_TYPE"


def test_extension_not_in_whitelist_rejected():
    with pytest.raises(FileValidationError) as exc_info:
        validate_extension("archive.rar")
    assert exc_info.value.code == "EXTENSION_NOT_ALLOWED"


def test_allowed_extension_passes():
    assert validate_extension("report.PDF") == ".pdf"


def test_size_bounds():
    with pytest.raises(FileValidationError):
        validate_size(0)
    with pytest.raises(FileValidationError):
        validate_size(MAX_UPLOAD_SIZE_BYTES + 1)
    validate_size(1024)  # نباید خطا بدهد


def test_executable_renamed_as_pdf_is_caught_by_magic_number():
    """کلاسیک‌ترین حمله: فایل اجرایی با پسوند pdf."""
    exe_header = b"MZ\x90\x00\x03\x00\x00\x00"
    with pytest.raises(FileValidationError) as exc_info:
        validate_magic_number_matches_extension(exe_header, ".pdf")
    assert exc_info.value.code == "UNKNOWN_FILE_SIGNATURE"


def test_real_pdf_header_accepted():
    validate_magic_number_matches_extension(b"%PDF-1.7\nrest...", ".pdf")


def test_docx_zip_family_accepted():
    zip_header = b"PK\x03\x04" + b"\x00" * 20
    validate_magic_number_matches_extension(zip_header, ".docx")


def test_mismatched_real_signature_rejected():
    """jpeg واقعی که ادعا می‌کند png است."""
    jpeg_header = b"\xff\xd8\xff\xe0"
    with pytest.raises(FileValidationError) as exc_info:
        validate_magic_number_matches_extension(jpeg_header, ".png")
    assert exc_info.value.code == "EXTENSION_MISMATCH"


# ── AvScanService: Fail-Closed ─────────────────────────────

class FakeSession:
    def __init__(self):
        self.added = []

    def add(self, obj):
        self.added.append(obj)

    async def commit(self):
        pass


class FakeStorage:
    def __init__(self, header, fail_read=False):
        self.header = header
        self.fail_read = fail_read
        self.deleted = []

    def get_object_bytes(self, key, n):
        if self.fail_read:
            raise StorageError("boom")
        return self.header

    def delete_object(self, key):
        self.deleted.append(key)


def make_upload(**kw):
    defaults = dict(id=uuid4(), uploader_id=uuid4(), object_key="k", original_name="doc.pdf", size_bytes=100)
    defaults.update(kw)
    return Upload(**defaults)


@run_async
async def test_scan_is_fail_closed_when_clamav_not_installed():
    """طبق pip list پروژه‌ی شما: pyclamd نصب نیست — پس هیچ فایلی نباید
    هرگز به‌طور خودکار 'clean' علامت بخورد."""
    upload = make_upload(original_name="doc.pdf")
    storage = FakeStorage(header=b"%PDF-1.7 ...")
    service = AvScanService(FakeSession(), storage, settings=object())

    await service.scan(upload)

    assert upload.scan_status == "error"
    assert upload.is_available is False


@run_async
async def test_signature_mismatch_marks_infected_and_deletes_object():
    upload = make_upload(original_name="evil.pdf")
    storage = FakeStorage(header=b"MZ\x90\x00\x03\x00\x00\x00")  # PE header
    service = AvScanService(FakeSession(), storage, settings=object())

    await service.scan(upload)

    assert upload.scan_status == "infected"
    assert upload.is_available is False
    assert "k" in storage.deleted


@run_async
async def test_storage_read_failure_is_fail_closed():
    upload = make_upload()
    storage = FakeStorage(header=b"", fail_read=True)
    service = AvScanService(FakeSession(), storage, settings=object())

    await service.scan(upload)

    assert upload.scan_status == "error"
    assert upload.is_available is False
```

==========================================================================================
## FILE: bastehG_tests/backend/tests/rbac/test_permission_service.py
## SIZE: 2951 bytes
==========================================================================================

```python
"""
tests/rbac/test_permission_service.py

اجرا:
    cd backend && pytest tests/rbac/test_permission_service.py -v
"""

from __future__ import annotations

import asyncio
import functools
from uuid import uuid4

from app.modules.rbac.services.permission_service import PermissionService


def run_async(fn):
    @functools.wraps(fn)
    def wrapper(*a, **k):
        return asyncio.run(fn(*a, **k))
    return wrapper


class FakeRedis:
    def __init__(self):
        self.store: dict[str, str] = {}
        self.setex_calls = 0
        self.delete_calls = 0

    async def get(self, key):
        return self.store.get(key)

    async def setex(self, key, ttl, value):
        self.setex_calls += 1
        self.store[key] = value

    async def delete(self, key):
        self.delete_calls += 1
        self.store.pop(key, None)


class BrokenRedis(FakeRedis):
    async def get(self, key):
        raise ConnectionError("redis down")


class FakeResult:
    def __init__(self, rows):
        self._rows = rows

    def fetchall(self):
        return self._rows


class FakeSession:
    def __init__(self, rows):
        self._rows = rows
        self.db_query_count = 0

    async def execute(self, *a, **k):
        self.db_query_count += 1
        return FakeResult(self._rows)


@run_async
async def test_second_call_hits_cache_not_db():
    user_id = uuid4()
    redis = FakeRedis()
    session = FakeSession(rows=[("goal.create",), ("goal.read",)])
    service = PermissionService(session, redis)

    first = await service.effective_permissions(user_id)
    second = await service.effective_permissions(user_id)

    assert first == second == {"goal.create", "goal.read"}
    assert session.db_query_count == 1  # دومین بار از کش آمد، نه DB
    assert redis.setex_calls == 1


@run_async
async def test_invalidate_forces_db_requery():
    user_id = uuid4()
    redis = FakeRedis()
    session = FakeSession(rows=[("goal.create",)])
    service = PermissionService(session, redis)

    await service.effective_permissions(user_id)
    await service.invalidate(user_id)
    await service.effective_permissions(user_id)

    assert session.db_query_count == 2
    assert redis.delete_calls == 1


@run_async
async def test_redis_outage_falls_back_to_db_without_crashing():
    user_id = uuid4()
    session = FakeSession(rows=[("x.y",)])
    service = PermissionService(session, BrokenRedis())

    perms = await service.effective_permissions(user_id)

    assert perms == {"x.y"}


@run_async
async def test_no_redis_configured_still_works():
    """اگر Redis تزریق نشود (None)، سرویس باید بدون کش درست کار کند."""
    user_id = uuid4()
    session = FakeSession(rows=[("a.b",), ("c.d",)])
    service = PermissionService(session, redis_client=None)

    perms = await service.effective_permissions(user_id)

    assert perms == {"a.b", "c.d"}
    assert session.db_query_count == 1
```

==========================================================================================
## FILE: bastehG_tests/backend/tests/ssoldap/test_sso_login_service.py
## SIZE: 5158 bytes
==========================================================================================

```python
"""
tests/ssoldap/test_sso_login_service.py

اجرا:
    cd backend && pytest tests/ssoldap/ -v
"""

from __future__ import annotations

import asyncio
import functools
from uuid import uuid4

import pytest

from app.core.errors import APIError
from app.modules.ssoldap.services.ldap_service import (
    LdapAuthError,
    LdapUserInfo,
    escape_ldap_filter_value,
    map_groups_to_roles,
)
from app.modules.ssoldap.services.sso_login_service import SsoLoginService


def run_async(fn):
    @functools.wraps(fn)
    def wrapper(*a, **k):
        return asyncio.run(fn(*a, **k))
    return wrapper


# ── توابع خالص (بدون وابستگی به ldap3/شبکه) ──────────────────

def test_escape_blocks_ldap_filter_injection():
    malicious = "admin)(|(uid=*"
    escaped = escape_ldap_filter_value(malicious)
    assert "(" not in escaped.replace(r"\28", "")
    assert ")" not in escaped.replace(r"\29", "")
    assert r"\28" in escaped and r"\29" in escaped and r"\2a" in escaped


def test_map_groups_to_roles_is_case_and_space_insensitive():
    group_map = {
        "CN=Managers,OU=Groups,DC=corp,DC=local": "manager",
        "CN=Admins, OU=Groups,DC=corp,DC=local": "admin",
    }
    member_of = [
        "cn=managers, ou=groups,dc=corp,dc=local",
        "CN=SomeOtherGroup,OU=Groups,DC=corp,DC=local",
    ]
    assert map_groups_to_roles(member_of, group_map) == ["manager"]


def test_map_groups_to_roles_no_duplicates():
    group_map = {"CN=A,DC=x": "role_a"}
    member_of = ["CN=A,DC=x", "cn=a,dc=x"]
    assert map_groups_to_roles(member_of, group_map) == ["role_a"]


# ── SsoLoginService (با LdapService/AuthService/UserRepo فیک) ─

class FakeUser:
    def __init__(self, **kw):
        self.id = uuid4()
        self.sso_enabled = kw.get("sso_enabled", True)
        self.is_active = kw.get("is_active", True)
        self.ldap_dn = None
        self.ldap_object_guid = None


class FakeSession:
    def __init__(self):
        self.added = []

    def add(self, obj):
        self.added.append(obj)


class FakeUserRepo:
    def __init__(self, user=None):
        self._user = user
        self.session = FakeSession()
        self.commits = 0

    async def get_by_national_id(self, nid):
        return self._user

    async def add(self, user):
        self._user = user

    async def commit(self):
        self.commits += 1


class FakeLdapService:
    def __init__(self, info=None, error=None):
        self._info = info
        self._error = error

    async def authenticate(self, username, password):
        if self._error:
            raise self._error
        return self._info


class FakeAuthService:
    async def _generate_tokens(self, user):
        return {"access_token": "fake", "user": {"id": str(user.id)}}


class FakeSettings:
    LDAP_AUTO_PROVISION = False
    LDAP_GROUP_ROLE_MAP: dict = {}


SAMPLE_LDAP_INFO = LdapUserInfo(
    dn="CN=Ali Rezaei,OU=Users,DC=corp,DC=local",
    object_guid="11111111-1111-1111-1111-111111111111",
    sam_account_name="ali",
    display_name="Ali Rezaei",
    national_id="0499370899",
    member_of=[],
)


@run_async
async def test_ldap_bind_failure_propagates_as_api_error():
    service = SsoLoginService(
        FakeSettings(), FakeUserRepo(),
        FakeLdapService(error=LdapAuthError("INVALID_CREDENTIALS", "bad")),
        FakeAuthService(),
    )
    with pytest.raises(APIError) as exc_info:
        await service.login("ali", "wrongpass")
    assert exc_info.value.error_code == "INVALID_CREDENTIALS"


@run_async
async def test_unprovisioned_user_rejected_when_auto_provision_off():
    service = SsoLoginService(
        FakeSettings(), FakeUserRepo(user=None),
        FakeLdapService(info=SAMPLE_LDAP_INFO), FakeAuthService(),
    )
    with pytest.raises(APIError) as exc_info:
        await service.login("ali", "pw")
    assert exc_info.value.error_code == "USER_NOT_PROVISIONED"


@run_async
async def test_sso_disabled_for_user_is_rejected():
    existing = FakeUser(sso_enabled=False)
    service = SsoLoginService(
        FakeSettings(), FakeUserRepo(user=existing),
        FakeLdapService(info=SAMPLE_LDAP_INFO), FakeAuthService(),
    )
    with pytest.raises(APIError) as exc_info:
        await service.login("ali", "pw")
    assert exc_info.value.error_code == "SSO_DISABLED_FOR_USER"


@run_async
async def test_inactive_account_is_rejected():
    existing = FakeUser(sso_enabled=True, is_active=False)
    service = SsoLoginService(
        FakeSettings(), FakeUserRepo(user=existing),
        FakeLdapService(info=SAMPLE_LDAP_INFO), FakeAuthService(),
    )
    with pytest.raises(APIError) as exc_info:
        await service.login("ali", "pw")
    assert exc_info.value.error_code == "ACCESS_DENIED"


@run_async
async def test_successful_login_returns_tokens():
    existing = FakeUser(sso_enabled=True, is_active=True)
    service = SsoLoginService(
        FakeSettings(), FakeUserRepo(user=existing),
        FakeLdapService(info=SAMPLE_LDAP_INFO), FakeAuthService(),
    )
    tokens = await service.login("ali", "pw")
    assert tokens["access_token"] == "fake"
```

