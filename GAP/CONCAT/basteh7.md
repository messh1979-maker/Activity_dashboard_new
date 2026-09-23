# BUNDLE: basteh7
# Source: GAP\basteh7
================================================================================

================================================================================
## FILE: backend/tests/architecture/test_module_boundaries.py
================================================================================

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

================================================================================
## FILE: backend/tests/conftest.py
================================================================================

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

================================================================================
## MISSING FILES (not found in source repo)
================================================================================

- [MISSING] `﻿backend/tests/test_auth.py`
- [MISSING] `backend/tests/test_rbac.py`
- [MISSING] `backend/tests/test_ws.py`
- [MISSING] `web/src/__tests__/auth.test.ts`
- [MISSING] `web/playwright.config.ts`

