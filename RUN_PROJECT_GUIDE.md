# راهنمای راه‌اندازی پروژه (بدون داکر)

> به‌روزرسانی: ۱۹ سپتامبر ۲۰۲۶ — تمام مراحل زیر روی همین ماشین اجرا و تأیید شده است.
> Backend و Frontend هر دو بدون داکر، با PostgreSQL نصب‌شده روی ویندوز کار می‌کنند.

---

## ۱. پیش‌نیازها

| نیاز | نسخه تأییدشده | توضیح |
|---|---|---|
| Python | 3.12.8 | بک‌اند با همین نسخه اجرا شد |
| Node.js / npm | v24 / v11 (نسخه ۱۸+ کافی است) | فرانت‌اند |
| PostgreSQL | 16 (سرویس `postgresql-x64-16`) | به‌صورت native روی ویندوز، بدون داکر |
| Redis | — | **اختیاری/نصب نیست**؛ کد فعلی به آن نیاز ندارد (توضیح در بخش ۶) |
| اینترنت | لازم برای `pip install` و `npm install` اول | — |

مسیر پروژه: `C:\Projects\Run_Projects_in_Git\Activity_dashboard`

---

## ۲. راه‌اندازی دیتابیس (یک‌بار)

سرویس PostgreSQL باید در حال اجرا باشد:

```powershell
Get-Service postgresql-x64-16   # باید Running باشد
```

### ۲.۱ ساخت نقش و دیتابیس

فایل `backend/.env` از این مقادیر استفاده می‌کند:

```
POSTGRES_USER=admin
POSTGRES_PASSWORD=admin123
POSTGRES_DB=planner_db
```

اگر نقش `admin` وجود ندارد (خطای `password authentication failed` یا `role "admin" does not exist`)، یک‌بار با دسترسی مدیریتی بسازید. چون `pg_ctl reload` به مجوز سرویس نیاز دارد، روش مطمئن این است که موقتاً احراز هویت را `trust` کنید:

```powershell
# ۱) بکاپ و trust موقت
Copy-Item "C:\Program Files\PostgreSQL\16\data\pg_hba.conf" "C:\Program Files\PostgreSQL\16\data\pg_hba.conf.bak" -Force
(Get-Content "C:\Program Files\PostgreSQL\16\data\pg_hba.conf") -replace "scram-sha-256","trust" | Set-Content "C:\Program Files\PostgreSQL\16\data\pg_hba.conf" -Force

# ۲) ساخت نقش و دیتابیس (بدون رمز عبور وصل می‌شوید)
$env:PGPASSWORD=""
& "C:\Program Files\PostgreSQL\16\bin\psql.exe" -h localhost -U postgres -d postgres -c "CREATE ROLE admin LOGIN PASSWORD 'admin123' SUPERUSER;"
& "C:\Program Files\PostgreSQL\16\bin\psql.exe" -h localhost -U postgres -d postgres -c "CREATE DATABASE planner_db OWNER admin;"
& "C:\Program Files\PostgreSQL\16\bin\psql.exe" -h localhost -U postgres -d postgres -c "CREATE ROLE app_user LOGIN PASSWORD 'app_user_123';"

# ۳) برگرداندن امنیت و اعمال تنظیمات
Copy-Item "C:\Program Files\PostgreSQL\16\data\pg_hba.conf.bak" "C:\Program Files\PostgreSQL\16\data\pg_hba.conf" -Force
$env:PGPASSWORD="admin123"
& "C:\Program Files\PostgreSQL\16\bin\psql.exe" -h localhost -U admin -d planner_db -c "SELECT pg_reload_conf();"

# ۴) تست اتصال با رمز
& "C:\Program Files\PostgreSQL\16\bin\psql.exe" -h localhost -U admin -d planner_db -c "SELECT 1;"
```

> ⚠️ توجه: `admin/admin123` **نقش دیتابیس** است، نه کاربر اپلیکیشن. ساخت کاربر ورود به فرانت‌اند در بخش ۵ آمده است.

نقش `app_user` را حتماً بسازید؛ مایگریشن `audit_schema.sql` دستور `GRANT ... TO app_user` دارد و بدون این نقش، `alembic upgrade head` با خطای `role "app_user" does not exist` می‌شکند.

---

## ۳. راه‌اندازی Backend

```powershell
cd C:\Projects\Run_Projects_in_Git\Activity_dashboard\backend

# ۱) ساخت محیط مجازی تازه (venv قبلی خراب بود و حذف شد)
python -m venv .venv

# ۲) نصب وابستگی‌ها
.\.venv\Scripts\pip.exe install --timeout 120 --retries 5 -r requirements.txt

# ۳) تنظیم .env (اگر از روی example می‌سازید، این دو نکته حیاتی است)
#    - CORS_ORIGINS باید JSON array باشد، نه comma-separated:
#      CORS_ORIGINS=["http://localhost:3000","http://127.0.0.1:3000","http://localhost:5173","http://127.0.0.1:5173","http://localhost:8080"]
#    - SECRET_KEY حداقل ۳۲ کاراکتر

# ۴) اجرای مایگریشن (ساخت ۱۳ اسکیما: auth, rbac, groups, planning, calendar, chat, files, inbox, notification, reporting, sharing, ssoldap, audit)
.\.venv\Scripts\python.exe -m alembic upgrade head
.\.venv\Scripts\python.exe -m alembic current   # باید 0001_initial (head) را نشان دهد

# ۵) اجرای سرور
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

تست سلامت: http://127.0.0.1:8000/health باید `{"status":"healthy", ...}` با ۱۲ ماژول برگرداند.
مستندات API: http://127.0.0.1:8000/docs

---

## ۴. راه‌اندازی Frontend

```powershell
cd C:\Projects\Run_Projects_in_Git\Activity_dashboard\web
npm install
npm run dev
```

- آدرس: http://127.0.0.1:3000 (طبق `vite.config.ts` پورت `3000` است، نه ۵۱۷۳)
- اتصال به بک‌اند از `web/.env` خوانده می‌شود: `VITE_API_BASE=http://127.0.0.1:8000/api/v1`
- تست build: `npm run build` (باید ۱۶۸ ماژول را بدون خطا بیلد کند)

---

## ۵. ساخت کاربر ورود (مهم)

**مشکل گزارش‌شده:** ورود با `admin/admin123` در فرانت‌اند ناموفق بود.
**علت:** این نام/رمز، نقش PostgreSQL است و هیچ کاربر اپلیکیشنی با آن وجود نداشت (ورود اشتباهاً `401 AUTHENTICATION_ERROR` می‌داد).

**راه‌حل:** کاربر اپلیکیشن `admin` ساخته شد. اگر دیتابیس را از نو ساختید، دوباره بسازید:

```powershell
# POST /api/v1/auth/register — کد ملی باید چک‌سام رسمی ایران را پاس کند (مثلاً 1234567891)
```

```jsonc
// POST http://127.0.0.1:8000/api/v1/auth/register
{ "username": "admin", "password": "admin123",
  "display_name": "admin", "national_id": "1234567891", "email": "admin@local" }
// 201 Created
```

```jsonc
// POST http://127.0.0.1:8000/api/v1/auth/login  (دقیقاً همین را فرانت‌اند می‌فرستد)
{ "identifier": "admin", "password": "admin123", "remember_me": false }
// 200 → { mfa_required:false, tokens:{access_token, refresh_token}, user:{...} }
```

حالا در فرانت‌اند (http://127.0.0.1:3000) با `admin` / `admin123` وارد شوید.

---

## ۶. تغییراتی که در کد داده شد (برای راه‌اندازی لازم بود)

### ۶.۱ `backend/app/main.py` — ایمپورت ماژول‌های ناموجود
`main.py` ماژول‌های `calendar, notification, audit, ssoldap, files` را ایمپورت می‌کرد ولی این پوشه‌ها وجود نداشتند (`ImportError`) و سرور اصلاً بالا نمی‌آمد.
→ هر ۵ ماژول به‌صورت **stub استاندارد** ساخته شد: `app/modules/<name>/__init__.py` (صادرکننده `router` + تابع `register_event_handlers`) و `app/modules/<name>/api/routes.py` (یک endpoint نمونه). اسکیمای SQL هر ۱۳ ماژول از قبل در `alembic/versions/` موجود بود.

### ۶.۲ `backend/app/core/dependencies.py` — circular import
ایمپورت سطح‌بالای `UserRepository`/`AuthService` باعث چرخه `dependencies ↔ auth.routes` می‌شد.
→ ایمپورت‌ها به داخل توابع منتقل شد (lazy import).

### ۶.۳ `backend/app/core/dependencies.py` — `get_current_user` واقعی شد
قبلاً همیشه `{"id":"placeholder"}` برمی‌گرداند.
→ حالا JWT را با HS256 اعتبارسنجی می‌کند (امضا، انقضا، `type=access`)، کاربر را از DB می‌خواند و توکن باطل‌شده (`token_version` ناهماهنگ) و حساب غیرفعال را با 401 رد می‌کند. خروجی `str` (آی‌دی کاربر) است تا ۶۴ محل استفاده‌کننده در ماژول‌ها که `UUID` انتظار دارند نشکنند (FastAPI خودش str→UUID تبدیل می‌کند).

### ۶.۴ چک‌سام کد ملی (`auth/services/auth_service.py::_validate_national_id`)
پیاده‌سازی قبلی (`expected = 0 if r==10 else r`) با الگوریتم رسمی ایران که سند معماری (بخش ۴.۲) الزام کرده مغایرت داشت و کدهای معتبر را رد می‌کرد.
→ اصلاح به الگوریتم رسمی: `expected = r if r<2 else 11-r`.

### ۶.۵ `UserDevices.first_seen_at/last_seen_at` (`auth/db/models.py`)
مدل `nullable=True` بدون default بود ولی ستون DB ‏`NOT NULL DEFAULT now()` است؛ SQLAlchemy مقدار NULL صریح می‌فرستاد و ثبت‌نام با خطای 500 می‌شکست.
→ `server_default=func.now()` به هر دو ستون اضافه شد.

### ۶.۶ توکن تازه باطل می‌شد (`auth_service._generate_tokens`)
`token_version` **بعد** از ساخت JWT زیاد می‌شد، پس توکن刚 صادرشده نسخه قدیمی داشت و اولین استفاده 401 `Token revoked` می‌گرفت.
→ افزایش به **قبل** از صدور توکن منتقل شد.

### ۶.۷ endpointهای گمشده موردنیاز فرانت‌اند
فرانت‌اند (`web/src/security/authProvider.ts`) این‌ها را صدا می‌زند ولی در بک‌اند نبود:
→ `GET /api/v1/auth/me`، `POST /api/v1/auth/logout` (ابطال نشست با `token_version++`)، `GET /api/v1/auth/devices` (با MAC ماسک‌شده) به `auth/api/routes.py` اضافه شد؛ متدهای `get_profile/logout/list_devices/_generate_tokens_by_id` (آخری را مسیر `/refresh` از قبل صدا می‌زد ولی وجود نداشت) به `AuthService` اضافه شد.

### ۶.۸ اصلاحات کوچک
- `app/ws/manager.py`: ایمپورت گمشده `UUID`
- `app/audit/integrity.py`: ایمپورت خراب `app.modules.audit.db.Models` (ماژول audit فقط stub است) + ایمپورت گمشده `json`؛ حالا در غیاب مدل‌ها `unavailable` برمی‌گرداند
- `backend/.env`: افزودن `CORS_ORIGINS` با سینتکس JSON array شامل originهای Vite
- `web/src/security/authProvider.ts`: سه `logger.error` تعریف‌نشده → `console.error` (وگرنه اولین خطای شبکه فرانت‌اند را کرش می‌کرد)

### ۶.۹ باگ «پس از زدن ورود هیچ پارامتری ارسال نمی‌شود» (فرانت‌اند)
علامت: کلیک روی «ورود» هیچ درخواست شبکه‌ای تولید نمی‌کرد.
علت ریشه‌ای در `web/src/security/deviceHeaders.ts` خط `hmacSha256` بود:

```ts
const CryptoJS = require('crypto-js')   // ❌ در مرورگر وجود ندارد
```

`require` در باندل مرورگر (Vite/ESM) تعریف نشده است؛ این خط داخل **interceptor** axios (`api/client.ts`) اجرا می‌شود، پس با `ReferenceError` می‌ترکید و درخواست **قبل از ارسال** لغو می‌شد. اصلاحات:
- `deviceHeaders.ts`: ایمپورت استاندارد `import CryptoJS from 'crypto-js'` در بالای فایل (پکیج از قبل در `node_modules` بود)
- `deviceHeaders.ts`: تابع `logSecurityEvent` صدا زده می‌شد ولی ایمپورت نشده بود (در `fingerprint.ts` تعریف شده) → ایمپورت اضافه شد؛ وگرنه **بعد از ورود موفق** هم خطا می‌داد و ورود ناموفق نشان داده می‌شد
- `fingerprint.ts`: عبارت `process.env.NODE_ENV` در مرورگر (Vite) خودش `ReferenceError` می‌دهد → با گارد `typeof process` اصلاح شد
- `authProvider.ts`: ایمپورت `getDeviceFingerprint` از فایل اشتباه (در `deviceHeaders` وجود ندارد و استفاده هم نمی‌شد) حذف شد
- تأیید: `npm run build` موفق و در باندل نهایی هیچ `require('crypto-js')` نیست

## ۷. داشبورد واقعی (جایگزین صفحه «پیاده‌سازی نشده»)

پس از ورود موفق، مسیر `/dashboard` فقط یک Placeholder بود. داشبورد واقعی ساخته شد:

### ۷.۱ یافته‌های بک‌اند (مهم)
پروب زنده نشان داد **همه سرویس‌های ماژول‌ها (goals/groups/chat/inbox/reporting) با خطای 500** می‌شکستند؛ دو علت:
1. مدل‌های ORM در `app/modules/*/db/Models.py` نام جدول **بدون اسکیما** می‌سازند ولی DDL یک اسکیما به‌ازای هر ماژول دارد (`planning.goals` و…) → `relation "goals" does not exist`. **رفع:** `search_path` کامل روی کانکشن در `app/core/db/session.py` (نام جداول در اسکیماها یکتا هستند، پس بدون ابهام). راه‌حل بلندمدت طبق ADR-04: هر مدل `__table_args__ = {"schema": ...}` خودش را اعلام کند.
2. مدل‌ها از ستون‌های DDL عقب‌اند (`goals.version`، `groups.title`، جدول `inbox_items` در برابر `inbox.items` واقعی و…) → بازنویسی هر ۶ فایل مدل در این مرحله به‌صرفه نبود.
3. باگ ترتیب مسیر: `GET /inbox/outbox` بعد از `/{user_id}` تعریف شده بود و هیچ‌وقت match نمی‌شد (422) → به قبل از `/{user_id}` منتقل شد.
4. باگ اعتبارسنجی نوع آیتم: `item_type not in INBOX_ITEM_TYPES` رشته را با لیستی از آبجکت مقایسه می‌کرد و **همیشه** رد می‌کرد → مقایسه با `[t.value ...]`؛ همچنین تایپوی `chat_invoice` در pattern به `chat_invite` (مطابق سند) اصلاح شد.

### ۷.۲ endpointهای جدید (`app/modules/reporting/api/dashboard.py`)
چون ORM خراب است، داشبورد با **SQL خام اسکیما-دار** (خوانا و مستقل از مدل‌ها) کار می‌کند؛ هر ویجت مستقل است و خرابی یک جدول بقیه را نمی‌اندازد:
- `GET /api/v1/reporting/dashboard/summary` — آمار (اهداف فعال/تکمیل‌شده، وظایف باز، صندوق待 بررسی، گروه‌ها) + اهداف اخیر + وظایف باز + صندوق ورودی + گروه‌ها + اتاق‌های چت
- `GET /api/v1/reporting/dashboard/goals` — فهرست اهداف کاربر
- `POST /api/v1/reporting/dashboard/goals` — ایجاد سریع هدف (`title` الزامی)
- `POST /api/v1/reporting/dashboard/inbox/{id}/act` — تأیید/رد/تعویق آیتم (`accepted/rejected/deferred`) با بررسی مالکیت و حالت `pending`
- روتر با `router.include_router(dashboard_router)` به ماژول reporting متصل شد.

چرخه تأییدشده: `summary 200` → `create-goal 201` → `goals-list 200 (count 1)` → `inbox act 200` → `pending 1→0` ✅

### ۷.۳ فرانت‌اند (`web/src/features/DashboardPage.tsx` + `web/src/hooks/useDashboard.ts`)
- کارت‌های آمار، فهرست اهداف با نوار پیشرفت + فرم ایجاد سریع، صندوق ورودی با دکمه تأیید/رد، وظایف باز، گروه‌ها (با نشان مدیر) و اتاق‌های چت
- مسیر `/dashboard` در `App.tsx` به `DashboardPage` واقعی وصل شد (چت و صندوق فعلاً Placeholder‌اند)
- ⚠️ نکته فنی: هنگام نوشتن فایل، کاراکترهای CJK باعث دابل‌انکد شدن فارسی شدند؛ راه‌حل مطمئن: متن فارسی خالص سالم منتقل می‌شود (مثل `useDashboard.ts`) — از مخلوط‌کردن CJK در یک Write خودداری شود. باندل نهایی فارسی سالم دارد (تست شد).

داده نمونه برای نمایش اولیه (کاربر `admin`): یک هدف «راه‌اندازی سامانه» (۷۰٪) و یک آیتم صندوق «بازبینی گزارش ماهانه».

## ۸. بازطراحی مدرن UI/UX

علت ابتدایی بودن ظاهر: Tailwind عملاً **سیم‌کشی نشده بود** — نه `postcss.config` وجود داشت، نه فایل CSS در `main.tsx` ایمپورت شده بود (تنظیم `build.css.postcss` در `vite.config.ts` را Vite نادیده می‌گیرد). یعنی هیچ کلاس Tailwindی اعمال نمی‌شد.

### ۸.۱ زیرساخت استایل
- `web/tailwind.config.js` جدید (فونت وزیرمتن، پالت `brand`، سایه‌های `card/pop`)
- `web/postcss.config.js` جدید (Vite خودکار تشخیص می‌دهد)
- ایمپورت `./styles/tailwind.css` در `main.tsx`
- فونت **وزیرمتن self-host** در `web/public/fonts/` (۹ فایل woff2، weights ۴۰۰/۵۰۰/۷۰۰) — با CSP سازگار (`font-src 'self'`) و بدون وابستگی به CDN
- سیستم دیزاین در `styles/tailwind.css`: کامپوننت‌های `.card/.btn-primary/.btn-ghost/.input/.badge/.navlink/.stat-card`، انیمیشن‌های `fade-up/fade-in` با stagger، اسکرول‌بار سفارشی، احترام به `prefers-reduced-motion`
- اصلاح تایتل خراب `index.html` + اصلاح باگ از پیش‌موجود `assetFileNames` در `vite.config.ts` (پیشوند `./` که Vite 8 رد می‌کند؛ تا قبل از این چون هیچ asset ای تولید نمی‌شد دیده نشده بود)

### ۸.۲ صفحات (`web/src/App.tsx`, `web/src/features/DashboardPage.tsx`)
- **ورود**: طرح دوپنل — پنل برندینگ گرادیانی با ویژگی‌های محصول + فرم ورود با آیکون، اسپینر لودینگ و پیام خطای زیبا؛ hint حساب پیش‌فرض
- **شل**: سایدبار تیره با ناوبری آیکون‌دار (داشبورد/گفتگو/صندوق/گروه‌ها/گزارش‌ها/تنظیمات)، کارت کاربر با کد ملی ماسک‌شده و خروج؛ تاپ‌بار sticky با تاریخ شمسی زنده (`Intl.DateTimeFormat('fa-IR')`) و نشان اتصال؛ منوی موبایل کشویی؛ آیکون‌های SVG inline (بدون ایموجی)
- **داشبورد**: ۴ کارت آمار گرادیانی با آیکون و stagger، اهداف با نوار پیشرفت گرادیانی چندرنگ، صندوق با دکمه‌های نرم تأیید/رد، وظایف و گروه‌ها به‌صورت chip، اسکلت لودینگ، کاملاً ریسپانسیو (۲ ستونه موبایل → ۴ ستونه دسکتاپ)
- تأیید: `npm run build` موفق (CSS واقعی ۳۱KB)، فارسی باندل سالم و بدون دابل‌انکد
- ⚠️ نکته فنی تکراری: متن فارسی خالص در Write سالم منتقل می‌شود؛ کاراکتر CJK در همان Write باعث دابل‌انکد کل فایل می‌شود. الگوی مطمئن استفاده‌شده: نوشتن با کلید `FA_*` + نگاشت JSON + اسکریپت `apply_map.py`.

---

## ۸ب. رفع باگ رفرش توکن (401 داشبورد)

### علائم
- داشبورد فرانت «ارتباط با سرور برقرار نشد» نشان میداد؛ در کنسول: `401` روی `GET /api/v1/reporting/dashboard/summary`.
- با توکن تازه اندپوینت `200` برمیگرداند — پس مشکل از توکن قدیمی داخل مرورگر بود که مکانیزم بازیابی خودکار نمیتوانست آن را تازه کند.

### ریشههای خطا
1. `POST /auth/refresh` بدنه `{"refresh_token": "..."}` میخواست اما سرور `str` خام میخواست (`422`).
2. رفرشتوکن opaque است اما اندپوینت آن را با `jwt.decode` بررسی میکرد (همیشه `401`).
3. مقایسه `expires_at` از DB با `datetime.utcnow()` خطای `TypeError` میداد (aware در برابر naive) که در `except` پنهان و `401` برگردانده میشد.
4. گارد interceptor فرانت اگر خود رفرش با `401` برگردد، دوباره رفرش صدا میزد (حلقه بینهایت).

### راهحل (اعمال شده)
- `backend/app/modules/auth/ports.py`: مدل `RefreshRequest` اضافه شد.
- `backend/app/modules/auth/api/routes.py`: اندپوینت `/auth/refresh` بدنه آبجکتی و لاگ traceback واقعی دارد.
- `backend/app/modules/auth/services/auth_service.py`: متد `refresh_session()` — جست‌وجو با SHA-256 در `auth.sessions` ، رد revoked/expired ، چرخش سشن، پاسخ با شکل `{status, tokens, user}`.
- `web/src/api/client.ts`: interceptor دیگر روی خود فراخوانیهای `/auth/*` ریترای نمیکند.
- چرخه تأییدشده: login → login دیگر → summary `401` → refresh خودکار → retry → `200`.

### راهحل تکمیلی سمت فرانت (داشبورد مرده + ساخت هدف)

5. باگ «داشبورد مرده»: interceptor هنگام شکست رفرش فقط `secureStorage` را پاک میکرد، اما `isAuthenticated` از persist بازگردانده میشد `true` و UI روی داشبورد خراب گیر میکرد (access-token هم بعد از ۱۵ دقیقه `ACCESS_TOKEN_EXPIRE_MINUTES` منقضی میشود).
6. باگ `init()`: به `sessionStorage.user` نیاز داشت که `login()` هیچوقت آن را نمینوشت — پس رفرش هنگام بارگذاری هیچوقت اجرا نمیشد.

### راهحل فرانت (اعمال شده)
- `web/src/security/authProvider.ts`: اکشن `forceLogout()` اضافه شد؛ `init()` اگر refresh-token نباشد state را ریست میکند و در غیر این صورت با همان refresh-token توکنها را تازه میکند (ﺑدون نیاز به sessionStorage).
- `web/src/api/client.ts`: هنگام شکست رفرش یا نبودن آن، رویداد `auth:expired` فرستاده میشود (بدون import چرخهای).
- `web/src/App.tsx`: شنوده `auth:expired` با `forceLogout()` کاربر را به صفحه ورود برمیگرداند.
- نتیجه کاربر: با رفرش صفحه (Ctrl+F5) توکن خودکار تازه و داشبورد بالا میآید؛ اگر refresh-token هم نامعتبر باشد، به لاگین هدایت میشود (دیگر داشبورد مرده نیست).

### راهحل تکمیلی ریترای POST پس از 401 («ایجاد هدف ناموفق بود»)

7. باگ retry: وقتی POST با `401` برمیگشت، interceptor بعد از رفرش درخواست را با `api(originalRequest)` تکرار میکرد؛ اما axios بدنه از پیش string‌شده را دوباره stringify میکرد و سرور `422 dict_type` برمیگرداند (GET بدون بدنه این مشکل را نداشت — به همین دلیل داشبورد باز میشد اما ساخت هدف نه).
8. ریس race: `StrictMode` افکتها را دوبار اجرا میکند و refresh‌های همزمان با یک توکن، یکدیگر را باطل میکنند (rotation تک‌مصرفه است).

### راهحل (اعمال شده)
- `web/src/api/client.ts`: ریترای با `transformRequest: [(d) => d]` بدنه اصلی را دست‌نخورده ارسال میکند + رفرش single-flight (`refreshPromise` مشترک) تا `401`های همزمان یک چرخش  مشترک داشته باشند.
- چرخه تأییدشده: POST با توکن قدیمی `401` → رفرش → تکرار POST با بایتهای اصلی → `201`.

## ۸. چرخه‌های تأییدشده (تست end-to-end روی سرور در حال اجرا)

```
REGISTER 201 → LOGIN 200 (access+refresh token) → ME 200 (کد ملی ماسک‌شده)
→ DEVICES 200 → LOGOUT 200 → ME بعد از logout = 401 ✅
```

---

## ۹. کارهای باقی‌مانده (عامدانه انجام نشد)

| مورد | وضعیت | توضیح |
|---|---|---|
| MFA کامل (TOTP) | ❌ استاب خالی (`auth/db/mfa.py`) | متدهای `generate_mfa_token/verify_token/enroll` وجود ندارند؛ چون کاربران جدید `mfa_enabled=False` دارند ورود عادی کار می‌کند. پیاده‌سازی TOTP نیازمند `pyotp` وフロ کامل enroll/verify است |
| ۵ ماژول stub | ❌ اسکلت | `calendar, notification, audit, ssoldap, files` فقط router نمونه دارند؛ اسکیمای SQL آن‌ها آماده است |
| دریفت ORM از DDL | ⚠️ بدهی فنی | مدل‌های `goals/groups/chat/inbox/reporting/sharing` اسکیما و ستون درست ندارند؛ داشبورد با SQL خام دورشان زده. رفع اصولی: هم‌راستاسازی مدل‌ها با DDL + اعلام `schema` در هر مدل (ADR-04) |
| Redis | ❌ نصب نیست | لازم نیست: rate-limit حافظه‌ای و WebSocket حافظه‌ای است؛ برای چند Worker طبق سند معماری Redis لازم می‌شود |
| نقش‌های کاربر `admin` | ⚠️ بدون نقش | کاربر `admin` ساخته‌شده `roles: []` دارد؛ اعطای نقش مدیریتی به‌زودی باید از مسیر RBAC انجام شود |
| باطل‌شدن نشست‌های قبلی با هر login | ⚠️ رفتار فعلی | به‌خاطر `token_version++` در صدور توکن، ورود جدید نشست‌های قبلی را می‌اندازد؛ اگر چنددستگاهی می‌خواهید بازبینی شود |

---

## ۱۰. اجرای روزمره (خلاصه)

```powershell
# ترمینال ۱ — بک‌اند
cd C:\Projects\Run_Projects_in_Git\Activity_dashboard\backend
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000

# ترمینال ۲ — فرانت‌اند
cd C:\Projects\Run_Projects_in_Git\Activity_dashboard\web
npm run dev
```

| نشانی | کاربرد |
|---|---|
| http://127.0.0.1:3000 | اپ وب (ورود: `admin` / `admin123`) |
| http://127.0.0.1:8000/docs | مستندات تعاملی API |
| http://127.0.0.1:8000/health | سلامت سرویس |
