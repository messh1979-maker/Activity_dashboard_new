# راهنمای راه‌اندازی پروژه (بدون داکر)

> به‌روزرسانی: ۲۲ سپتامبر ۲۰۲۶ — تمام مراحل زیر روی همین ماشین اجرا و تأیید شده است.
> Backend و Frontend هر دو بدون داکر، با PostgreSQL نصب‌شده روی ویندوز کار می‌کنند.

---

## ۱. پیش‌نیازها

| نیاز | نسخه تأییدشده | توضیح |
|---|---|---|
| Python | 3.12.8 | بک‌اند با همین نسخه اجرا شد |
| Node.js / npm | v24 / v11 (نسخه ۱۸+ کافی است) | فرانت‌اند |
| PostgreSQL | 16 (سرویس `postgresql-x64-16`) | به‌صورت native روی ویندوز، بدون داکر |
| Redis | — | **اختیاری/نصب نیست**؛ `RedisBroker` با fallback درون‌فرایندی کار می‌کند (توضیح در بخش ۶ و ۸و) |
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

# ۴) اجرای مایگریشن (ساخت ۱۳ اسکیما + اسکیمای هسته `core`)
#    head فعلی: 0002_core_outbox (جدول transactional-outbox در بخش ۲.۳ سند)
.\.venv\Scripts\python.exe -m alembic upgrade head
.\.venv\Scripts\python.exe -m alembic current   # باید 0002_core_outbox (head) را نشان دهد

# ۵) اجرای سرور (روش مطمئن در PowerShell — پشت‌زمینه و جدا از shell)
#    نکته: Start-Job فرانت از shell tool می‌میرد؛ cmd start /b فرزند را جدا می‌کند و زنده می‌ماند.
cmd /c "start /b .venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000 > %TEMP%\opencode\srv8000.log 2>&1"

# اجرای پیش‌رو (جلوی) برای دیباگ:
#     .\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

تست سلامت: http://127.0.0.1:8000/health باید `{"status":"healthy", ...}` با ۱۳ ماژول برگرداند.
مستندات API: http://127.0.0.1:8000/docs
پس از راه‌اندازی، بررسی کامل با اسکریپت‌های تست:
```powershell
$env:PYTHONIOENCODING='utf-8'
.\.venv\Scripts\python.exe "%TEMP%\opencode\smoke.py"    # 17 endpoint خواندنی → 16 OK + 1 SSO challenge (401)
```
> `401` روی `GET /api/v1/auth/sso/negotiate` **رفتار درست** است (چالش SPNEGO + هدر `WWW-Authenticate: Negotiate`)، نه خطا.
>
> ⚠️ بهداشت تست (مهم): هر `POST /auth/login` موفق `token_version` کاربر را زیاد می‌کند و **توکن‌های قبلی را باطل می‌کند**؛ پس لاگین‌های پشت‌سرهم/موازی همدیگر را می‌اندازند (`401 Token revoked`). همچنین محدودیت `RATE_LIMIT_AUTH=10/minute` روی لاگین است (پاسخ `429 RATE_LIMIT_EXCEEDED`). برای تست پایدار: در هر اسکریپت فقط **یک لاگین**، بین اجراها **۶۰+ ثانیه** صبر، و برای WS هم توکن تازه بگیرید (اسکریپت‌ها همین الگو را دارند). `401`های پراکنده‌ی میانیِ اجراهای شلوغ دقیقاً همین علت را دارند، نه باگ — با یک لاگین تمیز همه‌چیز 200 می‌شود.

---

## ۴. راه‌اندازی Frontend

```powershell
cd C:\Projects\Run_Projects_in_Git\Activity_dashboard\web
npm install
npm run dev
```

- آدرس: http://127.0.0.1:3000 (طبق `vite.config.ts` پورت `3000` است، نه ۵۱۷۳)
- اتصال به بک‌اند از `web/.env` خوانده می‌شود: `VITE_API_BASE=http://127.0.0.1:8000/api/v1`
- تست build: `npm run build` (باید بدون خطا بیلد کند؛ آخرین بیلد موفق: ۱۷۶ ماژول)

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
- همه مسیرها در `App.tsx` به صفحه‌های واقعی وصل شدند: `/dashboard` (داشبورد)، `/chat`، `/inbox`، `/groups`، `/reports`، `/settings` — جزئیات در بخش ۸د
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

## ۸ج. بازنویسی سرویس‌های ماژول‌ها روی DDL واقعی (۱۹ سپتامبر ۲۰۲۶)

### علت
مدل‌های ORM در `app/modules/*/db/Models.py` از DDL مهاجرت عقب بودند (جدول بدون اسکیما، ستون‌های خیالی، PK با تایپ اشتباه)؛ در نتیجه **همه endpointهای ماژول‌ها 500** می‌دادند (`/groups/`، `/goals/`، `/chat/rooms`، `/inbox/*`، `/sharing/*`، `/reporting/layouts`، `/reporting/widgets/settings`).

### تصمیم
به‌جای ترمیم مدل‌ها، لایه سرویس هر ۷ ماژول با **SQL خام schema-qualified** روی DDL واقعی بازنویسی شد (همان الگوی اثبات‌شده `reporting/api/dashboard.py`):
- `rbac/services/rbac_service.py` (اسکیما `rbac` + گاردهای anti-escalation: ممنوعیت self-assign و اعطای نقش هم‌سطح/بالاتر + بررسی مدیر گروه برای scope فراتر از global)
- `groups/services/groups_service.py` (اسکیما `groups`؛ ستون `path` از نوع ltree با uuid بدون خط‌تیره)
- `goals/services/goals_service.py` (اسکیما `planning`)
- `chat/services/chat_service.py` (اسکیما `chat`)
- `inbox/services/inbox_service.py` (اسکیما `inbox`؛ `InboxService = InboxStateMachine`)
- `sharing/services/sharing_service.py` (اسکیما `sharing`)
- `reporting/services/reporting_service.py` (اسکیما `reporting`)

اصلاحات پشتیبان: `rbac/ports.py` (فیلد `target_user_id` در Assign/Revoke)، `rbac/api/routes.py` (استفاده از `target_user_id` به‌جای self)، `sharing/api/routes.py` (`Body(..., embed=True)` برای revoke)، امضای `act_on_item(item_id, action, note, actor_id)` هماهنگ با route.

### یافته‌های DDL (مهم برای توسعه بعدی)
- `sharing.effective_permissions` یک **VIEW** است — فقط خواندنی؛ INSERT/UPDATE روی آن 500 می‌دهد.
- ایندکس یکتای `dashboard_layouts` **جزئی** است (`WHERE is_default = true`) پس `ON CONFLICT` نامعتبر است → upsert دستی SELECT→INSERT/UPDATE.
- پارامترهای jsonb در asyncpg باید **رشته JSON** باشند نه dict (`json.dumps`).
- نوع enum بدون پیشوند اسکیما است (`privacy_level` نه `planning.privacy_level`).
- `get_current_user` در `app/core/dependencies.py` **رشته** برمی‌گرداند (`str(user.id)`) نه UUID.
- جدول `sharing.shares` ستون `share_code` ندارد (id همان share_code است) و constraint یکتایی روی سه‌گانه ندارد → upsert دستی.

### Seed داده RBAC (یک‌بار اجرا شد)
۵ نقش (`super_admin=10`، `admin=8`، `manager=5`، `user=3`، `viewer=1`) + ۲۴ دسترسی + نگاشت نقش‌ها (super_admin هر ۲۴؛ admin بدون `rbac.manage/ldap.configure`؛ manager ۱۴؛ user ۹؛ viewer ۵) + اعطای `super_admin` به کاربر `admin`. (اسکریپت موقت در `%TEMP%\opencode\seed_rbac.sql` — برای دیتابیس تازه دوباره اجرا شود.)

### چرخه تأییدشده
- `smoke.py`: هر ۱۸ endpoint خواندنی 200 ✅
- `smoke2.py` (مسیر کامل نوشتن): ساخت گروه/هدف/تسک/اتاق/پیام/آیتم صندوق/اشتراک‌گذاری/چیدمان/ویجت + act/revoke — همگی 200 ✅ (اسکریپت‌ها در `%TEMP%\opencode\`)
- توجه: `POST /rbac/assign` با `target_user_id` برابر خودِ کاربر 403 می‌دهد (`CANNOT_SELF_ASSIGN`) — رفتار درست است، نه باگ.

---

## ۸د. صفحات واقعی فرانت‌اند (۱۹ سپتامبر ۲۰۲۶)

هر ۵ Placeholder در `App.tsx` با صفحه واقعی جایگزین شد (همان سیستم دیزاین بخش ۸: `.card/.btn-primary/.badge/.input`، آیکون SVG، RTL، انیمیشن‌ها):
- `web/src/features/ChatPage.tsx` (`/chat`) — فهرست اتاق‌ها + ساخت اتاق + پیام‌ها با polling هر ۴ ثانیه + ارسال پیام
- `web/src/features/InboxPage.tsx` (`/inbox`) — تب‌های ورودی/ارسال‌شده/آیتم جدید؛ تأیید/رد/تعویق؛ ساخت آیتم (`meeting_invite/share_request/task_assignment/chat_invite/approval`)
- `web/src/features/GroupsPage.tsx` (`/groups`) — فهرست گروه‌ها + ساخت گروه + اعضای گروه + افزودن عضو (توسط مدیر گروه)
- `web/src/features/ReportsPage.tsx` (`/reports`) — فهرست/ذخیره چیدمان داشبورد + تنظیمات ویجت‌ها (toggle + ذخیره + بازگشت به پیش‌فرض)
- `web/src/features/SettingsPage.tsx` (`/settings`) — پروفایل کاربر + نقش‌ها (`GET /rbac/user/{id}/roles`) + شمار دسترسی‌ها + خروج
- تأیید: `npm run build` موفق (۱۷۶ ماژول) و هر ۵ مسیر API در باندل نهایی موجود است؛ فارسی باندل سالم.

---

## ۸ه. مایگریشن `core.outbox_messages` (۲۱ سپتامبر ۲۰۲۶) — لاگین 500 می‌داد

### علائم
پس از راه‌اندازی تازه، `POST /api/v1/auth/login` با **500** شکست:
```
asyncpg.exceptions.UndefinedTableError: relation "core.outbox_messages" does not exist
[SQL: INSERT INTO core.outbox_messages (event_id, event_type, payload, ...)]
```
علت: الگوی **transactional outbox** (سند بخش ۲.۳) هنگام ورود، رویداد دامنه را در `core.outbox_messages` ثبت می‌کند ولی این جدول در دیتابیس وجود نداشت.

### ریشه
فایل `backend/alembic_versions/xxxx_create_core_outbox_messages.py` (قدیمی) یک **قالب** بود (`revision = REPLACE_ME`) و در دایرکتوری اشتباه رها شده بود (خارج از `script_location = alembic`)، پس هرگز توسط alembic شناسایی و اعمال نشد. `alembic heads` فقط `0001_initial` را نشان می‌داد.

### راه‌حل (اعمال شده)
- مایگریشن واقعی ساخته شد: `backend/alembic/versions/0002_core_outbox.py` (`revision = "0002_core_outbox"`, `down_revision = "0001_initial"`) — ساخت `SCHEMA core` + جدول `outbox_messages` + ایندکس جزئی `ix_outbox_pending`.
- اجرا: `.\.venv\Scripts\python.exe -m alembic upgrade head` → `current` اکنون `0002_core_outbox (head)`.
- قالب قدیمی `backend/alembic_versions/xxxx_...` حذف شد.
- تأیید: `smoke.py` — `login 200` و هر ۱۸ endpoint 200 ✅

### نکته برای دیتابیس تازه
اگر دیتابیس از نو ساخته می‌شود، `alembic upgrade head` این مایگریشن را هم می‌آورد؛ مراحل بخش ۳ نیازی به تغییر ندارد.

---

## ۸و. WebSocket + Redis + SSO/SPNEGO (۲۲ سپتامبر ۲۰۲۶)

### WebSocket (معماری 5.5 / 12.8) — پیاده‌سازی شد و تأیید شد
- `backend/app/ws/routes.py` — دو گیتوی:
  - `GET /ws/chat` — accept→origin check (4403)→JWT در query (4401)→revalidation هر 60s (4401)→idle 300s (4408)→سقف 8192 بایت (1009)→rate-limit 20 پیام/دقیقه (RATE_LIMITED)→فریم‌های `join/message/leave/ping`→بررسی عضویت به‌ازای هر پیام (NOT_A_MEMBER/NOT_JOINED)→ذخیره پیام با SQL خام در `chat.messages`→`_sanitize_html`
  - `GET /ws/notifications` — فریم اول `unread_count`، سپس اشتراک کانال `notifications:{user_id}` برای push زنده
- `backend/app/ws/manager.py` — `ConnectionManager` (ثبت سوکت درون‌فرایندی + relay روی کانال `room:{room_id}`)؛ `broadcast` فقط publish می‌کند و relay تحویل می‌دهد (ضد تحویل دوباره)
- `backend/app/core/redis.py` — `RedisBroker` (پابلیش/اشتراک async + cache); وقتی Redis در دسترس نیست به fan-out درون‌فرایندی ارتجاع می‌دهد (تک‌فرایند پابرجاست)
- `backend/app/core/security.py` — `get_device_fingerprint`، `verify_hmac_signature`، `hmac_sign`
- `backend/app/modules/notification/events.py::_publish_live` — بعد از درج notification، پیام JSON به کانال `notifications:{user_id}` پابلیش می‌شود
- mount در `main.py`: `app.include_router(websocket_router)` بدون پیشوند → مسیرها `/ws/chat` و `/ws/notifications`

### تأیید (همه روی سرور در حال اجرا)
```
bad token → close 4401 ✅   join ×2 → connected ✅   broadcast به a+b ✅
oversize → MESSAGE_TOO_LARGE ✅   non-member → NOT_A_MEMBER ✅
rate-limit: RATE_LIMITED بعد از پیام ۲۰ ✅
notifications: unread_count → login → push auth.login.succeeded → unread_count جدید ✅
```

### مدیریت کاربران ادمین و بخش‌های جدید تنظیمات (۲۲ سپتامبر ۲۰۲۶)
- روتر `/admin/users` (فهرست/ایجاد/ویرایش/تغییر انبوه حالت ورود) که نه mount بود نه deps واقعی داشت، سرهم‌بندی شد:
  - `app/modules/auth/api/deps.py` جدید — `get_admin_user_service` واقعی (با `UserRepository` زنده) + re-export شدن `get_current_user` از core تا `require_permission` رزولو شود
  - `app/modules/rbac/api/deps_internal.py` جدید — `get_permission_service` واقعی (PermissionService با session؛ بدون Redis)
  - `app/modules/auth/__init__.py` حالا هر دو روتر `auth` و `admin/users` را include می‌کند
  - `require_permission` در `rbac/api/deps.py` اصلاح شد: چون `get_current_user` رشته (id) برمی‌گرداند، `user.id` خطا می‌داد → حالا str و object هر دو پشتیبانی می‌شوند
  - `AdminUserService` حالا actor رشته‌ای را هم می‌پذیرد (`_actor_id`)
- مدل ORM `Users` با DDL هم‌خط شد: ستون‌های `sso_enabled` + `ldap_dn/object_guid/sam_account/synced_at` اضافه شدند (قبلاً `bulk_change_login_mode` روی attribute ناموجود می‌نشست)
- دسترسی‌های گمشده `user.read/user.create/user.manage` در `rbac.permissions` سید و به `super_admin` اعطا شد (قبلاً فقط `user.bulk_login_mode` بود → همه guardها 403 می‌دادند)
- endpoint جدید `GET /api/v1/auth/sso/status` در ssoldap: وضعیت SSO/LDAP بدون افشای secret (enabled، ldap3 نصب، server URI، base DN، auto-provision، kerberos، group-role-map + مسیرهای negotiate/ldap-login)
- چرخه تأییدشده: `list 200 (total=5)` → `create 201` → `deactivate 200` → `bulk sso 200 (updated=[id])` → `reactivate 200` ✅
- فرانت‌اند (`web/src/features/SettingsPage.tsx`): دو کارت جدید
  - **مدیریت کاربران (تعریف کاربر)** — فهرست + جست‌وجو + فرم ایجاد (username/کدملی/نام نمایشی/رمز موقت) + دکمه فعال/غیرفعال (محافظت از self) + دکمه فعال‌سازی/غیرفعال‌سازی SSO برای هر کاربر + **انتخاب نقش از dropdown** (assign/revoke با `/rbac/assign` و `/rbac/revoke`)؛ اگر 403 بگیرد «دسترسی ندارید» نشان می‌دهد
  - **SSO و LDAP** — خواندن `/auth/sso/status` و نمایش ۹ ردیف وضعیت + راهنمای فعال‌سازی SSO از بخش کاربران
- تأیید: `npm run build` موفق (۱۷۶ ماژول)؛ فرانت روی `http://127.0.0.1:3000` بالا و 200

### رفع مشکل گروه‌ها و افزودن عضو از لیست کاربران (۲۳ سپتامبر ۲۰۲۶)
- مشکل «ایجاد گروه ناموفق بود» در فرانت: بک‌اند سالمه (`POST /groups/` با همین بدنه 200 برمی‌گرداند؛ زنجیره‌ی
  stale-token→401→refresh→retry هم تأیید شد 200). علت واقعی، نوسان توکن در هنگام تست هم‌زمان (هر لاگین
  token_version را بالا می‌برد → 401) و پنجره‌ی ریت‌لیت auth (۱۰/دقیقه که شامل `/auth/refresh` هم هست → 429)
  بود. در فرانت حالا پیام خطای واقعی سرور نمایش داده می‌شود (به‌جای پیام generic).
- مشکل «کاربر ایجادشده را نمی‌توان به گروه اضافه کرد»: ریشه در این بود که فرم افزودن، یک input متنی برای
  user_id داشت و اگر کاربر `ghasemi` تایپ می‌کرد، بک‌اند `422` می‌داد (الگوی لاگ: `found 'g' at 1`).
- اصلاح `web/src/features/GroupsPage.tsx`:
  - فهرست کاربران سیستم (`/admin/users`) یک‌بار هنگام mount خوانده می‌شود (با برچسب فارسی مرتب‌شده).
  - فرم افزودن عضو → **dropdown «انتخاب از کاربران سیستم»** (نام نمایشی/کاربرنam نمایش داده می‌شود، به‌جای
    تایپ دستی)؛ کاربرانِ فعلاً عضوِ گروه از لیست حذف می‌شوند؛ کاربر غیرفعال با برچسب «غیرفعال» می‌آید.
  - لیست اعضا حالا **نام نمایشی + ۸ کاراکتر اول UUID** را نشان می‌دهد (نه UUID خام).
  - خطای create/add از response سرور به‌روز رسیدی می‌شود.
- تأیید E2E یک‌جا: login → create group 200 → owner_id==admin → `/admin/users` → add member با UUID
  (همان چیزی که dropdown می‌فرستد) 200 → members 200. `npm run build` موفق.

### نکته‌ی فرم ایجاد کاربر در تنظیمات

### اتصال Audit به رویدادها و integrity (۲۲ سپتامبر ۲۰۲۶)
- `app/modules/audit/__init__.py` از استاب به real تغییر کرد: `register_event_handlers` از `events.py` صدا زده می‌شود — حالا لاگین موفق/ناموفق و رویدادهای auth/rbac در `audit.login_audit_logs` / `audit.audit_logs` با زنجیره‌ی هش (advisory lock) ثبت می‌شوند.
- `app/audit/integrity.py` (که ایمپورت خرابی داشت) بازنویسی شد تا زنجیره‌ی هر دو جدول را با همان فرمول `AuditService` بازمحاسبه و تأیید کند؛ `GET /api/v1/audit/integrity-check` → `{"status":"integrity_ok","total_logs":…,"broken_links":0,…}`.
- ⚠️ ترگر سرگردان دیتابیس (`audit.compute_row_hash()` روی `audit_logs` و `login_audit_logs`) حذف شد: هم `login_audit_logs` (ستون `action` ندارد) را می‌شکست، هم با فرمول app تداخل داشت — مطابق کامنتِ خود `backend/alembic/versions/audit_schema.sql` هیچ ترگرهش روی این جدول‌ها نباید باشد.
- پاکسازی: فایل‌های اسکله‌ی بلااستفاده‌ی پچ قدیمی از `calendar` و `files` (که هیچ route به آن‌ها import نداشت و در git هم نبودند) حذف شدند؛ پیاده‌سازی واقعی `calendar_service.py` و `files_service.py` بی‌تغییر ماند.

### نکته تست push زنده (مهم)
برای تست live notification، لاگین **باید روی همان پروسه‌ای** باشد که سوکت WS روی آن باز است؛ در حالتی که سوکت روی 8001 و لاگین روی 8000 است، notification در دیتابیس مشترک ساخته می‌شود ولی پابلیش به broker پروسه‌ی اشتباه می‌رود و به سوکت نمی‌رسد.

### Redis
- سرور Redis هنوز نصب نیست؛ `RedisBroker` در بدترین حالت به in-memory pub/sub ارتجاع می‌دهد (لاگ: `redis unavailable; using in-memory pub/sub`).
- برای چند-worker پشت load balancer به Redis واقعی نیاز است (کانفیگ از قبل در `settings.redis_url` است).

### SSO / SPNEGO (معماری امنیت لایه‌بندی‌شده)
- `POST /api/v1/auth/sso/ldap-login` — کامل (با `ldap3`؛ در غیاب AD → 401 `LDAP_UNAVAILABLE`)
- `GET /api/v1/auth/sso/negotiate` — هنگام نبود هدر → 401 `SPNEGO_CHALLENGE` + هدر `WWW-Authenticate: Negotiate`؛ وقتی هدر `Authorization: Negotiate ...` هست ولی Kerberos کانفیگ نیست → 501 `KERBEROS_NOT_CONFIGURED`
- کلیدهای کانفیگ: `LDAP_KERBEROS_ENABLED` (پیش‌فرض `False`) و `LDAP_KERBEROS_KEYTAB` (خالی) در `app/core/config.py`

---

## ۸. چرخه‌های تأییدشده (تست end-to-end روی سرور در حال اجرا)

```
REGISTER 201 → LOGIN 200 (access+refresh token) → ME 200 (کد ملی ماسک‌شده)
→ DEVICES 200 → LOGOUT 200 → ME بعد از logout = 401 ✅
LOGIN 200 → audit.login_audit_logs+1 → GET /audit/integrity-check → {"status":"integrity_ok","broken_links":0} ✅
```

---

## ۹. کارهای باقی‌مانده (عامدانه انجام نشد)

| مورد | وضعیت | توضیح |
|---|---|---|
| MFA کامل (TOTP) | ✅ انجام شد | enroll/verify/enroll-confirm پیاده شد و چرخه login→mfa_required→verify→توکن تأیید شد (مستندات در OpenAPI `type: string` برای code) |
| WebSocket chat + notifications | ✅ انجام شد | بخش ۸و؛ `/ws/chat` و `/ws/notifications` با تمام کنترلها (origin/JWT/rate-limit/اندازه/بازارزیابی) |
| Redis | ✅ fallback درون‌فرایندی | سرور Redis نصب نیست؛ `RedisBroker` (بخش ۸و) با in-memory pub/sub ارتجاع دارد؛ Redis واقعی فقط برای چند-worker لازم است |
| SSO LDAP + Kerberos/SPNEGO | ✅/⚠️ جزئی | ldap-login کامل است؛ negotiate سؤال‌چالش SPNEGO و در غیاب Kerberos 501 می‌دهد؛ Kerberos واقعی نیاز به AD + Keytab دارد |
| ۵ ماژول stub (calendar, notification, audit, ssoldap, files) | ✅ کامل شد | همه با سرویس SQL خام روی DDL واقعی پیاده و تست شدند (بخش ۸ج/۸و) |
| دریفت ORM از DDL | ✅ دور زده شد | سرویس‌های هر ۷ ماژول با SQL خام روی DDL واقعی بازنویسی شدند (بخش ۸ج)؛ اسکله‌های ORM بلااستفاده (calendar/files) حذف شدند — مدل‌های منحرف باقی‌مانده در `db/Models.py` استفاده نمی‌شوند؛ بازنگری آتی |
| نقش‌های کاربر `admin` | ✅ انجام شد | seed RBAC (بخش ۸ج): ۵ نقش + ۲۴ دسترسی + اعطای `super_admin` به `admin` |
| باطل‌شدن نشست‌های قبلی با هر login | ⚠️ رفتار فعلی | به‌خاطر `token_version++` در صدور توکن، ورود جدید نشست‌های قبلی را می‌اندازد؛ اگر چنددستگاهی می‌خواهید بازبینی شود |

---

## ۱۰. اجرای روزمره (خلاصه)

```powershell
# ترمینال ۱ — بک‌اند (پشت‌زمینه، از هر shell که بسته شود هم زنده می‌ماند)
cd C:\Projects\Run_Projects_in_Git\Activity_dashboard\backend
cmd /c "start /b .venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000 > %TEMP%\opencode\srv8000.log 2>&1"

# ترمینال ۲ — فرانت‌اند
cd C:\Projects\Run_Projects_in_Git\Activity_dashboard\web
npm run dev
```

> نکته ویندوز: وقتی بک‌اند را با `cmd start /b` بالا می‌آورید، wrapper که shell را می‌بندد ممکن است پیام `ChildProcess.kill` بدهد؛ این **طبیعی است** — فرزند جدا شده و بالا می‌ماند. دستور `Stop-Process` زیر پیش از راه‌اندازی مجدد، همه‌ی پایتون‌های uvicorn را می‌کشد:
> `Get-CimInstance Win32_Process -Filter "Name='python.exe'" | Where-Object { $_.CommandLine -match 'uvicorn' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }`

### بررسی سلامت پس از راه‌اندازی
```powershell
Invoke-WebRequest http://127.0.0.1:8000/health     # {"status":"healthy", ... 13 module}
Invoke-WebRequest http://127.0.0.1:3000            # 200
# لاگین واقعی با Endpoint (نه فقط صفحه):
# POST /api/v1/auth/login  {"identifier":"admin","password":"admin123"}
```

| نشانی | کاربرد |
|---|---|
| http://127.0.0.1:3000 | اپ وب (ورود: `admin` / `admin123`) |
| http://127.0.0.1:8000/docs | مستندات تعاملی API |
| http://127.0.0.1:8000/health | سلامت سرویس |
