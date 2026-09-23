# GAP_ANALYSIS.md — تحلیل شکاف پروژه Activity Dashboard

> **نسخه:** v1.0-final
> **تاریخ:** ۲۰۲۶-۰۹-۲۳
> **مبنای تحلیل:** سند `architecture-v2.md` + ۱۵۴ فایل پروژه (۱۲ بخش PACK)
> **دامنه:** Backend (FastAPI) · Web (React/TS) · Desktop (PySide6) · Tests · Migrations
> **تهیه‌کننده:** تحلیل عمیق خودکار

---

## ۱. خلاصه مدیریتی

### وضعیت کلی: 🟢 ۷۵٪ آماده تولید — میانگین امتیاز ۸.۳/۱۰

پروژه در وضعیت **به‌مراتب بهتر از آنچه انتظار می‌رفت** است. اسکلت معماری Modular Monolith به‌درستی پیاده‌سازی شده و ADRهای کلیدی (Outbox، Hash Chain، Device Binding، MFA) رعایت شده‌اند.

### امتیاز به تفکیک ماژول

| ماژول | امتیاز | وضعیت |
|---|---|---|
| Core | 8.4/10 | 🟢 |
| Auth (M1) | 9.2/10 | 🟢 |
| RBAC (M2) | 9.5/10 | 🟢 |
| Groups (M3) | 7.5/10 | 🟡 |
| Goals (M4) | 8.5/10 | 🟢 |
| Calendar (M5) | 8.8/10 | 🟢 |
| Sharing (M6) | 8.0/10 | 🟡 |
| Chat (M7) | 8.8/10 | 🟢 |
| Inbox (M8) | 8.5/10 | 🟢 |
| Reporting (M9) | 8.0/10 | 🟡 |
| Notification (M10) | 9.0/10 | 🟢 |
| Audit (M11) | 8.5/10 | 🟢 |
| SSO/LDAP (M12) | 9.0/10 | 🟢 |
| Files (M13) | 9.3/10 | 🟢 |
| Migrations | 8.0/10 | 🟡 |
| Frontend Web | 7.5/10 | 🟡 |
| Desktop | 7.0/10 | 🟡 |
| Tests | 8.5/10 | 🟢 |
| **میانگین کل** | **8.3/10** | **🟢** |

### پنج شکاف بحرانی (Blocker برای Production)

1. 🔴 فایل‌های تکراری/قدیمی در هسته: `core/events.py` و `core/middleware.py`
2. 🔴 لایه‌های ۷، ۸، ۹ Middleware امنیتی غایب هستند
3. 🔴 باگ منطقی در `audit/integrity.py` خط ۸۸
4. 🔴 `web/src/security/sanitize.ts` — شیء پیکربندی DOMPurify تکراری و ناسازگار
5. 🔴 `web/src/hooks/useLayoutPersistence.ts` — خطای syntax جدی

---

## ۲. تحلیل تفصیلی به تفکیک ماژول

### ۲.۱. هسته (Backend Core) — ۸.۴/۱۰

#### ✅ نقاط قوت برجسته

- **`core/config.py`**: اعتبارسنجی داخل کلاس، Production hardening، HS256/RS256، AliasChoices
- **`core/context.py`**: استفاده درست از `ContextVar` بدون global leak
- **`core/events/bus.py`**: تفکیک transactional/async، پر کردن auto correlation_id
- **`core/events/dispatcher.py`**: `FOR UPDATE SKIP LOCKED` + SAVEPOINT + Dead-Letter
- **`core/middleware/*`**: Pure ASGI، client_ip با Trusted Proxies، body_guard با streaming count، rate_limit با bucket-based
- **`core/redis.py`**: Fallback خودکار به in-memory fanout

#### 🔴 شکاف‌های بحرانی

**شکاف ۱ — فایل‌های تکراری:**
```
backend/app/core/events.py       ← قدیمی (ThreadPoolExecutor، except: pass)
backend/app/core/middleware.py   ← قدیمی (global _request_context، rate limit hard-coded)
```
اقدام: **حذف هر دو فایل** و رفع importها.

**شکاف ۲ — `main.py` از فایل قدیمی import می‌کند:**
```python
from app.core.middleware import register_middlewares  # ❌
```

**شکاف ۳ — لایه‌های ۷، ۸، ۹ غایب:**
| لایه | فایل مورد انتظار | وضعیت |
|---|---|---|
| ۷ | `middleware/authentication.py` | 🔴 |
| ۸ | `middleware/device_binding.py` | 🔴 (فقط config) |
| ۹ | `middleware/session_validation.py` | 🔴 |

**شکاف ۴ — باگ در `audit/integrity.py` خط ۸۸:**
```python
"total_links": max(total - 2, 0),   # ❌ باید total - 1 باشد
```

**شکاف ۵ — `_InMemoryFanout.incr_expire` برای چند key کار نمی‌کند:**
نیازمند dict-based شدن.

---

### ۲.۲. Auth (M1) — ۹.۲/۱۰

#### ✅ نقاط قوت

- **`auth/db/mfa.py`**: RFC 6238 خالص، AES-GCM secret، Recovery codes
- **`auth_service.py`**: Argon2، National ID checksum، Account locking، Refresh token rotation با family_id
- **`admin_user_service.py`**: Bulk login mode با سه کد خطا، سقف ۵۰۰ کاربر

#### 🟡 شکاف‌ها

- `_encrypt_national_id` در دو جا تکرار شده
- Device Binding فقط ثبت می‌کند، enforcement واقعی نیازمند لایه ۸

---

### ۲.۳. RBAC (M2) — ۹.۵/۱۰

#### ✅ نقاط قوت

- **`role_assignment_service.py`**: سه قاعده ضد privilege escalation دقیقاً طبق سند ۷.۴
- **`rbac_service.py`**: raw SQL، anti-escalation، scope-aware
- **`permission_service.py`**: Redis cache TTL 60s + invalidation از رویداد

#### 🟡 شکاف

- دو پیاده‌سازی موازی `assign_role`
- PolicyEngine مستقل (ADR-11) وجود ندارد

---

### ۲.۴. Audit (M11) — ۸.۵/۱۰

#### ✅ نقاط قوت

- Hash chain با `pg_advisory_xact_lock`
- `mask_sensitive` برای redact
- جداول `audit_logs` و `login_audit_logs`

#### 🔴 شکاف

- باگ `total_links`
- API routes هنوز stub (`GET /audit/logs` → `[]`)
- PARTITION BY RANGE پیاده نشده

---

### ۲.۵. Chat + WebSocket (M7) — ۸.۸/۱۰

#### ✅ نقاط قوت

- `ws/manager.py`: Redis pub/sub bridge
- `ws/routes.py`: Origin validation، revalidation هر ۶۰s، idle timeout، rate limit
- `ws/handlers/chat.py`: per-message membership check

#### 🔴 شکاف‌ها

1. `ws/handlers/chat.py` از `get_redis_pool` import می‌کند (باید `get_redis_broker`)
2. `Users.id == str(user_id)` — مقایسه UUID با string
3. دو مسیر موازی: `ws/handlers/chat.py` و `api/routes.py`
4. `ChatWebSocketHandler` از `chat_ws_manager` import می‌کند که وجود ندارد

---

### ۲.۶. Files (M13) — ۹.۳/۱۰

#### ✅ نقاط قوت

- `validators.py`: Whitelist + Dangerous extensions، Magic number check
- `av_scan_service.py`: Fail-Closed واقعی
- `storage.py`: S3/MinIO با `Content-Disposition: attachment`

#### 🟡 شکاف‌ها

- سه فایل موازی: `file_service.py`, `files_service.py`, `av_scan_service.py`
- Storage محلی + S3 همزمان

---

### ۲.۷. Goals (M4) — ۸.۵/۱۰

#### ✅ نقاط قوت

- `_decision` برای privacy
- Task creation با ارث‌بری privacy از goal

#### 🟡 شکاف

- `goals/db/Models.py` با DDL همراستا نیست
- Dependency_service برای subtask DAG پیاده نشده

---

### ۲.۸. Groups (M3) — ۷.۵/۱۰

#### 🟡 شکاف‌ها

1. `get_group_with_privacy` بسیار محدود (فقط owner)
2. LTREE path format با DDL سند سازگار نیست
3. `list_groups` هیچ فیلتری بر اساس viewer اعمال نمی‌کند

---

### ۲.۹. Calendar (M5) — ۸.۸/۱۰

#### ✅ نقاط قوت

- `date_conversion.to_hijri_approximate` با `is_approximate=True` اجباری
- `widget_config.py` با اعتبارسنجی کامل

#### 🟡 شکاف

- ORM Models وجود ندارد
- Recurrence Rule پیاده نشده

---

### ۲.۱۰. Notification (M10) — ۹.۰/۱۰

#### ✅ نقاط قوت

- Subscription به رویدادها (بدون import مستقیم)
- Live push از طریق Redis به WS

#### 🟡 شکاف

- `db/Models.py` وجود ندارد
- `email_service.py` پیاده نشده

---

### ۲.۱۱. Inbox (M8) — ۸.۵/۱۰

#### ✅ نقاط قوت

- State machine (pending → accepted/rejected/deferred/expired)
- Read receipts (sent → seen → acted)

#### 🟡 شکاف

- `deferred_check.py` از `engine.begin()` sync استفاده می‌کند (async نیست)
- ORM با DDL ناسازگار

---

### ۲.۱۲. Reporting (M9) — ۸.۰/۱۰

#### ✅ نقاط قوت

- `dashboard.py` با widget-level degradation
- Layout persistence

#### 🟡 شکاف

- دو مسیر موازی: `routes.py` و `dashboard.py`

---

### ۲.۱۳. Sharing (M6) — ۸.۰/۱۰

#### 🟡 شکاف

- `revoke_share` هیچ‌گاه owner را چک نمی‌کند
- ACL inheritance از group پیاده نشده

---

### ۲.۱۴. SSO/LDAP (M12) — ۹.۰/۱۰

#### ✅ نقاط قوت

- LDAP Bind دو مرحله‌ای
- `escape_ldap_filter_value` (RFC 4515)
- Auto-provision

#### 🟡 شکاف

- `_sync_roles_from_ldap_groups` TODO
- Kerberos فقط 501

---

### ۲.۱۵. Migrations — ۸.۰/۱۰

#### 🟡 شکاف

- `alembic/head.py` باگ دارد (`Base.metadata.bind` deprecated)
- `alembic_versions/` با `alembic/versions/` تداخل دارد

---

### ۲.۱۶. Frontend Web — ۷.۵/۱۰

#### ✅ نقاط قوت

- `api/client.ts`: Single-flight refresh، device headers، transformRequest bypass
- `authProvider.ts`: forceLogout برای auth:expired
- صفحات Chat, Dashboard, Groups, Inbox, Reports, Settings کارکردی

#### 🔴 شکاف‌های بحرانی

**شکاف ۱ — `sanitize.ts`:**
- `ALLOWED_TAGS` هفت بار در یک شیء تکرار شده
- `import { JSDOM } from 'jsdom'` در مرورگر کار نمی‌کند

**شکاف ۲ — `useLayoutPersistence.ts`:**
- خطای syntax: `useSecurity: () => ({...}) = useAuth()`
- `useAuth` import نشده

**شکاف ۳ — `AuthLayout.tsx`:**
- `{...credentials.identifier ? {} : 'autoFocus'}` — رشته جای شیء

**شکاف ۴ — MFA UI پیاده نشده**

**شکاف ۵ — دو LoginPage موازی** (در App.tsx و AuthLayout.tsx)

**شکاف ۶ — `usePermissionCache.ts` دو پیاده‌سازی دارد**

**شکاف ۷ — `package.json`:**
- `vite": "^8.3.0"` — نسخه ۸ وجود ندارد

---

### ۲.۱۷. Desktop — ۷.۰/۱۰

#### ✅ نقاط قوت

- `device_identity.py`: MAC از psutil + MachineGuid از رجیستری
- `jalali_service.py`: تبدیل دوطرفه، Persian digits
- `token_store.py`: Platform keyring

#### 🔴 شکاف‌های بحرانی

**شکاف ۱ — `api_client.py`:**
- `platform` import نشده
- `get_system_fingerprint` import نشده
- `TokenStore` attribute `_device_identity` ندارد
- `TokenStore.refresh()` متد وجود ندارد

**شکاف ۲ — `auth_manager.py`:**
- `ApiClient._token_store._device_identity` وجود ندارد
- `QWebSocketProtocol` import ممکن است کار نکند

**شکاف ۳ — `bootstrap.py`:**
- `main()` تعریف نشده اما فراخوانی می‌شود
- `QColor` بدون استفاده

**شکاف ۴ — `ws_client.py`:**
- `_ reconnect_attempts = 0` با space (خطای syntax)
- `_ws` قبل از ساخت استفاده می‌شود

**شکاف ۵ — `main.py`:**
- `LoginWindow()` بدون `auth_manager` فراخوانی می‌شود

**شکاف ۶ — `dashboard_view.py`:**
- `from PySide6.QtGui = QColor` — خطای syntax

---

### ۲.۱۸. Tests — ۸.۵/۱۰

#### ✅ نقاط قوت

- `test_module_boundaries.py` — AST-based، بسیار حرفه‌ای
- تست Outbox atomicity، retry، dead-letter
- تست Fail-Closed AV
- تست LDAP injection

#### 🟡 شکاف

- تست WebSocket وجود ندارد
- تست Frontend (Vitest/Jest) وجود ندارد
- تست E2E (Playwright) وجود ندارد
- تست Performance/Load وجود ندارد

---

## ۳. اولویت‌بندی شکاف‌ها

### 🔴 بحرانی (Blocker) — ۴-۵ روز کاری

| # | شکاف | زمان |
|---|---|---|
| 1 | حذف `core/events.py` و `core/middleware.py` قدیمی | ۱ ساعت |
| 2 | ساخت ۳ Middleware غایب | ۱ روز |
| 3 | اصلاح `main.py` | ۲ ساعت |
| 4 | رفع باگ `audit/integrity.py` | ۱۰ دقیقه |
| 5 | رفع `sanitize.ts` | ۲ ساعت |
| 6 | رفع `useLayoutPersistence.ts` | ۱ ساعت |
| 7 | رفع `AuthLayout.tsx` | ۳۰ دقیقه |
| 8 | رفع `dashboard_view.py` | ۱۵ دقیقه |
| 9 | رفع `ws_client.py` | ۳۰ دقیقه |
| 10 | رفع `api_client.py` | ۲ ساعت |
| 11 | رفع `bootstrap.py` و `main.py` desktop | ۲ ساعت |
| 12 | یکپارچه‌سازی `ws/handlers/chat.py` | ۴ ساعت |
| 13 | رفع `get_redis_pool` → `get_redis_broker` | ۱۵ دقیقه |
| 14 | رفع `deferred_check.py` | ۳۰ دقیقه |
| 15 | یکپارچه‌سازی Files | ۴ ساعت |
| 16 | یکپارچه‌سازی Reporting | ۲ ساعت |
| 17 | رفع `package.json` (vite version) | ۱۵ دقیقه |

### 🟠 اولویت بالا — ۱۰-۱۲ روز کاری

| # | شکاف | زمان |
|---|---|---|
| 18 | PolicyEngine مستقل (ADR-11) | ۲ روز |
| 19 | MFA UI | ۱ روز |
| 20 | LDAP role sync | ۱ روز |
| 21 | یکپارچه‌سازی assign_role | ۴ ساعت |
| 22 | ORM Models Calendar/Notification | ۱ روز |
| 23 | Privacy Levels در Groups | ۱ روز |
| 24 | Recurrence Rule | ۱ روز |
| 25 | یکپارچه‌سازی LoginPage | ۲ ساعت |
| 26 | رفع usePermissionCache تکراری | ۱ ساعت |
| 27 | Frontend i18n کامل | ۱ روز |
| 28 | Widget Grid Drag&Drop | ۲ روز |

### 🟡 اولویت متوسط

| # | شکاف |
|---|---|
| 29 | تست WebSocket |
| 30 | تست Frontend |
| 31 | E2E با Playwright |
| 32 | CI/CD GitHub Actions |
| 33 | Docker Compose |
| 34 | مستندات OpenAPI |
| 35 | Email Service |
| 36 | Partition BY RANGE برای Audit |

### 🟢 اولویت پایین

| # | شکاف |
|---|---|
| 37 | Accessibility |
| 38 | PWA تست‌شده |
| 39 | Load Testing |
| 40 | Auto-update Desktop |
| 41 | Helm/K8s |

---

## ۴. برنامه اجرایی فاز‌به‌فاز

### فاز ۱: پاکسازی و رفع Syntax (۳ روز)

**هدف:** پروژه قابل اجرا شود.

1. حذف فایل‌های تکراری backend
2. رفع خطاهای syntax در desktop (۵ فایل)
3. رفع خطاهای syntax در web (۳ فایل)
4. یکپارچه‌سازی Files و Reporting
5. اصلاح `main.py` backend

**خروجی:** `pytest backend/tests/core/` و `npm run dev` بدون خطا.

### فاز ۲: تکمیل Middleware امنیتی (۴ روز)

**هدف:** رعایت کامل زنجیره ۱۰ لایه‌ای.

1. `middleware/authentication.py`
2. `middleware/device_binding.py` (ADR-08)
3. `middleware/session_validation.py`
4. به‌روزرسانی `main.py` + تست‌های integration
5. حذف `core/middleware.py` قدیمی

**خروجی:** زنجیره ۱۰ لایه‌ای کامل.

### فاز ۳: تکمیل Auth + RBAC (۵ روز)

1. PolicyEngine مستقل
2. LDAP role sync
3. یکپارچه‌سازی `assign_role`
4. یکپارچه‌سازی `_encrypt_national_id`
5. MFA API endpoints کامل

### فاز ۴: WebSocket + Notification (۴ روز)

1. یکپارچه‌سازی chat handlers
2. تست WS با `httpx_ws`
3. Live notification push
4. Frontend WS client با Backoff

### فاز ۵: Frontend (۶ روز)

1. MFA UI
2. Widget Grid Drag&Drop
3. i18n کامل
4. یکپارچه‌سازی LoginPage
5. تست Vitest

### فاز ۶: تست، مستندسازی، استقرار (۵ روز)

1. تست WebSocket + E2E
2. Docker Compose
3. CI/CD
4. مستندات OpenAPI
5. راهنمای Production

---

## ۵. کدهای پیشنهادی برای شکاف‌های بحرانی

### ۵.۱. Middleware Authentication (لایه ۷)

```python
# backend/app/core/middleware/authentication.py
"""لایه ۷: احراز هویت (پس از RateLimit، پیش از DeviceBinding)."""
from __future__ import annotations

from starlette.datastructures import Headers
from starlette.types import ASGIApp, Receive, Scope, Send

from app.core.context import bind_user, get_context
from app.core.middleware._http import send_error

_PUBLIC_PATHS = (
    "/health", "/ready", "/docs", "/redoc", "/openapi.json",
    "/api/v1/auth/login", "/api/v1/auth/refresh", "/api/v1/auth/register",
    "/api/v1/auth/mfa/verify", "/api/v1/auth/password/forgot",
    "/api/v1/auth/sso/ldap-login", "/api/v1/auth/sso/negotiate",
)


class AuthenticationMiddleware:
    """توکن JWT را از هدر می‌خواند و user_id را در context می‌گذارد."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        if any(path.startswith(p) for p in _PUBLIC_PATHS):
            await self.app(scope, receive, send)
            return

        h = Headers(scope=scope)
        auth = h.get("authorization", "")

        token: str | None = None
        if auth.lower().startswith("bearer "):
            token = auth[7:].strip()
        elif scope["type"] == "websocket":
            qs = scope.get("query_string", b"").decode()
            for kv in qs.split("&"):
                if kv.startswith("token="):
                    token = kv[6:]
                    break

        if not token:
            if scope["type"] == "websocket":
                await send({"type": "websocket.close", "code": 4401})
                return
            await send_error(scope, receive, send, status=401,
                             code="AUTHENTICATION_ERROR",
                             message="احراز هویت لازم است.")
            return

        from jose import JWTError, jwt as jose_jwt
        from app.core.config import settings

        try:
            claims = jose_jwt.decode(token, settings.SECRET_KEY,
                                     algorithms=[settings.ALGORITHM])
            if claims.get("type") != "access":
                raise JWTError("wrong token type")
            bind_user(claims.get("sub"))
        except JWTError:
            if scope["type"] == "websocket":
                await send({"type": "websocket.close", "code": 4401})
                return
            await send_error(scope, receive, send, status=401,
                             code="AUTHENTICATION_ERROR",
                             message="توکن نامعتبر یا منقضی شده.")
            return

        await self.app(scope, receive, send)
```

### ۵.۲. اصلاح `audit/integrity.py`

```python
# خط ۸۸ — قبل:
"total_links": max(total - 2, 0),

# بعد:
"total_links": max(total - 1, 0),  # اولین ردیف prev_link ندارد
```

### ۵.۳. اصلاح `sanitize.ts` (نسخه تمیز)

```typescript
import DOMPurify from 'dompurify'

const purifyConfig = {
  ALLOWED_TAGS: [
    'b', 'i', 'strong', 'em', 'u', 's', 'a', 'p', 'br', 'hr',
    'div', 'span', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
    'ul', 'ol', 'li', 'dl', 'dt', 'dd'
  ],
  ALLOWED_ATTR: ['class', 'href', 'target', 'rel', 'title', 'id'],
  ALLOWED_URI_REGEXP: /^(https?|mailto|tel):/i,
  FORBID_TAGS: ['script', 'style', 'iframe', 'object', 'embed'],
  FORBID_ATTR: ['onerror', 'onclick', 'onload', 'style'],
  KEEP_CONTENT: true,
  RETURN_DOM: false,
  RETURN_DOM_FRAGMENT: false,
}

export const sanitizeHtml = (html: string): string => {
  if (!html || typeof html !== 'string') return ''
  try {
    return DOMPurify.sanitize(html, purifyConfig)
  } catch (error) {
    console.error('[Sanitize]', error)
    return html.replace(/<[^>]*>/g, '')
  }
}

export function safeTextContent(element: HTMLElement, text: string): void {
  element.textContent = text
}
```

### ۵.۴. اصلاح `useLayoutPersistence.ts`

```typescript
// حذف این بلوک کاملاً نادرست:
useSecurity: () => ({
  getFingerprint, getMacAddress, isDeviceInitialized, initDeviceIdentity
}) = useAuth()

// جایگزین: کاملاً حذف شود یا از هوک واقعی استفاده شود
import { useAuth } from '../security/authProvider'
```

### ۵.۵. اصلاح `api_client.py` desktop

```python
# اضافه کردن در بالای فایل:
import platform

from desktop.app.core.device_identity import (
    get_primary_mac,
    get_system_fingerprint,
    _normalize_mac,
)
```

**در `TokenStore`:**
```python
def __init__(self):
    # ...
    self._device_identity = DeviceIdentity()
    self._device_identity.refresh()
    self._base_url = "https://api.corp.local/api/v1"

def refresh(self) -> bool:
    """Refresh access token. Returns True on success."""
    if not self._refresh_token:
        return False
    try:
        import httpx
        resp = httpx.post(
            f"{self._base_url}/auth/refresh",
            json={"refresh_token": self._refresh_token},
            timeout=10,
        )
        if resp.status_code != 200:
            return False
        data = resp.json()
        self.access_token = data["tokens"]["access_token"]
        self.refresh_token = data["tokens"]["refresh_token"]
        return True
    except Exception:
        return False
```

### ۵.۶. اصلاح `ws_client.py` desktop

```python
def __init__(self, token_store: TokenStore, parent: QObject = None):
    super().__init__(parent)
    self._token_store = token_store
    self._current_room: Optional[str] = None
    self._rooms: Set[str] = set()
    self._message_handlers: Dict[str, Callable] = {}
    self._reconnect_attempts = 0
    self._max_reconnect = 5
    self._reconnect_delay = 2000

    self._ws = QWebSocket()
    self._ws.textMessageReceived.connect(self._on_text_message)
    self._ws.error.connect(self._on_ws_error)
    self._ws.disconnected.connect(self._on_ws_disconnected)
```

### ۵.۷. اصلاح `dashboard_view.py`

```python
# جایگزین: from PySide6.QtGui = QColor
from PySide6.QtGui import QColor, QFont
```

### ۵.۸. اصلاح `bootstrap.py`

```python
if __name__ == "__main__":
    app = bootstrap()
    # ...
```

---

## ۶. نقاط قوت پروژه (باید حفظ شوند)

1. **Transactional Outbox** — نمونه‌ای از پیاده‌سازی درست ADR-02
2. **Fail-Closed AV Scan**
3. **Hash Chain Audit** با advisory lock
4. **RBAC Anti-Escalation**
5. **LDAP Injection Prevention**
6. **Hijri تقریبی** با flag اجباری
7. **Test معماری با AST**
8. **Fallback هوشمند Redis → In-memory**
9. **Contextvars به‌جای global**
10. **Rate limit bucket-based**

---

## ۷. توصیه‌های نهایی

### برای تیم توسعه

1. **قبل از هر چیز، فاز ۱ را کامل کنید.**
2. **`test_module_boundaries.py` را در CI قرار دهید.**
3. **هر شکاف را در یک PR جدا fix کنید.**
4. **`core/middleware.py` و `core/events.py` قدیمی را حذف کنید.**
5. **قبل از Production، `ENV=production` را تست کنید.**

### برای مستندسازی

1. ADRها را به `docs/adr/` استخراج کنید
2. OpenAPI tags کامل شوند
3. راهنمای Production با WAF/Nginx/Backup/Monitoring

### برای مدیریت پروژه

- فاز ۱-۲: ۱ هفته → آماده توسعه
- فاز ۳-۴: ۲ هفته → آماده تست داخلی
- فاز ۵: ۱.۵ هفته → آماده نمایش
- فاز ۶: ۱ هفته → آماده Production

**مجموع: حدود ۵-۶ هفته کار تیمی برای Production.**

---

## ۸. پیوست — چک‌لیست سریع

```
[ ] حذف backend/app/core/events.py
[ ] حذف backend/app/core/middleware.py
[ ] ساخت backend/app/core/middleware/authentication.py
[ ] ساخت backend/app/core/middleware/device_binding.py
[ ] ساخت backend/app/core/middleware/session_validation.py
[ ] اصلاح backend/app/main.py
[ ] رفع audit/integrity.py خط ۸۸
[ ] یکپارچه‌سازی Files
[ ] یکپارچه‌سازی Reporting
[ ] یکپارچه‌سازی ws/handlers/chat.py
[ ] رفع deferred_check.py
[ ] رفع web/src/security/sanitize.ts
[ ] رفع web/src/hooks/useLayoutPersistence.ts
[ ] رفع web/src/AuthLayout.tsx
[ ] رفع web/package.json (vite version)
[ ] رفع desktop/app/core/api_client.py
[ ] رفع desktop/app/core/ws_client.py
[ ] رفع desktop/app/core/bootstrap.py
[ ] رفع desktop/app/views/dashboard/dashboard_view.py
[ ] رفع desktop/main.py
[ ] PolicyEngine مستقل
[ ] MFA UI
[ ] LDAP role sync
[ ] تست WebSocket
[ ] تست Frontend
[ ] CI/CD
[ ] Docker Compose
```

---

**پایان گزارش GAP_ANALYSIS**

*این سند آماده‌ی استفاده به‌عنوان مرجع اصلی تکمیل پروژه است.*