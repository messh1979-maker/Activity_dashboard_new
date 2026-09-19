# Project Execution Guide - Planner Enterprise API

> All commands below were executed and verified on this machine on 2026-09-19
> (Windows, PowerShell). Expected outputs are shown so you can confirm each step.

## Verified status (what actually runs today)

- **Backend (FastAPI, venv Python 3.12.0)**: RUNNING at `http://127.0.0.1:8000`
  - `GET /health` returns `{"status":"healthy", ...}` with all 12 modules listed
  - `GET /docs` returns HTTP 200, `/openapi.json` exposes **47 paths**
  - 8 routers wired (59 routes): auth 10, chat 7, goals 9, groups 10,
    inbox 5, rbac 7, reporting 7, sharing 4
  - 4 stub modules (`audit`, `files`, `notification`, `ssoldap`) are empty
    directories and are skipped gracefully until their routes land
- **Frontend (React + Vite, Node v24.21.0 / npm 11.19.0)**: RUNNING at
  `http://127.0.0.1:3000/` (HTTP 200, Persian RTL shell, `npm run build` green)
  - Console verified clean: no font 404s, no favicon 404, no CSP
    `frame-ancestors` warning, no unused-preload warnings
- **Database**: PostgreSQL 16.15 installed, service running. `planner_db` (owner
  `admin`) holds **47 tables in 13 schemas**, `alembic_version = 0001_initial`.
  Verified end-to-end 2026-09-19: `POST /api/v1/auth/register` -> 201/409
  (proper duplicate handling), `POST /api/v1/auth/login` -> 200 with HS256 JWT
  (+ `exp`), refresh token and masked national ID (`*****7891`).

## Prerequisites (verified versions)

- Python **3.12.0** in `backend\.venv` (use it; system Python 3.15 is untested)
- Node.js **v24.21.0**, npm **11.19.0** (`C:\Program Files\nodejs\`)
- PostgreSQL 15+ — **missing, install manually** (no winget/docker on this box)
- Redis — optional; rate limiting/device code paths are placeholders

## 1. Backend

PowerShell, from `D:\Projects\Activity_dashboard\backend`:

```powershell
cd D:\Projects\Activity_dashboard\backend

# (first time only) create venv + install pinned deps
C:\Users\Es_E580\AppData\Local\Programs\Python\Python312\python.exe -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt

# sanity check: interpreter + full app import (must print route counts, no traceback)
.\.venv\Scripts\python.exe --version
# -> Python 3.12.0
.\.venv\Scripts\python.exe -c "import app.main as m; print('app OK, routes:', len(m.app.routes))"
# -> app OK, routes: 65
```

`.env` must exist in `backend\` (copy from the fixed template and edit secrets):

```powershell
copy .env.example .env
```

Required keys: `SECRET_KEY` (min 32 chars), `POSTGRES_SERVER/PORT/USER/PASSWORD/DB`,
`SQLALCHEMY_DATABASE_URI` (asyncpg URL for the app; alembic auto-converts it to
psycopg2). `CORS_ORIGINS`, if set, must be **JSON array** syntax, e.g.
`CORS_ORIGINS=["http://localhost:3000","http://localhost:8080"]` — a plain
comma-separated string crashes settings parsing. Omit it to use the defaults
(3000/8080), which already match the Vite dev server.

Start the server (foreground; stop with Ctrl+C):

```powershell
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Or in background:

```powershell
Start-Process -FilePath "D:\Projects\Activity_dashboard\backend\.venv\Scripts\python.exe" `
  -ArgumentList "-m","uvicorn","app.main:app","--host","127.0.0.1","--port","8000" `
  -WorkingDirectory "D:\Projects\Activity_dashboard\backend" -WindowStyle Hidden
```

Verify:

- `http://127.0.0.1:8000/health` -> `{"status":"healthy","service":"planner-enterprise-api",...}`
- `http://127.0.0.1:8000/docs` -> HTTP 200 (Swagger UI, 47 paths)

> Do NOT use bare `python` (venv is not on PATH) and do NOT pass `&&`-chained
> one-liners through the `cmd /c` tool wrapper — PowerShell 5.1 rejects `&&`.
> `python -m alembic` works (alembic 1.13 ships `__main__`), but prefer
> `.\.venv\Scripts\alembic.exe`.

## 2. Frontend

PowerShell, from `D:\Projects\Activity_dashboard\web`:

```powershell
cd D:\Projects\Activity_dashboard\web
npm install          # node_modules already present; rerun after package.json changes
npm run dev          # serves http://127.0.0.1:3000 (port fixed in vite.config.ts)
```

Open `http://127.0.0.1:3000/` (HTTP 200; the Vite entry is now a root
`web/index.html`, so `/` serves the app shell). Port 3000 is intentional: it
matches the backend's default `CORS_ORIGINS`. API base for local dev is pinned
in `web/.env`: `VITE_API_BASE=http://127.0.0.1:8000/api/v1`.

If the browser console was showing `Vazirmatn-*.woff2 404`, `favicon.ico 404`,
`frame-ancestors ... ignored`, or unused-preload warnings — all fixed:
- Entry moved from `public/index.html` (wrong place; also shadowed `/`) to
  root `index.html` with the `<script src="/src/main.tsx">` entry (it was
  missing, so React never booted).
- Dead `/fonts/*.woff2` preloads removed (files never existed; font stack falls
  back to system fonts until real woff2 files are added under `public/fonts/`).
- `public/favicon.svg` created and linked (kills the favicon 404);
  `public/manifest.json` icons now point at it (the old `/icons/*.png`
  never existed -> manifest icon download errors).
- `api/client.ts` device-identity message demoted `warn` -> `debug`
  (diagnostic noise on every pre-init request).
- Not from this codebase, no action: React's dev-only «Download React
  DevTools» info log, and the browser's «model ... no execution config»
  message (Edge/Chrome on-device AI). `public/sw.js` (workbox) is dead code —
  never registered, never built; wire it up or delete it later.
- CSP meta no longer contains `frame-ancestors` (browsers ignore it in `<meta>`;
  send it as an HTTP header from production instead); `connect-src` now allows
  the local backend (`http(s)://127.0.0.1:8000`, `localhost:8000`, incl. `ws:`),
  and `style-src` allows `'unsafe-inline'` for Vite dev injected styles.
- `src/App.tsx` rewritten to boot with real modules only (zustand `useAuth` +
  `init()`); unbuilt features render honest «not implemented» placeholders.
  `src/main.tsx` fixed (`gcTime`, no bogus `StrictMode` props, no `AxeProvider`).
- Installed (pinned in `package.json`): `zustand`, `crypto-js`,
  `@fingerprintjs/fingerprintjs` (all imported but absent).
- Fixed: unclosed `set(...)` parens in `authProvider.ts`, missing `api` export
  usage (`apiRef as api`), missing `init` in `AuthState` interface.

Production build check:

```powershell
npm run build        # outputs web\dist\
```

## 3. Database (done 2026-09-19 — keep for rebuilds)

PostgreSQL 16 is installed as service `postgresql-x64-16`. `psql` is NOT on
PATH; always call it by full path:

```powershell
& "C:\Program Files\PostgreSQL\16\bin\psql.exe" -U admin -h localhost -d planner_db -c "SELECT count(*) FROM auth.users;"
```

Setup that was performed (do not repeat unless rebuilding):

```powershell
# role + database (as postgres superuser)
& "C:\Program Files\PostgreSQL\16\bin\psql.exe" -U postgres -h localhost -c "CREATE ROLE admin WITH LOGIN PASSWORD 'admin123' SUPERUSER;"
& "C:\Program Files\PostgreSQL\16\bin\psql.exe" -U postgres -h localhost -c "CREATE DATABASE planner_db OWNER admin;"
# least-privilege role referenced by audit grants
& "C:\Program Files\PostgreSQL\16\bin\psql.exe" -U postgres -h localhost -d planner_db -c "CREATE ROLE app_user NOLOGIN;"
# schemas + 13 module SQL files in FK order (auth, rbac, groups, planning,
# calendar, chat, files, inbox, notification, reporting, sharing, ssoldap, audit),
# each with: psql --single-transaction -v ON_ERROR_STOP=1 -f <file>
.\.venv\Scripts\alembic.exe stamp head   # schema pre-existed; marks 0001_initial
.\.venv\Scripts\alembic.exe current      # -> 0001_initial (head)
```

SQL fixes applied while applying (files are now PG-16 clean): missing
`CREATE SCHEMA`s added via revision; inline `INDEX` in `CREATE TABLE`
(auth, rbac) moved out; expression/partial `UNIQUE`/`PRIMARY KEY`
(auth users, rbac user_roles, reporting layouts) converted to partial
`CREATE UNIQUE INDEX`; `CREATE TYPE ... AS SMALLINT CHECK` -> `CREATE DOMAIN`;
removed broken `groups.effective_privacy` view (referenced nonexistent columns);
audit PK changed to `(id, timestamp)` (partition key required);
`files.uploads` duplicate definition removed from `files_schema.sql`
(chat_schema.sql owns it); `app_user` role created for audit GRANTs.
`alembic/versions/0001_initial.py` replays everything on a fresh database.

Smoke test (backend must be running):

```powershell
$env:PYTHONUTF8 = "1"
# register -> 201 first time, 409 USER_EXISTS after; login -> 200 + JWT
```

> WARNING: never start the backend with system Python (`C:\...\Python312\python.exe
> -m uvicorn ...`). Stale system-python servers keep squatting on port 8000 with
> outdated code and steal requests from the venv server. Always use
> `backend\.venv\Scripts\python.exe`. Kill strays by PID:
> `Get-CimInstance Win32_Process -Filter "Name='python.exe'"` then
> `Stop-Process -Id <pid> -Force` (only the system-python uvicorn ones).

## Repairs applied to the project (2026-09-19 session)

Backend boot was broken by ~25 defects; all fixed and verified by import + HTTP:

1. `alembic.ini` created (was missing -> `FAILED: No config file`).
2. `alembic/env.py`: fixed `from backend.app...` import, bad `sys.path` hack,
   `.env` loading, `+asyncpg` -> `+psycopg2` conversion for sync migrations.
3. `app/core/config.py`: pydantic v2 `model_config` (killed deprecation crash
   path), `SQLALCHEMY_DATABASE_URI` accepts `SQLALCHEMY_DATABASE_URI` or
   `DATABASE_URL` (was `DATABASE_URL`-only while `.env` used the other name),
   `field_validator` migration.
4. `app/modules/auth/_init__.py` (misnamed, never executed) replaced by proper
   `__init__.py`; created `__init__.py` re-exporting `router` in all 8 routed
   modules.
5. `app/main.py`: guards for modules without `router`/`register_event_handlers`
   (4 empty stub modules), `shutdown_gracefully` made async (was awaited sync fn).
6. New `app/core/database.py` shim (`engine`, `get_session`,
   `async_session_context`, `get_async_session`) — 15 imports referenced a
   module that did not exist.
7. `app/core/dependencies.py`: added `uuid4` import, fixed `get_db_session` to
   return the async-CM factory (was `run_until_complete` on an async generator),
   added 8 lazy service factories (`get_mfa_service`, `get_rate_limit_check`,
   `get_chat/goals/groups/rbac/reporting/sharing_service`).
8. `app/core/db/base.py`: missing `List` import; `session.py`: `str()` around
   `PostgresDsn` (MultiHostUrl) for `create_async_engine`.
9. Installed + pinned: `PyJWT==2.8.0`, `asyncpg==0.29.0`, `structlog==24.4.0`,
   `argon2-cffi==23.1.0` (were imported but absent from venv/requirements).
10. `auth_service.py`: `argue_cost=3` typo -> `argon2__time_cost=3` (crashed
    `CryptContext` at import).
11. `auth/ports.py`: `TokenResponse.user: UserReadModel` (Protocol) -> `dict`
    (pydantic cannot schema a Protocol).
12. All 8 `routes.py`: added missing `from uuid import UUID` and
    `from typing import ...`; chat `+ Path`, inbox `+ Query`.
13. All 6 `db/Models.py`: `from sql import ...` -> sqlalchemy; added missing
    `AuditMixin`, `UUID`, `func`, `Text`/`JSON`/`Index`/`Table`/`UniqueConstraint`
    imports; `server_default=True/False/365/1` -> `default=`; removed
    `func.coalesce` from a UniqueConstraint; fixed `comment=` typo (rbac).
14. `inbox/ports.py`, `groups/ports.py`, `sharing/ports.py`: TypeScript-isms
    (`: string`, `field?: type`, `'a' | 'b'` unions) converted to valid Python;
    added missing `Field`/`Dict` imports; `InboxItemType.description` defaulted.
15. `inbox/services/inbox_service.py`: added missing `list_items`/`list_outbox`
    methods + `InboxService` alias; `Dict` imports.
16. `reporting/db/Models.py`: dropped invalid `ge=`/`le=` Column kwargs;
    removed Index on nonexistent `user_id` column.
17. `groups/Models.py`, `goals/Models.py`: added missing `List`/`Dict` imports.
18. Auth bootstrap stubs created (referenced but absent): `auth/db/__init__.py`,
    `auth/db/models.py` (`Users`, `UserDevices`, `Sessions`), `auth/db/repositories.py`
    (`UserRepository`), `auth/db/mfa.py` (`MFAService`), `auth/services/__init__.py`.
19. `web/vite.config.ts`: `server`/`preview`/`resolve` were nested inside `build`
    (silently ignored); moved to top level, dev port fixed at 3000 with host
    `127.0.0.1` to match backend CORS defaults.
20. `.env.example`: documented `SECRET_KEY` length rule, added
    `SQLALCHEMY_DATABASE_URI`, fixed `CORS_ORIGINS` to JSON-array syntax.
21. `requirements.txt`: added the 4 packages above.

## Known limitations (not fixed — need decisions/infra)

- Redis has no client config beyond host/port defaults; rate limiting and
  realtime paths that need it are placeholders. No Docker on this machine
  (not needed: everything runs natively).
- Auth persistence is real for register/login/refresh-password flows, but MFA
  endpoints (`verify_mfa`/`enroll_mfa` call stub `MFAService`), device
  trust-by-MFA, and the audit hash-chain writer (`_audit_log` skips silently
  until `app.modules.audit` lands) still need implementation.
- `ALGORITHM` is now `HS256` (was `RS256` with a symmetric secret, which can
  never work); move to RS256 + keypair or rotate the dev `SECRET_KEY` before
  any staging deploy.
- `alembic/versions/*.sql` are raw SQL (some PG-invalid, e.g. `INDEX` inside
  `CREATE TABLE`); no Python revisions exist, so migrations are manual for now.
- Auth DB models are bootstrap stubs (id/timestamps only); full columns live in
  `auth_schema.sql` and need porting to match.
- Endpoint business logic is partially placeholder (`get_current_user` returns a
  stub user; `check_rate_limit` always True; MFA/device flows need DB + Redis).
- Frontend feature pages (dashboard widgets, chat/inbox UIs, `DashboardLayout`)
  are placeholders: their modules reference files that don't exist yet
  (`useWidgetSettings`, `widgets/*`, `store/*`, `deviceIdentity`). `npm run build`
  is green because the boot path (`main.tsx` -> `App.tsx` -> `useAuth`) only
  imports existing modules. `sanitize.ts` pulls `jsdom` (node-only) — it is not
  in the boot path; do not import it into browser code without replacing jsdom.
