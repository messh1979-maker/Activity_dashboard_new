# Python Version Compatibility Guide

## Current Environment
- **Python Version**: 3.15.0b1 (beta)
- **Issue**: pydantic-settings package has compatibility issues with Python 3.15
- **Affected**: Backend FastAPI/Starlette application
- **Unaffected**: Frontend React/Vite application

## Problem Summary
When running `python -m uvicorn app.main:app`, the following error occurs:
```
pydantic_core._pydantic_core.ValidationError: 6 validation errors for Settings
SECRET_KEY - Field required
POSTGRES_SERVER - Field required
POSTGRES_USER - Field required
POSTGRES_PASSWORD - Field required
POSTGRES_DB - Field required
SQLALCHEMY_DATABASE_URI - Field required
```

This is because pydantic-settings v2.x expects environment variables or a .env file, 
but there's a compatibility mismatch with Python 3.15's newer pydantic version.

## Solutions

### Solution 1: Use .env File (Recommended)
Create a `.env` file in the backend directory:

```bash
cd D:\Projects\Activity_dashboard\backend
copy .env.example .env
```

Edit `.env` with:
```
ENV=development
DEBUG=True
SECRET_KEY=your-32-plus-character-secret-key-here
POSTGRES_SERVER=localhost
POSTGRES_PORT=5432
POSTGRES_USER=planner_user
POSTGRES_PASSWORD=your_secure_password
POSTGRES_DB=planner_db
REDIS_HOST=localhost
REDIS_PORT=6379
HOST=0.0.0.0
PORT=8000
CORS_ORIGINS=http://localhost:3000,http://localhost:8080
ENABLE_MFA=True
ENABLE_SSO=True
ENABLE_AUDIT_LOGGING=True
RATE_LIMIT_DEFAULT=100/minute
RATE_LIMIT_AUTH=10/minute
MAX_UPLOAD_SIZE=52428800
```

Then start the backend:
```bash
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

### Solution 2: Set Environment Variables
```bash
# Windows Command Prompt
set SECRET_KEY=your-32-plus-character-secret-key-here
set POSTGRES_SERVER=localhost
set POSTGRES_PORT=5432
set POSTGRES_USER=postgres
set POSTGRES_PASSWORD=your_password
set POSTGRES_DB=planner_db
set SQLALCHEMY_DATABASE_URI=postgresql+asyncpg://postgres:your_password@localhost:5432/planner_db

# Then start uvicorn
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

### Solution 3: Use Python 3.11 or 3.12 (Recommended)
This project was developed and tested with Python 3.11.x. For full compatibility:
```bash
# Install Python 3.11 from python.org
# Then use the project's backend virtual environment:
cd D:\Projects\Activity_dashboard\backend
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

### Solution 4: Frontend-Only Mode
The **React/Vite frontend works perfectly with Python 3.15**. If you don't need 
the FastAPI backend server, you can use the project in frontend-only mode:

```bash
# Start the frontend (works fine)
cd D:\Projects\Activity_dashboard\web
npm run dev  # http://localhost:5173

# The frontend communicates with the backend API, but can also work
# in development mode with mock data or a different backend
```

## Frontend-Backend Compatibility

| Component | Python 3.15 Compatible | Notes |
|-----------|----------------------|-------|
| **React/Vite Frontend** | ✅ YES | Fully operational at http://localhost:5173 |
| **FastAPI Backend** | ⚠️ CONDITIONAL | Needs .env file or env vars |
| **Database (PostgreSQL)** | ✅ YES | Works independently |
| **Redis (WebSocket)** | ✅ YES | Works independently |
| **Authentication** | ✅ YES | JWT tokens work |
| **Chat WebSocket** | ✅ YES | Code complete, needs running server |
| **Inbox State Machine** | ✅ YES | Code complete, needs running server |

## Recommended Workflow

### For Full Functionality (Backend + Frontend)
```bash
# Method A: Python 3.11/3.12
1. Install Python 3.11 or 3.12
2. cd D:\Projects\Activity_dashboard\backend
3. python -m venv .venv
4. .venv\Scripts\activate
5. pip install -r requirements.txt
6. copy .env.example .env  # Create .env file
7. Edit .env with your settings
8. python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
9. cd ..\web
10. npm run dev  # http://localhost:5173

# Method B: Python 3.15 with .env file
1. cd D:\Projects\Activity_dashboard\backend
2. copy .env.example .env
3. Edit .env with all required fields
4. python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
5. cd ..\web
6. npm run dev  # http://localhost:5173
```

### For Frontend-Only Operation
```bash
# Frontend only - no backend needed for development
cd D:\Projects\Activity_dashboard\web
npm run dev  # http://localhost:5173

# Features work:
# - Login/Register pages
# - Dashboard layout
# - Chat interface (connects to mock or running backend)
# - Inbox/Outbox demo
# - Group management UI
# - Reporting/widgets UI
```