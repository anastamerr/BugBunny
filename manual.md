# DataBug AI Manual (Runbook)

This file explains how to bring up the **backend + frontend** together for local development and for a demo.

## Prerequisites

- Windows PowerShell (examples below use PowerShell)
- Python installed (project currently tests with Python 3.x)
- Node.js + npm installed
- (Optional) Docker Desktop (if you want Docker-based services)

## 1) Configure env vars

### Backend env (`backend/.env`)

Create/update `backend/.env` (this file is gitignored). Minimum recommended:

- `DATABASE_URL` (Supabase Postgres, include `sslmode=require`)
- `REDIS_URL` (default in compose: `redis://redis:6379/0`)
- `PINECONE_API_KEY`, `PINECONE_ENVIRONMENT`
- GitHub ingestion:
  - `GITHUB_TOKEN`
  - `GITHUB_WEBHOOK_SECRET`
  - `GITHUB_REPOS` (comma-separated `owner/repo`)
- LLM (cloud via OpenRouter):
  - `OPEN_ROUTER_API_KEY`
  - `OPEN_ROUTER_MODEL` (example: `meta-llama/llama-3.1-8b-instruct`)

Reference template: `backend/.env.example` (or `.env.example`)

## 2) Database migrations (Supabase)

From `backend/`:

- If your network can’t resolve `db.<ref>.supabase.co` (IPv6-only), use the Supabase **Session Pooler** connection string.
- Optional: set `ALEMBIC_DATABASE_URL` (Session Pooler) while keeping `DATABASE_URL` for runtime.

```powershell
cd backend
.\.venv\Scripts\python -m alembic upgrade head
```

## 3) Start the backend (port 8000)

### Option A (local python, recommended)

```powershell
cd backend
.\.venv\Scripts\python -m uvicorn src.main:asgi_app --port 8000
```

Quick health check:

```powershell
irm http://localhost:8000/api/health
```

### Option B (Docker Compose backend)

If you want Docker-managed `redis` + `ollama` + `celery_worker` (and backend container):

```powershell
cd ..
docker compose up --build
```

Notes:
- In compose, backend reads env from `backend/.env` via `env_file`.
- `ollama` is optional if you're using OpenRouter.

## 4) Start the frontend (port 3000)

```powershell
cd frontend
npm install
npm run dev -- --port 3000
```

The frontend reads `VITE_API_URL` from `frontend/.env` (or defaults). For local backend:

- `VITE_API_URL=http://localhost:8000`

## 5) GitHub webhook + ngrok (real ingestion)

Expose the backend for GitHub webhooks:

```powershell
ngrok http 8000
```

### Dev helper: auto-fix webhook URL when ngrok changes

If your GitHub webhook is pointing to the **ngrok root** (`/`) or to an old ngrok URL, run:

```powershell
cd backend
.\.venv\Scripts\python -m src.integrations.github_webhook_sync
```

This will update any existing `ngrok-free.app` webhook URL to:
`https://<current-ngrok-host>/api/webhooks/github`
and trigger a GitHub ping for verification.

In your GitHub repo settings → Webhooks:
- Payload URL: `https://<ngrok-host>/api/webhooks/github`
- Content type: `application/json`
- Secret: your `GITHUB_WEBHOOK_SECRET`
- Events: enable **Issues** and **Issue comments**

You can also backfill existing issues into the DB:

```powershell
cd backend
.\.venv\Scripts\python -m src.integrations.github_backfill
```

## 6) Common checks

- Backend health: `GET /api/health`
- Bugs list: `GET /api/bugs`
- Predictions: `GET /api/predictions`
- Chat: `POST /api/chat` (uses OpenRouter if `OPEN_ROUTER_API_KEY` is set)

## Troubleshooting

- Supabase connection fails: use Supabase **Session Pooler** host and ensure `sslmode=require`.
- Alembic uses `db` host: set `DATABASE_URL` in `backend/.env` (see `backend/.env.example`).
- Supabase `db.<ref>.supabase.co` not resolvable: your network may be IPv4-only while the direct host is IPv6-only; switch to the Supabase **Connection pooling** DATABASE_URL (pooler host).
- Webhook 401: GitHub secret mismatch or backend `GITHUB_WEBHOOK_SECRET` not set.
- Frontend build errors (Tailwind): ensure `@tailwindcss/postcss` is installed and `frontend/postcss.config.js` uses it.
