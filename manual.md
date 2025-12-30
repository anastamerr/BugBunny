# ScanGuard AI Manual (Runbook)

This file explains how to bring up the **backend + frontend** together for local development and for a demo of context-aware Semgrep scans.

## Prerequisites

- Windows PowerShell (examples below use PowerShell)
- Python installed (project currently tests with Python 3.x)
- Node.js + npm installed
- Git installed (required for repo cloning during scans)
- (Optional) Docker Desktop (if you want Docker-based services)

## 1) Configure env vars

### Backend env (`backend/.env`)

Create/update `backend/.env` (this file is gitignored). Minimum recommended:

- `DATABASE_URL` (Supabase Postgres, include `sslmode=require`)
- `REDIS_URL` (default in compose: `redis://redis:6379/0`)
- LLM (cloud via OpenRouter or local via Ollama):
  - `OPEN_ROUTER_API_KEY`
  - `OPEN_ROUTER_MODEL` (example: `meta-llama/llama-3.1-8b-instruct`)
- Pinecone (optional, used for dedupe):
  - `PINECONE_API_KEY`, `PINECONE_ENVIRONMENT`
- GitHub (for scans and webhooks):
  - `GITHUB_TOKEN` (required for private repos)
  - `GITHUB_WEBHOOK_SECRET`
  - `GITHUB_REPOS` (comma-separated `owner/repo` allowlist)

Reference template: `backend/.env.example` (or `.env.example`)

Optional DAST settings:
- `DAST_ALLOWED_HOSTS` (comma-separated allowed host suffixes)
- `NUCLEI_TEMPLATES_PATH`, `NUCLEI_SEVERITIES`, `NUCLEI_RATE_LIMIT`
- `NUCLEI_TAGS`, `NUCLEI_EXCLUDE_TAGS`, `NUCLEI_PROTOCOLS`
- `NUCLEI_REQUEST_TIMEOUT_SECONDS`

Optional scan limits:
- `SCAN_MAX_ACTIVE` (max in-flight scans per user)
- `SCAN_MIN_INTERVAL_SECONDS` (cooldown between scans)

## 2) Database migrations (Supabase)

From `backend/`:

- If your network can't resolve `db.<ref>.supabase.co` (IPv6-only), use the Supabase **Session Pooler** connection string.
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

## 5) GitHub webhook + ngrok (scan triggers)

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

In your GitHub repo settings > Webhooks:
- Payload URL: `https://<ngrok-host>/api/webhooks/github`
- Content type: `application/json`
- Secret: your `GITHUB_WEBHOOK_SECRET`
- Events: enable **Push** and **Pull requests**
- Optional: enable **Issues** and **Issue comments** for bug ingestion

## 6) Run a scan manually

```powershell
irm -Method Post http://localhost:8000/api/scans `
  -ContentType "application/json" `
  -Body '{"repo_url":"https://github.com/OWASP/WebGoat","branch":"main"}'
```

## 7) Common checks

- Backend health: `GET /api/health`
- Scans: `GET /api/scans`
- Scan findings: `GET /api/scans/{id}/findings`
- Findings list: `GET /api/findings`
- Bugs list (legacy): `GET /api/bugs`
- Chat: `POST /api/chat`

## 8) Auto-fix previews + PRs

Auto-fix requires a GitHub token with repo access (set in Profile or backend env).

Preview a patch:

```powershell
irm -Method Post http://localhost:8000/api/findings/<finding_id>/autofix `
  -ContentType "application/json" `
  -Body '{\"create_pr\": false}'
```

Open a PR:

```powershell
irm -Method Post http://localhost:8000/api/findings/<finding_id>/autofix `
  -ContentType "application/json" `
  -Body '{\"create_pr\": true}'
```

## Troubleshooting

- Semgrep not found: install dependencies via `pip install -r backend/requirements.txt` or use Docker.
- Git clone fails: ensure `GITHUB_TOKEN` has access to private repos.
- Supabase connection fails: use Supabase **Session Pooler** host and ensure `sslmode=require`.
- Alembic uses `db` host: set `DATABASE_URL` in `backend/.env` (see `backend/.env.example`).
- Supabase `db.<ref>.supabase.co` not resolvable: your network may be IPv4-only while the direct host is IPv6-only; switch to the Supabase **Connection pooling** DATABASE_URL (pooler host).
- Webhook 401: GitHub secret mismatch or backend `GITHUB_WEBHOOK_SECRET` not set.
- Frontend build errors (Tailwind): ensure `@tailwindcss/postcss` is installed and `frontend/postcss.config.js` uses it.
