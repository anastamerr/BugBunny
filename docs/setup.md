# ScanGuard AI Setup (Supabase + GitHub + ngrok)

## 1) Backend env (`backend/.env`)

Required:
- `DATABASE_URL` (Supabase Postgres connection string; include `sslmode=require`)
  - If `db.<project-ref>.supabase.co` fails to resolve/connect (common on IPv4-only networks), use the **Connection pooling (Session)** URL instead:
    - `postgres://<db-user>.<project-ref>:<password>@aws-1-<region>.pooler.supabase.com:5432/postgres?sslmode=require`
- `PINECONE_API_KEY`, `PINECONE_ENVIRONMENT`
- `GITHUB_TOKEN` (PAT for private repos and sync)
- `GITHUB_WEBHOOK_SECRET` (for scan triggers)
- `GITHUB_REPOS` (comma-separated allowlist, e.g. `owner/repo1,owner/repo2`)

Optional:
- `GITHUB_BACKFILL_LIMIT` (default `50`)
- `GITHUB_BACKFILL_ON_START` (default `false`)
- LLM (pick one):
  - Local Ollama: `OLLAMA_HOST` (default `http://ollama:11434`), optional `OLLAMA_MODEL`
  - OpenRouter: `OPEN_ROUTER_API_KEY` (if set, backend uses OpenRouter by default), optional `OPEN_ROUTER_MODEL`

Optional DAST settings:
- `DAST_ALLOWED_HOSTS` (comma-separated allowed host suffixes)
- `ZAP_DOCKER_IMAGE`, `ZAP_API_KEY`, `ZAP_TIMEOUT_SECONDS`
- `ZAP_REQUEST_TIMEOUT_SECONDS`, `ZAP_MAX_DEPTH`, `ZAP_SCAN_POLICY`
- `ZAP_BASE_URL`, `ZAP_HOST_PORT`, `ZAP_KEEPALIVE_SECONDS`, `ZAP_HOST_HEADER`
DAST runs OWASP ZAP in Docker; ensure Docker is available on the host.

Optional dev auth bypass:
- `DEV_AUTH_BYPASS` (true/false)
- `DEV_AUTH_USER_ID`, `DEV_AUTH_EMAIL`

Optional scan limits:
- `SCAN_MAX_ACTIVE`
- `SCAN_MIN_INTERVAL_SECONDS`

## 2) Run DB migrations (Supabase)

From `backend/`:
```bash
alembic upgrade head
```

## 3) Start services (local)

Backend (Socket.IO served on `/ws`):
```bash
cd backend
uvicorn src.main:asgi_app --reload --port 8000
```

Frontend:
```bash
cd frontend
npm install
npm run dev
```

## 4) Expose webhook via ngrok

ngrok requires an authtoken (create one in the ngrok dashboard):
```bash
ngrok config add-authtoken <YOUR_TOKEN>
```

```bash
ngrok http 8000
```

GitHub repo **Settings > Webhooks > Add webhook**
- Payload URL: `https://<ngrok-host>/api/webhooks/github`
- Content type: `application/json`
- Secret: your `GITHUB_WEBHOOK_SECRET`
- Events: enable **Push** and **Pull requests**
- Optional: enable **Issues** and **Issue comments** (legacy bug ingestion)

## 5) Trigger a scan (manual)

```bash
curl -X POST http://localhost:8000/api/scans \
  -H "Content-Type: application/json" \
  -d '{"repo_url": "https://github.com/OWASP/WebGoat", "branch": "main"}'
```

## 6) Initial backfill (optional)

Pull the latest issues from the configured repos and ingest them into the DB:
```bash
cd backend
python -m src.integrations.github_backfill
```

---

## Quickstart: Local DAST Testing Without Supabase

For local development and DAST testing without setting up Supabase authentication:

### Backend Configuration

Add to `backend/.env`:
```bash
# ⚠️ DEV-ONLY: DO NOT USE IN PRODUCTION
DEV_AUTH_BYPASS=true
DEV_AUTH_USER_ID=00000000-0000-0000-0000-000000000001
DEV_AUTH_EMAIL=dev@example.com

# Minimal database (use local PostgreSQL or Docker)
DATABASE_URL=postgresql://postgres:postgres@localhost:5432/scanguard

# Skip Pinecone for faster dev startup
SKIP_PINECONE=true

# Use OpenRouter for LLM (or set up local Ollama)
OPEN_ROUTER_API_KEY=your-key-here
```

### Frontend Configuration

Add to `frontend/.env`:
```bash
# ⚠️ DEV-ONLY: DO NOT USE IN PRODUCTION
VITE_DEV_AUTH_BYPASS=true

# Backend URL
VITE_API_URL=http://localhost:8000
```

### Quick Start Commands

```bash
# 1. Start backend
cd backend
uvicorn src.main:asgi_app --reload --port 8000

# 2. Start frontend (in separate terminal)
cd frontend
npm install
npm run dev

# 3. Access UI (no login required when DEV_AUTH_BYPASS=true)
open http://localhost:5173

# 4. Trigger a DAST scan
curl -X POST http://localhost:8000/api/scans \
  -H "Content-Type: application/json" \
  -d '{
    "repo_url": "https://github.com/juice-shop/juice-shop",
    "branch": "main",
    "scan_type": "both",
    "dast_consent": true
  }'
```

### Helper Script

For convenience, use the dev mode helper:
```bash
./scripts/dev_mode.sh
```

This will:
- Generate sample `.env` files if missing
- Print recommended dev-only environment variables
- Remind you these settings are for local development only

### Security Notes

**⚠️ CRITICAL:** `DEV_AUTH_BYPASS` completely disables authentication.
- **NEVER** set this in production, staging, or any publicly accessible environment
- **NEVER** commit `.env` files with this flag enabled
- Only use on your local machine for testing
- The flag is `false` by default for safety

### Troubleshooting

**"401 Unauthorized" errors:**
- Ensure `DEV_AUTH_BYPASS=true` in `backend/.env`
- Restart backend server after changing env vars
- Check backend logs for auth bypass confirmation

**Frontend shows login screen:**
- Ensure `VITE_DEV_AUTH_BYPASS=true` in `frontend/.env`
- Restart frontend dev server (`npm run dev`)
- Clear browser cache/local storage

**DAST scans fail:**
- Ensure Docker is running: `docker info`
- Check ZAP image is pulled: `docker pull ghcr.io/zaproxy/zaproxy:stable`
- For localhost targets, ZAP will automatically use `host.docker.internal`
