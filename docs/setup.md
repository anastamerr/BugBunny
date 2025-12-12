# DataBug AI Setup (Supabase + GitHub + ngrok)

## 1) Backend env (`backend/.env`)

Required:
- `DATABASE_URL` (Supabase Postgres connection string; include `sslmode=require`)
  - If `db.<project-ref>.supabase.co` fails to resolve/connect (common on IPv4-only networks), use the **Connection pooling (Session)** URL instead:
    - `postgres://<db-user>.<project-ref>:<password>@aws-1-<region>.pooler.supabase.com:5432/postgres?sslmode=require`
- `PINECONE_API_KEY`, `PINECONE_ENVIRONMENT`
- `GITHUB_TOKEN` (PAT for backfill/sync)
- `GITHUB_WEBHOOK_SECRET`
- `GITHUB_REPOS` (comma-separated, e.g. `anastamerr/Quantumflow`)

Optional:
- `GITHUB_BACKFILL_LIMIT` (default `50`)
- `GITHUB_BACKFILL_ON_START` (default `false`)
- LLM (pick one):
  - Local Ollama: `OLLAMA_HOST` (default `http://ollama:11434`), optional `OLLAMA_MODEL`
  - OpenRouter: `OPEN_ROUTER_API_KEY` (if set, backend uses OpenRouter by default), optional `OPEN_ROUTER_MODEL`

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

GitHub repo → **Settings → Webhooks → Add webhook**
- Payload URL: `https://<ngrok-host>/api/webhooks/github`
- Content type: `application/json`
- Secret: your `GITHUB_WEBHOOK_SECRET`
- Events: enable **Issues** (optional: **Issue comments**)

## 5) Initial backfill (recommended)

Pull the latest issues from the configured repos and ingest them into the DB:
```bash
cd backend
python -m src.integrations.github_backfill
```
