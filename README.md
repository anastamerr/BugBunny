# ScanGuard AI

ScanGuard AI is a context-aware static analysis platform that runs Semgrep and uses LLM triage to reduce false positives, adjust severity, and prioritize exploitable findings. It combines a FastAPI backend, a React dashboard, and optional dynamic and dependency scanning to provide actionable security insights.

## Highlights
- Semgrep-based SAST with language detection (Python, JS/TS, Go, Java) and local Semgrep configs.
- Context extraction (function/class scope, test/generated detection) plus reachability heuristics.
- LLM triage (OpenRouter or Ollama) to mark false positives and explain exploitability.
- Prioritization and semantic deduplication (Pinecone optional).
- Auto-fix previews and GitHub PRs for eligible high-confidence SAST findings.
- Optional DAST with Nuclei and correlation against SAST findings.
- Dependency CVE scanning via Trivy and dependency health checks from registries.
- Real-time scan updates over Socket.IO and optional PDF scan reports.

## How it works
1. Clone the repository and detect languages.
2. Run Semgrep and parse findings.
3. Extract code context and reachability signals.
4. Use the LLM to triage findings and adjust severity.
5. Filter, dedupe, and prioritize results.
6. Optionally run DAST and dependency scans, then correlate results.

## Architecture
- Backend: FastAPI, SQLAlchemy, Alembic, PostgreSQL, Redis, Socket.IO.
- Frontend: React 18, TypeScript, Vite, Tailwind, shadcn/ui, TanStack Query.
- AI and scanning: Semgrep, OpenRouter or Ollama, Pinecone (optional), Nuclei (optional), Trivy (optional).

## Repo layout
- backend/ - API, scanning pipeline, models, migrations, and integrations.
- frontend/ - React UI dashboard.
- docs/ - setup notes and proposal.
- demo/ - demo assets and fixtures.
- manual.md - runbook for local and demo setup.
- docker-compose.yml - full stack dev environment.

## Prerequisites
- Python 3.x
- Node.js and npm
- Git
- PostgreSQL and Redis (or Docker Compose)
- Semgrep CLI (installed with backend requirements)
- Optional tools: Nuclei (DAST) and Trivy (dependency CVEs)
- Optional services: Supabase (auth + storage), Pinecone, OpenRouter or Ollama

## Configuration
Backend env file: `backend/.env` (start from `backend/.env.example`).
Frontend env file: `frontend/.env` (set `VITE_API_URL`, `VITE_SUPABASE_URL`, `VITE_SUPABASE_ANON_KEY`).

Minimum backend variables:
- `DATABASE_URL`
- `SUPABASE_JWT_SECRET` (and optional `SUPABASE_JWT_ISSUER`)
- LLM provider config (`OPEN_ROUTER_API_KEY` or `OLLAMA_HOST`)
- `GITHUB_TOKEN` for private repo scans

Optional backend variables include:
- `PINECONE_API_KEY`, `PINECONE_ENVIRONMENT`
- `SUPABASE_URL`, `SUPABASE_SERVICE_KEY` (PDF reports)
- `NUCLEI_*` and `DAST_ALLOWED_HOSTS`
- `SCAN_MAX_ACTIVE`, `SCAN_MIN_INTERVAL_SECONDS`

## Local development (PowerShell example)
Backend:
```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\python -m pip install -r requirements.txt
Copy-Item .env.example .env
.\.venv\Scripts\python -m alembic upgrade head
.\.venv\Scripts\python -m uvicorn src.main:asgi_app --port 8000
```

Frontend:
```powershell
cd frontend
npm install
npm run dev -- --port 3000
```

## Trigger a scan
```powershell
curl -X POST http://localhost:8000/api/scans `
  -H "Authorization: Bearer <SUPABASE_JWT>" `
  -H "Content-Type: application/json" `
  -d '{"repo_url":"https://github.com/OWASP/WebGoat","branch":"main"}'
```

## Docker
```powershell
docker compose up --build
```

## API overview
- `GET /api/health`
- `POST /api/scans`
- `GET /api/scans`
- `GET /api/scans/{id}`
- `GET /api/scans/{id}/findings`
- `GET /api/findings`
- `PATCH /api/findings/{id}`
- `POST /api/findings/{id}/autofix`
- `GET /api/scans/{id}/report`
- `POST /api/webhooks/github`
- `POST /api/chat`
- `GET /api/bugs`

Auth: All routes except `/api/health` require `Authorization: Bearer <Supabase JWT>`.

## DAST safety notes
DAST scans require `scan_type` set to `dast` or `both`, a `target_url`, and `dast_consent=true`.
Targets must be public http(s) URLs; optional allowlisting via `DAST_ALLOWED_HOSTS`.

## Webhooks
Configure GitHub webhooks to send `push` and `pull_request` events to:
`/api/webhooks/github` with `GITHUB_WEBHOOK_SECRET` and a repo allowlist in `GITHUB_REPOS`.

## Docs
- `manual.md`
- `docs/setup.md`
