# BugBunny

BugBunny is a context-aware security scanning platform. It runs Semgrep for SAST, enriches findings with code context and LLM triage, then prioritizes what is actually exploitable. It ships with a FastAPI backend, a React dashboard, real-time scan updates, and optional dynamic and dependency scans.

**What It Does**
- Clones a repo, detects languages, and runs Semgrep rulesets.
- Extracts code context (scope, tests, generated code, imports) and reachability signals.
- Uses an LLM to classify false positives, adjust severity, and explain exploitability.
- Deduplicates and prioritizes findings, with optional semantic similarity via Pinecone.
- Optionally verifies SAST with DAST (OWASP ZAP) and scans dependencies with Trivy.
- Provides a dashboard, API, webhooks, and auto-fix previews/PRs for eligible findings.

**How It Works**
1. Clone repo and detect languages.
2. Run Semgrep and parse raw findings.
3. Extract code context around each finding.
4. LLM triage to flag false positives and re-score severity.
5. Filter, dedupe, and rank findings.
6. Optional DAST verification and dependency scanning.
7. Publish results to the dashboard and API with live progress updates.

**Core Features**
- SAST with Semgrep and language detection for Python, JS/TS, Go, and Java.
- Context extraction: function/class scope, test/generated file detection, imports.
- LLM-powered triage using OpenRouter or Ollama.
- Finding prioritization with optional Pinecone-backed dedupe.
- DAST verification via OWASP ZAP in Docker, including targeted verification of SAST findings.
- Dependency CVE scanning with Trivy.
- Auto-fix previews and GitHub PR creation for supported findings.
- Real-time scan status via Socket.IO.
- GitHub webhooks to trigger scans on push and PR events.

**Architecture**
- Backend: FastAPI, SQLAlchemy, Alembic, PostgreSQL, Redis, Socket.IO.
- Frontend: React 18, TypeScript, Vite, Tailwind CSS, shadcn/ui, TanStack Query.
- Scanning: Semgrep, OWASP ZAP (DAST), Trivy (dependencies).
- AI: OpenRouter or Ollama, optional Pinecone for semantic grouping.

**Repo Layout**
- backend/ API, scan pipeline, models, migrations, integrations.
- frontend/ React UI dashboard.
- docs/ Setup notes and references.
- demo/ Demo fixtures and sample data.
- scripts/ Helper scripts for dev and demo.
- manual.md Runbook for local and demo setup.

**Quickstart (Local Dev)**
Backend:
```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\python -m pip install -r requirements.txt
Copy-Item .env.example .env
.\.venv\Scripts\python -m alembic upgrade head
.\.venv\Scripts\python -m uvicorn src.main:asgi_app --port 8000
```
Note: use `asgi_app` to serve Socket.IO at `/ws`.

Frontend:
```powershell
cd frontend
npm install
npm run dev -- --port 3000
```

**Configuration**
Backend env file: `backend/.env` (start from `backend/.env.example`).
Frontend env file: `frontend/.env`.

Minimum backend variables:
- `DATABASE_URL`
- `SUPABASE_JWT_SECRET`
- LLM provider config (`OPEN_ROUTER_API_KEY` or `OLLAMA_HOST`)
- `GITHUB_TOKEN` for private repo scans

Optional backend variables:
- `PINECONE_API_KEY`, `PINECONE_ENVIRONMENT`
- `SUPABASE_URL`, `SUPABASE_SERVICE_KEY` (PDF reports)
- `ZAP_*` and `DAST_ALLOWED_HOSTS`
- `DEV_AUTH_BYPASS`, `DEV_AUTH_USER_ID`, `DEV_AUTH_EMAIL` (local dev only)
- `SCAN_MAX_ACTIVE`, `SCAN_MIN_INTERVAL_SECONDS`

Frontend variables:
- `VITE_API_URL`
- `VITE_SUPABASE_URL`
- `VITE_SUPABASE_ANON_KEY`
- `VITE_DEV_AUTH_BYPASS` (local dev only)

**Trigger a Scan**
```powershell
curl -X POST http://localhost:8000/api/scans `
  -H "Authorization: Bearer <SUPABASE_JWT>" `
  -H "Content-Type: application/json" `
  -d '{"repo_url":"https://github.com/OWASP/WebGoat","branch":"main"}'
```

**Scan Types**
- `sast` runs Semgrep + LLM triage.
- `dast` runs OWASP ZAP against a live target URL.
- `both` runs SAST and verifies findings with targeted DAST when possible.

DAST scans require `dast_consent=true` and a `target_url`. Targets must be public HTTP(S) URLs and can be restricted via `DAST_ALLOWED_HOSTS`.

**API Overview**
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

**DAST Notes**
- DAST uses OWASP ZAP in Docker. Ensure a working Docker daemon.
- You can attach to an existing ZAP daemon with `ZAP_BASE_URL`.
- For local targets, use `http://host.docker.internal:<port>`.

**Legacy Bug Triage**
The repo includes a legacy bug intake and LLM triage system (`/api/bugs` and `/api/chat`). It can be used alongside scans, but the primary focus is the scan pipeline described above.

**Docs**
- `manual.md`
- `docs/setup.md`
