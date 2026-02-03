# Components to Test

This list covers the concrete components in this repo (backend, frontend, and infrastructure).

## Backend

### API routes (integration tests)
- [x] `backend/src/api/routes/health.py`
- [x] `backend/src/api/routes/bugs.py`
- [x] `backend/src/api/routes/scans.py`
- [x] `backend/src/api/routes/repositories.py`
- [x] `backend/src/api/routes/chat.py`
- [x] `backend/src/api/routes/demo.py`
- [x] `backend/src/api/routes/profile.py`
- [x] `backend/src/api/routes/webhooks.py`

### Models and schemas (unit tests)
- [x] `backend/src/models/base.py`
- [x] `backend/src/models/bug.py`
- [x] `backend/src/models/scan.py`
- [x] `backend/src/models/finding.py`
- [x] `backend/src/models/repository.py`
- [x] `backend/src/models/user_settings.py`
- [x] `backend/src/schemas/bug.py`
- [x] `backend/src/schemas/scan.py`
- [x] `backend/src/schemas/finding.py`
- [x] `backend/src/schemas/repository.py`
- [x] `backend/src/schemas/chat.py`
- [x] `backend/src/schemas/demo.py`
- [x] `backend/src/schemas/profile.py`

### Scanner pipeline (unit + integration tests)
- [x] `backend/src/services/scanner/repo_fetcher.py`
- [x] `backend/src/services/scanner/semgrep_runner.py`
- [x] `backend/src/services/scanner/context_extractor.py`
- [x] `backend/src/services/scanner/ai_triage.py`
- [x] `backend/src/services/scanner/finding_aggregator.py`
- [x] `backend/src/services/scanner/correlation.py`
- [x] `backend/src/services/scanner/reachability_analyzer.py`
- [x] `backend/src/services/scanner/dependency_health_scanner.py`
- [x] `backend/src/services/scanner/dependency_scanner.py`
- [x] `backend/src/services/scanner/dast_runner.py`
- [x] `backend/src/services/scanner/scan_pipeline.py`
- [x] `backend/src/services/scanner/types.py`

### Bug triage services (unit tests)
- [x] `backend/src/services/bug_triage/classifier.py`
- [x] `backend/src/services/bug_triage/duplicate_detector.py`
- [x] `backend/src/services/bug_triage/auto_router.py`
- [x] `backend/src/services/bug_triage/bug_correlation.py`

### Intelligence and reports (unit tests)
- [x] `backend/src/services/intelligence/llm_service.py`
- [x] `backend/src/services/reports/scan_report.py`
- [x] `backend/src/services/reports/report_insights.py`

### Integrations (contract tests with mocks)
- [x] `backend/src/integrations/github_client.py`
- [x] `backend/src/integrations/github_webhook.py`
- [x] `backend/src/integrations/github_webhook_sync.py`
- [x] `backend/src/integrations/github_ingestor.py`
- [x] `backend/src/integrations/github_backfill.py`
- [x] `backend/src/integrations/pinecone_client.py`

### Realtime, config, and storage (unit + integration tests)
- [x] `backend/src/realtime.py`
- [x] `backend/src/config.py`
- [x] `backend/src/services/storage.py`
- [x] `backend/src/db/session.py`
- [x] `backend/src/db/seed.py`
- [x] `backend/alembic/` (migrations and env)

## Frontend

### Pages (UI and routing)
- [ ] `frontend/src/pages/Dashboard.tsx`
- [ ] `frontend/src/pages/Scans.tsx`
- [ ] `frontend/src/pages/ScanDetail.tsx`
- [ ] `frontend/src/pages/Bugs.tsx`
- [ ] `frontend/src/pages/BugDetail.tsx`
- [ ] `frontend/src/pages/Repositories.tsx`
- [ ] `frontend/src/pages/Chat.tsx`
- [ ] `frontend/src/pages/Login.tsx`
- [ ] `frontend/src/pages/Register.tsx`
- [ ] `frontend/src/pages/Profile.tsx`
- [ ] `frontend/src/pages/Settings.tsx`

### Components (unit + visual tests)
- [ ] `frontend/src/components/FindingCard.tsx`
- [ ] `frontend/src/components/dashboard/BugQueue.tsx`
- [ ] `frontend/src/components/dashboard/StatsCard.tsx`
- [ ] `frontend/src/components/layout/Layout.tsx`
- [ ] `frontend/src/components/auth/RequireAuth.tsx`
- [ ] `frontend/src/components/realtime/RealtimeListener.tsx`
- [ ] `frontend/src/components/realtime/RealtimeStatus.tsx`

### API layer and hooks (contract tests)
- [ ] `frontend/src/api/client.ts`
- [ ] `frontend/src/api/bugs.ts`
- [ ] `frontend/src/api/scans.ts`
- [ ] `frontend/src/api/repositories.ts`
- [ ] `frontend/src/api/chat.ts`
- [ ] `frontend/src/api/demo.ts`
- [ ] `frontend/src/api/profile.ts`
- [ ] `frontend/src/hooks/useWebSocket.ts`
- [ ] `frontend/src/hooks/useAuth.tsx`

### App shell and shared types
- [ ] `frontend/src/App.tsx`
- [ ] `frontend/src/main.tsx`
- [ ] `frontend/src/types/index.ts`
- [ ] `frontend/src/lib/supabase.ts`
- [ ] `frontend/src/index.css`
- [ ] `frontend/src/App.css`

## Infrastructure and external dependencies
- [ ] `docker-compose.yml` (service wiring and env)
- [ ] `backend/.env.example` and `frontend/.env.example` (required variables)
- [ ] External tools and services used by the code: Semgrep, Nuclei, Trivy, LLM provider, Pinecone, GitHub webhooks.

## Current Test Coverage Map

### API routes (integration)
- `backend/src/api/routes/bugs.py` -> `backend/tests/integration/test_bugs_api.py`
- `backend/src/api/routes/scans.py` -> `backend/tests/integration/test_scans_api.py`
- `backend/src/api/routes/chat.py` -> `backend/tests/integration/test_chat_api.py`
- `backend/src/api/routes/demo.py` -> `backend/tests/integration/test_demo_api.py`
- `backend/src/api/routes/health.py` -> `backend/tests/integration/test_health_endpoints.py`
- `backend/src/api/routes/repositories.py` -> `backend/tests/integration/test_repositories_api.py`
- `backend/src/api/routes/profile.py` -> `backend/tests/integration/test_profile_api.py`
- `backend/src/api/routes/webhooks.py` -> `backend/tests/integration/test_github_webhook_api.py`, `backend/tests/integration/test_scan_webhook_api.py`

### Models and schemas (exercised via API/integration)
- `backend/src/models/bug.py` -> `backend/tests/integration/test_bugs_api.py`, `backend/tests/integration/test_chat_api.py`, `backend/tests/integration/test_github_webhook_api.py`
- `backend/src/models/scan.py` -> `backend/tests/integration/test_scans_api.py`, `backend/tests/integration/test_scan_webhook_api.py`
- `backend/src/models/finding.py` -> `backend/tests/integration/test_scans_api.py`
- `backend/src/models/repository.py` -> `backend/tests/integration/test_github_webhook_api.py`, `backend/tests/integration/test_scan_webhook_api.py`, `backend/tests/integration/test_repositories_api.py`
- `backend/src/models/user_settings.py` -> `backend/tests/integration/test_profile_api.py`
- `backend/src/schemas/bug.py` -> `backend/tests/integration/test_bugs_api.py`
- `backend/src/schemas/scan.py` -> `backend/tests/integration/test_scans_api.py`
- `backend/src/schemas/finding.py` -> `backend/tests/integration/test_scans_api.py`
- `backend/src/schemas/repository.py` -> `backend/tests/integration/test_repositories_api.py`
- `backend/src/schemas/chat.py` -> `backend/tests/integration/test_chat_api.py`
- `backend/src/schemas/demo.py` -> `backend/tests/integration/test_demo_api.py`
- `backend/src/schemas/profile.py` -> `backend/tests/integration/test_profile_api.py`

### Scanner pipeline (unit)
- `backend/src/services/scanner/repo_fetcher.py` -> `backend/tests/unit/test_repo_fetcher.py`
- `backend/src/services/scanner/semgrep_runner.py` -> `backend/tests/unit/test_semgrep_runner.py`
- `backend/src/services/scanner/context_extractor.py` -> `backend/tests/unit/test_context_extractor.py`
- `backend/src/services/scanner/ai_triage.py` -> `backend/tests/unit/test_ai_triage.py`
- `backend/src/services/scanner/finding_aggregator.py` -> `backend/tests/unit/test_finding_aggregator.py`
- `backend/src/services/scanner/reachability_analyzer.py` -> `backend/tests/unit/test_reachability_analyzer.py`
- `backend/src/services/scanner/correlation.py` -> `backend/tests/unit/test_scanner_correlation.py`
- `backend/src/services/scanner/dependency_health_scanner.py` -> `backend/tests/unit/test_dependency_health_scanner.py`
- `backend/src/services/scanner/dependency_scanner.py` -> `backend/tests/unit/test_dependency_scanner.py`
- `backend/src/services/scanner/dast_runner.py` -> `backend/tests/unit/test_dast_runner.py`
- `backend/src/services/scanner/scan_pipeline.py` -> `backend/tests/unit/test_scan_pipeline.py`
- `backend/src/services/scanner/types.py` -> `backend/tests/unit/test_scanner_correlation.py`

### Bug triage services (unit)
- `backend/src/services/bug_triage/classifier.py` -> `backend/tests/unit/test_classifier.py`
- `backend/src/services/bug_triage/duplicate_detector.py` -> `backend/tests/unit/test_duplicate_detector.py`
- `backend/src/services/bug_triage/auto_router.py` -> `backend/tests/unit/test_auto_router.py`
- `backend/src/services/bug_triage/bug_correlation.py` -> `backend/tests/unit/test_bug_correlation.py`

### Intelligence and integrations (unit)
- `backend/src/services/intelligence/llm_service.py` -> `backend/tests/unit/test_llm_service.py`
- `backend/src/integrations/github_client.py` -> `backend/tests/unit/test_github_client.py`
- `backend/src/integrations/github_webhook.py` -> `backend/tests/unit/test_github_webhook.py`
- `backend/src/integrations/github_ingestor.py` -> `backend/tests/integration/test_github_webhook_api.py`
- `backend/src/integrations/github_webhook_sync.py` -> `backend/tests/unit/test_github_webhook_sync.py`
- `backend/src/integrations/github_backfill.py` -> `backend/tests/unit/test_github_backfill.py`
- `backend/src/integrations/pinecone_client.py` -> `backend/tests/unit/test_pinecone_client.py`

### Realtime, config, and storage (unit)
- `backend/src/realtime.py` -> `backend/tests/unit/test_realtime.py`
- `backend/src/config.py` -> `backend/tests/unit/test_config.py`
- `backend/src/services/storage.py` -> `backend/tests/unit/test_storage.py`
- `backend/src/db/session.py` -> `backend/tests/unit/test_db_session.py`
- `backend/src/db/seed.py` -> `backend/tests/unit/test_db_seed.py`
- `backend/alembic/` -> `backend/tests/unit/test_alembic_smoke.py`

### Reports (unit)
- `backend/src/services/reports/scan_report.py` -> `backend/tests/unit/test_scan_report.py`
- `backend/src/services/reports/report_insights.py` -> `backend/tests/unit/test_report_insights.py`

### Models (unit)
- `backend/src/models/base.py` -> `backend/tests/unit/test_models_base.py`

## Gaps (No Direct Tests Yet)

### Backend API routes
- None

### Models and schemas
- None

### Scanner pipeline
- None

### Integrations, realtime, and storage
- None

### Reports
- None

### Frontend
- All `frontend/src/pages/*`
- All `frontend/src/components/*`
- All `frontend/src/api/*` and `frontend/src/hooks/*`
- `frontend/src/App.tsx`, `frontend/src/main.tsx`
