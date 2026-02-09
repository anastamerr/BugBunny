## BugBunny — Hackathon Pitch Deck (Concise Text Version)

**Validation note:** I attempted web verification, but the repo points to local/ngrok-style URLs (no stable public demo URL). Validation below is code-backed.
**Proof:** `/Users/mohamed/projects/DataBug/README.md:91`, `/Users/mohamed/projects/DataBug/frontend/.env.example:2`, `/Users/mohamed/projects/DataBug/docs/setup.md:70`

---

### 1) One-liner

BugBunny turns noisy security scans into an exploitability-ranked, fix-ready queue by combining Semgrep, AI triage, and runtime DAST verification in one workflow.

---

### 2) The Problem (pain + stakes)

* **Who suffers:** application teams, security engineers, platform teams buried in low-signal findings.
* **Why now:** repos move fast; static findings without runtime/context create triage bottlenecks.
* **What’s broken:** pattern-only scanners over-alert, under-prioritize exploitability, and force manual proof of what’s real.
  **Proof:** `ai_triage.py:111`, `finding_aggregator.py:83`, `scan_pipeline.py:514`

---

### 3) The Solution (what we built)

* **Multi-mode scans:** `sast`, `dast`, `both` from one UI/API trigger.
* **AI triage:** code context + reachability to reduce false positives and re-severity.
* **Runtime verification:** targeted DAST maps SAST findings to real endpoints and attempts exploit confirmation.
* **Dependency risk:** Trivy CVEs + dependency health (outdated/deprecated/yanked).
* **Action loop:** confirm/dismiss, PDF reports, contextual chat, one-click auto-fix/PR for eligible findings.

**How it works (plain language):**

1. Trigger scan (UI/API) → 2) clone + Semgrep → 3) enrich with context/reachability + AI reasoning →
2. optional DAST verification → 5) correlate + prioritize + realtime progress → 6) act (dashboard/chat/reports/autofix).
   **Proof:** `scans.py:99`, `scan_pipeline.py:45`, `Scans.tsx:891`

---

### 4) WOW Factors (prioritized)

**1) Exploitability-first hybrid pipeline**

* Runs SAST → AI triage → correlation → optional targeted/full DAST → dependency checks in one async pipeline.
* Value: faster MTTR, fewer wasted triage hours, clearer posture.
* **Proof:** `scan_pipeline.py:45/282/634`; UI: `Scans.tsx:541/571`, `ScanDetail.tsx:321` (live URL not publicly verifiable).

**2) Spider-first targeted DAST for SAST findings**

* Spider app, fuzzy-map findings to discovered endpoints/params, then run focused attacks per finding.
* Value: higher trust, lower false-positive cost, defensible prioritization.
* **Proof:** `targeted_dast_runner.py:105/305/630/1090`; UI: `FindingCard.tsx:244/422`, `ScanDetail.tsx:280`.

**3) Commit-aware runtime verification**

* Verifies deployment commit via `/.well-known/scanguard-version` before trusting DAST conclusions.
* Value: prevents “verified wrong build” failures; improves compliance/change-control integrity.
* **Proof:** `commit_verifier.py:23`, `scan_pipeline.py:370`, `scan.py:62`; UI: `ScanDetail.tsx:280/536`.

**4) Safe AutoFix with optional GitHub PR**

* Gated autofix with patch validation, single-file constraints, optional PR create/comments.
* Value: shorter fix cycle, less context switching, measurable productivity gain.
* **Proof:** `autofix_service.py:60/404/492`, `scans.py:579`; UI: `FindingCard.tsx:288/307/579`.

**5) Executive-ready PDF reporting with AI insights**

* Cached PDF: overview, risk stats, critical findings, trend chart, AI exec summary.
* Value: governance-ready output, audit trail, stakeholder communication.
* **Proof:** `scans.py:322`, `scan_report.py:102`, `report_insights.py:24`, `storage.py:24`; UI: `ScanDetail.tsx:214/674`.

---

### 5) Business Differentials (why we win)

| Differential                 | What alternatives miss | Why BugBunny wins                                                                                                                            |
| ---------------------------- | ---------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| SAST + AI + DAST correlation | Stop at one signal     | Correlates SAST with runtime evidence and reprioritizes. Proof: `correlation.py:9`, `scan_pipeline.py:514`                                   |
| Reachability-aware triage    | Severity inflation     | Reachability/entry points persisted and used in priority. Proof: `context_extractor.py:69`, `finding_aggregator.py:121`                      |
| Verification integrity       | Wrong deployment risk  | Commit verifier enforces build trust. Proof: `commit_verifier.py:23`                                                                         |
| Remediation loop included    | Findings backlog       | AutoFix preview/PR shortens detection→fix. Proof: `autofix_service.py:157`, `FindingCard.tsx:319`                                            |
| Workflow stickiness          | Weak retention         | Repo watchlists + webhooks + profile toggles + chat + reports. Proof: `repositories.py:18`, `webhooks.py:36`, `profile.py:29`, `chat.py:727` |

**Defensibility/moat**

* Project-memory embeddings with redaction + metadata filters. Proof: `project_memory.py:116/128`
* Multi-index semantic infra (bugs, patterns, project memory). Proof: `pinecone_client.py:47/63`

**Who pays and why (inference):**

* Buyers: security/platform leads shipping multiple repos/PRs.
* Reason: triage-hour savings, higher confidence, faster remediation loops.

---

### 6) Full Feature & Tool Catalog (complete coverage)

#### Authentication & Accounts

* Supabase email/password auth (`/login`, `/register`) → session/JWT; no SSO/reset in repo.
  **Code:** `Login.tsx:38`, `Register.tsx:23`, `AuthProvider.tsx:45`
* Route protection + redirect via `RequireAuth`; dev bypass can override.
  **Code:** `RequireAuth.tsx:22`, `App.tsx:30`
* Backend JWT verification (`Authorization: Bearer <token>`), requires `SUPABASE_JWT_SECRET` unless dev bypass.
  **Code:** `deps.py:32/66`
* Dev auth bypass via env flags (dev-only, risky in prod).
  **Code:** `deps.py:36`, `setup.md:103`
* Profile credential/settings management (`/profile`, `GET/PATCH /api/profile`), allowlist normalization, empty string clears secrets.
  **Code:** `profile.py:16/29`, `Profile.tsx:89`

#### Core Tools (pipeline + actions)

* Scan trigger/orchestration (`POST /api/scans` / Scans UI), active scan cap + interval limits.
  **Code:** `scans.py:99/131`, `scan_pipeline.py:45`
* Semgrep SAST for `sast/both` (requires Semgrep CLI).
  **Code:** `semgrep_runner.py:20/24`
* Repo clone + language detection (skips vendor/build, branch fallback).
  **Code:** `repo_fetcher.py:19/93`
* Context extraction: snippet/scope/imports/test/generated flags; safe fallback on missing files.
  **Code:** `context_extractor.py:30/142`
* Reachability analysis: reachability score/path; heuristic confidence varies by language.
  **Code:** `reachability_analyzer.py:90`, `context_extractor.py:69`
* AI triage engine: filters false positives + re-severity; LLM fallback.
  **Code:** `ai_triage.py:25/187`
* SAST endpoint metadata enrichment: endpoint/method/param mapping with route-parser fallback.
  **Code:** `sast_metadata.py:20`, `route_parser.py:21`
* Priority scoring + dedupe; Pinecone optional semantic dedupe.
  **Code:** `finding_aggregator.py:22/47`
* Targeted DAST for `both`: needs target/deploy; remote-target targeted DAST currently skipped.
  **Code:** `targeted_dast_runner.py:491`, `scan_pipeline.py:424`
* Full DAST for `dast`: requires ZAP availability; supports optional auth/cookies.
  **Code:** `dast_runner.py:27/35`
* Commit verifier: outputs `verified/commit_mismatch/verification_error`; requires `/.well-known/scanguard-version`.
  **Code:** `commit_verifier.py:23`
* Dependency CVE scan (Trivy): CVEs with CVSS; requires Trivy CLI.
  **Code:** `dependency_scanner.py:21/57`
* Dependency health: deprecated/outdated/yanked; external registry calls; optional LLM severity.
  **Code:** `dependency_health_scanner.py:50/320`
* Correlation layer (SAST↔DAST): correlated/unmatched sets; matching depends on endpoint/location signals.
  **Code:** `correlation.py:9`, `scan_pipeline.py:514`
* Finding lifecycle actions: confirm/dismiss (`PATCH /api/findings/{id}`), realtime event, auth-scoped.
  **Code:** `scans.py:555`, UI: `FindingCard.tsx:329`
* AutoFix preview + PR (`POST /api/findings/{id}/autofix`): gated by confidence/severity/file type/reachability.
  **Code:** `scans.py:579`, `autofix_service.py:282`, UI: `FindingCard.tsx:288`
* PDF report (`GET /api/scans/{id}/report`): cached; regen gated by cache deletion.
  **Code:** `scans.py:322/335/429`
* AI chat assistant: `/api/chat`, `/api/chat/stream`; fallback behavior if LLM unavailable.
  **Code:** `chat.py:423/727`, UI: `Chat.tsx:459`
* Demo injection (`POST /api/demo/inject-scan`): synthetic demo data, not real scan execution.
  **Code:** `demo.py:446`, UI: `Scans.tsx:1134`
* Scan policy gate (CI/CD): `/api/scans/{id}/policy` or CLI; severity threshold enum enforced.
  **Code:** `scans.py:651`, `scan_policy.py:77`, `cli/scan_policy.py:23`
* Legacy bug triage: `/api/bugs` + pages; coexists with scan-centric flow.
  **Code:** `bugs.py:57`, `classifier.py:49`, `auto_router.py:6`

#### Data/Storage

* `Scan` model (status/stats/history; enum fields). **Code:** `scan.py:20`
* `Finding` model (DAST/autofix/reachability; multiple enums). **Code:** `finding.py:21`
* Bug/repo/settings models; unique repo URL per user. **Code:** `bug.py:8`, `repository.py:13`, `user_settings.py:10`
* Supabase report storage cache (requires URL/service key). **Code:** `storage.py:15/24`
* Pinecone semantic indexes (requires API key/model). **Code:** `pinecone_client.py:29/63`
* Project memory with redaction; bounded limits. **Code:** `project_memory.py:15/124`

#### Integrations

* GitHub webhook verification/dispatch (`/api/webhooks/github`), secret required; filters/toggles apply.
  **Code:** `webhooks.py:36`, `github_webhook.py:8`
* Push/PR triggers; per-repo/user 60s rate limit. **Code:** `webhooks.py:91/129/274`
* Issue/comment ingestion; PR issues ignored here. **Code:** `webhooks.py:177`, `github_ingestor.py:80`
* GitHub backfill (CLI/startup). **Code:** `github_backfill.py:12`, `main.py:32`
* Webhook sync helper for ngrok URLs (dev). **Code:** `github_webhook_sync.py:45/192`
* Autofix PR/comment via GitHub token. **Code:** `autofix_service.py:492`, `github_client.py:72`
* LLM providers (OpenRouter/Ollama) abstraction. **Code:** `llm_service.py:49/114`
* OWASP ZAP integration (Docker or `ZAP_BASE_URL`). **Code:** `dast_runner.py:27`, `zap_client.py:95`
* Trivy integration. **Code:** `dependency_scanner.py:18`
* Socket.IO realtime via `/ws`. **Code:** `main.py:65`, UI: `RealtimeListener.tsx:32`, `useWebSocket.ts:25`

#### Admin/Settings

* Profile webhook controls + allowlist; per-event filtering. **Code:** `profile.py:29`, `webhooks.py:341`, UI: `Profile.tsx:183`
* DAST consent + target restrictions (blocks private/localhost unless allowlisted).
  **Code:** `scan.py:93/141`, UI: `Scans.tsx:596`
* Scan throttling (429). **Code:** `scans.py:131/147`
* Pause/resume (not for completed/failed). **Code:** `scans.py:265/292`, UI: `ScanDetail.tsx:147`
* Report cache management (download/delete; regen gated). **Code:** `scans.py:335/429`, UI: `ScanDetail.tsx:193`
* Settings shortcuts page only. **Code:** `Settings.tsx:37`

#### Observability

* Phase-level telemetry and realtime UI. **Code:** `scan_pipeline.py:72`, UI: `ScanDetail.tsx:321`
* Realtime invalidation via `RealtimeListener`. **Code:** `RealtimeListener.tsx:32`, `Layout.tsx:53`
* Completion logging; log transport not configured. **Code:** `scan_pipeline.py:775`
* API error toasts + auth expiry redirects; 401 → login. **Code:** `client.ts:57/60`
* Test anchors; not all integrations fully e2e.
  **Code:** `test_scans_api.py:36`, `test_github_webhook_api.py:13`, `ScanDetail.test.tsx:66`

---

### 7) Top 3 Demo Flows (judge-friendly)

**Flow 1: “87 alerts → 12 real issues” (under 2 minutes)**

* `/scans` → “Seed a pre-scanned repo...” → open scan card → show stats + grouped findings.
* Backup: `POST /api/demo/inject-scan`; show test evidence for default counts.
* **Proof:** UI `Scans.tsx:1134`; backend `demo.py schemas:31/32`; test `test_demo_api.py:53`

**Flow 2: “Runtime proof, not just static suspicion”**

* `/scans` choose `both` → set target URL + DAST consent (+ optional auth/cookies) → scan detail → show verification badges + evidence/curl in finding card.
* Backup: seeded demo scan with DAST-labeled findings + evidence fields.
* **Proof:** UI `Scans.tsx:571/631`, `FindingCard.tsx:423`; backend `targeted_dast_runner.py:630`

**Flow 3: “Finding → patch → PR”**

* Open eligible finding → “Generate Fix” (patch preview) → “Open PR” (PR URL) → optional policy gate output.
* Backup: patch-only if PR fails (token/permissions).
* **Proof:** UI `FindingCard.tsx:288`; backend `autofix_service.py:157`; policy `scans.py:651`

---

### 8) Architecture Overview (simple but credible)

**Diagram-in-words**

1. React frontend triggers `/api/scans`
2. FastAPI persists `Scan`, starts async pipeline/thread
3. Pipeline: clone → Semgrep → context/reachability → LLM triage
4. Optional targeted/full DAST + dependency scans
5. Correlate + persist findings in Postgres
6. Realtime updates over Socket.IO `/ws`
7. Reports/chat/autofix use persisted findings + optional vector memory
   **Proof:** `main.py:50/65`, `scans.py:202`, `scan_pipeline.py:45`

**Key tech choices**

* FastAPI + SQLAlchemy
* Semgrep + ZAP + Trivy
* OpenRouter/Ollama abstraction
* Pinecone for semantic dedupe + project memory retrieval

**Security basics**

* JWT bearer auth guard
* GitHub webhook HMAC verification
* DAST target normalization/host restrictions + explicit consent
* AutoFix patch validation (single-file, bounded size, path checks)
  **Proof:** `deps.py:48`, `github_webhook.py:8`, `scan.py:93`, `autofix_service.py:404`

**Scalability notes**

* Async stages + batched triage (`TRIAGE_BATCH_SIZE=8`) + pause/resume
* Pinecone optional for lean local/dev
* Next lever: remote-target targeted DAST support (currently local-target focused for `both`)
  **Proof:** `scan_pipeline.py:38/838/928/424`

---

### 9) Metrics & Impact (estimates)

* Noise reduction: **~86%** (demo defaults: **87 → 12**, 75 false positives, 12 real issues). Proof: `demo.py schemas:31/32`
* Manual triage time saved: **~6.25 engineer-hours/scan** (75 FPs × ~5 min = 375 min).
* Prioritization lift: **High** (severity + confidence + exploitability + reachability + DAST confirmation). Proof: `finding_aggregator.py:83`
* Report turnaround: **minutes to seconds after completion** (cached PDF). Proof: `scans.py:322`
* Remediation cycle compression: **significant** for eligible findings (patch + optional PR). Proof: `scans.py:579`, `autofix_service.py:157`

---

### 10) What’s Next (roadmap)

1. Remote-target targeted DAST for `both` (currently skips remote targeted mode).
2. Org governance: RBAC, policy templates, approval workflows.
3. CI-native annotations: PR comments/check runs with deep links.
4. Broader autofix playbooks/languages.
5. Stronger trend analytics + SLA tracking.
6. Monetization (inference): tiers by repos/scan-minutes + premium modules (PR automation, compliance reporting, enterprise governance).
   **Proof for current gaps:** `scan_pipeline.py:424`, `autofix_service.py:226`

---

### 11) Appendix: Evidence Index (kept complete, compressed)

* **Claim → proof table:** unchanged in scope (API mounting, websocket path, scans/findings endpoints, policy, bugs, chat, webhooks, demo injection, pipeline, targeted DAST, commit verifier, autofix, reports, project memory, Pinecone, webhook verification, profile model).
* **Repo entry points:** UI routes (`/login`, `/register`, `/`, `/scans`, `/scans/:id`, `/repos`, `/profile`, `/bugs`, `/bugs/:id`, `/chat`, `/settings`) and API routes list remain complete as originally specified.
* **CLI commands + background jobs:** scan policy CLI, webhook sync, backfill, db seed; async pipeline thread launch, optional startup backfill, webhook-triggered scans, realtime emits remain complete as originally specified.
