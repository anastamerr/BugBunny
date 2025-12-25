# ScanGuard AI - Context-Aware Static Analysis Platform

## Vision

**ScanGuard AI** transforms static code analysis by combining Semgrep with LLM intelligence to eliminate false positives and properly prioritize security findings - solving the #1 pain point that wastes developer time.

**Core Innovation**: Run Semgrep, then use AI to understand code context and filter out noise. Developers see only real issues, ranked by actual exploitability.

---

## The Problem

Static analysis tools like Semgrep are powerful but noisy:

| Pain Point | Impact |
|------------|--------|
| **False Positive Flood** | 70-90% of findings are not real issues |
| **Alert Fatigue** | Developers ignore all findings due to noise |
| **Wrong Severity** | Tools mark everything as "critical" without context |
| **Wasted Time** | Hours spent investigating non-issues |
| **No Code Understanding** | Pattern matching without semantic awareness |

**Example**: Semgrep flags `eval(user_input)` as critical. But if `user_input` comes from a hardcoded config file, it's not exploitable. Traditional tools can't tell the difference.

---

## Our Solution: 4 Layers of Intelligence

```
┌─────────────────────────────────────────────────────────────────┐
│  Layer 1: SCAN          Semgrep static analysis                 │
│  - Multi-language support (Python, JS/TS, Go, Java, etc.)       │
│  - 2000+ security rules from Semgrep registry                   │
│  - Fast scanning (<60s for most repos)                          │
├─────────────────────────────────────────────────────────────────┤
│  Layer 2: CONTEXT       Code understanding                      │
│  - Extract ±20 lines around each finding                        │
│  - Identify function/class scope                                │
│  - Detect test files, generated code, vendored deps             │
│  - Trace data flow for exploitability analysis                  │
├─────────────────────────────────────────────────────────────────┤
│  Layer 3: TRIAGE        LLM-powered analysis                    │
│  - Analyze each finding with full code context                  │
│  - Determine: real issue vs false positive                      │
│  - Adjust severity based on exploitability                      │
│  - Generate human-readable reasoning                            │
├─────────────────────────────────────────────────────────────────┤
│  Layer 4: PRIORITIZE    Smart ranking                           │
│  - Group related findings (same root cause)                     │
│  - Deduplicate via semantic similarity                          │
│  - Rank by actual risk, not pattern match severity              │
│  - Present actionable fix recommendations                       │
└─────────────────────────────────────────────────────────────────┘
```

---

## Key Differentiators

| Capability | Semgrep Alone | ScanGuard AI |
|------------|---------------|--------------|
| Static code scanning | Yes | Yes |
| Multi-language support | Yes | Yes |
| False positive filtering | No | **Yes (AI-powered)** |
| Context-aware severity | No | **Yes** |
| Exploitability analysis | No | **Yes** |
| Human-readable reasoning | No | **Yes** |
| Smart deduplication | No | **Yes (Pinecone)** |
| Noise reduction | 0% | **70-90%** |

---

## Hackathon Track Alignment

### Primary: Track 1 - AI-Enhanced DevSecOps Pipeline
> "Reduce false positives in SAST/DAST scans, auto-prioritize vulnerabilities by exploitability"

**Our Approach**:
- Semgrep provides SAST scanning
- LLM filters false positives with code context
- AI assesses exploitability for each finding
- Results: 70%+ noise reduction

### Secondary: Track 4 - Bug Triage Automation
> "Build an AI assistant that sorts and prioritizes software bugs automatically"

**Our Approach**:
- Security findings treated as bugs
- AI classifies severity and assigns priority
- Semantic deduplication groups related issues
- Existing bug webhook integration for user reports

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        TRIGGER LAYER                            │
├─────────────────────┬───────────────────────────────────────────┤
│  GitHub Webhook     │  Manual API                               │
│  (push/PR events)   │  POST /api/scans {repo_url}               │
└─────────┬───────────┴───────────────────┬───────────────────────┘
          │                               │
          ▼                               ▼
┌─────────────────────────────────────────────────────────────────┐
│                      SCAN ORCHESTRATOR                          │
│  1. Clone repo to temp directory                                │
│  2. Detect languages (Python, JS, Go, etc.)                     │
│  3. Run Semgrep with appropriate rulesets                       │
│  4. Parse JSON output → raw findings                            │
└─────────────────────────────┬───────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                   AI TRIAGE ENGINE                              │
│  For each finding:                                              │
│  1. Extract code context (±20 lines)                            │
│  2. Send to LLM with security analysis prompt                   │
│  3. Receive: is_false_positive, adjusted_severity, reasoning    │
│  4. Filter and re-rank findings                                 │
└─────────────────────────────┬───────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                     DASHBOARD                                   │
│  - Scan history with noise reduction stats                      │
│  - Finding list: Semgrep severity vs AI severity                │
│  - AI reasoning for each finding                                │
│  - One-click confirm/dismiss actions                            │
└─────────────────────────────────────────────────────────────────┘
```

---

## Technology Stack

### Backend (FastAPI + Python)
| Component | Technology |
|-----------|------------|
| API Framework | FastAPI |
| Database | PostgreSQL + SQLAlchemy |
| Vector Search | Pinecone |
| Static Analysis | Semgrep CLI |
| LLM Provider | OpenRouter / Ollama |
| Real-time | Socket.IO |

### Frontend (React)
| Component | Technology |
|-----------|------------|
| Framework | React 18 + TypeScript |
| Build Tool | Vite |
| Styling | Tailwind CSS |
| Components | shadcn/ui |
| Data Fetching | TanStack Query |

### AI Stack
| Component | Purpose |
|-----------|---------|
| Semgrep | Static analysis engine |
| LLaMA 3 / GPT-4 | Context analysis & triage |
| Sentence-Transformers | Embeddings for deduplication |
| Pinecone | Vector similarity search |

---

## API Endpoints

### Scans
```
POST   /api/scans              # Trigger scan {repo_url, branch?}
GET    /api/scans              # List all scans with stats
GET    /api/scans/{id}         # Get scan details
GET    /api/scans/{id}/findings # Get findings for a scan
```

### Findings
```
GET    /api/findings           # List findings (filterable)
GET    /api/findings/{id}      # Get finding with context
PATCH  /api/findings/{id}      # Update status (confirm/dismiss)
```

### Webhooks
```
POST   /api/webhooks/github    # GitHub push/PR triggers scan
```

### Existing (Bug Triage)
```
POST   /api/bugs               # Manual bug submission
GET    /api/bugs               # List bugs
POST   /api/chat               # LLM triage assistant
```

---

## Demo Script (Hackathon Presentation)

### 1. The Problem (30 sec)
> "Static analysis tools flood developers with false positives. This repo has 87 'critical' findings from Semgrep. Are they all real? Let's find out."

### 2. Trigger Scan (1 min)
- Paste GitHub URL into dashboard
- Click "Scan Repository"
- Watch real-time progress: cloning → scanning → analyzing

### 3. AI Magic (1 min)
- Results appear: **87 raw findings → 12 real issues**
- Show stat: "75 false positives filtered (86% noise reduction)"
- Highlight severity adjustments: "32 'ERROR' downgraded to 'low'"

### 4. Deep Dive (1 min)
- Click on a filtered finding
- Show side-by-side: Semgrep said "ERROR" → AI said "false positive"
- Expand AI reasoning: "This SQL query uses parameterized inputs from ORM, making injection impossible"

### 5. Real Issue (30 sec)
- Show a confirmed critical finding
- AI reasoning: "User input flows directly to subprocess.call() with shell=True - command injection possible"
- Exploitability: "Attacker can execute arbitrary commands via the 'filename' parameter"

### 6. Impact (30 sec)
> "Developers now see 12 real issues instead of 87 false alarms. That's 86% less noise, faster fixes, and happier teams."

---

## Success Metrics

| Metric | Target |
|--------|--------|
| False positive reduction | >70% |
| Scan time (avg repo) | <60 seconds |
| Languages supported | 3+ (Python, JS, Go) |
| AI reasoning accuracy | >85% |
| Demo "wow factor" | Visible noise reduction |

---

## Implementation Roadmap

### Current State (What Exists)

The repo already has a working bug triage system:

| Component | Status | Location |
|-----------|--------|----------|
| FastAPI backend | Done | `backend/src/main.py` |
| PostgreSQL + SQLAlchemy | Done | `backend/src/models/` |
| BugReport model | Done | `backend/src/models/bug.py` |
| Bug classifier (ML) | Done | `backend/src/services/bug_triage/classifier.py` |
| Duplicate detector | Done | `backend/src/services/bug_triage/duplicate_detector.py` |
| Auto-router | Done | `backend/src/services/bug_triage/auto_router.py` |
| LLM service | Done | `backend/src/services/intelligence/llm_service.py` |
| Pinecone integration | Done | `backend/src/integrations/pinecone_client.py` |
| GitHub webhook | Done | `backend/src/api/routes/webhooks.py` |
| Chat API | Done | `backend/src/api/routes/chat.py` |
| React frontend | Done | `frontend/src/` |
| Socket.IO realtime | Done | Backend + Frontend |

---

### Milestone 1: Database Models & Schemas
**Goal**: Define data structures for scans and findings

| Task | File | Description |
|------|------|-------------|
| Create Scan model | `backend/src/models/scan.py` | SQLAlchemy model for scan jobs |
| Create Finding model | `backend/src/models/finding.py` | SQLAlchemy model for Semgrep findings |
| Export models | `backend/src/models/__init__.py` | Add Scan, Finding to exports |
| Create Scan schemas | `backend/src/schemas/scan.py` | Pydantic schemas for API |
| Create Finding schemas | `backend/src/schemas/finding.py` | Pydantic schemas for API |
| Export schemas | `backend/src/schemas/__init__.py` | Add new schemas to exports |
| Run migrations | Terminal | `alembic revision --autogenerate && alembic upgrade head` |

**Acceptance Criteria**:
- [ ] `Scan` model has: id, repo_url, branch, status, total_findings, filtered_findings
- [ ] `Finding` model has: id, scan_id, rule_id, semgrep_severity, ai_severity, is_false_positive, ai_reasoning
- [ ] Models linked via foreign key (Finding → Scan)
- [ ] Database migrations run without errors

---

### Milestone 2: Repository Fetcher
**Goal**: Clone GitHub repos for scanning

| Task | File | Description |
|------|------|-------------|
| Create scanner package | `backend/src/services/scanner/__init__.py` | Package init |
| Implement repo fetcher | `backend/src/services/scanner/repo_fetcher.py` | Clone repos to temp dir |

**Key Functions**:
```python
class RepoFetcher:
    async def clone(self, repo_url: str, branch: str = "main") -> Path:
        """Clone repo to temp directory, return path."""

    async def cleanup(self, repo_path: Path) -> None:
        """Delete cloned repo after scan."""

    def detect_languages(self, repo_path: Path) -> List[str]:
        """Detect languages by file extensions."""
```

**Acceptance Criteria**:
- [ ] Can clone public GitHub repos
- [ ] Can clone private repos (with GITHUB_TOKEN)
- [ ] Detects languages: Python (.py), JavaScript (.js/.ts), Go (.go)
- [ ] Cleans up temp directories after use
- [ ] Handles clone failures gracefully

---

### Milestone 3: Semgrep Runner
**Goal**: Execute Semgrep and parse results

| Task | File | Description |
|------|------|-------------|
| Implement Semgrep runner | `backend/src/services/scanner/semgrep_runner.py` | Run Semgrep CLI, parse JSON |

**Key Functions**:
```python
class SemgrepRunner:
    async def scan(self, repo_path: Path, languages: List[str]) -> List[RawFinding]:
        """Run Semgrep with auto config, return parsed findings."""

    def _get_rulesets(self, languages: List[str]) -> str:
        """Map languages to Semgrep rulesets (p/python, p/javascript, etc.)"""

    def _parse_results(self, json_output: dict) -> List[RawFinding]:
        """Parse Semgrep JSON into RawFinding objects."""
```

**RawFinding Schema**:
```python
class RawFinding:
    rule_id: str
    rule_message: str
    severity: str  # ERROR, WARNING, INFO
    file_path: str
    line_start: int
    line_end: int
    code_snippet: str
```

**Acceptance Criteria**:
- [ ] Runs `semgrep --config=auto --json` on repo
- [ ] Parses all findings from JSON output
- [ ] Handles Semgrep errors (not installed, timeout, etc.)
- [ ] Returns structured RawFinding objects

---

### Milestone 4: Context Extractor
**Goal**: Extract code context around findings

| Task | File | Description |
|------|------|-------------|
| Implement context extractor | `backend/src/services/scanner/context_extractor.py` | Get surrounding code |

**Key Functions**:
```python
class ContextExtractor:
    def extract(self, repo_path: Path, finding: RawFinding, context_lines: int = 20) -> CodeContext:
        """Extract ±20 lines around finding, identify function scope."""

    def _get_function_scope(self, lines: List[str], target_line: int) -> Optional[str]:
        """Find the function/method containing this line."""

    def _is_test_file(self, file_path: str) -> bool:
        """Check if file is a test (test_, _test.py, __tests__/)."""
```

**CodeContext Schema**:
```python
class CodeContext:
    snippet: str           # ±20 lines
    function_name: str     # Containing function
    class_name: str        # Containing class
    is_test_file: bool
    is_generated: bool     # Auto-generated code
    imports: List[str]     # File imports
```

**Acceptance Criteria**:
- [ ] Extracts 20 lines before and after finding
- [ ] Identifies containing function/method name
- [ ] Detects test files (test_, _test, __tests__)
- [ ] Detects generated files (auto-generated comments)
- [ ] Handles edge cases (start/end of file)

---

### Milestone 5: AI Triage Engine
**Goal**: Use LLM to filter false positives

| Task | File | Description |
|------|------|-------------|
| Implement AI triage | `backend/src/services/scanner/ai_triage.py` | LLM-powered analysis |

**Key Functions**:
```python
class AITriageEngine:
    async def triage_finding(self, finding: RawFinding, context: CodeContext) -> TriagedFinding:
        """Analyze finding with LLM, determine if false positive."""

    async def triage_batch(self, findings: List[Tuple[RawFinding, CodeContext]]) -> List[TriagedFinding]:
        """Batch process findings (with rate limiting)."""
```

**LLM Prompt Template**:
```
You are a security expert reviewing static analysis findings.

## Finding
- Rule: {rule_id}
- Message: {rule_message}
- Semgrep Severity: {severity}
- File: {file_path}:{line_start}

## Code Context
```{language}
{code_context}
```

## Task
Analyze this finding and respond in JSON:
{
  "is_false_positive": true/false,
  "adjusted_severity": "critical|high|medium|low|info",
  "confidence": 0.0-1.0,
  "reasoning": "Brief explanation",
  "exploitability": "How it could be exploited, or why not"
}

Consider:
- Is the vulnerable code actually reachable?
- Is there input validation elsewhere?
- Is this a test file or example code?
- Would exploitation require unlikely conditions?
```

**TriagedFinding Schema**:
```python
class TriagedFinding:
    # Original finding data
    rule_id: str
    file_path: str
    line_start: int
    code_snippet: str
    semgrep_severity: str

    # AI enrichment
    is_false_positive: bool
    ai_severity: str
    ai_confidence: float
    ai_reasoning: str
    exploitability: str
```

**Acceptance Criteria**:
- [ ] Sends finding + context to LLM
- [ ] Parses JSON response correctly
- [ ] Handles LLM errors/timeouts gracefully
- [ ] Rate limits API calls (avoid quota issues)
- [ ] Uses existing LLM service (OpenRouter/Ollama)

---

### Milestone 6: Finding Aggregator
**Goal**: Group, dedupe, and prioritize findings

| Task | File | Description |
|------|------|-------------|
| Implement aggregator | `backend/src/services/scanner/finding_aggregator.py` | Post-process findings |

**Key Functions**:
```python
class FindingAggregator:
    async def process(self, findings: List[TriagedFinding]) -> List[ProcessedFinding]:
        """Filter, group, dedupe, and rank findings."""

    def _filter_false_positives(self, findings: List[TriagedFinding]) -> List[TriagedFinding]:
        """Remove findings marked as false positives."""

    def _group_related(self, findings: List[TriagedFinding]) -> List[FindingGroup]:
        """Group findings by same rule + same file pattern."""

    async def _deduplicate(self, findings: List[TriagedFinding]) -> List[TriagedFinding]:
        """Use Pinecone to find semantic duplicates."""

    def _calculate_priority(self, finding: TriagedFinding) -> int:
        """Score 0-100 based on severity, confidence, exploitability."""
```

**Acceptance Criteria**:
- [ ] Filters out is_false_positive=True findings
- [ ] Groups findings with same rule_id in same file
- [ ] Uses Pinecone for semantic deduplication
- [ ] Ranks by priority score (critical+high confidence = top)
- [ ] Returns sorted list ready for display

---

### Milestone 7: Scan API Routes
**Goal**: REST endpoints to trigger and view scans

| Task | File | Description |
|------|------|-------------|
| Create scans router | `backend/src/api/routes/scans.py` | Scan endpoints |
| Register router | `backend/src/main.py` | Add to FastAPI app |

**Endpoints**:
```python
@router.post("/scans")
async def create_scan(request: ScanCreate) -> ScanRead:
    """Trigger a new scan. Runs async in background."""

@router.get("/scans")
async def list_scans() -> List[ScanRead]:
    """List all scans with stats."""

@router.get("/scans/{scan_id}")
async def get_scan(scan_id: UUID) -> ScanRead:
    """Get scan details."""

@router.get("/scans/{scan_id}/findings")
async def get_scan_findings(scan_id: UUID, include_false_positives: bool = False) -> List[FindingRead]:
    """Get findings for a scan."""

@router.patch("/findings/{finding_id}")
async def update_finding(finding_id: UUID, update: FindingUpdate) -> FindingRead:
    """Update finding status (confirm/dismiss)."""
```

**Background Task Flow**:
```python
async def run_scan_pipeline(scan_id: UUID, repo_url: str, branch: str):
    # 1. Update status: cloning
    # 2. Clone repo
    # 3. Update status: scanning
    # 4. Run Semgrep
    # 5. Update status: analyzing
    # 6. Extract context for each finding
    # 7. AI triage each finding
    # 8. Aggregate and store findings
    # 9. Update status: completed
    # 10. Emit Socket.IO event: scan.completed
```

**Acceptance Criteria**:
- [ ] POST /scans triggers background scan
- [ ] GET /scans returns list with stats
- [ ] GET /scans/{id}/findings returns filtered findings
- [ ] PATCH /findings/{id} updates status
- [ ] Socket.IO emits scan progress events
- [ ] Handles errors and updates scan status to "failed"

---

### Milestone 8: Frontend - Scan Pages
**Goal**: UI to trigger scans and view results

| Task | File | Description |
|------|------|-------------|
| Create Scans page | `frontend/src/pages/Scans.tsx` | List scans, trigger new |
| Create ScanDetail page | `frontend/src/pages/ScanDetail.tsx` | View findings |
| Create FindingCard | `frontend/src/components/FindingCard.tsx` | Finding display |
| Add routes | `frontend/src/App.tsx` | Register new pages |
| Add API hooks | `frontend/src/api/scans.ts` | TanStack Query hooks |

**Scans Page Features**:
- Input field for GitHub repo URL
- "Scan Repository" button
- List of recent scans with:
  - Repo name, branch
  - Status (pending/scanning/completed)
  - Stats: total findings → filtered findings (% reduction)
  - Timestamp

**ScanDetail Page Features**:
- Scan info header (repo, branch, commit)
- Stats banner: "87 findings → 12 real issues (86% filtered)"
- Findings list with:
  - File path + line number
  - Semgrep severity vs AI severity (side-by-side)
  - Rule name and message
  - Expandable AI reasoning
  - Confirm/Dismiss buttons

**Acceptance Criteria**:
- [ ] Can trigger scan from UI
- [ ] Shows real-time scan progress (via Socket.IO)
- [ ] Displays findings with AI severity comparison
- [ ] Can expand to see AI reasoning
- [ ] Can confirm/dismiss findings
- [ ] Responsive design (mobile-friendly)

---

### Milestone 9: Webhook Enhancement
**Goal**: Auto-trigger scans on GitHub push/PR

| Task | File | Description |
|------|------|-------------|
| Enhance webhook | `backend/src/api/routes/webhooks.py` | Add push/PR handlers |

**New Event Handlers**:
```python
# Handle push events
if event_type == "push":
    repo_url = payload["repository"]["html_url"]
    branch = payload["ref"].replace("refs/heads/", "")
    # Trigger scan in background

# Handle pull_request events
if event_type == "pull_request":
    if payload["action"] in ["opened", "synchronize"]:
        repo_url = payload["repository"]["html_url"]
        branch = payload["pull_request"]["head"]["ref"]
        # Trigger scan in background
```

**Acceptance Criteria**:
- [ ] Push to any branch triggers scan
- [ ] PR open/update triggers scan
- [ ] Respects repository allowlist
- [ ] Stores PR reference for result linking
- [ ] Rate limits (1 scan per repo per minute)

---

### Milestone 10: Polish & Demo Prep
**Goal**: Final touches for hackathon presentation

| Task | Description |
|------|-------------|
| Add demo repo | Pre-scan OWASP WebGoat or similar for demo data |
| Test full pipeline | End-to-end test: URL → scan → AI → dashboard |
| Add loading states | Skeleton loaders, progress indicators |
| Add error handling | User-friendly error messages |
| Prepare demo script | Practice the 5-minute presentation |
| Record backup video | In case live demo fails |

**Demo Checklist**:
- [ ] Pre-scanned repo with impressive stats (87 → 12)
- [ ] Real-time scan works reliably
- [ ] AI reasoning is compelling and accurate
- [ ] Dashboard looks polished
- [ ] Can explain the "why" (value proposition)

---

### Implementation Priority

```
CRITICAL PATH (Must Have)
├── M1: Database Models ──────────────────► Foundation
├── M2: Repo Fetcher ─────────────────────► Can clone repos
├── M3: Semgrep Runner ───────────────────► Can scan code
├── M5: AI Triage ────────────────────────► Core innovation
├── M7: Scan API ─────────────────────────► Backend complete
└── M8: Frontend ─────────────────────────► Demo-ready

NICE TO HAVE
├── M4: Context Extractor ────────────────► Better AI results
├── M6: Finding Aggregator ───────────────► Cleaner output
├── M9: Webhook Enhancement ──────────────► CI/CD integration
└── M10: Polish ──────────────────────────► Wow factor
```

---

## Project Structure

```
unifonic/
├── backend/
│   ├── src/
│   │   ├── api/routes/
│   │   │   ├── scans.py          # Scan endpoints
│   │   │   ├── bugs.py           # Bug triage (existing)
│   │   │   └── webhooks.py       # GitHub integration
│   │   ├── models/
│   │   │   ├── scan.py           # Scan model
│   │   │   ├── finding.py        # Finding model
│   │   │   └── bug.py            # Bug model (existing)
│   │   ├── services/
│   │   │   ├── scanner/
│   │   │   │   ├── semgrep_runner.py
│   │   │   │   ├── repo_fetcher.py
│   │   │   │   ├── context_extractor.py
│   │   │   │   ├── ai_triage.py
│   │   │   │   └── finding_aggregator.py
│   │   │   ├── bug_triage/       # Existing
│   │   │   └── intelligence/     # LLM services
│   │   └── integrations/
│   │       ├── pinecone_client.py
│   │       └── github_client.py
│   └── tests/
├── frontend/
│   └── src/
│       ├── pages/
│       │   ├── Scans.tsx
│       │   ├── ScanDetail.tsx
│       │   └── Bugs.tsx          # Existing
│       └── components/
└── docs/
```

---

## Quick Start

```bash
# Clone repository
git clone <repo-url>
cd unifonic

# Set environment variables
cp backend/.env.example backend/.env
# Add: OPEN_ROUTER_API_KEY, PINECONE_API_KEY, DATABASE_URL

# Start services
docker-compose up -d

# Run a scan
curl -X POST http://localhost:8000/api/scans \
  -H "Content-Type: application/json" \
  -d '{"repo_url": "https://github.com/OWASP/WebGoat"}'
```

---

## Environment Variables

```bash
# Required
DATABASE_URL=postgresql://user:pass@localhost:5432/scanguard
OPEN_ROUTER_API_KEY=sk-or-...       # LLM provider
PINECONE_API_KEY=...                # Vector database

# Optional
GITHUB_TOKEN=ghp_...                # For private repos
GITHUB_WEBHOOK_SECRET=...           # Webhook verification
OLLAMA_HOST=http://localhost:11434  # Local LLM fallback
```

---

*Team CSIS - Unifonic AI Hackathon 2025*

**ScanGuard AI: Static analysis that actually works.**
