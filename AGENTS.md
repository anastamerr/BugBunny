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
- [x] `Scan` model has: id, repo_url, branch, status, total_findings, filtered_findings
- [x] `Finding` model has: id, scan_id, rule_id, semgrep_severity, ai_severity, is_false_positive, ai_reasoning
- [x] Models linked via foreign key (Finding → Scan)
- [x] Database migrations run without errors

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
- [x] Can clone public GitHub repos
- [x] Can clone private repos (with GITHUB_TOKEN)
- [x] Detects languages: Python (.py), JavaScript (.js/.ts), Go (.go)
- [x] Cleans up temp directories after use
- [x] Handles clone failures gracefully

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
- [x] Runs `semgrep --config=auto --json` on repo
- [x] Parses all findings from JSON output
- [x] Handles Semgrep errors (not installed, timeout, etc.)
- [x] Returns structured RawFinding objects

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
- [x] Extracts 20 lines before and after finding
- [x] Identifies containing function/method name
- [x] Detects test files (test_, _test, __tests__)
- [x] Detects generated files (auto-generated comments)
- [x] Handles edge cases (start/end of file)

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
- [x] Sends finding + context to LLM
- [x] Parses JSON response correctly
- [x] Handles LLM errors/timeouts gracefully
- [x] Rate limits API calls (avoid quota issues)
- [x] Uses existing LLM service (OpenRouter/Ollama)

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
- [x] Filters out is_false_positive=True findings
- [x] Groups findings with same rule_id in same file
- [x] Uses Pinecone for semantic deduplication
- [x] Ranks by priority score (critical+high confidence = top)
- [x] Returns sorted list ready for display

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
- [x] POST /scans triggers background scan
- [x] GET /scans returns list with stats
- [x] GET /scans/{id}/findings returns filtered findings
- [x] PATCH /findings/{id} updates status
- [x] Socket.IO emits scan progress events
- [x] Handles errors and updates scan status to "failed"

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
- [x] Can trigger scan from UI
- [x] Shows real-time scan progress (via Socket.IO)
- [x] Displays findings with AI severity comparison
- [x] Can expand to see AI reasoning
- [x] Can confirm/dismiss findings
- [x] Responsive design (mobile-friendly)

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
- [x] Push to any branch triggers scan
- [x] PR open/update triggers scan
- [x] Respects repository allowlist
- [x] Stores PR reference for result linking
- [x] Rate limits (1 scan per repo per minute)

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

### Milestone 11: Dynamic Analysis (DAST) Integration
**Goal**: Add optional dynamic scanning to complement static analysis

#### Why Dynamic Analysis?

| Analysis Type | What It Does | Limitations |
|---------------|--------------|-------------|
| **SAST (Semgrep)** | Reads code patterns | Can't confirm exploitability |
| **DAST (Nuclei)** | Tests running apps | Needs live target |
| **Combined** | Best of both | Maximum confidence |

**Key Insight**: When SAST + DAST both find the same issue, confidence goes from 60% → 99%

---

#### New Database Fields

| Task | File | Description |
|------|------|-------------|
| Update Scan model | `backend/src/models/scan.py` | Add scan_type, target_url fields |

**Schema Changes**:
```python
class Scan(Base):
    # Existing fields...

    # NEW: Scan type selection
    scan_type = Column(
        Enum("sast", "dast", "both", name="scan_type"),
        nullable=False,
        default="sast",
    )

    # NEW: For DAST - live target URL
    target_url = Column(String, nullable=True)  # e.g., https://app.example.com

    # NEW: DAST-specific stats
    dast_findings = Column(Integer, nullable=True, default=0)
    endpoints_scanned = Column(Integer, nullable=True)
    nuclei_templates_used = Column(Integer, nullable=True)
```

**Acceptance Criteria**:
- [ ] Scan model supports scan_type: sast, dast, both
- [ ] target_url stored for DAST scans
- [ ] DAST stats tracked separately

---

#### New Files to Create

| Task | File | Description |
|------|------|-------------|
| Create DAST runner | `backend/src/services/scanner/dast_runner.py` | Execute Nuclei, parse results |
| Create dependency scanner | `backend/src/services/scanner/dependency_scanner.py` | Run Trivy for CVEs |
| Update types | `backend/src/services/scanner/types.py` | Add DynamicFinding type |
| Update scan pipeline | `backend/src/services/scanner/scan_pipeline.py` | Orchestrate SAST + DAST |

---

#### DAST Runner Implementation

**File**: `backend/src/services/scanner/dast_runner.py`

```python
class DASTRunner:
    """Run Nuclei dynamic security scans against live targets."""

    def __init__(self, templates_dir: str = None):
        self.templates = templates_dir or "nuclei-templates"
        self.timeout = 300  # 5 minutes max

    async def scan(self, target_url: str, template_categories: List[str] = None) -> List[DynamicFinding]:
        """
        Run Nuclei against a live target URL.

        Args:
            target_url: The live application URL (e.g., https://app.example.com)
            template_categories: Which templates to use (cves, vulnerabilities, exposures, etc.)

        Returns:
            List of DynamicFinding objects
        """
        categories = template_categories or ["cves", "vulnerabilities", "exposures", "misconfigurations"]

        cmd = [
            "nuclei",
            "-u", target_url,
            "-jsonl",                    # JSON lines output
            "-silent",                   # Less noise
            "-timeout", "10",            # Per-request timeout
            "-rate-limit", "100",        # Requests per second
        ]

        # Add template categories
        for category in categories:
            cmd.extend(["-t", f"{category}/"])

        result = await asyncio.subprocess.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        stdout, _ = await asyncio.wait_for(
            result.communicate(),
            timeout=self.timeout
        )

        return self._parse_results(stdout.decode())

    def _parse_results(self, output: str) -> List[DynamicFinding]:
        findings = []
        for line in output.strip().split("\n"):
            if not line:
                continue
            try:
                data = json.loads(line)
                findings.append(DynamicFinding(
                    template_id=data["template-id"],
                    template_name=data["info"].get("name", ""),
                    severity=data["info"]["severity"],
                    matched_at=data["matched-at"],
                    endpoint=data.get("host", ""),
                    curl_command=data.get("curl-command", ""),
                    evidence=data.get("extracted-results", []),
                    description=data["info"].get("description", ""),
                    remediation=data["info"].get("remediation", ""),
                    cve_ids=data["info"].get("classification", {}).get("cve-id", []),
                    cwe_ids=data["info"].get("classification", {}).get("cwe-id", []),
                ))
            except (json.JSONDecodeError, KeyError):
                continue
        return findings

    def get_version(self) -> str:
        """Get Nuclei version."""
        result = subprocess.run(["nuclei", "-version"], capture_output=True, text=True)
        return result.stdout.strip() or "unknown"

    def is_available(self) -> bool:
        """Check if Nuclei is installed."""
        try:
            subprocess.run(["nuclei", "-version"], capture_output=True, check=True)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False
```

**DynamicFinding Type**:
```python
@dataclass
class DynamicFinding:
    template_id: str           # e.g., "CVE-2021-44228"
    template_name: str         # e.g., "Log4j RCE"
    severity: str              # critical, high, medium, low, info
    matched_at: str            # Full URL where issue was found
    endpoint: str              # Target host
    curl_command: str          # Reproducible curl command
    evidence: List[str]        # Extracted data proving the issue
    description: str           # What the vulnerability is
    remediation: str           # How to fix it
    cve_ids: List[str]         # Associated CVEs
    cwe_ids: List[str]         # Associated CWEs
```

**Acceptance Criteria**:
- [ ] DASTRunner executes Nuclei CLI
- [ ] Parses JSON lines output correctly
- [ ] Handles timeouts gracefully
- [ ] Returns structured DynamicFinding objects
- [ ] Includes curl command for reproduction

---

#### Dependency Scanner (Bonus)

**File**: `backend/src/services/scanner/dependency_scanner.py`

```python
class DependencyScanner:
    """Scan dependencies for known CVEs using Trivy."""

    async def scan(self, repo_path: Path) -> List[DependencyFinding]:
        """Scan package files for vulnerable dependencies."""
        result = await asyncio.subprocess.create_subprocess_exec(
            "trivy", "fs", str(repo_path),
            "--format", "json",
            "--scanners", "vuln",
            "--severity", "CRITICAL,HIGH,MEDIUM",
            stdout=asyncio.subprocess.PIPE,
        )

        stdout, _ = await result.communicate()
        data = json.loads(stdout.decode())

        findings = []
        for result in data.get("Results", []):
            for vuln in result.get("Vulnerabilities", []):
                findings.append(DependencyFinding(
                    cve_id=vuln["VulnerabilityID"],
                    package_name=vuln["PkgName"],
                    installed_version=vuln["InstalledVersion"],
                    fixed_version=vuln.get("FixedVersion", "No fix available"),
                    severity=vuln["Severity"],
                    description=vuln.get("Description", ""),
                    cvss_score=vuln.get("CVSS", {}).get("nvd", {}).get("V3Score"),
                ))
        return findings
```

**Acceptance Criteria**:
- [ ] Scans requirements.txt, package.json, go.mod, etc.
- [ ] Returns CVE IDs with fix versions
- [ ] Includes CVSS scores for prioritization

---

#### Updated Scan Pipeline

**File**: `backend/src/services/scanner/scan_pipeline.py`

```python
async def run_scan_pipeline(
    scan_id: uuid.UUID,
    repo_url: str,
    branch: str,
    scan_type: str = "sast",        # NEW: sast, dast, or both
    target_url: str = None,          # NEW: for DAST
) -> None:
    db = SessionLocal()
    repo_path = None

    try:
        # Initialize runners based on scan type
        sast_findings = []
        dast_findings = []
        dependency_findings = []

        # ===== SAST PHASE =====
        if scan_type in ("sast", "both"):
            _update_scan(db, scan_id, status="cloning")
            await sio.emit("scan.updated", {"scan_id": str(scan_id), "status": "cloning"})

            fetcher = RepoFetcher()
            repo_path, resolved_branch = await fetcher.clone(repo_url, branch=branch)

            _update_scan(db, scan_id, status="scanning")
            await sio.emit("scan.updated", {"scan_id": str(scan_id), "status": "scanning", "phase": "SAST"})

            # Run Semgrep
            runner = SemgrepRunner()
            raw_findings = await runner.scan(repo_path, fetcher.detect_languages(repo_path))

            # Context extraction + AI triage
            extractor = ContextExtractor()
            triage = AITriageEngine()
            contexts = [extractor.extract(repo_path, f) for f in raw_findings]
            sast_findings = await triage.triage_batch(list(zip(raw_findings, contexts)))

            # Dependency scan (bonus)
            dep_scanner = DependencyScanner()
            if dep_scanner.is_available():
                dependency_findings = await dep_scanner.scan(repo_path)

        # ===== DAST PHASE =====
        if scan_type in ("dast", "both") and target_url:
            _update_scan(db, scan_id, status="scanning")
            await sio.emit("scan.updated", {"scan_id": str(scan_id), "status": "scanning", "phase": "DAST"})

            dast_runner = DASTRunner()
            if dast_runner.is_available():
                dast_findings = await dast_runner.scan(target_url)
                _update_scan(db, scan_id, dast_findings=len(dast_findings))

        # ===== CORRELATION PHASE =====
        _update_scan(db, scan_id, status="analyzing")
        await sio.emit("scan.updated", {"scan_id": str(scan_id), "status": "analyzing", "phase": "Correlation"})

        # Correlate SAST + DAST findings
        correlated = await correlate_findings(sast_findings, dast_findings)

        # AI triage with combined evidence
        final_findings = await ai_triage_with_dast_evidence(correlated)

        # Store findings...
        # (existing storage logic)

    except Exception as exc:
        _update_scan(db, scan_id, status="failed", error_message=str(exc))
    finally:
        if repo_path:
            await fetcher.cleanup(repo_path)
        db.close()


async def correlate_findings(
    sast_findings: List[TriagedFinding],
    dast_findings: List[DynamicFinding],
) -> List[CorrelatedFinding]:
    """
    Correlate static and dynamic findings.

    When SAST and DAST both find the same issue:
    - Confidence increases significantly
    - Severity confirmed by real exploitation
    """
    correlated = []

    for sast in sast_findings:
        matching_dast = None

        # Try to match by vulnerability type
        for dast in dast_findings:
            if _findings_match(sast, dast):
                matching_dast = dast
                break

        correlated.append(CorrelatedFinding(
            sast_finding=sast,
            dast_finding=matching_dast,
            confidence_boost=0.3 if matching_dast else 0.0,
            confirmed_exploitable=matching_dast is not None,
            combined_evidence=_build_evidence(sast, matching_dast),
        ))

    # Add DAST-only findings (not found by SAST)
    matched_dast_ids = {c.dast_finding.template_id for c in correlated if c.dast_finding}
    for dast in dast_findings:
        if dast.template_id not in matched_dast_ids:
            correlated.append(CorrelatedFinding(
                sast_finding=None,
                dast_finding=dast,
                confidence_boost=0.0,
                confirmed_exploitable=True,  # DAST proves it
                combined_evidence=dast.evidence,
            ))

    return correlated


def _findings_match(sast: TriagedFinding, dast: DynamicFinding) -> bool:
    """Check if SAST and DAST findings refer to same vulnerability."""
    # Match by CWE
    sast_cwe = _extract_cwe_from_rule(sast.rule_id)
    if sast_cwe and sast_cwe in dast.cwe_ids:
        return True

    # Match by vulnerability type keywords
    sqli_keywords = ["sql", "injection", "sqli"]
    xss_keywords = ["xss", "cross-site", "scripting"]
    rce_keywords = ["rce", "command", "exec", "eval"]

    sast_text = f"{sast.rule_id} {sast.rule_message}".lower()
    dast_text = f"{dast.template_id} {dast.description}".lower()

    for keywords in [sqli_keywords, xss_keywords, rce_keywords]:
        if any(k in sast_text for k in keywords) and any(k in dast_text for k in keywords):
            return True

    return False
```

**Acceptance Criteria**:
- [ ] Pipeline supports scan_type: sast, dast, both
- [ ] DAST runs against target_url when provided
- [ ] Findings are correlated between SAST and DAST
- [ ] Confidence boosted when both find same issue
- [ ] Socket.IO emits phase updates (SAST → DAST → Correlation)

---

#### API Updates

**File**: `backend/src/api/routes/scans.py`

```python
@router.post("", response_model=ScanRead, status_code=status.HTTP_201_CREATED)
async def create_scan(
    payload: ScanCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
) -> Scan:
    # Validate: DAST requires target_url
    if payload.scan_type in ("dast", "both") and not payload.target_url:
        raise HTTPException(
            status_code=400,
            detail="target_url is required for DAST scans"
        )

    # Validate: SAST requires repo_url
    if payload.scan_type in ("sast", "both") and not payload.repo_url:
        raise HTTPException(
            status_code=400,
            detail="repo_url is required for SAST scans"
        )

    scan = Scan(
        repo_url=payload.repo_url,
        branch=payload.branch or "main",
        scan_type=payload.scan_type,      # NEW
        target_url=payload.target_url,    # NEW
        status="pending",
        trigger="manual",
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    background_tasks.add_task(
        run_scan_pipeline,
        scan.id,
        scan.repo_url,
        scan.branch,
        scan.scan_type,      # NEW
        scan.target_url,     # NEW
    )

    return scan
```

**Updated ScanCreate Schema**:
```python
class ScanCreate(BaseModel):
    repo_url: Optional[str] = None           # Required for SAST
    branch: Optional[str] = "main"
    scan_type: Literal["sast", "dast", "both"] = "sast"  # NEW
    target_url: Optional[str] = None         # Required for DAST
```

**Acceptance Criteria**:
- [ ] API accepts scan_type parameter
- [ ] API accepts target_url for DAST
- [ ] Validation: DAST requires target_url
- [ ] Validation: SAST requires repo_url
- [ ] Both can be provided for combined scan

---

#### Frontend Updates

**File**: `frontend/src/pages/Scans.tsx`

**New Form Fields**:
```tsx
export default function Scans() {
  const [scanType, setScanType] = useState<"sast" | "dast" | "both">("sast");
  const [repoUrl, setRepoUrl] = useState("");
  const [targetUrl, setTargetUrl] = useState("");
  const [branch, setBranch] = useState("main");

  return (
    <div className="surface-solid p-6">
      {/* Scan Type Selector */}
      <div className="flex gap-2 mb-4">
        <button
          className={`btn ${scanType === "sast" ? "btn-primary" : "btn-ghost"}`}
          onClick={() => setScanType("sast")}
        >
          SAST (Code)
        </button>
        <button
          className={`btn ${scanType === "dast" ? "btn-primary" : "btn-ghost"}`}
          onClick={() => setScanType("dast")}
        >
          DAST (Live App)
        </button>
        <button
          className={`btn ${scanType === "both" ? "btn-primary" : "btn-ghost"}`}
          onClick={() => setScanType("both")}
        >
          Both
        </button>
      </div>

      {/* SAST: Repository URL */}
      {scanType !== "dast" && (
        <div>
          <label>Repository URL</label>
          <input
            placeholder="https://github.com/org/repo"
            value={repoUrl}
            onChange={(e) => setRepoUrl(e.target.value)}
          />
        </div>
      )}

      {/* DAST: Target URL */}
      {scanType !== "sast" && (
        <div>
          <label>Live Target URL</label>
          <input
            placeholder="https://app.example.com"
            value={targetUrl}
            onChange={(e) => setTargetUrl(e.target.value)}
          />
        </div>
      )}

      <button onClick={triggerScan}>
        {scanType === "both" ? "Run SAST + DAST" : `Run ${scanType.toUpperCase()}`}
      </button>
    </div>
  );
}
```

**ScanDetail Updates**:
```tsx
// Show which scan types were run
<div className="flex gap-2">
  {scan.scan_type === "sast" || scan.scan_type === "both" ? (
    <span className="badge">SAST</span>
  ) : null}
  {scan.scan_type === "dast" || scan.scan_type === "both" ? (
    <span className="badge">DAST</span>
  ) : null}
</div>

// Show DAST-specific stats
{scan.dast_findings != null && (
  <div className="stat">
    <div className="label">DAST Findings</div>
    <div className="value">{scan.dast_findings}</div>
  </div>
)}

// Show correlation badge on findings
{finding.confirmed_exploitable && (
  <span className="badge badge-critical">
    Confirmed Exploitable (SAST + DAST)
  </span>
)}
```

**Acceptance Criteria**:
- [ ] UI has SAST / DAST / Both toggle
- [ ] Repo URL field shown for SAST
- [ ] Target URL field shown for DAST
- [ ] Both fields shown when "Both" selected
- [ ] Findings show "Confirmed Exploitable" badge when SAST + DAST match

---

#### Docker Setup for Nuclei

**File**: `docker-compose.yml` (update)

```yaml
services:
  backend:
    build: ./backend
    environment:
      - NUCLEI_TEMPLATES_PATH=/nuclei-templates
    volumes:
      - nuclei-templates:/nuclei-templates
    depends_on:
      - nuclei-updater

  nuclei-updater:
    image: projectdiscovery/nuclei:latest
    entrypoint: ["/bin/sh", "-c"]
    command:
      - |
        nuclei -update-templates
        cp -r /root/nuclei-templates /shared/
    volumes:
      - nuclei-templates:/shared

volumes:
  nuclei-templates:
```

**Acceptance Criteria**:
- [ ] Nuclei available in backend container
- [ ] Templates auto-updated on startup
- [ ] Templates shared via volume

---

#### Demo Script for DAST

**Hackathon Demo Addition**:

> "We've shown how AI filters false positives in static analysis. But what if we could PROVE the vulnerability exists?"

1. **SAST finds SQL injection pattern**
   - "Semgrep found string interpolation in SQL query"
   - AI says: "Likely vulnerable, confidence 70%"

2. **Trigger DAST scan**
   - "Now let's scan the live app..."
   - Nuclei sends actual SQL injection payloads

3. **DAST confirms**
   - "Nuclei confirmed! Payload `1' OR '1'='1` returned 500 rows"
   - Evidence: curl command to reproduce

4. **Correlation**
   - "SAST + DAST agree → Confidence: 99%"
   - Badge: "Confirmed Exploitable"

---

### Implementation Priority (Updated)

```
CRITICAL PATH (Must Have)
├── M1: Database Models ──────────────────► Foundation
├── M2: Repo Fetcher ─────────────────────► Can clone repos
├── M3: Semgrep Runner ───────────────────► Can scan code
├── M5: AI Triage ────────────────────────► Core innovation
├── M7: Scan API ─────────────────────────► Backend complete
└── M8: Frontend ─────────────────────────► Demo-ready

NICE TO HAVE (Phase 2)
├── M4: Context Extractor ────────────────► Better AI results
├── M6: Finding Aggregator ───────────────► Cleaner output
├── M9: Webhook Enhancement ──────────────► CI/CD integration
├── M10: Polish ──────────────────────────► Wow factor
└── M11: Dynamic Analysis ────────────────► DAST + Correlation (NEW)

DAST IMPLEMENTATION ORDER
├── 11a: DASTRunner (Nuclei) ─────────────► Core DAST capability
├── 11b: DependencyScanner (Trivy) ───────► Bonus: CVE detection
├── 11c: Correlation Engine ──────────────► SAST + DAST matching
├── 11d: API + Schema Updates ────────────► scan_type, target_url
├── 11e: Frontend Toggle ─────────────────► User selects SAST/DAST/Both
└── 11f: Docker + Nuclei Setup ───────────► Production ready
```

---

## Project Structure

```
unifonic/
├── backend/
│   ├── src/
│   │   ├── api/routes/
│   │   │   ├── scans.py          # Scan endpoints (SAST + DAST)
│   │   │   ├── bugs.py           # Bug triage (existing)
│   │   │   └── webhooks.py       # GitHub integration
│   │   ├── models/
│   │   │   ├── scan.py           # Scan model (scan_type, target_url)
│   │   │   ├── finding.py        # Finding model (SAST + DAST fields)
│   │   │   └── bug.py            # Bug model (existing)
│   │   ├── services/
│   │   │   ├── scanner/
│   │   │   │   ├── semgrep_runner.py      # SAST: Semgrep execution
│   │   │   │   ├── dast_runner.py         # DAST: Nuclei execution (NEW)
│   │   │   │   ├── dependency_scanner.py  # Trivy CVE scanning (NEW)
│   │   │   │   ├── repo_fetcher.py        # Clone repos
│   │   │   │   ├── context_extractor.py   # Code context
│   │   │   │   ├── ai_triage.py           # LLM false positive detection
│   │   │   │   ├── finding_aggregator.py  # Group/dedupe/prioritize
│   │   │   │   ├── correlation.py         # SAST + DAST matching (NEW)
│   │   │   │   ├── scan_pipeline.py       # Orchestrates full scan
│   │   │   │   └── types.py               # RawFinding, DynamicFinding, etc.
│   │   │   ├── bug_triage/       # Existing
│   │   │   └── intelligence/     # LLM services
│   │   └── integrations/
│   │       ├── pinecone_client.py
│   │       └── github_client.py
│   └── tests/
├── frontend/
│   └── src/
│       ├── pages/
│       │   ├── Scans.tsx         # SAST/DAST/Both toggle
│       │   ├── ScanDetail.tsx    # Correlation badges
│       │   └── Bugs.tsx          # Existing
│       └── components/
│           └── FindingCard.tsx   # "Confirmed Exploitable" badge
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
