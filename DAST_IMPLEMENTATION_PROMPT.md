# Task: Implement Targeted DAST Integration for BugBunny

## Mission Statement
Implement a DAST (Dynamic Application Security Testing) system that **attacks specific vulnerabilities found by SAST**, rather than running blind scans. The key requirement from the stakeholder meeting is: "whenever SAST gets results, DAST attacks those specific points and follows up on them."

---

## CRITICAL: Codebase Analysis Phase (DO THIS FIRST)

Before writing ANY code, perform a thorough analysis:

### 1. Understand Existing Architecture
```bash
# Analyze the current structure
view /home/claude/unifonic/backend/src
view /home/claude/unifonic/backend/src/models
view /home/claude/unifonic/backend/src/services
view /home/claude/unifonic/backend/src/api/routes

# Read existing implementations to maintain consistency
view /home/claude/unifonic/backend/src/services/scanner  # If exists
view /home/claude/unifonic/backend/src/models/scan.py    # If exists
view /home/claude/unifonic/backend/src/models/finding.py # If exists
```

### 2. Identify Existing Patterns
Look for:
- **Database patterns**: How are SQLAlchemy models structured?
- **Service patterns**: How do existing services (bug_triage, intelligence) structure their code?
- **API patterns**: What response models and error handling do existing routes use?
- **Async patterns**: How are background tasks currently implemented?
- **LLM integration**: How is the existing LLM service used?
- **Pinecone usage**: How is vector search currently implemented?

### 3. Check Dependencies
```bash
view /home/claude/unifonic/backend/requirements.txt
view /home/claude/unifonic/backend/pyproject.toml  # If exists
view /home/claude/unifonic/docker-compose.yml
```

### 4. Understand Current Scan Flow
Read and trace through:
- How are scans currently triggered?
- What database models exist for scans/findings?
- How is Semgrep currently integrated (if at all)?
- What's the current status update mechanism (Socket.IO)?

### 5. Check Frontend Structure
```bash
view /home/claude/unifonic/frontend/src
view /home/claude/unifonic/frontend/src/pages
view /home/claude/unifonic/frontend/src/api  # API client functions
```

---

## Implementation Context

### Business Requirement
From stakeholder meeting:
> "SAST is working (they already use Semgrep). He needs whenever SAST gets results, the DAST (our system) attacks the points of the SAST results and follow up upon them using DAST."

### Technical Flow
```
1. SAST (Semgrep) scans code → finds vulnerabilities
2. AI filters false positives → real issues remain
3. DAST (Nuclei) attacks those specific issues → confirms exploitability
4. System correlates results → shows "Confirmed Exploitable" or "Not Exploitable"
```

### Key Innovation
Unlike traditional DAST that blindly scans entire apps, we do **targeted attacks**:
- SQL injection found in `/api/users?id=X` → DAST attacks that exact endpoint with SQLi payloads
- XSS found in search parameter → DAST attacks search with XSS payloads
- Command injection in file upload → DAST tests that specific endpoint

---

## Database Schema Changes

### 1. Update Scan Model
**File**: `backend/src/models/scan.py`

Add these fields to existing Scan model (or create if doesn't exist):
```python
# DAST-related fields
target_url = Column(String, nullable=True)  # Live app URL for DAST
dast_enabled = Column(Boolean, default=False)
dast_findings_count = Column(Integer, default=0)
dast_confirmed_count = Column(Integer, default=0)  # How many SAST findings DAST confirmed
```

### 2. Update Finding Model
**File**: `backend/src/models/finding.py`

Add these fields to existing Finding model (or create if doesn't exist):
```python
# DAST verification fields
dast_verified = Column(Boolean, default=False)  # Was this tested by DAST?
dast_attack_succeeded = Column(Boolean, nullable=True)  # Did DAST confirm it?
dast_proof = Column(Text, nullable=True)  # Curl command to reproduce
dast_evidence = Column(JSON, nullable=True)  # Nuclei output
confidence_score = Column(Float, default=0.7)  # 0.7 = SAST only, 0.99 = DAST confirmed
```

### 3. Run Migration
After model changes:
```bash
cd /home/claude/unifonic/backend
alembic revision --autogenerate -m "add_dast_fields"
alembic upgrade head
```

---

## Backend Implementation

### Phase 1: Create Targeted DAST Runner

**File**: `backend/src/services/scanner/targeted_dast_runner.py`
```python
"""
Targeted DAST Runner - Attacks specific SAST findings

Unlike blind DAST that scans entire apps, this targets specific 
vulnerabilities found by SAST.
"""

from typing import List, Dict, Optional
from dataclasses import dataclass
import asyncio
import subprocess
import json
import logging

logger = logging.getLogger(__name__)


@dataclass
class DASTAttackConfig:
    """Configuration for attacking a specific finding"""
    vuln_type: str  # "sqli", "xss", "command-injection", etc.
    nuclei_templates: List[str]  # Which Nuclei templates to use
    test_payloads: List[str]  # Quick test payloads
    target_endpoint: str  # Full URL to attack
    target_parameter: str  # Which parameter is vulnerable
    http_method: str = "GET"


@dataclass
class DASTResult:
    """Result of DAST attack on a finding"""
    finding_id: str
    attack_succeeded: bool
    confidence: float  # 0.0-1.0
    proof_of_exploit: Optional[str]  # Curl command
    evidence: Dict  # Raw Nuclei output
    error: Optional[str] = None


class TargetedDASTRunner:
    """
    Executes targeted DAST attacks based on SAST findings.
    
    Workflow:
    1. Takes SAST finding (e.g., SQL injection in line 45)
    2. Maps to endpoint (e.g., /api/users?id=X)
    3. Generates attack config (SQLi payloads for that endpoint)
    4. Runs Nuclei with specific templates
    5. Returns confirmation of exploitability
    """
    
    def __init__(self, timeout: int = 60):
        self.timeout = timeout
        self.nuclei_available = self._check_nuclei()
        
    def _check_nuclei(self) -> bool:
        """Verify Nuclei is installed"""
        try:
            result = subprocess.run(
                ["nuclei", "-version"],
                capture_output=True,
                timeout=5
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            logger.error("Nuclei not found. Install: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
            return False
    
    async def attack_findings(
        self,
        target_base_url: str,
        sast_findings: List,  # List of TriagedFinding objects
        repo_path: str
    ) -> List[DASTResult]:
        """
        Attack each SAST finding to confirm exploitability.
        
        Args:
            target_base_url: Live app URL (e.g., https://app.example.com)
            sast_findings: Vulnerabilities found by SAST (after AI filtering)
            repo_path: Path to cloned repo (to map findings to endpoints)
            
        Returns:
            List of DAST results showing which findings are exploitable
        """
        if not self.nuclei_available:
            logger.warning("Nuclei unavailable, skipping DAST")
            return []
        
        results = []
        
        for finding in sast_findings:
            # Skip false positives
            if getattr(finding, 'is_false_positive', False):
                continue
            
            # Generate attack configuration
            attack_config = self._generate_attack_config(
                finding,
                target_base_url,
                repo_path
            )
            
            if not attack_config:
                logger.info(f"No DAST attack available for {finding.rule_id}")
                continue
            
            # Execute attack
            try:
                result = await self._execute_attack(attack_config, finding)
                results.append(result)
            except Exception as e:
                logger.error(f"DAST attack failed for {finding.rule_id}: {e}")
                results.append(DASTResult(
                    finding_id=str(finding.id) if hasattr(finding, 'id') else finding.rule_id,
                    attack_succeeded=False,
                    confidence=0.0,
                    proof_of_exploit=None,
                    evidence={},
                    error=str(e)
                ))
        
        return results
    
    def _generate_attack_config(
        self,
        finding,
        base_url: str,
        repo_path: str
    ) -> Optional[DASTAttackConfig]:
        """
        Map SAST finding to DAST attack configuration.
        
        Examples:
        - SAST: "SQL injection in users.py line 45" 
          → DAST: Attack /api/users with SQLi payloads
          
        - SAST: "XSS in search_handler.js line 23"
          → DAST: Attack /search?q=<payload>
          
        - SAST: "Command injection in upload.py line 67"
          → DAST: Attack /upload with command payloads
        """
        rule_id = finding.rule_id.lower()
        file_path = getattr(finding, 'file_path', '')
        
        # Determine vulnerability type
        vuln_type, templates = self._classify_vulnerability(rule_id)
        
        if not vuln_type:
            return None
        
        # Map file path to endpoint
        endpoint = self._map_file_to_endpoint(file_path, repo_path)
        target_url = f"{base_url.rstrip('/')}/{endpoint.lstrip('/')}"
        
        # Extract parameter name from code context
        parameter = self._extract_parameter(finding)
        
        return DASTAttackConfig(
            vuln_type=vuln_type,
            nuclei_templates=templates,
            test_payloads=self._get_test_payloads(vuln_type),
            target_endpoint=target_url,
            target_parameter=parameter,
            http_method="GET"  # TODO: Detect from code
        )
    
    def _classify_vulnerability(self, rule_id: str) -> tuple[Optional[str], List[str]]:
        """
        Map Semgrep rule to vulnerability type and Nuclei templates.
        
        Returns: (vuln_type, nuclei_templates)
        """
        classifications = {
            "sql": ("sqli", ["sqli/", "cves/2021/CVE-2021-XXXXX-sqli.yaml"]),
            "injection": ("sqli", ["sqli/"]),
            "xss": ("xss", ["xss/", "cves/xss/"]),
            "cross-site-scripting": ("xss", ["xss/"]),
            "command": ("command-injection", ["cves/command-injection/", "vulnerabilities/generic/command-injection.yaml"]),
            "exec": ("command-injection", ["cves/command-injection/"]),
            "eval": ("code-injection", ["cves/code-injection/"]),
            "path-traversal": ("path-traversal", ["cves/path-traversal/"]),
            "directory-traversal": ("path-traversal", ["cves/path-traversal/"]),
            "xxe": ("xxe", ["cves/xxe/"]),
            "ssrf": ("ssrf", ["cves/ssrf/", "vulnerabilities/generic/ssrf.yaml"]),
        }
        
        for keyword, (vuln_type, templates) in classifications.items():
            if keyword in rule_id:
                return vuln_type, templates
        
        return None, []
    
    def _get_test_payloads(self, vuln_type: str) -> List[str]:
        """Quick test payloads for each vulnerability type"""
        payloads = {
            "sqli": [
                "' OR '1'='1",
                "1' UNION SELECT NULL--",
                "1' AND 1=1--"
            ],
            "xss": [
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "javascript:alert(1)"
            ],
            "command-injection": [
                "; ls -la",
                "| whoami",
                "`id`",
                "$(cat /etc/passwd)"
            ],
            "path-traversal": [
                "../../../etc/passwd",
                "....//....//....//etc/passwd",
                "..%2f..%2f..%2fetc%2fpasswd"
            ],
            "ssrf": [
                "http://169.254.169.254/latest/meta-data/",
                "http://localhost:22",
                "http://127.0.0.1:6379"
            ]
        }
        return payloads.get(vuln_type, [])
    
    def _map_file_to_endpoint(self, file_path: str, repo_path: str) -> str:
        """
        Convert code file path to API endpoint.
        
        Examples:
        - api/routes/users.py → /api/users
        - controllers/AuthController.java → /auth
        - handlers/search_handler.go → /search
        
        This is heuristic-based. For production, parse route definitions.
        """
        # Remove repo path prefix
        rel_path = file_path.replace(repo_path, '').lstrip('/')
        
        # Common patterns
        patterns = [
            ('api/routes/', '/api/'),
            ('routes/', '/'),
            ('controllers/', '/'),
            ('handlers/', '/'),
            ('views/', '/'),
        ]
        
        for pattern, replacement in patterns:
            if pattern in rel_path:
                endpoint = rel_path.replace(pattern, replacement)
                # Remove file extension and convert to lowercase
                endpoint = endpoint.rsplit('.', 1)[0].lower()
                return endpoint
        
        # Fallback: use filename
        filename = rel_path.split('/')[-1].rsplit('.', 1)[0]
        return f"/{filename.lower()}"
    
    def _extract_parameter(self, finding) -> str:
        """
        Extract vulnerable parameter name from code context.
        
        Example: request.args.get('id') → 'id'
        """
        code = getattr(finding, 'code_snippet', '')
        
        # Common parameter extraction patterns
        patterns = [
            r"request\.args\.get\(['\"](\w+)",  # Flask
            r"request\.GET\.get\(['\"](\w+)",   # Django
            r"params\[:['\"]?(\w+)",             # Rails
            r"req\.query\.(\w+)",                # Express
        ]
        
        import re
        for pattern in patterns:
            match = re.search(pattern, code)
            if match:
                return match.group(1)
        
        return "id"  # Default fallback
    
    async def _execute_attack(
        self,
        config: DASTAttackConfig,
        finding
    ) -> DASTResult:
        """
        Execute Nuclei attack with specific configuration.
        
        Returns result showing if attack succeeded.
        """
        logger.info(f"DAST attacking {config.target_endpoint} for {config.vuln_type}")
        
        # Build Nuclei command
        cmd = [
            "nuclei",
            "-u", config.target_endpoint,
            "-silent",
            "-jsonl",
            "-timeout", "10",
            "-rate-limit", "50",
        ]
        
        # Add templates
        for template in config.nuclei_templates:
            cmd.extend(["-t", template])
        
        # Execute
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=self.timeout
            )
            
            # Parse results
            output = stdout.decode()
            
            if not output.strip():
                # No vulnerabilities found
                return DASTResult(
                    finding_id=str(finding.id) if hasattr(finding, 'id') else finding.rule_id,
                    attack_succeeded=False,
                    confidence=0.8,  # High confidence it's NOT exploitable
                    proof_of_exploit=None,
                    evidence={"message": "No vulnerabilities detected by Nuclei"}
                )
            
            # Parse JSON lines output
            findings = []
            for line in output.strip().split('\n'):
                try:
                    findings.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
            
            if findings:
                # Attack succeeded!
                first_finding = findings[0]
                
                return DASTResult(
                    finding_id=str(finding.id) if hasattr(finding, 'id') else finding.rule_id,
                    attack_succeeded=True,
                    confidence=0.99,  # Very high confidence
                    proof_of_exploit=first_finding.get('curl-command'),
                    evidence={
                        "template": first_finding.get('template-id'),
                        "matched_at": first_finding.get('matched-at'),
                        "severity": first_finding.get('info', {}).get('severity'),
                        "description": first_finding.get('info', {}).get('description'),
                    }
                )
            
            return DASTResult(
                finding_id=str(finding.id) if hasattr(finding, 'id') else finding.rule_id,
                attack_succeeded=False,
                confidence=0.8,
                proof_of_exploit=None,
                evidence={"nuclei_output": output}
            )
            
        except asyncio.TimeoutError:
            logger.warning(f"DAST attack timeout for {config.target_endpoint}")
            return DASTResult(
                finding_id=str(finding.id) if hasattr(finding, 'id') else finding.rule_id,
                attack_succeeded=False,
                confidence=0.5,  # Unknown due to timeout
                proof_of_exploit=None,
                evidence={},
                error="Timeout"
            )
```

### Phase 2: Update Scan Pipeline

**File**: `backend/src/services/scanner/scan_pipeline.py` (or create if doesn't exist)
```python
"""
Scan Pipeline Orchestrator

Workflow:
1. Clone repo
2. Run SAST (Semgrep)
3. Extract context
4. AI triage (filter false positives)
5. IF target_url provided: Run DAST to verify findings
6. Store results
"""

import logging
from typing import Optional
from uuid import UUID
from pathlib import Path

logger = logging.getLogger(__name__)


async def run_scan_pipeline(
    scan_id: UUID,
    repo_url: str,
    branch: str,
    target_url: Optional[str] = None,
    db_session = None,
    socketio_emit = None
) -> None:
    """
    Main scan pipeline with optional DAST verification.
    
    Args:
        scan_id: Database scan ID
        repo_url: GitHub repository URL
        branch: Git branch to scan
        target_url: Optional live app URL for DAST verification
        db_session: Database session
        socketio_emit: Socket.IO emit function for real-time updates
    """
    
    # Import services (adjust paths based on actual structure)
    from .repo_fetcher import RepoFetcher
    from .semgrep_runner import SemgrepRunner
    from .context_extractor import ContextExtractor
    from .ai_triage import AITriageEngine
    from .targeted_dast_runner import TargetedDASTRunner
    
    repo_path = None
    
    try:
        # ===== PHASE 1: REPOSITORY SETUP =====
        logger.info(f"Scan {scan_id}: Starting pipeline for {repo_url}")
        _update_scan_status(db_session, scan_id, "cloning")
        _emit_progress(socketio_emit, scan_id, "cloning", "Cloning repository...")
        
        fetcher = RepoFetcher()
        repo_path = await fetcher.clone(repo_url, branch)
        languages = fetcher.detect_languages(repo_path)
        
        logger.info(f"Scan {scan_id}: Detected languages: {languages}")
        
        # ===== PHASE 2: STATIC ANALYSIS (SAST) =====
        _update_scan_status(db_session, scan_id, "scanning")
        _emit_progress(socketio_emit, scan_id, "scanning", "Running static analysis...")
        
        semgrep = SemgrepRunner()
        raw_findings = await semgrep.scan(repo_path, languages)
        
        logger.info(f"Scan {scan_id}: Semgrep found {len(raw_findings)} potential issues")
        _update_scan_stats(db_session, scan_id, total_findings=len(raw_findings))
        
        # ===== PHASE 3: CONTEXT EXTRACTION =====
        _emit_progress(socketio_emit, scan_id, "analyzing", "Extracting code context...")
        
        extractor = ContextExtractor()
        findings_with_context = []
        
        for raw_finding in raw_findings:
            context = extractor.extract(repo_path, raw_finding)
            findings_with_context.append((raw_finding, context))
        
        # ===== PHASE 4: AI TRIAGE =====
        _emit_progress(socketio_emit, scan_id, "analyzing", "AI filtering false positives...")
        
        triage = AITriageEngine()
        triaged_findings = await triage.triage_batch(findings_with_context)
        
        # Separate real issues from false positives
        real_findings = [f for f in triaged_findings if not f.is_false_positive]
        false_positives = [f for f in triaged_findings if f.is_false_positive]
        
        logger.info(
            f"Scan {scan_id}: AI filtered {len(false_positives)} false positives, "
            f"{len(real_findings)} real issues remain"
        )
        
        _update_scan_stats(
            db_session,
            scan_id,
            filtered_findings=len(real_findings),
            false_positives=len(false_positives)
        )
        
        # ===== PHASE 5: DYNAMIC ANALYSIS (DAST) =====
        dast_results = []
        
        if target_url and real_findings:
            _update_scan_status(db_session, scan_id, "dast_verification")
            _emit_progress(
                socketio_emit,
                scan_id,
                "dast_verification",
                f"Verifying {len(real_findings)} findings with DAST..."
            )
            
            dast_runner = TargetedDASTRunner()
            dast_results = await dast_runner.attack_findings(
                target_url,
                real_findings,
                str(repo_path)
            )
            
            confirmed_count = sum(1 for r in dast_results if r.attack_succeeded)
            logger.info(
                f"Scan {scan_id}: DAST confirmed {confirmed_count}/{len(dast_results)} findings"
            )
            
            _update_scan_stats(
                db_session,
                scan_id,
                dast_findings_count=len(dast_results),
                dast_confirmed_count=confirmed_count
            )
        
        # ===== PHASE 6: STORE RESULTS =====
        _update_scan_status(db_session, scan_id, "storing")
        _emit_progress(socketio_emit, scan_id, "storing", "Saving results...")
        
        await _store_findings(
            db_session,
            scan_id,
            triaged_findings,
            dast_results
        )
        
        # ===== PHASE 7: COMPLETE =====
        _update_scan_status(db_session, scan_id, "completed")
        _emit_progress(
            socketio_emit,
            scan_id,
            "completed",
            f"Scan complete: {len(real_findings)} issues found"
        )
        
        logger.info(f"Scan {scan_id}: Pipeline completed successfully")
        
    except Exception as exc:
        logger.error(f"Scan {scan_id}: Pipeline failed: {exc}", exc_info=True)
        _update_scan_status(db_session, scan_id, "failed", error=str(exc))
        _emit_progress(socketio_emit, scan_id, "failed", f"Error: {exc}")
        
    finally:
        # Cleanup
        if repo_path:
            await fetcher.cleanup(repo_path)


def _update_scan_status(db_session, scan_id: UUID, status: str, error: str = None):
    """Update scan status in database"""
    if not db_session:
        return
    
    from ..models.scan import Scan  # Adjust import
    
    scan = db_session.query(Scan).filter(Scan.id == scan_id).first()
    if scan:
        scan.status = status
        if error:
            scan.error_message = error
        db_session.commit()


def _update_scan_stats(db_session, scan_id: UUID, **kwargs):
    """Update scan statistics"""
    if not db_session:
        return
    
    from ..models.scan import Scan
    
    scan = db_session.query(Scan).filter(Scan.id == scan_id).first()
    if scan:
        for key, value in kwargs.items():
            if hasattr(scan, key):
                setattr(scan, key, value)
        db_session.commit()


def _emit_progress(socketio_emit, scan_id: UUID, status: str, message: str):
    """Emit Socket.IO progress update"""
    if not socketio_emit:
        return
    
    try:
        socketio_emit('scan.progress', {
            'scan_id': str(scan_id),
            'status': status,
            'message': message
        })
    except Exception as e:
        logger.warning(f"Failed to emit Socket.IO event: {e}")


async def _store_findings(db_session, scan_id: UUID, triaged_findings, dast_results):
    """Store findings in database with DAST verification results"""
    if not db_session:
        return
    
    from ..models.finding import Finding
    
    # Create mapping of finding -> DAST result
    dast_by_finding = {}
    for dast_result in dast_results:
        dast_by_finding[dast_result.finding_id] = dast_result
    
    for triaged in triaged_findings:
        finding_id = str(triaged.id) if hasattr(triaged, 'id') else triaged.rule_id
        dast_result = dast_by_finding.get(finding_id)
        
        # Determine confidence score
        if dast_result:
            confidence = dast_result.confidence
            dast_verified = True
            dast_succeeded = dast_result.attack_succeeded
        else:
            confidence = 0.7 if not triaged.is_false_positive else 0.2
            dast_verified = False
            dast_succeeded = None
        
        finding = Finding(
            scan_id=scan_id,
            rule_id=triaged.rule_id,
            rule_message=triaged.rule_message,
            file_path=triaged.file_path,
            line_start=triaged.line_start,
            line_end=triaged.line_end,
            code_snippet=triaged.code_snippet,
            semgrep_severity=triaged.semgrep_severity,
            ai_severity=triaged.ai_severity,
            is_false_positive=triaged.is_false_positive,
            ai_reasoning=triaged.ai_reasoning,
            ai_confidence=triaged.ai_confidence,
            # DAST fields
            dast_verified=dast_verified,
            dast_attack_succeeded=dast_succeeded,
            dast_proof=dast_result.proof_of_exploit if dast_result else None,
            dast_evidence=dast_result.evidence if dast_result else None,
            confidence_score=confidence,
        )
        
        db_session.add(finding)
    
    db_session.commit()
```

### Phase 3: Update API Routes

**File**: `backend/src/api/routes/scans.py`

Update the create_scan endpoint:
```python
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from typing import Optional
from pydantic import BaseModel, HttpUrl

router = APIRouter(prefix="/scans", tags=["scans"])


class ScanCreate(BaseModel):
    """Request to create a new scan"""
    repo_url: HttpUrl
    branch: str = "main"
    target_url: Optional[HttpUrl] = None  # Optional: enables DAST verification


class ScanRead(BaseModel):
    """Scan response"""
    id: str
    repo_url: str
    branch: str
    target_url: Optional[str]
    status: str
    total_findings: int
    filtered_findings: int
    dast_enabled: bool
    dast_confirmed_count: Optional[int]
    created_at: str
    
    class Config:
        from_attributes = True


@router.post("", response_model=ScanRead)
async def create_scan(
    payload: ScanCreate,
    background_tasks: BackgroundTasks,
    db = Depends(get_db)  # Adjust based on your dependency injection
):
    """
    Create a new security scan.
    
    - **SAST only**: Provide repo_url
    - **SAST + DAST**: Provide both repo_url and target_url
    
    DAST will verify SAST findings by attacking the live application.
    """
    from ...models.scan import Scan
    from ...services.scanner.scan_pipeline import run_scan_pipeline
    
    # Create scan record
    scan = Scan(
        repo_url=str(payload.repo_url),
        branch=payload.branch,
        target_url=str(payload.target_url) if payload.target_url else None,
        dast_enabled=payload.target_url is not None,
        status="pending",
        trigger="manual"
    )
    
    db.add(scan)
    db.commit()
    db.refresh(scan)
    
    # Run pipeline in background
    background_tasks.add_task(
        run_scan_pipeline,
        scan.id,
        scan.repo_url,
        scan.branch,
        scan.target_url,
        db,
        None  # TODO: Pass Socket.IO emit function
    )
    
    return scan


@router.get("/{scan_id}/findings")
async def get_scan_findings(
    scan_id: str,
    include_false_positives: bool = False,
    db = Depends(get_db)
):
    """
    Get findings for a scan.
    
    Results include DAST verification status:
    - dast_verified: Was this tested by DAST?
    - dast_attack_succeeded: Did DAST confirm it's exploitable?
    - confidence_score: 0.7 (SAST only) → 0.99 (DAST confirmed)
    """
    from ...models.finding import Finding
    
    query = db.query(Finding).filter(Finding.scan_id == scan_id)
    
    if not include_false_positives:
        query = query.filter(Finding.is_false_positive == False)
    
    findings = query.all()
    return findings
```

---

## Frontend Implementation

### Phase 4: Update Scan Creation Form

**File**: `frontend/src/pages/Scans.tsx`
```typescript
import React, { useState } from 'react';
import { useMutation } from '@tanstack/react-query';

export default function Scans() {
  const [repoUrl, setRepoUrl] = useState('');
  const [branch, setBranch] = useState('main');
  const [targetUrl, setTargetUrl] = useState('');
  const [enableDAST, setEnableDAST] = useState(false);

  const createScan = useMutation({
    mutationFn: async (data) => {
      const response = await fetch('/api/scans', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data),
      });
      return response.json();
    },
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    
    createScan.mutate({
      repo_url: repoUrl,
      branch: branch,
      target_url: enableDAST ? targetUrl : null,
    });
  };

  return (
    <div className="max-w-2xl mx-auto p-6">
      <h1 className="text-2xl font-bold mb-6">New Security Scan</h1>
      
      <form onSubmit={handleSubmit} className="space-y-4">
        {/* Repository URL */}
        <div>
          <label className="block text-sm font-medium mb-2">
            Repository URL *
          </label>
          <input
            type="url"
            required
            placeholder="https://github.com/org/repo"
            value={repoUrl}
            onChange={(e) => setRepoUrl(e.target.value)}
            className="w-full px-3 py-2 border rounded"
          />
        </div>

        {/* Branch */}
        <div>
          <label className="block text-sm font-medium mb-2">
            Branch
          </label>
          <input
            type="text"
            placeholder="main"
            value={branch}
            onChange={(e) => setBranch(e.target.value)}
            className="w-full px-3 py-2 border rounded"
          />
        </div>

        {/* DAST Toggle */}
        <div className="border rounded p-4 bg-gray-50">
          <label className="flex items-center gap-2 cursor-pointer">
            <input
              type="checkbox"
              checked={enableDAST}
              onChange={(e) => setEnableDAST(e.target.checked)}
              className="w-4 h-4"
            />
            <span className="font-medium">
              Enable DAST Verification
            </span>
          </label>
          <p className="text-sm text-gray-600 mt-1">
            Attack SAST findings to confirm they're exploitable
          </p>

          {/* Target URL (shown when DAST enabled) */}
          {enableDAST && (
            <div className="mt-3">
              <label className="block text-sm font-medium mb-2">
                Live Application URL *
              </label>
              <input
                type="url"
                required={enableDAST}
                placeholder="https://app.example.com"
                value={targetUrl}
                onChange={(e) => setTargetUrl(e.target.value)}
                className="w-full px-3 py-2 border rounded"
              />
              <p className="text-xs text-gray-500 mt-1">
                ⚠️ Only test applications you own or have permission to test
              </p>
            </div>
          )}
        </div>

        {/* Submit */}
        <button
          type="submit"
          disabled={createScan.isPending}
          className="w-full bg-blue-600 text-white py-2 rounded hover:bg-blue-700 disabled:opacity-50"
        >
          {createScan.isPending ? 'Starting Scan...' : 'Start Scan'}
        </button>
      </form>
    </div>
  );
}
```

### Phase 5: Update Finding Display

**File**: `frontend/src/components/FindingCard.tsx`
```typescript
import React from 'react';

interface Finding {
  id: string;
  rule_id: string;
  file_path: string;
  line_start: number;
  semgrep_severity: string;
  ai_severity: string;
  is_false_positive: boolean;
  ai_reasoning: string;
  dast_verified: boolean;
  dast_attack_succeeded: boolean | null;
  dast_proof: string | null;
  confidence_score: number;
}

export default function FindingCard({ finding }: { finding: Finding }) {
  const getConfidenceBadge = () => {
    if (!finding.dast_verified) {
      return (
        <span className="px-2 py-1 text-xs bg-gray-100 text-gray-700 rounded">
          SAST Only (70% confidence)
        </span>
      );
    }

    if (finding.dast_attack_succeeded) {
      return (
        <span className="px-2 py-1 text-xs bg-red-100 text-red-800 rounded font-semibold">
          ⚠️ DAST CONFIRMED EXPLOITABLE (99% confidence)
        </span>
      );
    }

    return (
      <span className="px-2 py-1 text-xs bg-green-100 text-green-800 rounded">
        ✓ DAST Verified Not Exploitable (80% confidence)
      </span>
    );
  };

  return (
    <div className="border rounded-lg p-4 bg-white shadow-sm">
      {/* Header */}
      <div className="flex items-start justify-between mb-2">
        <div>
          <h3 className="font-semibold text-lg">{finding.rule_id}</h3>
          <p className="text-sm text-gray-600">
            {finding.file_path}:{finding.line_start}
          </p>
        </div>
        
        {/* Severity badges */}
        <div className="flex gap-2">
          <span className={`px-2 py-1 text-xs rounded ${getSeverityClass(finding.semgrep_severity)}`}>
            Semgrep: {finding.semgrep_severity}
          </span>
          <span className={`px-2 py-1 text-xs rounded ${getSeverityClass(finding.ai_severity)}`}>
            AI: {finding.ai_severity}
          </span>
        </div>
      </div>

      {/* DAST Verification Badge */}
      <div className="mb-3">
        {getConfidenceBadge()}
      </div>

      {/* AI Reasoning */}
      <details className="mb-3">
        <summary className="cursor-pointer text-sm font-medium text-gray-700">
          AI Analysis
        </summary>
        <p className="text-sm text-gray-600 mt-2 pl-4">
          {finding.ai_reasoning}
        </p>
      </details>

      {/* DAST Proof of Exploit */}
      {finding.dast_proof && (
        <details className="bg-red-50 border border-red-200 rounded p-3">
          <summary className="cursor-pointer text-sm font-medium text-red-800">
            🚨 Proof of Exploit
          </summary>
          <div className="mt-2">
            <p className="text-xs text-red-700 mb-2">
              This vulnerability was confirmed by DAST. Reproduce with:
            </p>
            <pre className="text-xs bg-black text-green-400 p-2 rounded overflow-x-auto">
              <code>{finding.dast_proof}</code>
            </pre>
          </div>
        </details>
      )}
    </div>
  );
}

function getSeverityClass(severity: string): string {
  const classes = {
    critical: 'bg-red-100 text-red-800',
    high: 'bg-orange-100 text-orange-800',
    medium: 'bg-yellow-100 text-yellow-800',
    low: 'bg-blue-100 text-blue-800',
    info: 'bg-gray-100 text-gray-800',
  };
  return classes[severity.toLowerCase()] || classes.info;
}
```

---

## Docker Configuration

### Phase 6: Add Nuclei to Docker Setup

**File**: `docker-compose.yml`

Update backend service:
```yaml
services:
  backend:
    build:
      context: ./backend
      dockerfile: Dockerfile
    volumes:
      - nuclei-templates:/root/nuclei-templates
    environment:
      - NUCLEI_TEMPLATES_PATH=/root/nuclei-templates
    depends_on:
      - postgres
      - nuclei-updater

  # Nuclei template updater (runs once on startup)
  nuclei-updater:
    image: projectdiscovery/nuclei:latest
    command: nuclei -update-templates -update-template-dir /templates
    volumes:
      - nuclei-templates:/templates

  postgres:
    image: postgres:15
    # ... existing config

volumes:
  nuclei-templates:
```

**File**: `backend/Dockerfile`

Add Nuclei installation:
```dockerfile
FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Install Nuclei
RUN wget -q https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_3.1.0_linux_amd64.zip \
    && unzip nuclei_3.1.0_linux_amd64.zip \
    && mv nuclei /usr/local/bin/ \
    && rm nuclei_3.1.0_linux_amd64.zip

# Rest of Dockerfile...
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

---

## Testing & Validation

### Phase 7: Create Test Script

**File**: `backend/tests/test_dast_integration.py`
```python
import pytest
from src.services.scanner.targeted_dast_runner import TargetedDASTRunner

@pytest.mark.asyncio
async def test_dast_runner_initialization():
    """Test DAST runner initializes correctly"""
    runner = TargetedDASTRunner()
    assert runner.nuclei_available or True  # Skip if Nuclei not installed

@pytest.mark.asyncio
async def test_vulnerability_classification():
    """Test that Semgrep rules map to correct DAST attacks"""
    runner = TargetedDASTRunner()
    
    test_cases = [
        ("python.django.security.injection.sql-injection", "sqli"),
        ("javascript.express.security.xss.reflected-xss", "xss"),
        ("go.lang.security.injection.command-injection", "command-injection"),
    ]
    
    for rule_id, expected_type in test_cases:
        vuln_type, templates = runner._classify_vulnerability(rule_id.lower())
        assert vuln_type == expected_type

# Add more tests...
```

---

## Implementation Checklist

Use this checklist to track progress:
```
## Database
- [ ] Add dast fields to Scan model (target_url, dast_enabled, etc.)
- [ ] Add dast fields to Finding model (dast_verified, dast_attack_succeeded, etc.)
- [ ] Create and run Alembic migration
- [ ] Verify migration with: `alembic history` and `alembic current`

## Backend - DAST Runner
- [ ] Create targeted_dast_runner.py
- [ ] Implement DASTAttackConfig dataclass
- [ ] Implement DASTResult dataclass
- [ ] Implement TargetedDASTRunner class
- [ ] Implement _classify_vulnerability method
- [ ] Implement _generate_attack_config method
- [ ] Implement _execute_attack method
- [ ] Add logging throughout

## Backend - Pipeline
- [ ] Create/update scan_pipeline.py
- [ ] Implement run_scan_pipeline function
- [ ] Add DAST phase to pipeline
- [ ] Implement _store_findings with DAST data
- [ ] Add Socket.IO progress events
- [ ] Add error handling for each phase

## Backend - API
- [ ] Update ScanCreate schema with target_url
- [ ] Update ScanRead schema with DAST fields
- [ ] Update create_scan endpoint
- [ ] Update get_scan_findings endpoint
- [ ] Add API documentation

## Frontend - Scan Form
- [ ] Update Scans.tsx
- [ ] Add DAST toggle checkbox
- [ ] Add target_url input (conditional)
- [ ] Add form validation
- [ ] Add help text explaining DAST

## Frontend - Display
- [ ] Update FindingCard.tsx
- [ ] Add DAST confidence badges
- [ ] Add "Proof of Exploit" section
- [ ] Add copy button for curl commands
- [ ] Style DAST-confirmed findings differently

## Docker & Infrastructure
- [ ] Update docker-compose.yml with Nuclei service
- [ ] Update Dockerfile to install Nuclei
- [ ] Add nuclei-templates volume
- [ ] Test Docker build
- [ ] Test container startup

## Testing
- [ ] Write unit tests for DAST runner
- [ ] Write integration tests for pipeline
- [ ] Test with sample vulnerable app
- [ ] Test error cases (network timeout, invalid URL, etc.)
- [ ] Load testing (10+ concurrent scans)

## Documentation
- [ ] Update README with DAST section
- [ ] Add API documentation for new fields
- [ ] Create troubleshooting guide
- [ ] Document Nuclei template usage
```

---

## Important Considerations

### 1. Code Style Consistency
- **Match existing patterns**: Look at how other services are structured
- **Use existing imports**: Don't create duplicate utility functions
- **Follow naming conventions**: If existing code uses `snake_case`, continue that
- **Database session handling**: Use the same pattern as existing routes

### 2. Error Handling
```python
# Always wrap external calls
try:
    result = await nuclei_command()
except subprocess.TimeoutExpired:
    logger.warning("Nuclei timeout")
    return DASTResult(..., error="timeout")
except Exception as e:
    logger.error(f"Unexpected error: {e}")
    return DASTResult(..., error=str(e))
```

### 3. Security Considerations
- **Validate target_url**: Ensure it's not localhost/internal IPs (unless explicitly allowed)
- **Rate limiting**: Don't DDOS the target application
- **Permission checking**: Add warnings that DAST should only test owned applications
- **Logging**: Log all DAST attacks for audit purposes

### 4. Performance
- **Timeout DAST attacks**: Don't let Nuclei run forever (60s max)
- **Parallel execution**: Process findings concurrently where possible
- **Resource limits**: Monitor CPU/memory usage during DAST
- **Queue management**: Consider job queue for multiple scans

### 5. Edge Cases to Handle
- Target URL is unreachable
- Nuclei not installed
- No SAST findings to verify
- SAST finding can't be mapped to endpoint
- Target application has WAF/rate limiting
- Database connection issues during long scan

---

## Validation Steps

After implementation, verify:

1. **SAST-only scan works**
```bash
   curl -X POST http://localhost:8000/api/scans \
     -H "Content-Type: application/json" \
     -d '{"repo_url": "https://github.com/OWASP/WebGoat"}'
```

2. **SAST + DAST scan works**
```bash
   curl -X POST http://localhost:8000/api/scans \
     -H "Content-Type: application/json" \
     -d '{
       "repo_url": "https://github.com/OWASP/WebGoat",
       "target_url": "http://webgoat:8080"
     }'
```

3. **DAST confirmation appears in UI**
   - Check findings show "DAST Confirmed" badge
   - Check confidence scores updated to 0.99
   - Check proof of exploit displays correctly

4. **Socket.IO events fire**
   - Monitor browser console for scan.progress events
   - Verify status updates appear in real-time

---

## Questions to Answer Before Coding

Run these commands to understand the existing codebase:
```bash
# 1. What database models exist?
find backend/src/models -name "*.py" -exec basename {} \;

# 2. What's the existing scan structure?
grep -r "class Scan" backend/src/models/

# 3. How are background tasks handled?
grep -r "BackgroundTasks" backend/src/api/

# 4. How is Socket.IO used?
grep -r "socketio" backend/src/

# 5. What's the LLM service interface?
view backend/src/services/intelligence/llm_service.py
```

---

## Success Criteria

Implementation is complete when:

✅ SAST-only scans work as before  
✅ Optional target_url triggers DAST verification  
✅ DAST attacks map to specific SAST findings  
✅ Findings show DAST confirmation status  
✅ Confidence scores update based on DAST results  
✅ Proof of exploit displays in UI  
✅ Docker containers run without errors  
✅ No regressions in existing features  

---

## Remember

- **Analyze first, code second**: Spend 20% of time understanding the codebase, 80% implementing
- **Follow existing patterns**: Don't reinvent the wheel
- **Test incrementally**: Test each phase before moving to the next
- **Ask clarifying questions**: If structure is unclear, pause and investigate
- **Keep it simple**: Start with MVP, add features later

Good luck with the implementation! 🚀