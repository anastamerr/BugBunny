from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import List

from fastapi import APIRouter, BackgroundTasks, Depends, status
from sqlalchemy.orm import Session

from ...api.deps import CurrentUser, get_current_user, get_db
from ...models import BugReport, Finding, Scan
from ...realtime import sio
from ...schemas.bug import BugReportRead
from ...schemas.demo import (
    DemoInjectBugRequest,
    DemoInjectBugResponse,
    DemoInjectScanRequest,
    DemoInjectScanResponse,
)
from ...schemas.scan import ScanRead
from ...services.bug_triage import AutoRouter, BugClassifier

router = APIRouter(prefix="/demo", tags=["demo"])


def _generate_bug_code() -> str:
    return f"DEMO-{uuid.uuid4().hex[:6].upper()}"


_classifier: BugClassifier | None = None
_router: AutoRouter | None = None


def _get_classifier() -> BugClassifier:
    global _classifier
    if _classifier is None:
        _classifier = BugClassifier()
    return _classifier


def _get_router() -> AutoRouter:
    global _router
    if _router is None:
        _router = AutoRouter()
    return _router


def _safe_target_url(value: str | None) -> str:
    return value or "https://demo.scanguard.local"


def _demo_sast_templates(target_url: str, include_dast_evidence: bool) -> List[dict]:
    base = [
        {
            "rule_id": "python.lang.security.sql.injection",
            "rule_message": "SQL query built from user input",
            "semgrep_severity": "ERROR",
            "finding_type": "sast",
            "ai_severity": "critical",
            "ai_confidence": 0.92,
            "ai_reasoning": (
                "User-controlled id is concatenated into the SQL string without "
                "parameterization."
            ),
            "exploitability": "Remote attacker can extract data by injecting SQL.",
            "file_path": "backend/app/routes/users.py",
            "line_start": 214,
            "line_end": 218,
            "code_snippet": 'query = f"SELECT * FROM users WHERE id = {user_id}"',
            "context_snippet": (
                "def get_user(user_id):\n"
                '    query = f"SELECT * FROM users WHERE id = {user_id}"\n'
                "    return db.execute(query)"
            ),
            "function_name": "get_user",
            "class_name": "UserController",
            "imports": ["sqlalchemy"],
            "confirmed_exploitable": True,
            "matched_at": f"{target_url}/api/users?id=1",
            "endpoint": target_url,
            "curl_command": (
                f'curl -i "{target_url}/api/users?id=1%27%20OR%201=1--"'
            ),
            "evidence": ["200 OK", "response contains 500 rows"],
            "priority_score": 96,
        },
        {
            "rule_id": "python.lang.security.command-injection",
            "rule_message": "User input passed to shell",
            "semgrep_severity": "ERROR",
            "finding_type": "sast",
            "ai_severity": "critical",
            "ai_confidence": 0.9,
            "ai_reasoning": "Filename input reaches a shell=True subprocess call.",
            "exploitability": "Attacker can execute arbitrary commands.",
            "file_path": "backend/app/utils/backup.py",
            "line_start": 88,
            "line_end": 92,
            "code_snippet": 'subprocess.run(f"tar -czf {name} {path}", shell=True)',
            "context_snippet": (
                "def create_backup(name, path):\n"
                '    subprocess.run(f"tar -czf {name} {path}", shell=True)'
            ),
            "function_name": "create_backup",
            "class_name": None,
            "priority_score": 90,
        },
        {
            "rule_id": "python.lang.security.ssrf",
            "rule_message": "Server-side request with user-controlled URL",
            "semgrep_severity": "ERROR",
            "finding_type": "sast",
            "ai_severity": "high",
            "ai_confidence": 0.84,
            "ai_reasoning": "User supplied URL is fetched without allowlist checks.",
            "exploitability": "Allows access to internal services.",
            "file_path": "backend/app/services/fetcher.py",
            "line_start": 47,
            "line_end": 49,
            "code_snippet": "requests.get(payload['url'], timeout=5)",
            "context_snippet": (
                "def fetch(payload):\n"
                "    return requests.get(payload['url'], timeout=5)"
            ),
            "function_name": "fetch",
            "class_name": None,
            "priority_score": 80,
        },
        {
            "rule_id": "python.lang.security.path-traversal",
            "rule_message": "File path built from request input",
            "semgrep_severity": "ERROR",
            "finding_type": "sast",
            "ai_severity": "high",
            "ai_confidence": 0.82,
            "ai_reasoning": "Filename is concatenated without validation.",
            "exploitability": "Attacker can read arbitrary files.",
            "file_path": "backend/app/routes/files.py",
            "line_start": 132,
            "line_end": 134,
            "code_snippet": 'open(f"/srv/data/{filename}", "rb")',
            "context_snippet": (
                "def download(filename):\n"
                '    return open(f"/srv/data/{filename}", "rb")'
            ),
            "function_name": "download",
            "class_name": None,
            "priority_score": 82,
        },
        {
            "rule_id": "python.lang.security.auth-bypass",
            "rule_message": "Hardcoded auth bypass token",
            "semgrep_severity": "ERROR",
            "finding_type": "sast",
            "ai_severity": "critical",
            "ai_confidence": 0.88,
            "ai_reasoning": "A hardcoded token short-circuits authentication.",
            "exploitability": "Attacker can log in with a static token.",
            "file_path": "backend/app/auth/session.py",
            "line_start": 61,
            "line_end": 66,
            "code_snippet": "if token == 'dev': return True",
            "context_snippet": (
                "def validate_token(token):\n"
                "    if token == 'dev':\n"
                "        return True"
            ),
            "function_name": "validate_token",
            "class_name": None,
            "priority_score": 92,
        },
        {
            "rule_id": "javascript.dom.xss",
            "rule_message": "Unsanitized HTML injected into the DOM",
            "semgrep_severity": "ERROR",
            "finding_type": "sast",
            "ai_severity": "high",
            "ai_confidence": 0.81,
            "ai_reasoning": "User content is rendered with dangerouslySetInnerHTML.",
            "exploitability": "Stored XSS executes in victims' browsers.",
            "file_path": "frontend/src/components/MarkdownPreview.tsx",
            "line_start": 52,
            "line_end": 54,
            "code_snippet": "dangerouslySetInnerHTML={{ __html: userHtml }}",
            "context_snippet": (
                "return (\n"
                "  <div dangerouslySetInnerHTML={{ __html: userHtml }} />\n"
                ")"
            ),
            "function_name": None,
            "class_name": None,
            "priority_score": 78,
        },
        {
            "rule_id": "python.lang.security.deserialization",
            "rule_message": "Pickle loads data from request",
            "semgrep_severity": "WARNING",
            "finding_type": "sast",
            "ai_severity": "medium",
            "ai_confidence": 0.72,
            "ai_reasoning": "Untrusted payload is passed to pickle.loads.",
            "exploitability": "Could lead to arbitrary code execution.",
            "file_path": "backend/app/utils/cache.py",
            "line_start": 39,
            "line_end": 40,
            "code_snippet": "pickle.loads(payload)",
            "context_snippet": "data = pickle.loads(payload)",
            "function_name": "load_cache",
            "class_name": None,
            "priority_score": 62,
        },
        {
            "rule_id": "python.lang.security.weak-hash",
            "rule_message": "Weak hash function (md5) used",
            "semgrep_severity": "WARNING",
            "finding_type": "sast",
            "ai_severity": "low",
            "ai_confidence": 0.65,
            "ai_reasoning": "MD5 is not collision resistant.",
            "exploitability": "Weakens integrity for sensitive tokens.",
            "file_path": "backend/app/auth/crypto.py",
            "line_start": 27,
            "line_end": 28,
            "code_snippet": "hashlib.md5(password.encode()).hexdigest()",
            "context_snippet": (
                "def hash_password(password):\n"
                "    return hashlib.md5(password.encode()).hexdigest()"
            ),
            "function_name": "hash_password",
            "class_name": None,
            "priority_score": 38,
        },
        {
            "rule_id": "generic.secrets",
            "rule_message": "Hardcoded API key",
            "semgrep_severity": "WARNING",
            "finding_type": "sast",
            "ai_severity": "low",
            "ai_confidence": 0.6,
            "ai_reasoning": "Static API key found in source code.",
            "exploitability": "Key could be harvested from repository history.",
            "file_path": "backend/app/config.py",
            "line_start": 12,
            "line_end": 12,
            "code_snippet": 'API_KEY = "sk_live_demo_123"',
            "context_snippet": 'API_KEY = "sk_live_demo_123"',
            "function_name": None,
            "class_name": None,
            "priority_score": 32,
        },
        {
            "rule_id": "CVE-2021-44228",
            "rule_message": "Vulnerable dependency log4j 2.14.1",
            "semgrep_severity": "ERROR",
            "finding_type": "sast",
            "ai_severity": "high",
            "ai_confidence": 1.0,
            "ai_reasoning": "Trivy reported a vulnerable dependency.",
            "exploitability": "Remote code execution via JNDI lookup.",
            "file_path": "backend/pom.xml",
            "line_start": 81,
            "line_end": 81,
            "code_snippet": "<version>2.14.1</version>",
            "context_snippet": "<artifactId>log4j-core</artifactId>",
            "description": "Log4j JNDI lookup vulnerability.",
            "remediation": "Upgrade to 2.17.1.",
            "cve_ids": ["CVE-2021-44228"],
            "priority_score": 88,
        },
    ]

    if not include_dast_evidence:
        sanitized = []
        for item in base:
            clean = dict(item)
            clean["confirmed_exploitable"] = False
            clean["matched_at"] = None
            clean["endpoint"] = None
            clean["curl_command"] = None
            clean["evidence"] = None
            sanitized.append(clean)
        return sanitized

    return [dict(item) for item in base]


def _demo_dast_templates(target_url: str) -> List[dict]:
    return [
        {
            "rule_id": "CVE-2021-41773",
            "rule_message": "Apache 2.4.49 path traversal",
            "semgrep_severity": "ERROR",
            "finding_type": "dast",
            "ai_severity": "high",
            "ai_confidence": 1.0,
            "ai_reasoning": "Nuclei confirmed a traversal payload.",
            "exploitability": "Confirmed via dynamic scan.",
            "file_path": f"{target_url}/cgi-bin/.%2e/.%2e/.%2e/etc/passwd",
            "line_start": 0,
            "line_end": 0,
            "matched_at": f"{target_url}/cgi-bin/.%2e/.%2e/.%2e/etc/passwd",
            "endpoint": target_url,
            "curl_command": (
                f'curl -i "{target_url}/cgi-bin/.%2e/.%2e/.%2e/etc/passwd"'
            ),
            "evidence": ["root:x:0:0:root:/root:/bin/bash"],
            "description": "Apache path traversal allows reading arbitrary files.",
            "remediation": "Upgrade Apache to 2.4.51 or apply backport patch.",
            "cve_ids": ["CVE-2021-41773"],
            "cwe_ids": ["CWE-22"],
            "confirmed_exploitable": True,
            "priority_score": 86,
        },
        {
            "rule_id": "open-redirect",
            "rule_message": "Open redirect in redirect endpoint",
            "semgrep_severity": "WARNING",
            "finding_type": "dast",
            "ai_severity": "medium",
            "ai_confidence": 1.0,
            "ai_reasoning": "Nuclei confirmed a redirect to an external host.",
            "exploitability": "Confirmed via dynamic scan.",
            "file_path": f"{target_url}/redirect?next=https://evil.example",
            "line_start": 0,
            "line_end": 0,
            "matched_at": f"{target_url}/redirect?next=https://evil.example",
            "endpoint": target_url,
            "curl_command": (
                f'curl -i "{target_url}/redirect?next=https://evil.example"'
            ),
            "evidence": ["302 redirect to https://evil.example"],
            "description": "Open redirect can be abused for phishing.",
            "remediation": "Validate redirect targets against an allowlist.",
            "cwe_ids": ["CWE-601"],
            "confirmed_exploitable": True,
            "priority_score": 60,
        },
    ]


def _build_extra_real_finding(scan_id: uuid.UUID, index: int) -> Finding:
    line_no = 120 + index
    severity = "medium" if index % 2 == 0 else "low"
    semgrep = "WARNING" if severity == "medium" else "INFO"
    score = 58 if severity == "medium" else 32
    return Finding(
        scan_id=scan_id,
        rule_id=f"demo.extra.finding.{index + 1}",
        rule_message="Demo security finding",
        semgrep_severity=semgrep,
        finding_type="sast",
        ai_severity=severity,
        is_false_positive=False,
        ai_reasoning="Synthetic demo issue for presentation purposes.",
        ai_confidence=0.6,
        exploitability="Limited impact but worth addressing.",
        file_path="backend/app/demo.py",
        line_start=line_no,
        line_end=line_no,
        code_snippet="demo_placeholder = True",
        context_snippet="demo_placeholder = True",
        function_name=None,
        class_name=None,
        is_test_file=False,
        is_generated=False,
        imports=None,
        status="new",
        priority_score=score,
    )


def _build_false_positive(scan_id: uuid.UUID, index: int) -> Finding:
    line_no = 20 + index
    return Finding(
        scan_id=scan_id,
        rule_id="python.lang.security.audit.eval",
        rule_message="Use of eval with user input",
        semgrep_severity="WARNING",
        finding_type="sast",
        ai_severity="low",
        is_false_positive=True,
        ai_reasoning="Test helper uses static input only.",
        ai_confidence=0.12,
        exploitability="Not exploitable in production.",
        file_path=f"tests/test_helpers_{index % 8}.py",
        line_start=line_no,
        line_end=line_no,
        code_snippet="eval('1 + 1')",
        context_snippet="def test_eval_helper():\n    eval('1 + 1')",
        function_name="test_eval_helper",
        class_name=None,
        is_test_file=True,
        is_generated=False,
        imports=["pytest"],
        status="dismissed",
        priority_score=0,
    )


@router.post(
    "/inject-bug",
    response_model=DemoInjectBugResponse,
    status_code=status.HTTP_201_CREATED,
)
async def inject_bug(
    payload: DemoInjectBugRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
) -> DemoInjectBugResponse:
    classifier = _get_classifier()
    classification = classifier.classify(payload.title, payload.description or "")

    bug = BugReport(
        bug_id=payload.bug_id or _generate_bug_code(),
        source=payload.source,
        title=payload.title,
        description=payload.description,
        created_at=payload.created_at or datetime.now(timezone.utc),
        reporter=payload.reporter,
        labels=payload.labels,
        classified_type=classification["type"],
        classified_component=classification["component"],
        classified_severity=classification["severity"],
        confidence_score=classification["overall_confidence"],
        status="new",
    )
    db.add(bug)
    db.commit()
    db.refresh(bug)

    auto_router = _get_router()
    routing = auto_router.route_bug(classification)
    bug.assigned_team = routing["team"]
    db.add(bug)
    db.commit()
    db.refresh(bug)

    bug_event = BugReportRead.model_validate(bug).model_dump(mode="json")
    background_tasks.add_task(sio.emit, "bug.created", bug_event)

    return DemoInjectBugResponse(
        bug=bug,
    )


@router.post(
    "/inject-scan",
    response_model=DemoInjectScanResponse,
    status_code=status.HTTP_201_CREATED,
)
async def inject_scan(
    payload: DemoInjectScanRequest,
    background_tasks: BackgroundTasks,
    current_user: CurrentUser = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> DemoInjectScanResponse:
    scan_type = payload.scan_type.value
    repo_url = (
        None
        if scan_type == "dast"
        else (payload.repo_url or "https://github.com/semgrep/semgrep-pro-tests")
    )
    target_url = (
        None
        if scan_type == "sast"
        else (payload.target_url or "https://demo.scanguard.local")
    )
    safe_target = _safe_target_url(target_url)

    scan = Scan(
        user_id=current_user.id,
        repo_id=None,
        repo_url=repo_url,
        branch=(payload.branch or "main").strip() or "main",
        scan_type=scan_type,
        target_url=target_url,
        status="completed",
        trigger="manual",
        total_findings=0,
        filtered_findings=0,
        dast_findings=0,
        detected_languages=["python", "typescript"],
        rulesets=["p/python", "p/javascript"],
        scanned_files=284,
        semgrep_version="1.69.0",
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    include_sast = scan_type in {"sast", "both"}
    include_dast = scan_type in {"dast", "both"}

    templates: List[dict] = []
    if include_sast:
        templates.extend(_demo_sast_templates(safe_target, include_dast))
    if include_dast:
        templates.extend(_demo_dast_templates(safe_target))

    requested_real = max(0, int(payload.real_findings))
    selected = templates[:requested_real]
    findings: List[Finding] = [
        Finding(scan_id=scan.id, status="new", **template) for template in selected
    ]
    if include_sast and requested_real > len(selected):
        for index in range(requested_real - len(selected)):
            findings.append(_build_extra_real_finding(scan.id, index))

    false_count = max(0, int(payload.false_positives)) if include_sast else 0
    for index in range(false_count):
        findings.append(_build_false_positive(scan.id, index))

    db.add_all(findings)
    db.commit()

    real_count = sum(1 for item in findings if not item.is_false_positive)
    dast_count = sum(1 for item in findings if item.finding_type == "dast")
    scan.total_findings = len(findings)
    scan.filtered_findings = real_count
    scan.dast_findings = dast_count
    db.add(scan)
    db.commit()
    db.refresh(scan)

    scan_event = ScanRead.model_validate(scan).model_dump(mode="json")
    background_tasks.add_task(sio.emit, "scan.created", scan_event)
    background_tasks.add_task(
        sio.emit,
        "scan.completed",
        {
            "scan_id": str(scan.id),
            "status": "completed",
            "total_findings": scan.total_findings,
            "filtered_findings": scan.filtered_findings,
            "dast_findings": scan.dast_findings,
        },
    )

    return DemoInjectScanResponse(
        scan=scan,
        findings_created=len(findings),
        real_findings=real_count,
        false_positives=false_count,
    )
