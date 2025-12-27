from __future__ import annotations

import uuid
from typing import Optional

from sqlalchemy.orm import Session

from ...db.session import SessionLocal
from ...integrations.pinecone_client import PineconeService
from ...models import Finding, Scan, UserSettings
from ...realtime import sio
from .ai_triage import AITriageEngine
from .correlation import correlate_findings
from .context_extractor import ContextExtractor
from .finding_aggregator import FindingAggregator
from .dast_runner import DASTRunner
from .dependency_scanner import DependencyScanner
from .repo_fetcher import RepoFetcher
from .semgrep_runner import SemgrepRunner


async def run_scan_pipeline(
    scan_id: uuid.UUID,
    repo_url: str | None,
    branch: str,
    scan_type: str = "sast",
    target_url: str | None = None,
) -> None:
    db = SessionLocal()
    repo_path = None
    fetcher = RepoFetcher()
    runner = SemgrepRunner()
    extractor = ContextExtractor()
    triage = AITriageEngine()
    pinecone = _get_pinecone()
    aggregator = FindingAggregator(pinecone)
    dast_runner = DASTRunner()
    dependency_scanner = DependencyScanner()

    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        github_token = None
        if scan and scan.user_id:
            settings = (
                db.query(UserSettings)
                .filter(UserSettings.user_id == scan.user_id)
                .first()
            )
            if settings and settings.github_token:
                github_token = settings.github_token

        scan_type = (scan_type or "sast").lower()
        target_url = target_url or (scan.target_url if scan else None)

        triaged = []
        dast_findings = []
        dependency_findings = []
        dast_error: str | None = None

        if scan_type in {"sast", "both"}:
            if not repo_url:
                raise RuntimeError("repo_url is required for SAST scans")

            _update_scan(db, scan_id, status="cloning")
            await sio.emit(
                "scan.updated",
                {"scan_id": str(scan_id), "status": "cloning", "phase": "SAST"},
            )

            repo_path, resolved_branch = await fetcher.clone(
                repo_url,
                branch=branch,
                github_token=github_token,
            )
            if resolved_branch != branch:
                branch = resolved_branch
                _update_scan(db, scan_id, branch=resolved_branch)
                await sio.emit(
                    "scan.updated",
                    {"scan_id": str(scan_id), "branch": resolved_branch},
                )
            _update_scan(db, scan_id, status="scanning")
            await sio.emit(
                "scan.updated",
                {"scan_id": str(scan_id), "status": "scanning", "phase": "SAST"},
            )

            languages, scanned_files = fetcher.analyze_repo(repo_path)
            configs = runner.resolve_configs(repo_path, languages)
            semgrep_version = runner.get_version()
            rulesets_used = runner.format_config_labels(repo_path, configs) or ["auto"]
            _update_scan(
                db,
                scan_id,
                detected_languages=languages,
                rulesets=rulesets_used,
                scanned_files=scanned_files,
                semgrep_version=semgrep_version,
            )
            raw_findings = await runner.scan(repo_path, languages)

            _update_scan(
                db,
                scan_id,
                status="analyzing",
                total_findings=len(raw_findings),
            )
            await sio.emit(
                "scan.updated",
                {"scan_id": str(scan_id), "status": "analyzing", "phase": "SAST"},
            )

            contexts = [extractor.extract(repo_path, finding) for finding in raw_findings]
            triaged = await triage.triage_batch(list(zip(raw_findings, contexts)))
            # Update priority scores and Pinecone dedupe index.
            await aggregator.process(triaged)

            if dependency_scanner.is_available():
                dependency_findings = await dependency_scanner.scan(repo_path)

        if scan_type in {"dast", "both"} and target_url:
            _update_scan(db, scan_id, status="scanning")
            await sio.emit(
                "scan.updated",
                {"scan_id": str(scan_id), "status": "scanning", "phase": "DAST"},
            )
            if dast_runner.is_available():
                dast_findings = await dast_runner.scan(target_url)
                if dast_runner.last_error:
                    dast_error = f"DAST error: {dast_runner.last_error}"
            else:
                dast_error = "DAST error: Nuclei binary not found."
            _update_scan(db, scan_id, dast_findings=len(dast_findings))
            if dast_error:
                error_message = _merge_error_message(
                    scan.error_message if scan else None,
                    dast_error,
                )
                if scan_type == "dast":
                    _update_scan(
                        db,
                        scan_id,
                        status="failed",
                        error_message=error_message,
                    )
                    await sio.emit(
                        "scan.failed",
                        {
                            "scan_id": str(scan_id),
                            "status": "failed",
                            "error": dast_error,
                        },
                    )
                    return
                _update_scan(db, scan_id, error_message=error_message)

        _update_scan(db, scan_id, status="analyzing")
        await sio.emit(
            "scan.updated",
            {
                "scan_id": str(scan_id),
                "status": "analyzing",
                "phase": "correlation",
            },
        )

        triaged, unmatched_dast = correlate_findings(triaged, dast_findings)

        for item in triaged:
            priority_score = aggregator.calculate_priority(item)
            if item.is_false_positive:
                priority_score = 0

            db.add(
                Finding(
                    scan_id=scan_id,
                    rule_id=item.rule_id,
                    rule_message=item.rule_message,
                    semgrep_severity=item.semgrep_severity,
                    finding_type="sast",
                    ai_severity=item.ai_severity,
                    is_false_positive=item.is_false_positive,
                    ai_reasoning=item.ai_reasoning,
                    ai_confidence=item.ai_confidence,
                    exploitability=item.exploitability,
                    file_path=item.file_path,
                    line_start=item.line_start,
                    line_end=item.line_end,
                    code_snippet=item.code_snippet,
                    context_snippet=item.context_snippet,
                    function_name=item.function_name,
                    class_name=item.class_name,
                    is_test_file=item.is_test_file,
                    is_generated=item.is_generated,
                    imports=item.imports,
                    matched_at=item.dast_matched_at,
                    endpoint=item.dast_endpoint,
                    curl_command=item.dast_curl_command,
                    evidence=item.dast_evidence,
                    cve_ids=item.dast_cve_ids,
                    cwe_ids=item.dast_cwe_ids,
                    confirmed_exploitable=item.confirmed_exploitable,
                    status="new",
                    priority_score=priority_score,
                )
            )

        for item in unmatched_dast:
            severity = _normalize_dast_severity(item.severity)
            ai_severity = _normalize_ai_severity(item.severity)
            priority_score = _priority_from_dast(item.severity)
            db.add(
                Finding(
                    scan_id=scan_id,
                    rule_id=item.template_id,
                    rule_message=item.template_name,
                    semgrep_severity=severity,
                    finding_type="dast",
                    ai_severity=ai_severity,
                    is_false_positive=False,
                    ai_reasoning="Confirmed by dynamic analysis (Nuclei).",
                    ai_confidence=1.0,
                    exploitability="Confirmed via dynamic scan.",
                    file_path=item.matched_at or item.endpoint,
                    line_start=0,
                    line_end=0,
                    code_snippet=None,
                    context_snippet=None,
                    function_name=None,
                    class_name=None,
                    is_test_file=False,
                    is_generated=False,
                    imports=None,
                    matched_at=item.matched_at,
                    endpoint=item.endpoint,
                    curl_command=item.curl_command,
                    evidence=item.evidence,
                    description=item.description,
                    remediation=item.remediation,
                    cve_ids=item.cve_ids,
                    cwe_ids=item.cwe_ids,
                    confirmed_exploitable=True,
                    status="new",
                    priority_score=priority_score,
                )
            )

        for item in dependency_findings:
            severity = _normalize_dependency_severity(item.severity)
            ai_severity = _normalize_ai_severity(item.severity)
            priority_score = _priority_from_dependency(item.severity, item.cvss_score)
            package_label = f"{item.package_name} {item.installed_version}".strip()
            rule_message = f"Vulnerable dependency {package_label}".strip()
            remediation = (
                f"Upgrade to {item.fixed_version}"
                if item.fixed_version and item.fixed_version != "No fix available"
                else "No fix available"
            )
            db.add(
                Finding(
                    scan_id=scan_id,
                    rule_id=item.cve_id,
                    rule_message=rule_message,
                    semgrep_severity=severity,
                    finding_type="sast",
                    ai_severity=ai_severity,
                    is_false_positive=False,
                    ai_reasoning="Trivy reported a vulnerable dependency.",
                    ai_confidence=1.0,
                    exploitability=(
                        f"Known vulnerability in {package_label}."
                        if package_label
                        else "Known dependency vulnerability."
                    ),
                    file_path=item.target or f"dependency:{item.package_name}",
                    line_start=0,
                    line_end=0,
                    code_snippet=None,
                    context_snippet=None,
                    function_name=None,
                    class_name=None,
                    is_test_file=False,
                    is_generated=False,
                    imports=None,
                    description=item.description,
                    remediation=remediation,
                    cve_ids=[item.cve_id],
                    cwe_ids=None,
                    confirmed_exploitable=False,
                    status="new",
                    priority_score=priority_score,
                )
            )

        db.commit()

        total_findings = len(triaged) + len(unmatched_dast) + len(dependency_findings)
        filtered_sast = sum(
            1 for finding in triaged if not finding.is_false_positive
        )
        filtered_findings = (
            filtered_sast + len(unmatched_dast) + len(dependency_findings)
        )

        _update_scan(
            db,
            scan_id,
            status="completed",
            total_findings=total_findings,
            filtered_findings=filtered_findings,
        )

        await sio.emit(
            "scan.completed",
            {
                "scan_id": str(scan_id),
                "status": "completed",
                "total_findings": total_findings,
                "filtered_findings": filtered_findings,
                "dast_findings": len(dast_findings),
            },
        )
    except Exception as exc:
        _update_scan(db, scan_id, status="failed", error_message=str(exc))
        await sio.emit(
            "scan.failed",
            {"scan_id": str(scan_id), "status": "failed", "error": str(exc)},
        )
    finally:
        if repo_path:
            await fetcher.cleanup(repo_path)
        db.close()


def _update_scan(
    db: Session,
    scan_id: uuid.UUID,
    status: Optional[str] = None,
    branch: Optional[str] = None,
    total_findings: Optional[int] = None,
    filtered_findings: Optional[int] = None,
    dast_findings: Optional[int] = None,
    error_message: Optional[str] = None,
    detected_languages: Optional[list[str]] = None,
    rulesets: Optional[list[str]] = None,
    scanned_files: Optional[int] = None,
    semgrep_version: Optional[str] = None,
) -> None:
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        return
    if status is not None:
        scan.status = status
    if branch is not None:
        scan.branch = branch
    if total_findings is not None:
        scan.total_findings = total_findings
    if filtered_findings is not None:
        scan.filtered_findings = filtered_findings
    if dast_findings is not None:
        scan.dast_findings = dast_findings
    if error_message is not None:
        scan.error_message = error_message
    if detected_languages is not None:
        scan.detected_languages = detected_languages
    if rulesets is not None:
        scan.rulesets = rulesets
    if scanned_files is not None:
        scan.scanned_files = scanned_files
    if semgrep_version is not None:
        scan.semgrep_version = semgrep_version

    db.add(scan)
    db.commit()
    db.refresh(scan)


def _get_pinecone() -> Optional[PineconeService]:
    try:
        return PineconeService()
    except Exception:
        return None


def _normalize_dast_severity(value: str) -> str:
    normalized = (value or "").lower()
    if normalized in {"critical", "high"}:
        return "ERROR"
    if normalized in {"medium", "moderate"}:
        return "WARNING"
    return "INFO"


def _normalize_ai_severity(value: str) -> str:
    normalized = (value or "").lower()
    if normalized in {"critical", "high", "medium", "low", "info"}:
        return normalized
    return "info"


def _normalize_dependency_severity(value: str) -> str:
    normalized = (value or "").lower()
    if normalized in {"critical", "high"}:
        return "ERROR"
    if normalized in {"medium", "moderate"}:
        return "WARNING"
    return "INFO"


def _priority_from_dast(value: str) -> int:
    mapping = {
        "critical": 95,
        "high": 80,
        "medium": 60,
        "moderate": 55,
        "low": 40,
        "info": 15,
    }
    return mapping.get((value or "").lower(), 35)


def _priority_from_dependency(value: str, cvss_score: Optional[float]) -> int:
    if cvss_score is not None:
        if cvss_score >= 9.0:
            return 95
        if cvss_score >= 7.0:
            return 80
        if cvss_score >= 4.0:
            return 55
        return 35
    return _priority_from_dast(value)


def _merge_error_message(current: Optional[str], new_message: str) -> str:
    if not current:
        return new_message
    if new_message in current:
        return current
    return f"{current}\n{new_message}"
