from __future__ import annotations

import asyncio
import uuid
from typing import TYPE_CHECKING, Optional

from sqlalchemy.orm import Session

from ...db.session import SessionLocal
from ...models import Finding, Scan, UserSettings
from ...realtime import sio
from .ai_triage import AITriageEngine
from .correlation import correlate_findings
from .context_extractor import ContextExtractor
from .finding_aggregator import FindingAggregator
from .dast_runner import DASTRunner
from .deployment_service import DeploymentService
from .targeted_dast_runner import TargetedDASTRunner
from .dependency_health_scanner import DependencyHealthScanner
from .dependency_scanner import DependencyScanner
from .repo_fetcher import RepoFetcher
from .semgrep_runner import SemgrepRunner

if TYPE_CHECKING:
    from ...integrations.pinecone_client import PineconeService


PAUSE_POLL_SECONDS = 2.0
TRIAGE_BATCH_SIZE = 8


class ScanCancelled(RuntimeError):
    pass


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
    dependency_health_scanner = DependencyHealthScanner()
    deployment_service = DeploymentService()

    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        github_token = None
        commit_sha = scan.commit_sha if scan else None
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
        targeted_dast_runner = TargetedDASTRunner(
            auth_headers=scan.dast_auth_headers if scan else None,
            cookies=scan.dast_cookies if scan else None,
        )

        triaged = []
        dast_findings = []
        dependency_findings = []
        dependency_health_findings = []
        dast_error: str | None = None
        dependency_health_error: str | None = None
        dependency_health_enabled = True
        if scan is not None and scan.dependency_health_enabled is not None:
            dependency_health_enabled = scan.dependency_health_enabled

        if scan_type in {"sast", "both"}:
            if not repo_url:
                raise RuntimeError("repo_url is required for SAST scans")

            await _wait_for_resume(db, scan_id)
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
            commit_sha = await fetcher.get_commit_sha(repo_path) or commit_sha
            if commit_sha:
                commit_url = _build_commit_url(repo_url, commit_sha)
                _update_scan(
                    db,
                    scan_id,
                    commit_sha=commit_sha,
                    commit_url=commit_url,
                )
                await sio.emit(
                    "scan.updated",
                    {
                        "scan_id": str(scan_id),
                        "commit_sha": commit_sha,
                        "commit_url": commit_url,
                    },
                )
            if resolved_branch != branch:
                branch = resolved_branch
                _update_scan(db, scan_id, branch=resolved_branch)
                await sio.emit(
                    "scan.updated",
                    {"scan_id": str(scan_id), "branch": resolved_branch},
                )
            await _wait_for_resume(db, scan_id)
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

            await _wait_for_resume(db, scan_id)
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
            triage_inputs = list(zip(raw_findings, contexts))
            triaged = []
            for offset in range(0, len(triage_inputs), TRIAGE_BATCH_SIZE):
                await _wait_for_resume(db, scan_id)
                batch = triage_inputs[offset : offset + TRIAGE_BATCH_SIZE]
                triaged.extend(await triage.triage_batch(batch))
            # Apply dedupe and update Pinecone index for actionable findings.
            triaged = await aggregator.process(triaged)

            if dependency_scanner.is_available():
                await _wait_for_resume(db, scan_id)
                dependency_findings = await dependency_scanner.scan(repo_path)
            if dependency_health_enabled:
                try:
                    await _wait_for_resume(db, scan_id)
                    dependency_health_findings = await dependency_health_scanner.scan(
                        repo_path
                    )
                except Exception as exc:
                    dependency_health_error = (
                        f"Dependency health error: {exc}"
                    )

        # Track which findings were tested by targeted DAST
        targeted_dast_results = []
        dast_confirmed_count = 0

        if scan_type == "both":
            if not repo_path:
                raise RuntimeError(
                    "SAST repository is required to deploy for DAST verification."
                )
            if not commit_sha:
                raise RuntimeError(
                    "Commit SHA is required to deploy for DAST verification."
                )
            if not deployment_service.is_configured():
                raise RuntimeError(
                    "DAST verification requires DAST_DEPLOY_SCRIPT to deploy the SAST commit."
                )

            await _wait_for_resume(db, scan_id)
            _update_scan(db, scan_id, status="scanning")
            await sio.emit(
                "scan.updated",
                {"scan_id": str(scan_id), "status": "scanning", "phase": "deploy"},
            )

            target_url = await deployment_service.deploy(
                repo_path, commit_sha, branch
            )
            _update_scan(db, scan_id, target_url=target_url)
            await sio.emit(
                "scan.updated",
                {"scan_id": str(scan_id), "target_url": target_url},
            )

        if scan_type in {"dast", "both"} and target_url:
            await _wait_for_resume(db, scan_id)
            _update_scan(db, scan_id, status="scanning")
            await sio.emit(
                "scan.updated",
                {"scan_id": str(scan_id), "status": "scanning", "phase": "DAST"},
            )

            # Run targeted DAST if we have SAST findings to verify
            if triaged:
                await sio.emit(
                    "scan.updated",
                    {
                        "scan_id": str(scan_id),
                        "status": "scanning",
                        "phase": "DAST",
                        "message": f"Targeting {len([f for f in triaged if not f.is_false_positive])} SAST findings for verification",
                    },
                )
                targeted_dast_results = await targeted_dast_runner.attack_findings(
                    target_url,
                    triaged,
                    str(repo_path) if repo_path else "",
                )
                # Map results back to findings
                triaged, dast_confirmed_count = targeted_dast_runner.map_results_to_findings(
                    triaged,
                    targeted_dast_results,
                    str(repo_path) if repo_path else "",
                )
                if targeted_dast_runner.last_error:
                    dast_error = f"Targeted DAST error: {targeted_dast_runner.last_error}"

            # Also run blind DAST scan for additional coverage
            if dast_runner.is_available():
                dast_findings = await dast_runner.scan(target_url)
                if dast_runner.last_error:
                    dast_error = _merge_error_message(
                        dast_error,
                        f"DAST error: {dast_runner.last_error}",
                    ) if dast_error else f"DAST error: {dast_runner.last_error}"
            else:
                dast_error = _merge_error_message(
                    dast_error,
                    "DAST error: Nuclei binary not found.",
                ) if dast_error else "DAST error: Nuclei binary not found."

            _update_scan(
                db,
                scan_id,
                dast_findings=len(dast_findings),
                dast_confirmed_count=dast_confirmed_count,
            )
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

        if dependency_health_error:
            error_message = _merge_error_message(
                scan.error_message if scan else None,
                dependency_health_error,
            )
            _update_scan(db, scan_id, error_message=error_message)

        await _wait_for_resume(db, scan_id)
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

        # Build mapping of finding IDs to targeted DAST results
        dast_result_map = {r.finding_id: r for r in targeted_dast_results}

        for item in triaged:
            priority_score = aggregator.calculate_priority(item)
            if item.is_false_positive:
                priority_score = 0

            # Check if this finding was tested by targeted DAST
            finding_key = f"{item.rule_id}:{item.file_path}:{item.line_start}"
            dast_result = dast_result_map.get(finding_key)
            dast_status = (
                dast_result.verification_status
                if dast_result
                else "not_run"
            )
            was_dast_verified = dast_status != "not_run"

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
                    dast_verified=was_dast_verified,
                    dast_verification_status=dast_status,
                    is_reachable=getattr(item, "is_reachable", True),
                    reachability_score=getattr(item, "reachability_score", 1.0),
                    reachability_reason=getattr(item, "reachability_reason", None),
                    entry_points=getattr(item, "entry_points", None),
                    call_path=getattr(item, "call_path", None),
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
                    dast_verified=True,
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

        for item in dependency_health_findings:
            ai_severity = _normalize_ai_severity(item.ai_severity)
            semgrep_severity = _semgrep_from_ai(ai_severity)
            priority_score = _priority_from_dependency_health(item)
            rule_label = item.installed_version or item.requirement
            rule_message = (
                f"{item.status.capitalize()} dependency: {item.package_name}"
            )
            if rule_label:
                rule_message = f"{rule_message} ({rule_label})"
            code_snippet = (
                f"{item.package_name} {rule_label}".strip()
                if rule_label
                else item.package_name
            )
            exploitability = (
                "Deprecated dependency with operational or security risk."
                if item.status == "deprecated"
                else "Outdated dependency may miss fixes and support."
            )
            db.add(
                Finding(
                    scan_id=scan_id,
                    rule_id=f"dependency.{item.status}",
                    rule_message=rule_message,
                    semgrep_severity=semgrep_severity,
                    finding_type="sast",
                    ai_severity=ai_severity,
                    is_false_positive=False,
                    ai_reasoning=item.ai_reasoning,
                    ai_confidence=item.ai_confidence,
                    exploitability=exploitability,
                    file_path=item.file_path,
                    line_start=0,
                    line_end=0,
                    code_snippet=code_snippet,
                    context_snippet=code_snippet,
                    function_name=None,
                    class_name=None,
                    is_test_file=False,
                    is_generated=False,
                    imports=None,
                    description=item.description,
                    remediation=item.remediation,
                    cve_ids=None,
                    cwe_ids=None,
                    confirmed_exploitable=False,
                    status="new",
                    priority_score=priority_score,
                )
            )

        db.commit()

        total_findings = (
            len(triaged)
            + len(unmatched_dast)
            + len(dependency_findings)
            + len(dependency_health_findings)
        )
        filtered_sast = sum(
            1 for finding in triaged if not finding.is_false_positive
        )
        filtered_findings = (
            filtered_sast
            + len(unmatched_dast)
            + len(dependency_findings)
            + len(dependency_health_findings)
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
    except ScanCancelled:
        return
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


async def _wait_for_resume(db: Session, scan_id: uuid.UUID) -> None:
    while True:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            raise ScanCancelled("Scan was deleted.")
        if not scan.is_paused:
            return
        await asyncio.sleep(PAUSE_POLL_SECONDS)
        db.expire_all()


def _update_scan(
    db: Session,
    scan_id: uuid.UUID,
    status: Optional[str] = None,
    branch: Optional[str] = None,
    commit_sha: Optional[str] = None,
    commit_url: Optional[str] = None,
    target_url: Optional[str] = None,
    total_findings: Optional[int] = None,
    filtered_findings: Optional[int] = None,
    dast_findings: Optional[int] = None,
    dast_confirmed_count: Optional[int] = None,
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
    if commit_sha is not None:
        scan.commit_sha = commit_sha
    if commit_url is not None:
        scan.commit_url = commit_url
    if target_url is not None:
        scan.target_url = target_url
    if total_findings is not None:
        scan.total_findings = total_findings
    if filtered_findings is not None:
        scan.filtered_findings = filtered_findings
    if dast_findings is not None:
        scan.dast_findings = dast_findings
    if dast_confirmed_count is not None:
        scan.dast_confirmed_count = dast_confirmed_count
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


def _get_pinecone() -> Optional["PineconeService"]:
    try:
        from ...integrations.pinecone_client import PineconeService

        return PineconeService()
    except Exception:
        return None


def _build_commit_url(repo_url: str | None, commit_sha: str | None) -> str | None:
    if not repo_url or not commit_sha:
        return None
    repo = repo_url.strip().rstrip("/")
    if repo.endswith(".git"):
        repo = repo[:-4]
    if not repo:
        return None
    return f"{repo}/commit/{commit_sha}"


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


def _semgrep_from_ai(ai_severity: str | None) -> str:
    normalized = (ai_severity or "").lower()
    if normalized in {"critical", "high"}:
        return "ERROR"
    if normalized == "medium":
        return "WARNING"
    return "INFO"


def _priority_from_dependency_health(item) -> int:
    severity_weights = {
        "critical": 90,
        "high": 75,
        "medium": 55,
        "low": 35,
        "info": 10,
    }
    base = severity_weights.get(getattr(item, "ai_severity", "low"), 30)
    confidence = getattr(item, "ai_confidence", 0.5) or 0.5
    score = base * (0.5 + 0.5 * max(0.0, min(confidence, 1.0)))
    dependency_type = (getattr(item, "dependency_type", "") or "").lower()
    if dependency_type in {"dev", "optional", "peer"}:
        score -= 10
    if getattr(item, "status", "") == "deprecated" and getattr(item, "is_yanked", False):
        score += 10
    return max(0, min(100, int(round(score))))


def _merge_error_message(current: Optional[str], new_message: str) -> str:
    if not current:
        return new_message
    if new_message in current:
        return current
    return f"{current}\n{new_message}"
