from __future__ import annotations

import uuid
from typing import Optional

from sqlalchemy.orm import Session

from ...db.session import SessionLocal
from ...integrations.pinecone_client import PineconeService
from ...models import Finding, Scan
from ...realtime import sio
from .ai_triage import AITriageEngine
from .context_extractor import ContextExtractor
from .finding_aggregator import FindingAggregator
from .repo_fetcher import RepoFetcher
from .semgrep_runner import SemgrepRunner


async def run_scan_pipeline(scan_id: uuid.UUID, repo_url: str, branch: str) -> None:
    db = SessionLocal()
    repo_path = None
    fetcher = RepoFetcher()
    runner = SemgrepRunner()
    extractor = ContextExtractor()
    triage = AITriageEngine()
    pinecone = _get_pinecone()
    aggregator = FindingAggregator(pinecone)

    try:
        _update_scan(db, scan_id, status="cloning")
        await sio.emit("scan.updated", {"scan_id": str(scan_id), "status": "cloning"})

        repo_path, resolved_branch = await fetcher.clone(repo_url, branch=branch)
        if resolved_branch != branch:
            branch = resolved_branch
            _update_scan(db, scan_id, branch=resolved_branch)
            await sio.emit(
                "scan.updated",
                {"scan_id": str(scan_id), "branch": resolved_branch},
            )
        _update_scan(db, scan_id, status="scanning")
        await sio.emit("scan.updated", {"scan_id": str(scan_id), "status": "scanning"})

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
        await sio.emit("scan.updated", {"scan_id": str(scan_id), "status": "analyzing"})

        contexts = [extractor.extract(repo_path, finding) for finding in raw_findings]
        triaged = await triage.triage_batch(list(zip(raw_findings, contexts)))
        filtered = await aggregator.process(triaged)

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
                    status="new",
                    priority_score=priority_score,
                )
            )

        db.commit()

        _update_scan(
            db,
            scan_id,
            status="completed",
            total_findings=len(triaged),
            filtered_findings=len(filtered),
        )

        await sio.emit(
            "scan.completed",
            {
                "scan_id": str(scan_id),
                "status": "completed",
                "total_findings": len(triaged),
                "filtered_findings": len(filtered),
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
