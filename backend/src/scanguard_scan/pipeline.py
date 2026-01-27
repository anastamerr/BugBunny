from __future__ import annotations

import asyncio
import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Dict, Optional

from sqlalchemy.orm import Session

from ..db.session import SessionLocal
from .config import get_scan_settings
from .correlation import correlate_findings
from .models import DastAlertV2, SastFindingV2
from .repository import (
    get_scan_job,
    save_correlations,
    save_dast_alerts,
    save_sast_findings,
    update_scan_job_status,
)
from .runners import repo_fetcher
from .runners.semgrep_runner import SemgrepRunner, SemgrepError
from .runners.zap_runner import ZapRunner

logger = logging.getLogger(__name__)


@dataclass
class ScanContext:
    scan_id: uuid.UUID
    scan_type: str
    repo_url: Optional[str]
    branch: Optional[str]
    target_url: Optional[str]
    github_token: Optional[str]
    semgrep_config: str
    sast_timeout_seconds: int
    dast_timeout_seconds: int
    auth_headers: Dict[str, str] = field(default_factory=dict)
    auth_cookies: str = ""
    spider_minutes: int = 5
    active_scan_minutes: int = 20


async def run_scan_job(
    context: ScanContext,
    *,
    semgrep_runner: Optional[SemgrepRunner] = None,
    zap_runner: Optional[ZapRunner] = None,
) -> None:
    settings = get_scan_settings()
    semgrep_runner = semgrep_runner or SemgrepRunner()
    zap_runner = zap_runner or ZapRunner()
    db = SessionLocal()
    repo_path = None
    metrics: Dict[str, object] = {}

    try:
        scan = get_scan_job(db, context.scan_id)
        if scan is None:
            logger.error("Scan job %s not found", context.scan_id)
            return

        update_scan_job_status(db, context.scan_id, status="running")

        if context.scan_type in {"sast", "both"}:
            if not context.repo_url:
                raise RuntimeError("repo_url is required for SAST scans")
            repo_start = time.monotonic()
            repo_path = await asyncio.to_thread(
                repo_fetcher.clone_repo,
                context.repo_url,
                context.branch or "main",
                context.github_token,
                settings.repo_clone_timeout_seconds,
            )
            findings = await asyncio.to_thread(
                semgrep_runner.run,
                repo_path,
                config=context.semgrep_config,
                timeout_seconds=context.sast_timeout_seconds,
                docker_image=settings.semgrep_docker_image,
            )
            sast_records = [
                SastFindingV2(
                    scan_id=context.scan_id,
                    rule_id=item.rule_id,
                    message=item.message,
                    severity=item.severity,
                    file_path=item.file_path,
                    line_start=item.line_start,
                    line_end=item.line_end,
                    cwe_ids=item.cwe_ids,
                    fingerprint=item.fingerprint,
                    raw=item.raw,
                )
                for item in findings
            ]
            saved_findings = save_sast_findings(db, context.scan_id, sast_records)
            metrics["sast_duration_seconds"] = int(time.monotonic() - repo_start)
            metrics["sast_finding_count"] = len(saved_findings)
        else:
            saved_findings = []

        dast_result = None
        saved_alerts = []
        if context.scan_type in {"dast", "both"}:
            if not context.target_url:
                raise RuntimeError("target_url is required for DAST scans")
            dast_start = time.monotonic()
            dast_result = await zap_runner.run(
                context.target_url,
                headers=context.auth_headers,
                cookies=context.auth_cookies,
                timeout_seconds=context.dast_timeout_seconds,
                spider_minutes=context.spider_minutes,
                active_scan_minutes=context.active_scan_minutes,
            )
            alert_records = [
                DastAlertV2(
                    scan_id=context.scan_id,
                    plugin_id=item.plugin_id,
                    name=item.name,
                    risk=item.risk,
                    confidence=item.confidence,
                    url=item.url,
                    param=item.param,
                    evidence=item.evidence,
                    cwe_id=item.cwe_id,
                    raw=item.raw,
                )
                for item in dast_result.alerts
            ]
            saved_alerts = save_dast_alerts(db, context.scan_id, alert_records)
            metrics["dast_duration_seconds"] = int(time.monotonic() - dast_start)
            metrics["dast_alert_count"] = len(saved_alerts)
            metrics["dast_spider_url_count"] = dast_result.metrics.get(
                "spider_url_count", 0
            )
            if dast_result.error_kind:
                metrics["dast_error_kind"] = dast_result.error_kind
                metrics["dast_error_message"] = dast_result.error_message

        if context.scan_type == "both":
            error_kind = dast_result.error_kind if dast_result else "tool_error"
            error_message = (
                dast_result.error_message if dast_result else "DAST did not run."
            )
            correlations = correlate_findings(
                saved_findings,
                saved_alerts,
                dast_error_kind=error_kind,
                dast_error_message=error_message,
            )
            save_correlations(db, context.scan_id, correlations)

        update_scan_job_status(
            db, context.scan_id, status="completed", metrics=metrics
        )
    except SemgrepError as exc:
        update_scan_job_status(
            db,
            context.scan_id,
            status="failed",
            error_message=str(exc),
            metrics=metrics,
        )
    except Exception as exc:  # pragma: no cover
        logger.exception("Scan job failed")
        update_scan_job_status(
            db,
            context.scan_id,
            status="failed",
            error_message=str(exc),
            metrics=metrics,
        )
    finally:
        if repo_path is not None:
            await asyncio.to_thread(repo_fetcher.cleanup_repo, repo_path)
        db.close()
