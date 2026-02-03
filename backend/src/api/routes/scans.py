from __future__ import annotations

import asyncio
import inspect
import logging
import os
import threading
import uuid
from datetime import datetime, timedelta, timezone
from io import BytesIO
from typing import List, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, status
from fastapi.responses import Response, StreamingResponse
from sqlalchemy import case, desc
from sqlalchemy.orm import Session

from ...api.deps import CurrentUser, get_current_user, get_db
from ...config import get_settings
from ...db.session import SessionLocal
from ...models import Finding, Repository, Scan, UserSettings
from ...realtime import sio
from ...schemas.autofix import AutoFixRequest, AutoFixResponse
from ...schemas.finding import FindingRead, FindingUpdate
from ...schemas.scan import ScanCreate, ScanRead
from ...services.reports import build_scan_report_pdf
from ...services.reports.report_insights import generate_report_insights_sync
from ...services.autofix_service import AutoFixService
from ...services.scanner import run_scan_pipeline
from ...services.storage import delete_pdf, download_pdf, get_pdf_url, upload_pdf

logger = logging.getLogger(__name__)


def _mark_scan_failed(scan_id: uuid.UUID, error: str) -> None:
    """Best-effort fallback to avoid scans stuck in pending."""
    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan or scan.status in {"completed", "failed"}:
            return
        scan.status = "failed"
        scan.error_message = error[:2000]
        db.add(scan)
        db.commit()
    except Exception:
        logger.exception("Failed to mark scan %s as failed", scan_id)
    finally:
        db.close()


def _run_scan_pipeline_sync(scan_id, repo_url, branch, scan_type, target_url, commit_sha):
    """Start the async scan pipeline in a separate daemon thread.

    FastAPI BackgroundTasks run in-process and would otherwise block the
    server worker while the scan is running. Spawning a thread keeps the API
    responsive with a single Uvicorn worker (and avoids Socket.IO issues that
    appear with multiple workers without a message queue).
    """

    def _runner() -> None:
        logger.info(f"Starting scan pipeline for scan_id={scan_id}")
        try:
            signature = inspect.signature(run_scan_pipeline)
            supported = signature.parameters.keys()
            kwargs = {
                "scan_id": scan_id,
                "repo_url": repo_url,
                "branch": branch,
                "scan_type": scan_type,
                "target_url": target_url,
                "requested_commit_sha": commit_sha,
            }
            filtered_kwargs = {k: v for k, v in kwargs.items() if k in supported}
            asyncio.run(run_scan_pipeline(**filtered_kwargs))
            logger.info(f"Scan pipeline completed for scan_id={scan_id}")
        except Exception as e:
            logger.error(
                f"Scan pipeline failed for scan_id={scan_id}: {e}", exc_info=True
            )
            _mark_scan_failed(scan_id, str(e))

    thread = threading.Thread(
        target=_runner,
        name=f"scan-pipeline-{scan_id}",
        daemon=True,
    )
    try:
        thread.start()
    except Exception as exc:
        logger.error("Failed to start scan thread for %s: %s", scan_id, exc)
        _mark_scan_failed(scan_id, f"Failed to start scan thread: {exc}")


router = APIRouter(prefix="/scans", tags=["scans"])
findings_router = APIRouter(prefix="/findings", tags=["findings"])


@router.post("", response_model=ScanRead, status_code=status.HTTP_201_CREATED)
async def create_scan(
    payload: ScanCreate,
    background_tasks: BackgroundTasks,
    current_user: CurrentUser = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Scan:
    repo_url = payload.repo_url
    branch = (payload.branch or "main").strip() or "main"
    repo_id = None
    if payload.repo_id is not None:
        repo = (
            db.query(Repository)
            .filter(
                Repository.id == payload.repo_id,
                Repository.user_id == current_user.id,
            )
            .first()
        )
        if not repo:
            raise HTTPException(status_code=404, detail="Repository not found")
        repo_url = repo.repo_url
        repo_id = repo.id
        if payload.branch:
            branch = payload.branch.strip() or "main"
        else:
            branch = repo.default_branch or "main"

    if repo_url:
        repo_url = _normalize_repo_url(repo_url)

    settings = get_settings()
    if settings.scan_max_active:
        active_statuses = ["pending", "cloning", "scanning", "analyzing"]
        active_count = (
            db.query(Scan)
            .filter(
                Scan.user_id == current_user.id,
                Scan.status.in_(active_statuses),
            )
            .count()
        )
        if active_count >= settings.scan_max_active:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many active scans. Please wait for existing scans to finish.",
            )

    if settings.scan_min_interval_seconds:
        cutoff = datetime.now(timezone.utc) - timedelta(
            seconds=settings.scan_min_interval_seconds
        )
        recent = (
            db.query(Scan)
            .filter(
                Scan.user_id == current_user.id,
                Scan.created_at >= cutoff,
            )
            .order_by(Scan.created_at.desc())
            .first()
        )
        if recent is not None:
            elapsed = datetime.now(timezone.utc) - recent.created_at
            remaining = settings.scan_min_interval_seconds - int(
                elapsed.total_seconds()
            )
            if remaining > 0:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=f"Scan rate limit exceeded. Try again in {remaining}s.",
                )

    # Determine initial DAST verification status
    dast_verification_status = "not_applicable"
    if payload.target_url and payload.scan_type.value in ["sast", "both"]:
        # Manual target_url provided - will need verification
        if payload.scan_type.value != "both":
            dast_verification_status = "unverified_url"

    scan = Scan(
        user_id=current_user.id,
        repo_id=repo_id,
        repo_url=repo_url,
        branch=branch,
        commit_sha=payload.commit_sha,
        scan_type=payload.scan_type.value,
        dependency_health_enabled=payload.dependency_health_enabled,
        target_url=payload.target_url,
        dast_auth_headers=payload.dast_auth_headers,
        dast_cookies=payload.dast_cookies,
        dast_verification_status=dast_verification_status,
        status="pending",
        phase="pending",
        phase_message="Queued",
        trigger="manual",
        total_findings=0,
        filtered_findings=0,
        dast_findings=0,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    # Kick off the scan immediately. The helper spawns a daemon thread, so this
    # returns quickly without blocking the request worker.
    logger.info(f"Starting scan pipeline thread for scan_id={scan.id}")
    if os.getenv("PYTEST_CURRENT_TEST"):
        signature = inspect.signature(run_scan_pipeline)
        supported = signature.parameters.keys()
        kwargs = {
            "scan_id": scan.id,
            "repo_url": scan.repo_url,
            "branch": scan.branch,
            "scan_type": scan.scan_type,
            "target_url": scan.target_url,
            "requested_commit_sha": payload.commit_sha,
        }
        filtered_kwargs = {k: v for k, v in kwargs.items() if k in supported}
        await run_scan_pipeline(**filtered_kwargs)
    else:
        _run_scan_pipeline_sync(
            scan.id,
            scan.repo_url,
            scan.branch,
            scan.scan_type,
            scan.target_url,
            payload.commit_sha,
        )
    background_tasks.add_task(
        sio.emit,
        "scan.created",
        ScanRead.model_validate(scan).model_dump(mode="json"),
    )
    return scan


@router.get("", response_model=List[ScanRead])
def list_scans(
    current_user: CurrentUser = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> List[Scan]:
    return (
        db.query(Scan)
        .filter(Scan.user_id == current_user.id)
        .order_by(Scan.created_at.desc())
        .all()
    )


@router.get("/{scan_id}", response_model=ScanRead)
def get_scan(
    scan_id: str,
    current_user: CurrentUser = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Scan:
    scan_uuid = _parse_uuid(scan_id, "Scan not found")
    scan = (
        db.query(Scan)
        .filter(Scan.id == scan_uuid, Scan.user_id == current_user.id)
        .first()
    )
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.post("/{scan_id}/pause", response_model=ScanRead)
def pause_scan(
    scan_id: str,
    background_tasks: BackgroundTasks,
    current_user: CurrentUser = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Scan:
    scan = get_scan(scan_id, current_user=current_user, db=db)
    if scan.status in {"completed", "failed"}:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Completed scans cannot be paused.",
        )
    if scan.is_paused:
        return scan
    scan.is_paused = True
    db.add(scan)
    db.commit()
    db.refresh(scan)
    background_tasks.add_task(
        sio.emit,
        "scan.updated",
        ScanRead.model_validate(scan).model_dump(mode="json"),
    )
    return scan


@router.post("/{scan_id}/resume", response_model=ScanRead)
def resume_scan(
    scan_id: str,
    background_tasks: BackgroundTasks,
    current_user: CurrentUser = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Scan:
    scan = get_scan(scan_id, current_user=current_user, db=db)
    if scan.status in {"completed", "failed"}:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Completed scans cannot be resumed.",
        )
    if not scan.is_paused:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Scan is not paused.",
        )
    scan.is_paused = False
    db.add(scan)
    db.commit()
    db.refresh(scan)
    background_tasks.add_task(
        sio.emit,
        "scan.updated",
        ScanRead.model_validate(scan).model_dump(mode="json"),
    )
    return scan


@router.get("/{scan_id}/report")
def get_scan_report(
    scan_id: str,
    regenerate: bool = Query(default=False),
    current_user: CurrentUser = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> StreamingResponse:
    scan = get_scan(scan_id, current_user=current_user, db=db)

    # Always use cached report if it already exists.
    cached_url = scan.report_url
    cached_bytes = download_pdf(str(scan.id))
    if cached_bytes is not None:
        if regenerate:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Report already generated; regeneration is disabled.",
            )
        if not cached_url:
            cached_url = get_pdf_url(str(scan.id))
            if cached_url:
                scan.report_url = cached_url
                if not scan.report_generated_at:
                    scan.report_generated_at = datetime.now(timezone.utc)
                db.add(scan)
                db.commit()
        filename = f"scan-report-{scan.id}.pdf"
        headers = {"Content-Disposition": f'attachment; filename="{filename}"'}
        return StreamingResponse(
            BytesIO(cached_bytes),
            media_type="application/pdf",
            headers=headers,
        )

    if cached_url:
        if regenerate:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Report already generated; regeneration is disabled.",
            )
        import httpx
        response = httpx.get(cached_url, timeout=30.0)
        if response.status_code != 200:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="Failed to fetch report from storage.",
            )
        filename = f"scan-report-{scan.id}.pdf"
        headers = {"Content-Disposition": f'attachment; filename="{filename}"'}
        return StreamingResponse(
            BytesIO(response.content),
            media_type="application/pdf",
            headers=headers,
        )

    if scan.report_generated_at:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Report already generated; cached file is missing or storage is unavailable.",
        )

    # Generate new report
    findings = (
        db.query(Finding)
        .filter(
            Finding.scan_id == scan.id,
            Finding.is_false_positive.is_(False),
        )
        .order_by(desc(Finding.priority_score), Finding.created_at.desc())
        .all()
    )
    trend_scans = (
        db.query(Scan)
        .filter(Scan.user_id == current_user.id, Scan.status == "completed")
        .order_by(Scan.created_at.desc())
        .limit(12)
        .all()
    )
    insights = generate_report_insights_sync(scan, findings, trend_scans)
    pdf_bytes = build_scan_report_pdf(
        scan,
        findings,
        trend_scans,
        insights=insights,
    )

    # Upload to Supabase storage and cache URL
    report_url = upload_pdf(str(scan.id), pdf_bytes, upsert=False)
    if not report_url:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Failed to store report in Supabase.",
        )
    scan.report_url = report_url
    scan.report_generated_at = datetime.now(timezone.utc)
    db.add(scan)
    db.commit()

    filename = f"scan-report-{scan.id}.pdf"
    headers = {"Content-Disposition": f'attachment; filename="{filename}"'}
    return StreamingResponse(
        BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers=headers,
    )


@router.delete(
    "/{scan_id}/report",
    status_code=status.HTTP_204_NO_CONTENT,
    response_model=None,
    response_class=Response,
)
def delete_scan_report(
    scan_id: str,
    current_user: CurrentUser = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Response:
    """Delete cached PDF report to allow regeneration."""
    scan = get_scan(scan_id, current_user=current_user, db=db)
    if scan.report_url:
        delete_pdf(str(scan.id))
        scan.report_url = None
        scan.report_generated_at = None
        db.add(scan)
        db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.delete(
    "/{scan_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_model=None,
    response_class=Response,
)
def delete_scan(
    scan_id: str,
    background_tasks: BackgroundTasks,
    current_user: CurrentUser = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Response:
    scan = get_scan(scan_id, current_user=current_user, db=db)
    if (
        scan.status not in {"pending", "completed", "failed"}
        and not scan.is_paused
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Active scans cannot be deleted unless paused.",
        )
    delete_pdf(str(scan.id))
    db.query(Finding).filter(Finding.scan_id == scan.id).delete(
        synchronize_session=False
    )
    db.delete(scan)
    db.commit()
    background_tasks.add_task(
        sio.emit,
        "scan.deleted",
        {"scan_id": str(scan.id)},
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/{scan_id}/findings", response_model=List[FindingRead])
def get_scan_findings(
    scan_id: str,
    include_false_positives: bool = Query(default=False),
    current_user: CurrentUser = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> List[Finding]:
    scan = get_scan(scan_id, current_user=current_user, db=db)
    q = db.query(Finding).filter(Finding.scan_id == scan.id)
    if not include_false_positives:
        q = q.filter(Finding.is_false_positive.is_(False))
    priority_rank = case((Finding.priority_score.is_(None), 0), else_=1)
    return (
        q.order_by(
            desc(priority_rank),
            desc(Finding.priority_score),
            Finding.created_at.desc(),
        )
        .all()
    )


@findings_router.get("", response_model=List[FindingRead])
def list_findings(
    scan_id: Optional[str] = Query(default=None),
    status_filter: Optional[str] = Query(default=None, alias="status"),
    include_false_positives: bool = Query(default=False),
    limit: Optional[int] = Query(default=None, ge=1, le=100),
    current_user: CurrentUser = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> List[Finding]:
    q = db.query(Finding).join(Scan, Finding.scan_id == Scan.id)
    q = q.filter(Scan.user_id == current_user.id)
    if scan_id:
        scan_uuid = _parse_uuid(scan_id, "Scan not found")
        q = q.filter(Finding.scan_id == scan_uuid)
    if status_filter:
        q = q.filter(Finding.status == status_filter)
    if not include_false_positives:
        q = q.filter(Finding.is_false_positive.is_(False))
    priority_rank = case((Finding.priority_score.is_(None), 0), else_=1)
    q = q.order_by(
        desc(priority_rank),
        desc(Finding.priority_score),
        Finding.created_at.desc(),
    )
    if limit is not None:
        q = q.limit(limit)
    return q.all()


@findings_router.get("/{finding_id}", response_model=FindingRead)
def get_finding(
    finding_id: str,
    current_user: CurrentUser = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Finding:
    finding_uuid = _parse_uuid(finding_id, "Finding not found")
    finding = (
        db.query(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .filter(Finding.id == finding_uuid, Scan.user_id == current_user.id)
        .first()
    )
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding


@findings_router.patch("/{finding_id}", response_model=FindingRead)
def update_finding(
    finding_id: str,
    payload: FindingUpdate,
    background_tasks: BackgroundTasks,
    current_user: CurrentUser = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Finding:
    finding = get_finding(finding_id, current_user=current_user, db=db)
    updates = payload.model_dump(exclude_unset=True)
    for key, value in updates.items():
        setattr(finding, key, value)
    db.add(finding)
    db.commit()
    db.refresh(finding)

    background_tasks.add_task(
        sio.emit,
        "finding.updated",
        FindingRead.model_validate(finding).model_dump(mode="json"),
    )
    return finding


@findings_router.post("/{finding_id}/autofix", response_model=AutoFixResponse)
async def autofix_finding(
    finding_id: str,
    payload: AutoFixRequest,
    background_tasks: BackgroundTasks,
    current_user: CurrentUser = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> AutoFixResponse:
    finding = get_finding(finding_id, current_user=current_user, db=db)
    scan = (
        db.query(Scan)
        .filter(Scan.id == finding.scan_id, Scan.user_id == current_user.id)
        .first()
    )
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    settings = (
        db.query(UserSettings)
        .filter(UserSettings.user_id == current_user.id)
        .first()
    )
    github_token = None
    if settings and settings.github_token:
        github_token = settings.github_token.strip() or None

    service = AutoFixService()
    result = await service.generate_fix(
        finding=finding,
        scan=scan,
        github_token=github_token,
        create_pr=payload.create_pr,
        regenerate=payload.regenerate,
    )

    now = datetime.now(timezone.utc)
    finding.fix_status = result.status
    finding.fix_error = result.error
    finding.fix_generated_at = now
    if result.patch is not None:
        finding.fix_patch = result.patch
    if result.summary is not None:
        finding.fix_summary = result.summary
    if result.confidence is not None:
        finding.fix_confidence = result.confidence
    if result.pr_url is not None:
        finding.fix_pr_url = result.pr_url
    if result.branch is not None:
        finding.fix_branch = result.branch

    db.add(finding)
    db.commit()
    db.refresh(finding)

    background_tasks.add_task(
        sio.emit,
        "finding.updated",
        FindingRead.model_validate(finding).model_dump(mode="json"),
    )

    return AutoFixResponse(
        status=result.status,
        patch=result.patch,
        summary=result.summary,
        confidence=result.confidence,
        pr_url=result.pr_url,
        branch=result.branch,
        error=result.error,
        finding=FindingRead.model_validate(finding),
    )


@router.get("/{id}/policy")
async def evaluate_scan_policy(
    id: str,
    fail_on: str = Query(default="high", pattern="^(info|low|medium|high|critical)$"),
    include_false_positives: bool = Query(default=False),
    current_user: CurrentUser = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Evaluate scan findings against policy threshold for CI/CD integration.

    Returns a policy result indicating whether the scan passes or fails based on
    the severity threshold. Exit code 0 = pass, 1 = fail.

    Args:
        id: Scan UUID
        fail_on: Minimum severity to fail on (info|low|medium|high|critical). Default: high
        include_false_positives: Whether to include findings marked as false positives

    Returns:
        JSON with: {passed, exit_code, fail_on, violations_count, violations}
    """
    from ...services.scanner.scan_policy import evaluate_scan_policy as eval_policy

    scan_uuid = _parse_uuid(id, "Scan not found")
    scan = db.query(Scan).filter(Scan.id == scan_uuid).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.user_id != current_user.id:
        raise HTTPException(status_code=404, detail="Scan not found")

    try:
        result = eval_policy(
            db=db,
            scan_id=str(scan_uuid),
            fail_on=fail_on,
            include_false_positives=include_false_positives,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    return {
        "passed": result.passed,
        "exit_code": result.exit_code,
        "fail_on": result.fail_on,
        "violations_count": result.violations_count,
        "violations": [
            {
                "finding_id": v.finding_id,
                "severity": v.severity,
                "rule_id": v.rule_id,
                "rule_message": v.rule_message,
                "file_path": v.file_path,
                "line_start": v.line_start,
            }
            for v in result.violations
        ],
    }


def _parse_uuid(value: str, message: str) -> uuid.UUID:
    try:
        return uuid.UUID(value)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=message) from exc


def _normalize_repo_url(value: str) -> str:
    trimmed = value.strip().rstrip("/")
    return trimmed[:-4] if trimmed.endswith(".git") else trimmed
