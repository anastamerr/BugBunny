from __future__ import annotations

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
from ...models import Finding, Repository, Scan
from ...realtime import sio
from ...schemas.finding import FindingRead, FindingUpdate
from ...schemas.scan import ScanCreate, ScanRead
from ...services.reports import build_scan_report_pdf
from ...services.reports.report_insights import generate_report_insights_sync
from ...services.scanner import run_scan_pipeline
from ...services.storage import delete_pdf, download_pdf, get_pdf_url, upload_pdf

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

    scan = Scan(
        user_id=current_user.id,
        repo_id=repo_id,
        repo_url=repo_url,
        branch=branch,
        scan_type=payload.scan_type.value,
        dependency_health_enabled=payload.dependency_health_enabled,
        target_url=payload.target_url,
        status="pending",
        trigger="manual",
        total_findings=0,
        filtered_findings=0,
        dast_findings=0,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    background_tasks.add_task(
        run_scan_pipeline,
        scan.id,
        scan.repo_url,
        scan.branch,
        scan.scan_type,
        scan.target_url,
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
        db.add(scan)
        db.commit()
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




def _parse_uuid(value: str, message: str) -> uuid.UUID:
    try:
        return uuid.UUID(value)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=message) from exc


def _normalize_repo_url(value: str) -> str:
    trimmed = value.strip().rstrip("/")
    return trimmed[:-4] if trimmed.endswith(".git") else trimmed
