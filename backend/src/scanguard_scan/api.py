from __future__ import annotations

import uuid
from pathlib import Path

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from ..api.deps import get_db
from .config import get_scan_settings
from .pipeline import ScanContext, run_scan_job
from .repository import (
    create_scan_job,
    get_correlations,
    get_dast_alerts,
    get_sast_findings,
    get_scan_job,
)
from .schemas import (
    BothScanRequest,
    DastScanRequest,
    DastZapConfig,
    SastScanRequest,
    ScanCreateResponse,
    ScanJobRead,
    ScanResultsResponse,
    ScanStatus,
    ScanType,
)

router = APIRouter(prefix="/v2/scans", tags=["scans_v2"])
ui_router = APIRouter(tags=["scans_v2_ui"])


@router.post("/sast", response_model=ScanCreateResponse)
async def create_sast_scan(
    payload: SastScanRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
) -> ScanCreateResponse:
    scan = create_scan_job(
        db,
        scan_type="sast",
        repo_url=payload.repo_url,
        branch=payload.branch,
        target_url=None,
        auth_present=False,
    )
    context = ScanContext(
        scan_id=scan.id,
        scan_type="sast",
        repo_url=payload.repo_url,
        branch=payload.branch,
        target_url=None,
        github_token=payload.github_token,
        semgrep_config=payload.semgrep_config,
        sast_timeout_seconds=payload.timeout_seconds,
        dast_timeout_seconds=get_scan_settings().default_dast_timeout_seconds,
    )
    background_tasks.add_task(run_scan_job, context)
    return ScanCreateResponse(scan_id=scan.id, type=ScanType.sast, status=ScanStatus.queued)


@router.post("/dast", response_model=ScanCreateResponse)
async def create_dast_scan(
    payload: DastScanRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
) -> ScanCreateResponse:
    zap_config = payload.zap or DastZapConfig()
    auth = payload.auth
    auth_headers = auth.headers if auth else {}
    auth_cookies = auth.cookies if auth else ""
    auth_present = bool(auth_headers) or bool(auth_cookies)

    scan = create_scan_job(
        db,
        scan_type="dast",
        repo_url=None,
        branch=None,
        target_url=payload.target_url,
        auth_present=auth_present,
    )
    context = ScanContext(
        scan_id=scan.id,
        scan_type="dast",
        repo_url=None,
        branch=None,
        target_url=payload.target_url,
        github_token=None,
        semgrep_config="auto",
        sast_timeout_seconds=get_scan_settings().default_sast_timeout_seconds,
        dast_timeout_seconds=zap_config.timeout_seconds,
        auth_headers=auth_headers,
        auth_cookies=auth_cookies,
        spider_minutes=zap_config.spider_minutes,
        active_scan_minutes=zap_config.active_scan_minutes,
    )
    background_tasks.add_task(run_scan_job, context)
    return ScanCreateResponse(scan_id=scan.id, type=ScanType.dast, status=ScanStatus.queued)


@router.post("/both", response_model=ScanCreateResponse)
async def create_both_scan(
    payload: BothScanRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
) -> ScanCreateResponse:
    auth = payload.auth
    auth_headers = auth.headers if auth else {}
    auth_cookies = auth.cookies if auth else ""
    auth_present = bool(auth_headers) or bool(auth_cookies)

    scan = create_scan_job(
        db,
        scan_type="both",
        repo_url=payload.repo_url,
        branch=payload.branch,
        target_url=payload.target_url,
        auth_present=auth_present,
    )
    context = ScanContext(
        scan_id=scan.id,
        scan_type="both",
        repo_url=payload.repo_url,
        branch=payload.branch,
        target_url=payload.target_url,
        github_token=payload.github_token,
        semgrep_config=payload.semgrep_config,
        sast_timeout_seconds=payload.timeouts.sast_seconds,
        dast_timeout_seconds=payload.timeouts.dast_seconds,
        auth_headers=auth_headers,
        auth_cookies=auth_cookies,
        spider_minutes=get_scan_settings().default_spider_minutes,
        active_scan_minutes=get_scan_settings().default_active_scan_minutes,
    )
    background_tasks.add_task(run_scan_job, context)
    return ScanCreateResponse(scan_id=scan.id, type=ScanType.both, status=ScanStatus.queued)


@router.get("/{scan_id}", response_model=ScanJobRead)
async def get_scan(scan_id: str, db: Session = Depends(get_db)) -> ScanJobRead:
    scan_uuid = _parse_uuid(scan_id)
    scan = get_scan_job(db, scan_uuid)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.get("/{scan_id}/results", response_model=ScanResultsResponse)
async def get_scan_results(scan_id: str, db: Session = Depends(get_db)) -> ScanResultsResponse:
    scan_uuid = _parse_uuid(scan_id)
    scan = get_scan_job(db, scan_uuid)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    sast_findings = get_sast_findings(db, scan_uuid)
    dast_alerts = get_dast_alerts(db, scan_uuid)
    correlations = get_correlations(db, scan_uuid)

    return ScanResultsResponse(
        scan=scan,
        sast_findings=sast_findings,
        dast_alerts=dast_alerts,
        correlations=correlations,
    )


@ui_router.get("/ui")
async def scanguard_ui() -> FileResponse:
    return FileResponse(_frontend_dir() / "index.html")


@ui_router.get("/ui/app.js")
async def scanguard_ui_js() -> FileResponse:
    return FileResponse(_frontend_dir() / "app.js")


def _frontend_dir() -> Path:
    return Path(__file__).resolve().parent / "frontend_min"


def _parse_uuid(value: str) -> uuid.UUID:
    try:
        return uuid.UUID(value)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="Scan not found") from exc
