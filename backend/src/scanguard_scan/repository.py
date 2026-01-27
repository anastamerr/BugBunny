from __future__ import annotations

from typing import Iterable, List, Optional
import uuid

from sqlalchemy.orm import Session

from .models import CorrelationV2, DastAlertV2, SastFindingV2, ScanJobV2


def create_scan_job(
    db: Session,
    *,
    scan_type: str,
    repo_url: str | None,
    branch: str | None,
    target_url: str | None,
    auth_present: bool,
) -> ScanJobV2:
    scan = ScanJobV2(
        scan_type=scan_type,
        status="queued",
        repo_url=repo_url,
        branch=branch,
        target_url=target_url,
        auth_present=auth_present,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


def get_scan_job(db: Session, scan_id: uuid.UUID) -> Optional[ScanJobV2]:
    return db.query(ScanJobV2).filter(ScanJobV2.id == scan_id).first()


def update_scan_job_status(
    db: Session,
    scan_id: uuid.UUID,
    *,
    status: str,
    error_message: str | None = None,
    metrics: dict | None = None,
) -> None:
    scan = db.query(ScanJobV2).filter(ScanJobV2.id == scan_id).first()
    if scan is None:
        return
    scan.status = status
    if error_message is not None:
        scan.error_message = error_message
    if metrics is not None:
        scan.metrics = metrics
    db.add(scan)
    db.commit()


def save_sast_findings(
    db: Session, scan_id: uuid.UUID, findings: Iterable[SastFindingV2]
) -> List[SastFindingV2]:
    items = list(findings)
    if not items:
        return []
    db.add_all(items)
    db.commit()
    return items


def save_dast_alerts(
    db: Session, scan_id: uuid.UUID, alerts: Iterable[DastAlertV2]
) -> List[DastAlertV2]:
    items = list(alerts)
    if not items:
        return []
    db.add_all(items)
    db.commit()
    return items


def save_correlations(
    db: Session, scan_id: uuid.UUID, correlations: Iterable[CorrelationV2]
) -> List[CorrelationV2]:
    items = list(correlations)
    if not items:
        return []
    db.add_all(items)
    db.commit()
    return items


def get_sast_findings(db: Session, scan_id: uuid.UUID) -> List[SastFindingV2]:
    return (
        db.query(SastFindingV2)
        .filter(SastFindingV2.scan_id == scan_id)
        .order_by(SastFindingV2.file_path.asc())
        .all()
    )


def get_dast_alerts(db: Session, scan_id: uuid.UUID) -> List[DastAlertV2]:
    return (
        db.query(DastAlertV2)
        .filter(DastAlertV2.scan_id == scan_id)
        .order_by(DastAlertV2.name.asc())
        .all()
    )


def get_correlations(db: Session, scan_id: uuid.UUID) -> List[CorrelationV2]:
    return (
        db.query(CorrelationV2)
        .filter(CorrelationV2.scan_id == scan_id)
        .order_by(CorrelationV2.correlation_score.desc())
        .all()
    )
