from __future__ import annotations

import uuid
from typing import List, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from ...api.deps import get_db
from ...models import BugIncidentCorrelation, BugReport, DataIncident
from ...schemas.correlation import CorrelationCreate, CorrelationRead, CorrelationView
from ...realtime import sio

router = APIRouter(prefix="/correlations", tags=["correlations"])


@router.post(
    "",
    response_model=CorrelationRead,
    status_code=status.HTTP_201_CREATED,
)
def create_correlation(
    payload: CorrelationCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
) -> BugIncidentCorrelation:
    corr = BugIncidentCorrelation(**payload.model_dump())
    db.add(corr)
    db.commit()
    db.refresh(corr)

    event_payload = CorrelationRead.model_validate(corr).model_dump(mode="json")
    background_tasks.add_task(sio.emit, "correlation.created", event_payload)
    return corr


@router.get("", response_model=List[CorrelationView])
def list_correlations(
    bug_id: Optional[str] = Query(default=None, alias="bug_id"),
    incident_id: Optional[str] = Query(default=None, alias="incident_id"),
    db: Session = Depends(get_db),
) -> List[CorrelationView]:
    q = db.query(BugIncidentCorrelation)
    if bug_id:
        try:
            bug_uuid = uuid.UUID(bug_id)
            q = q.filter(BugIncidentCorrelation.bug_id == bug_uuid)
        except ValueError:
            return []
    if incident_id:
        try:
            inc_uuid = uuid.UUID(incident_id)
            q = q.filter(BugIncidentCorrelation.incident_id == inc_uuid)
        except ValueError:
            return []

    correlations = q.order_by(BugIncidentCorrelation.created_at.desc()).all()
    views: List[CorrelationView] = []
    for c in correlations:
        bug = db.query(BugReport).filter(BugReport.id == c.bug_id).first()
        incident = (
            db.query(DataIncident)
            .filter(DataIncident.id == c.incident_id)
            .first()
        )
        if not bug or not incident:
            continue
        views.append(
            CorrelationView(
                id=str(c.id),
                bug=bug,
                incident=incident,
                correlation_score=c.correlation_score,
                temporal_score=c.temporal_score,
                component_score=c.component_score,
                keyword_score=c.keyword_score,
                explanation=c.explanation,
                created_at=c.created_at,
            )
        )
    return views


@router.get("/{correlation_id}", response_model=CorrelationView)
def get_correlation(
    correlation_id: str, db: Session = Depends(get_db)
) -> CorrelationView:
    try:
        corr_uuid = uuid.UUID(correlation_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Correlation not found")

    corr = (
        db.query(BugIncidentCorrelation)
        .filter(BugIncidentCorrelation.id == corr_uuid)
        .first()
    )
    if not corr:
        raise HTTPException(status_code=404, detail="Correlation not found")

    bug = db.query(BugReport).filter(BugReport.id == corr.bug_id).first()
    incident = (
        db.query(DataIncident)
        .filter(DataIncident.id == corr.incident_id)
        .first()
    )
    if not bug or not incident:
        raise HTTPException(status_code=404, detail="Correlation not found")

    return CorrelationView(
        id=str(corr.id),
        bug=bug,
        incident=incident,
        correlation_score=corr.correlation_score,
        temporal_score=corr.temporal_score,
        component_score=corr.component_score,
        keyword_score=corr.keyword_score,
        explanation=corr.explanation,
        created_at=corr.created_at,
    )
