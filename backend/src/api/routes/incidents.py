from __future__ import annotations

import uuid
from typing import List, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from ...api.deps import get_db
from ...models import BugReport, DataIncident
from ...schemas.bug import BugReportRead
from ...schemas.incident import DataIncidentCreate, DataIncidentRead
from ...realtime import sio

router = APIRouter(prefix="/incidents", tags=["incidents"])


@router.post(
    "",
    response_model=DataIncidentRead,
    status_code=status.HTTP_201_CREATED,
)
def create_incident(
    payload: DataIncidentCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
) -> DataIncident:
    incident = DataIncident(**payload.model_dump())
    db.add(incident)
    db.commit()
    db.refresh(incident)

    event_payload = (
        DataIncidentRead.model_validate(incident).model_dump(mode="json")
    )
    background_tasks.add_task(sio.emit, "incident.created", event_payload)
    return incident


@router.get("", response_model=List[DataIncidentRead])
def list_incidents(
    status_filter: Optional[str] = Query(default=None, alias="status"),
    severity_filter: Optional[str] = Query(default=None, alias="severity"),
    db: Session = Depends(get_db),
) -> List[DataIncident]:
    q = db.query(DataIncident)
    if status_filter:
        q = q.filter(DataIncident.status == status_filter)
    if severity_filter:
        q = q.filter(DataIncident.severity == severity_filter)
    return q.order_by(DataIncident.timestamp.desc()).all()


@router.get("/{incident_id}", response_model=DataIncidentRead)
def get_incident(
    incident_id: str, db: Session = Depends(get_db)
) -> DataIncident:
    try:
        incident_uuid = uuid.UUID(incident_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Incident not found")

    incident = db.query(DataIncident).filter(DataIncident.id == incident_uuid).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident


@router.get("/{incident_id}/bugs", response_model=List[BugReportRead])
def get_related_bugs(
    incident_id: str, db: Session = Depends(get_db)
) -> List[BugReport]:
    try:
        incident_uuid = uuid.UUID(incident_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Incident not found")

    bugs = (
        db.query(BugReport)
        .filter(BugReport.correlated_incident_id == incident_uuid)
        .all()
    )
    return bugs
