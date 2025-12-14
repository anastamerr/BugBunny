from __future__ import annotations

from datetime import datetime, timezone
import uuid
from typing import List, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from ...api.deps import get_db
from ...models import BugPrediction, BugReport, DataIncident, IncidentAction, ResolutionPattern
from ...schemas.action import IncidentActionCreate, IncidentActionRead, IncidentActionUpdate
from ...schemas.bug import BugReportRead
from ...schemas.incident import DataIncidentCreate, DataIncidentRead, DataIncidentUpdate
from ...schemas.postmortem import IncidentPostmortemRead
from ...schemas.prediction import BugPredictionRead
from ...realtime import sio
from ...services.incident_response.playbook import (
    build_postmortem_markdown,
    ensure_incident_actions,
    upsert_resolution_pattern,
)
from ...services.intelligence.prediction_engine import PredictionEngine

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

    try:
        engine = PredictionEngine(db)
        result = engine.predict_bugs(incident)
        prediction = BugPrediction(
            incident_id=incident.id,
            predicted_bug_count=result["predicted_bug_count"],
            predicted_components=result.get("predicted_components"),
            confidence=result.get("confidence"),
            prediction_window_hours=result.get("prediction_window_hours", 6),
            actual_bug_count=None,
            was_accurate=None,
        )
        db.add(prediction)
        db.commit()
        db.refresh(prediction)

        prediction_event = BugPredictionRead.model_validate(prediction).model_dump(
            mode="json"
        )
        background_tasks.add_task(sio.emit, "prediction.created", prediction_event)
    except Exception:
        pass

    try:
        ensure_incident_actions(db, incident)
    except Exception:
        pass

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


@router.patch("/{incident_id}", response_model=DataIncidentRead)
def update_incident(
    incident_id: str,
    payload: DataIncidentUpdate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
) -> DataIncident:
    try:
        incident_uuid = uuid.UUID(incident_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Incident not found")

    incident = db.query(DataIncident).filter(DataIncident.id == incident_uuid).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    data = payload.model_dump(exclude_unset=True)
    for key, value in data.items():
        setattr(incident, key, value)

    if data.get("status") == "RESOLVED" and incident.resolved_at is None:
        incident.resolved_at = datetime.now(timezone.utc)

    db.add(incident)
    db.commit()
    db.refresh(incident)

    if incident.status == "RESOLVED":
        related_bugs = (
            db.query(BugReport)
            .filter(BugReport.correlated_incident_id == incident.id)
            .all()
        )
        try:
            upsert_resolution_pattern(db, incident, related_bugs=related_bugs)
        except Exception:
            pass

    event_payload = DataIncidentRead.model_validate(incident).model_dump(mode="json")
    background_tasks.add_task(sio.emit, "incident.updated", event_payload)

    return incident


@router.get("/{incident_id}/actions", response_model=List[IncidentActionRead])
def list_incident_actions(incident_id: str, db: Session = Depends(get_db)) -> list[IncidentAction]:
    try:
        incident_uuid = uuid.UUID(incident_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Incident not found")

    incident = db.query(DataIncident).filter(DataIncident.id == incident_uuid).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    return ensure_incident_actions(db, incident)


@router.post(
    "/{incident_id}/actions",
    response_model=IncidentActionRead,
    status_code=status.HTTP_201_CREATED,
)
def create_incident_action(
    incident_id: str,
    payload: IncidentActionCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
) -> IncidentAction:
    try:
        incident_uuid = uuid.UUID(incident_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Incident not found")

    incident = db.query(DataIncident).filter(DataIncident.id == incident_uuid).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    action = IncidentAction(
        incident_id=incident.id,
        title=payload.title,
        description=payload.description,
        owner_team=payload.owner_team,
        status=str(payload.status),
        source=str(payload.source),
        sort_order=payload.sort_order,
    )
    db.add(action)
    db.commit()
    db.refresh(action)

    event_payload = IncidentActionRead.model_validate(action).model_dump(mode="json")
    background_tasks.add_task(sio.emit, "incident.action.created", event_payload)

    return action


@router.patch(
    "/{incident_id}/actions/{action_id}",
    response_model=IncidentActionRead,
)
def update_incident_action(
    incident_id: str,
    action_id: str,
    payload: IncidentActionUpdate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
) -> IncidentAction:
    try:
        incident_uuid = uuid.UUID(incident_id)
        action_uuid = uuid.UUID(action_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Action not found")

    action = (
        db.query(IncidentAction)
        .filter(IncidentAction.id == action_uuid, IncidentAction.incident_id == incident_uuid)
        .first()
    )
    if not action:
        raise HTTPException(status_code=404, detail="Action not found")

    data = payload.model_dump(exclude_unset=True)
    for key, value in data.items():
        setattr(action, key, value)

    if data.get("status") == "done":
        action.completed_at = datetime.now(timezone.utc)
    if data.get("status") in {"todo", "doing"}:
        action.completed_at = None

    db.add(action)
    db.commit()
    db.refresh(action)

    event_payload = IncidentActionRead.model_validate(action).model_dump(mode="json")
    background_tasks.add_task(sio.emit, "incident.action.updated", event_payload)

    return action


@router.get("/{incident_id}/postmortem", response_model=IncidentPostmortemRead)
def get_incident_postmortem(
    incident_id: str,
    db: Session = Depends(get_db),
) -> IncidentPostmortemRead:
    try:
        incident_uuid = uuid.UUID(incident_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Incident not found")

    incident = db.query(DataIncident).filter(DataIncident.id == incident_uuid).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    related_bugs = (
        db.query(BugReport)
        .filter(BugReport.correlated_incident_id == incident.id)
        .order_by(BugReport.created_at.asc())
        .all()
    )

    actions = (
        db.query(IncidentAction)
        .filter(IncidentAction.incident_id == incident.id)
        .order_by(IncidentAction.sort_order.asc().nullslast(), IncidentAction.created_at.asc())
        .all()
    )
    if not actions:
        actions = ensure_incident_actions(db, incident)

    prediction = (
        db.query(BugPrediction)
        .filter(BugPrediction.incident_id == incident.id)
        .order_by(BugPrediction.created_at.desc())
        .first()
    )

    pattern = (
        db.query(ResolutionPattern)
        .filter(
            ResolutionPattern.incident_type == str(incident.incident_type),
            ResolutionPattern.affected_table == incident.table_name,
        )
        .first()
    )

    markdown = build_postmortem_markdown(
        incident,
        related_bugs=related_bugs,
        actions=actions,
        prediction=prediction,
        resolution_pattern=pattern,
    )

    return IncidentPostmortemRead(
        incident_id=incident.id,
        markdown=markdown,
        generated_at=datetime.now(timezone.utc),
    )
