from __future__ import annotations

import uuid
from typing import List

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from sqlalchemy.orm import Session

from ...api.deps import get_db
from ...models import BugPrediction, DataIncident
from ...schemas.prediction import BugPredictionRead
from ...realtime import sio
from ...services.intelligence.prediction_engine import PredictionEngine

router = APIRouter(prefix="/predictions", tags=["predictions"])


@router.get("", response_model=List[BugPredictionRead])
def list_predictions(db: Session = Depends(get_db)) -> List[BugPrediction]:
    return db.query(BugPrediction).order_by(BugPrediction.created_at.desc()).all()


@router.post(
    "/{incident_id}",
    response_model=BugPredictionRead,
    status_code=status.HTTP_201_CREATED,
)
def predict_for_incident(
    incident_id: str,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
) -> BugPrediction:
    try:
        inc_uuid = uuid.UUID(incident_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Incident not found")

    incident = db.query(DataIncident).filter(DataIncident.id == inc_uuid).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

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

    event_payload = BugPredictionRead.model_validate(prediction).model_dump(
        mode="json"
    )
    background_tasks.add_task(sio.emit, "prediction.created", event_payload)
    return prediction
