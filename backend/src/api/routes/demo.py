from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, BackgroundTasks, Depends, status
from sqlalchemy.orm import Session

from ...api.deps import get_db
from ...config import get_settings
from ...models import BugIncidentCorrelation, BugPrediction, BugReport, DataIncident
from ...realtime import sio
from ...schemas.bug import BugReportRead
from ...schemas.correlation import CorrelationRead
from ...schemas.demo import (
    DemoInjectBugRequest,
    DemoInjectBugResponse,
    DemoInjectIncidentRequest,
)
from ...schemas.incident import DataIncidentRead
from ...schemas.prediction import BugPredictionRead
from ...services.bug_triage import AutoRouter, BugClassifier
from ...services.correlation.temporal_matcher import TemporalMatcher
from ...services.intelligence.explanation_generator import ExplanationGenerator
from ...services.intelligence.llm_service import get_llm_service
from ...services.intelligence.prediction_engine import PredictionEngine
from ...services.incident_response.playbook import ensure_incident_actions

router = APIRouter(prefix="/demo", tags=["demo"])


def _generate_incident_code() -> str:
    date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    return f"DI-{date}-{uuid.uuid4().hex[:3].upper()}"


def _generate_bug_code() -> str:
    return f"DEMO-{uuid.uuid4().hex[:6].upper()}"


_classifier: BugClassifier | None = None
_router: AutoRouter | None = None


def _get_classifier() -> BugClassifier:
    global _classifier
    if _classifier is None:
        _classifier = BugClassifier()
    return _classifier


def _get_router() -> AutoRouter:
    global _router
    if _router is None:
        _router = AutoRouter()
    return _router


@router.post(
    "/inject-incident",
    response_model=DataIncidentRead,
    status_code=status.HTTP_201_CREATED,
)
def inject_incident(
    payload: DemoInjectIncidentRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
) -> DataIncident:
    incident = DataIncident(
        incident_id=payload.incident_id or _generate_incident_code(),
        timestamp=payload.timestamp or datetime.now(timezone.utc),
        table_name=payload.table_name,
        incident_type=payload.incident_type,
        severity=payload.severity,
        details=payload.details,
        affected_columns=payload.affected_columns,
        anomaly_score=payload.anomaly_score,
        downstream_systems=payload.downstream_systems,
        status=payload.status,
    )
    db.add(incident)
    db.commit()
    db.refresh(incident)

    event_payload = DataIncidentRead.model_validate(incident).model_dump(mode="json")
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


@router.post(
    "/inject-bug",
    response_model=DemoInjectBugResponse,
    status_code=status.HTTP_201_CREATED,
)
async def inject_bug(
    payload: DemoInjectBugRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
) -> DemoInjectBugResponse:
    classifier = _get_classifier()
    classification = classifier.classify(payload.title, payload.description or "")

    bug = BugReport(
        bug_id=payload.bug_id or _generate_bug_code(),
        source=payload.source,
        title=payload.title,
        description=payload.description,
        created_at=payload.created_at or datetime.now(timezone.utc),
        reporter=payload.reporter,
        labels=payload.labels,
        classified_type=classification["type"],
        classified_component=classification["component"],
        classified_severity=classification["severity"],
        confidence_score=classification["overall_confidence"],
        status="new",
    )
    db.add(bug)
    db.commit()
    db.refresh(bug)

    corr: BugIncidentCorrelation | None = None
    matched_incident: DataIncident | None = None

    if payload.auto_correlate:
        matcher = TemporalMatcher(db)
        matches = matcher.find_correlated_incidents(bug)
        if matches:
            matched_incident, score = matches[0]

            bug.is_data_related = True
            bug.correlated_incident_id = matched_incident.id
            bug.correlation_score = score
            db.add(bug)
            db.commit()
            db.refresh(bug)

            corr = BugIncidentCorrelation(
                bug_id=bug.id,
                incident_id=matched_incident.id,
                correlation_score=score,
                temporal_score=matcher._temporal_score(bug, matched_incident),
                component_score=matcher._component_score(bug, matched_incident),
                keyword_score=matcher._keyword_score(bug, matched_incident),
                explanation=None,
            )

            if payload.generate_explanation:
                settings = get_settings()
                llm = get_llm_service(settings)
                explanation = (
                    f"Likely root cause: {matched_incident.incident_type} in "
                    f"{matched_incident.table_name} affecting {bug.classified_component}."
                )
                try:
                    if await llm.is_available():
                        generator = ExplanationGenerator(llm)
                        explanation = await generator.generate_root_cause_explanation(
                            bug, matched_incident, score
                        )
                except Exception:
                    pass
                corr.explanation = explanation

            db.add(corr)
            db.commit()
            db.refresh(corr)

    auto_router = _get_router()
    routing = auto_router.route_bug(
        classification,
        is_data_related=bug.is_data_related,
        correlation_score=bug.correlation_score,
    )
    bug.assigned_team = routing["team"]
    db.add(bug)
    db.commit()
    db.refresh(bug)

    bug_event = BugReportRead.model_validate(bug).model_dump(mode="json")
    background_tasks.add_task(sio.emit, "bug.created", bug_event)

    corr_read = None
    incident_read = None
    if corr:
        corr_read = CorrelationRead.model_validate(corr).model_dump(mode="json")
        background_tasks.add_task(sio.emit, "correlation.created", corr_read)
    if matched_incident:
        incident_read = (
            DataIncidentRead.model_validate(matched_incident).model_dump(mode="json")
        )

    return DemoInjectBugResponse(
        bug=bug,
        correlation=corr_read,
        incident=incident_read,
    )
