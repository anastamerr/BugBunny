from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, BackgroundTasks, Depends, status
from sqlalchemy.orm import Session

from ...api.deps import get_db
from ...models import BugReport
from ...realtime import sio
from ...schemas.bug import BugReportRead
from ...schemas.demo import (
    DemoInjectBugRequest,
    DemoInjectBugResponse,
)
from ...services.bug_triage import AutoRouter, BugClassifier

router = APIRouter(prefix="/demo", tags=["demo"])


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

    auto_router = _get_router()
    routing = auto_router.route_bug(classification)
    bug.assigned_team = routing["team"]
    db.add(bug)
    db.commit()
    db.refresh(bug)

    bug_event = BugReportRead.model_validate(bug).model_dump(mode="json")
    background_tasks.add_task(sio.emit, "bug.created", bug_event)

    return DemoInjectBugResponse(
        bug=bug,
    )
