from __future__ import annotations

import uuid
from functools import lru_cache
from typing import List, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from ...api.deps import get_db
from ...integrations.pinecone_client import PineconeService
from ...models import BugReport
from ...schemas.bug import BugReportCreate, BugReportRead
from ...realtime import sio
from ...services.bug_triage import AutoRouter, BugClassifier, DuplicateDetector

router = APIRouter(prefix="/bugs", tags=["bugs"])


@lru_cache
def get_classifier() -> BugClassifier:
    return BugClassifier()


@lru_cache
def get_router() -> AutoRouter:
    return AutoRouter()


def get_duplicate_detector() -> Optional[DuplicateDetector]:
    try:
        pinecone = PineconeService()
    except Exception:
        return None
    return DuplicateDetector(pinecone)


@router.post(
    "",
    response_model=BugReportRead,
    status_code=status.HTTP_201_CREATED,
)
def create_bug(
    payload: BugReportCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
) -> BugReport:
    classifier = get_classifier()
    classification = classifier.classify(payload.title, payload.description or "")

    data = payload.model_dump()
    data.update(
        {
            "classified_type": classification["type"],
            "classified_component": classification["component"],
            "classified_severity": classification["severity"],
            "confidence_score": classification["overall_confidence"],
        }
    )

    bug = BugReport(**data)
    db.add(bug)
    db.commit()
    db.refresh(bug)

    duplicate_detector = get_duplicate_detector()
    if duplicate_detector:
        duplicates = duplicate_detector.find_duplicates(
            bug_id=str(bug.id),
            title=bug.title,
            description=bug.description or "",
        )
        if duplicates:
            bug.is_duplicate = True
            bug.duplicate_score = duplicates[0]["similarity_score"]
            try:
                bug.duplicate_of_id = uuid.UUID(duplicates[0]["bug_id"])
            except ValueError:
                bug.duplicate_of_id = None
            db.add(bug)
            db.commit()

        duplicate_detector.register_bug(bug)

    auto_router = get_router()
    routing = auto_router.route_bug(
        classification,
        is_data_related=bug.is_data_related,
        correlation_score=bug.correlation_score,
    )
    bug.assigned_team = routing["team"]
    db.add(bug)
    db.commit()
    db.refresh(bug)

    event_payload = BugReportRead.model_validate(bug).model_dump(mode="json")
    background_tasks.add_task(sio.emit, "bug.created", event_payload)

    return bug


@router.get("", response_model=List[BugReportRead])
def list_bugs(
    status_filter: Optional[str] = Query(default=None, alias="status"),
    is_data_related: Optional[bool] = Query(default=None, alias="is_data_related"),
    db: Session = Depends(get_db),
) -> List[BugReport]:
    q = db.query(BugReport)
    if status_filter:
        q = q.filter(BugReport.status == status_filter)
    if is_data_related is not None:
        q = q.filter(BugReport.is_data_related == is_data_related)
    return q.order_by(BugReport.created_at.desc()).all()


@router.get("/{bug_id}", response_model=BugReportRead)
def get_bug(bug_id: str, db: Session = Depends(get_db)) -> BugReport:
    try:
        bug_uuid = uuid.UUID(bug_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Bug not found")

    bug = db.query(BugReport).filter(BugReport.id == bug_uuid).first()
    if not bug:
        raise HTTPException(status_code=404, detail="Bug not found")
    return bug


@router.get("/{bug_id}/duplicates")
def get_duplicates(bug_id: str, db: Session = Depends(get_db)):
    bug = get_bug(bug_id, db)
    duplicate_detector = get_duplicate_detector()
    if not duplicate_detector:
        return []

    return duplicate_detector.find_duplicates(
        bug_id=str(bug.id),
        title=bug.title,
        description=bug.description or "",
    )
