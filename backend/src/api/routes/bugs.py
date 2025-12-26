from __future__ import annotations

import uuid
from functools import lru_cache
from typing import List, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, status
from sqlalchemy import case, desc
from sqlalchemy.orm import Session

from ...api.deps import get_db
from ...integrations.pinecone_client import PineconeService
from ...models import BugReport
from ...schemas.bug import BugReportCreate, BugReportRead, BugReportUpdate
from ...realtime import sio
from ...services.bug_triage import (
    AutoRouter,
    BugClassifier,
    BugCorrelationService,
    DuplicateDetector,
)

router = APIRouter(prefix="/bugs", tags=["bugs"])


@lru_cache
def get_classifier() -> BugClassifier:
    return BugClassifier()


@lru_cache
def get_router() -> AutoRouter:
    return AutoRouter()


@lru_cache
def get_pinecone() -> PineconeService:
    return PineconeService()


def get_duplicate_detector() -> Optional[DuplicateDetector]:
    try:
        pinecone = get_pinecone()
    except Exception:
        return None
    return DuplicateDetector(pinecone)


def get_correlation_service() -> BugCorrelationService:
    try:
        pinecone = get_pinecone()
    except Exception:
        pinecone = None
    return BugCorrelationService(pinecone)


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
        try:
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
            else:
                bug.is_duplicate = False
                bug.duplicate_of_id = None
                bug.duplicate_score = None

            db.add(bug)
            db.commit()
            db.refresh(bug)

            duplicate_detector.register_bug(bug)
            bug.embedding_id = str(bug.id)
            db.add(bug)
            db.commit()
            db.refresh(bug)
        except Exception:
            pass

    auto_router = get_router()
    routing = auto_router.route_bug(classification)
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
    sort: str = Query(default="priority", alias="sort"),
    limit: Optional[int] = Query(default=None, ge=1, le=100),
    db: Session = Depends(get_db),
) -> List[BugReport]:
    q = db.query(BugReport)
    if status_filter:
        q = q.filter(BugReport.status == status_filter)

    if sort == "created_at":
        q = q.order_by(BugReport.created_at.desc())
        if limit is not None:
            q = q.limit(limit)
        return q.all()

    severity_rank = case(
        (BugReport.classified_severity == "critical", 4),
        (BugReport.classified_severity == "high", 3),
        (BugReport.classified_severity == "medium", 2),
        (BugReport.classified_severity == "low", 1),
        else_=0,
    )
    status_rank = case((BugReport.status == "resolved", 0), else_=1)

    q = q.order_by(
        desc(status_rank),
        desc(severity_rank),
        BugReport.created_at.desc(),
    )
    if limit is not None:
        q = q.limit(limit)
    return q.all()


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


@router.get("/{bug_id}/correlations")
def get_correlations(bug_id: str, db: Session = Depends(get_db)):
    bug = get_bug(bug_id, db)
    correlator = get_correlation_service()
    return correlator.find_correlated(bug, db, top_k=10)


@router.patch("/{bug_id}", response_model=BugReportRead)
def update_bug(
    bug_id: str,
    payload: BugReportUpdate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
) -> BugReport:
    bug = get_bug(bug_id, db)

    data = payload.model_dump(exclude_unset=True)
    for key, value in data.items():
        setattr(bug, key, value)

    db.add(bug)
    db.commit()
    db.refresh(bug)

    event_payload = BugReportRead.model_validate(bug).model_dump(mode="json")
    background_tasks.add_task(sio.emit, "bug.updated", event_payload)
    return bug
