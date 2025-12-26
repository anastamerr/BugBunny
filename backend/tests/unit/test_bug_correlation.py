from datetime import datetime, timezone
from unittest.mock import MagicMock

from src.models import BugReport
from src.services.bug_triage.bug_correlation import BugCorrelationService


def _make_bug(*, bug_id: str, title: str, description: str) -> BugReport:
    return BugReport(
        bug_id=bug_id,
        source="manual",
        title=title,
        description=description,
        created_at=datetime.now(timezone.utc),
        reporter="qa",
        status="new",
        classified_component="api",
        classified_severity="high",
    )


def test_find_correlated_returns_explicit_duplicates(db_session):
    root = _make_bug(
        bug_id="BUG-100",
        title="Payments failing with 500",
        description="checkout requests return 500 error",
    )
    dup = _make_bug(
        bug_id="BUG-101",
        title="Checkout 500s for card payments",
        description="Same 500 error on checkout",
    )
    sibling = _make_bug(
        bug_id="BUG-102",
        title="Billing service failing",
        description="Payment API returns 500 on submit",
    )

    db_session.add_all([root, dup, sibling])
    db_session.commit()
    db_session.refresh(root)
    db_session.refresh(dup)
    db_session.refresh(sibling)

    dup.duplicate_of_id = root.id
    sibling.duplicate_of_id = root.id
    db_session.add_all([dup, sibling])
    db_session.commit()

    service = BugCorrelationService(pinecone=None)
    results = service.find_correlated(dup, db_session, top_k=10)

    ids = {item["bug_id"] for item in results}
    assert str(root.id) in ids
    assert str(sibling.id) in ids
    assert str(dup.id) not in ids

    relationships = {
        item["bug_id"]: item["relationship"]
        for item in results
        if item["bug_id"] in {str(root.id), str(sibling.id)}
    }
    assert relationships[str(root.id)] == "duplicate"
    assert relationships[str(sibling.id)] == "duplicate"


def test_find_correlated_filters_low_semantic(db_session):
    bug = _make_bug(
        bug_id="BUG-200",
        title="Search endpoint timing out",
        description="Search API takes 30s and times out",
    )
    candidate_good = _make_bug(
        bug_id="BUG-201",
        title="Search API latency spike",
        description="Search service taking 25s to respond",
    )
    candidate_bad = _make_bug(
        bug_id="BUG-202",
        title="UI alignment off",
        description="Buttons are misaligned on mobile",
    )

    candidate_bad.classified_component = "frontend"

    db_session.add_all([bug, candidate_good, candidate_bad])
    db_session.commit()
    db_session.refresh(bug)
    db_session.refresh(candidate_good)
    db_session.refresh(candidate_bad)

    match_good = MagicMock(id=str(candidate_good.id), score=0.81)
    match_bad = MagicMock(id=str(candidate_bad.id), score=0.55)
    match_self = MagicMock(id=str(bug.id), score=0.99)

    mock_pinecone = MagicMock()
    mock_pinecone.find_similar_bugs.return_value = [
        match_good,
        match_bad,
        match_self,
    ]

    service = BugCorrelationService(pinecone=mock_pinecone)
    results = service.find_correlated(bug, db_session, top_k=5)

    ids = {item["bug_id"] for item in results}
    assert str(candidate_good.id) in ids
    assert str(candidate_bad.id) not in ids
