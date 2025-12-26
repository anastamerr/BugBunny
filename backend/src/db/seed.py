from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy.exc import IntegrityError

from ..models import BugReport
from .session import SessionLocal


def seed_sample_data() -> None:
    """Insert a small set of sample bugs for local demos."""
    session = SessionLocal()
    try:
        bug = BugReport(
            bug_id="GH-123",
            source="github",
            title="Dashboard shows $0 revenue",
            description="Revenue dashboard displaying zero values since this morning",
            created_at=datetime.now(timezone.utc),
            reporter="demo-user",
            labels=["data", "analytics"],
            classified_type="bug",
            classified_component="analytics_dashboard",
            classified_severity="critical",
            confidence_score=0.92,
            status="new",
        )
        session.add(bug)

        session.commit()
    except IntegrityError:
        session.rollback()
    finally:
        session.close()


if __name__ == "__main__":
    seed_sample_data()
