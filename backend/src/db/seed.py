from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy.exc import IntegrityError

from ..models import BugIncidentCorrelation, BugReport, DataIncident
from .session import SessionLocal


def seed_sample_data() -> None:
    """Insert a small set of sample incidents/bugs for local demos."""
    session = SessionLocal()
    try:
        incident = DataIncident(
            incident_id="DI-2025-01-15-001",
            timestamp=datetime.now(timezone.utc),
            table_name="user_transactions",
            incident_type="SCHEMA_DRIFT",
            severity="CRITICAL",
            details={"new_column": "discount_code"},
            affected_columns=["user_id"],
            anomaly_score=0.9,
            downstream_systems=["analytics_dashboard", "user_api"],
            status="ACTIVE",
        )
        session.add(incident)
        session.flush()

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
            is_data_related=True,
            correlated_incident_id=incident.id,
            correlation_score=0.88,
            status="new",
        )
        session.add(bug)
        session.flush()

        session.add(
            BugIncidentCorrelation(
                bug_id=bug.id,
                incident_id=incident.id,
                correlation_score=0.88,
                temporal_score=0.9,
                component_score=1.0,
                keyword_score=0.7,
                explanation="Schema drift in user_transactions is propagating NULL/incorrect values to analytics_dashboard and user_api.",
            )
        )

        session.commit()
    except IntegrityError:
        session.rollback()
    finally:
        session.close()


if __name__ == "__main__":
    seed_sample_data()
