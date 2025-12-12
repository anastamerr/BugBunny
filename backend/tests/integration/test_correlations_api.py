from datetime import datetime, timezone

from fastapi.testclient import TestClient

from src.api.deps import get_db
from src.main import app
from src.models import BugReport, DataIncident


def test_create_and_list_correlations(db_sessionmaker):
    def override_get_db():
        db = db_sessionmaker()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)

    seed_db = db_sessionmaker()
    incident = DataIncident(
        incident_id="DI-001",
        timestamp=datetime.now(timezone.utc),
        table_name="user_transactions",
        incident_type="SCHEMA_DRIFT",
        severity="CRITICAL",
        status="ACTIVE",
    )
    seed_db.add(incident)
    seed_db.commit()
    seed_db.refresh(incident)

    bug = BugReport(
        bug_id="GH-1",
        source="github",
        title="Dashboard shows $0 revenue",
        description="schema drift in user_transactions",
        created_at=datetime.now(timezone.utc),
        status="new",
        classified_component="analytics_dashboard",
        classified_severity="critical",
    )
    seed_db.add(bug)
    seed_db.commit()
    seed_db.refresh(bug)
    incident_uuid = str(incident.id)
    bug_uuid = str(bug.id)
    seed_db.close()

    payload = {
        "bug_id": bug_uuid,
        "incident_id": incident_uuid,
        "correlation_score": 0.8,
        "temporal_score": 0.9,
        "component_score": 1.0,
        "keyword_score": 0.7,
        "explanation": "test",
    }

    create_resp = client.post("/api/correlations", json=payload)
    assert create_resp.status_code == 201

    list_resp = client.get("/api/correlations")
    assert list_resp.status_code == 200
    data = list_resp.json()
    assert len(data) == 1
    assert data[0]["bug"]["bug_id"] == "GH-1"

    app.dependency_overrides.clear()
