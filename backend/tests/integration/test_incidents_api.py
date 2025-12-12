from datetime import datetime, timezone

from fastapi.testclient import TestClient

from src.api.deps import get_db
from src.main import app


def test_create_and_get_incident(db_sessionmaker):
    def override_get_db():
        db = db_sessionmaker()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)

    payload = {
        "incident_id": "DI-2025-01-15-001",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "table_name": "user_transactions",
        "incident_type": "SCHEMA_DRIFT",
        "severity": "CRITICAL",
        "details": {"foo": "bar"},
        "affected_columns": ["user_id"],
        "anomaly_score": 0.9,
        "downstream_systems": ["analytics_dashboard"],
        "status": "ACTIVE",
    }

    create_resp = client.post("/api/incidents", json=payload)
    assert create_resp.status_code == 201
    created = create_resp.json()
    assert created["incident_id"] == payload["incident_id"]

    list_resp = client.get("/api/incidents")
    assert list_resp.status_code == 200
    assert len(list_resp.json()) == 1

    incident_id = created["id"]
    get_resp = client.get(f"/api/incidents/{incident_id}")
    assert get_resp.status_code == 200
    assert get_resp.json()["id"] == incident_id

    app.dependency_overrides.clear()
