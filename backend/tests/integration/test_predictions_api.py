from datetime import datetime, timezone

from fastapi.testclient import TestClient

from src.api.deps import get_db
from src.main import app
from src.models import DataIncident


def test_predict_for_incident(db_sessionmaker, monkeypatch):
    def override_get_db():
        db = db_sessionmaker()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db

    from src.api.routes import predictions as predictions_routes

    class DummyEngine:
        def __init__(self, db):
            self.db = db

        def predict_bugs(self, incident):
            return {
                "predicted_bug_count": 2,
                "predicted_components": ["user_api"],
                "confidence": 0.7,
                "prediction_window_hours": 6,
            }

    monkeypatch.setattr(predictions_routes, "PredictionEngine", DummyEngine)

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
    seed_db.close()

    resp = client.post(f"/api/predictions/{incident.id}")
    assert resp.status_code == 201
    assert resp.json()["predicted_bug_count"] == 2

    list_resp = client.get("/api/predictions")
    assert list_resp.status_code == 200
    assert len(list_resp.json()) == 1

    app.dependency_overrides.clear()
