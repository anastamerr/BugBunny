from datetime import datetime, timezone

from fastapi.testclient import TestClient

from src.api.deps import get_db
from src.main import app
from src.models import DataIncident


def test_chat_fallback_when_ollama_unavailable(db_sessionmaker, monkeypatch):
    from src.api.routes import chat as chat_routes

    async def fake_is_available(self):  # noqa: ANN001
        return False

    monkeypatch.setattr(chat_routes.OllamaService, "is_available", fake_is_available)

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
    incident_uuid = str(incident.id)
    seed_db.close()

    resp = client.post(
        "/api/chat",
        json={
            "message": "Explain the likely root cause.",
            "incident_id": incident_uuid,
        },
    )
    assert resp.status_code == 200
    payload = resp.json()
    assert payload["used_llm"] is False
    assert "LLM is unavailable" in payload["response"]
    assert "user_transactions" in payload["response"]

    app.dependency_overrides.clear()

