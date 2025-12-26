from datetime import datetime, timezone

from fastapi.testclient import TestClient

import uuid

from src.api.deps import CurrentUser, get_current_user, get_db
from src.main import app
from src.models import BugReport


def test_chat_fallback_when_ollama_unavailable(db_sessionmaker, monkeypatch):
    from src.api.routes import chat as chat_routes

    class FakeLLM:
        provider = "test"
        model = "test-model"

        async def is_available(self):  # noqa: ANN001
            return False

        async def generate(self, prompt, system=None):  # noqa: ANN001
            return "should not be called"

    monkeypatch.setattr(chat_routes, "get_llm_service", lambda _settings: FakeLLM())

    def override_get_db():
        db = db_sessionmaker()
        try:
            yield db
        finally:
            db.close()

    test_user_id = uuid.uuid4()

    def override_current_user():
        return CurrentUser(id=test_user_id, email="tester@example.com")

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_current_user] = override_current_user
    client = TestClient(app)

    seed_db = db_sessionmaker()
    bug = BugReport(
        bug_id="GH-001",
        source="github",
        title="Revenue dashboard shows $0",
        description="Dashboard shows $0 for all regions.",
        created_at=datetime.now(timezone.utc),
        classified_type="bug",
        classified_component="analytics_dashboard",
        classified_severity="critical",
        confidence_score=0.9,
        status="new",
    )
    seed_db.add(bug)
    seed_db.commit()
    seed_db.refresh(bug)
    bug_uuid = str(bug.id)
    seed_db.close()

    resp = client.post(
        "/api/chat",
        json={
            "message": "Explain the likely root cause.",
            "bug_id": bug_uuid,
        },
    )
    assert resp.status_code == 200
    payload = resp.json()
    assert payload["used_llm"] is False
    assert "LLM is unavailable" in payload["response"]
    assert "Revenue dashboard shows $0" in payload["response"]

    app.dependency_overrides.clear()
