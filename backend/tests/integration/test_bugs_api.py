from datetime import datetime, timezone
from unittest.mock import MagicMock

from fastapi.testclient import TestClient

import uuid

from src.api.deps import CurrentUser, get_current_user, get_db
from src.main import app


def test_create_and_get_bug(db_sessionmaker, monkeypatch):
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

    from src.api.routes import bugs as bugs_routes

    mock_classifier = MagicMock()
    mock_classifier.classify.return_value = {
        "type": "bug",
        "component": "backend",
        "severity": "high",
        "overall_confidence": 0.9,
    }
    monkeypatch.setattr(bugs_routes, "get_classifier", lambda: mock_classifier)
    monkeypatch.setattr(bugs_routes, "get_duplicate_detector", lambda: None)

    mock_router = MagicMock()
    mock_router.route_bug.return_value = {"team": "backend_team"}
    monkeypatch.setattr(bugs_routes, "get_router", lambda: mock_router)

    client = TestClient(app)

    payload = {
        "bug_id": "GH-123",
        "source": "github",
        "title": "API returns empty response",
        "description": "User API returning null for profile",
        "created_at": datetime.now(timezone.utc).isoformat(),
    }

    create_resp = client.post("/api/bugs", json=payload)
    assert create_resp.status_code == 201
    created = create_resp.json()
    assert created["bug_id"] == payload["bug_id"]
    assert created["classified_type"] == "bug"

    list_resp = client.get("/api/bugs")
    assert list_resp.status_code == 200
    assert len(list_resp.json()) == 1

    bug_id = created["id"]
    get_resp = client.get(f"/api/bugs/{bug_id}")
    assert get_resp.status_code == 200
    assert get_resp.json()["id"] == bug_id

    update_resp = client.patch(
        f"/api/bugs/{bug_id}",
        json={"status": "resolved", "resolution_notes": "Patched serializer and added a regression test."},
    )
    assert update_resp.status_code == 200
    assert update_resp.json()["status"] == "resolved"
    assert update_resp.json()["resolution_notes"] == "Patched serializer and added a regression test."

    app.dependency_overrides.clear()
