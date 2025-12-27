from __future__ import annotations

import uuid

from fastapi.testclient import TestClient

from src.api.deps import CurrentUser, get_current_user, get_db
from src.main import app


class DummySio:
    async def emit(self, *args, **kwargs):  # noqa: ANN001
        return None


def _override_db(db_sessionmaker):
    def _get_db():
        db = db_sessionmaker()
        try:
            yield db
        finally:
            db.close()

    return _get_db


TEST_USER_ID = uuid.uuid4()


def _override_current_user():
    return CurrentUser(id=TEST_USER_ID, email="tester@example.com")


def test_demo_inject_scan(db_sessionmaker, monkeypatch):
    from src.api.routes import demo as demo_routes

    monkeypatch.setattr(demo_routes, "sio", DummySio())
    app.dependency_overrides[get_db] = _override_db(db_sessionmaker)
    app.dependency_overrides[get_current_user] = _override_current_user
    client = TestClient(app)

    resp = client.post("/api/demo/inject-scan", json={})
    assert resp.status_code == 201
    payload = resp.json()

    assert payload["findings_created"] == 87
    assert payload["real_findings"] == 12
    assert payload["false_positives"] == 75

    scan = payload["scan"]
    assert scan["status"] == "completed"
    assert scan["scan_type"] == "both"
    assert scan["repo_url"] == "https://github.com/semgrep/semgrep-pro-tests"
    assert scan["target_url"] == "https://demo.scanguard.local"
    assert scan["total_findings"] == 87
    assert scan["filtered_findings"] == 12
    assert scan["dast_findings"] == 2

    app.dependency_overrides.clear()
