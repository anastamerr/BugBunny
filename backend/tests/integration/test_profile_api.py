import uuid

from fastapi.testclient import TestClient

from src.api.deps import CurrentUser, get_current_user, get_db
from src.main import app


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


def test_get_profile_defaults(db_sessionmaker):
    app.dependency_overrides[get_db] = _override_db(db_sessionmaker)
    app.dependency_overrides[get_current_user] = _override_current_user
    client = TestClient(app)

    resp = client.get("/api/profile")
    assert resp.status_code == 200
    payload = resp.json()
    settings = payload["settings"]
    assert settings["github_token_set"] is False
    assert settings["github_webhook_secret_set"] is False
    assert settings["github_allowlist"] == []
    assert settings["enable_scan_push"] is True
    assert settings["enable_scan_pr"] is True
    assert settings["enable_issue_ingest"] is True
    assert settings["enable_issue_comment_ingest"] is True

    app.dependency_overrides.clear()


def test_update_profile_normalizes_allowlist_and_clears_tokens(db_sessionmaker):
    app.dependency_overrides[get_db] = _override_db(db_sessionmaker)
    app.dependency_overrides[get_current_user] = _override_current_user
    client = TestClient(app)

    update_resp = client.patch(
        "/api/profile",
        json={
            "github_token": "token-123",
            "github_allowlist": ["Acme/Tools, acme/tools/", "Other/Repo.git"],
            "enable_scan_push": False,
        },
    )
    assert update_resp.status_code == 200
    settings = update_resp.json()["settings"]
    assert settings["github_token_set"] is True
    assert settings["github_allowlist"] == ["acme/tools", "other/repo"]
    assert settings["enable_scan_push"] is False

    clear_resp = client.patch(
        "/api/profile",
        json={"github_token": "", "github_webhook_secret": ""},
    )
    assert clear_resp.status_code == 200
    cleared = clear_resp.json()["settings"]
    assert cleared["github_token_set"] is False
    assert cleared["github_webhook_secret_set"] is False

    app.dependency_overrides.clear()
