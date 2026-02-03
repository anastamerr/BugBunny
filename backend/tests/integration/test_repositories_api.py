from datetime import datetime, timedelta, timezone
import uuid

from fastapi.testclient import TestClient

from src.api.deps import CurrentUser, get_current_user, get_db
from src.main import app
from src.models import Repository


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


def test_create_and_list_repositories(db_sessionmaker):
    app.dependency_overrides[get_db] = _override_db(db_sessionmaker)
    app.dependency_overrides[get_current_user] = _override_current_user
    client = TestClient(app)

    create_resp = client.post(
        "/api/repos",
        json={
            "repo_url": "https://github.com/acme/tools.git",
            "default_branch": "main",
        },
    )
    assert create_resp.status_code == 201
    created = create_resp.json()
    assert created["repo_url"] == "https://github.com/acme/tools"
    assert created["repo_full_name"] == "acme/tools"

    seed_db = db_sessionmaker()
    older = Repository(
        user_id=TEST_USER_ID,
        repo_url="https://github.com/acme/old",
        repo_full_name="acme/old",
        default_branch="main",
        created_at=datetime.now(timezone.utc) - timedelta(days=1),
        updated_at=datetime.now(timezone.utc) - timedelta(days=1),
    )
    other_user_repo = Repository(
        user_id=uuid.uuid4(),
        repo_url="https://github.com/other/repo",
        repo_full_name="other/repo",
        default_branch="main",
    )
    seed_db.add_all([older, other_user_repo])
    seed_db.commit()
    seed_db.close()

    list_resp = client.get("/api/repos")
    assert list_resp.status_code == 200
    payload = list_resp.json()
    assert len(payload) == 2
    assert payload[0]["repo_url"] == "https://github.com/acme/tools"
    assert payload[1]["repo_url"] == "https://github.com/acme/old"

    app.dependency_overrides.clear()


def test_create_repository_conflict_and_delete(db_sessionmaker):
    app.dependency_overrides[get_db] = _override_db(db_sessionmaker)
    app.dependency_overrides[get_current_user] = _override_current_user
    client = TestClient(app)

    create_resp = client.post(
        "/api/repos",
        json={"repo_url": "https://github.com/acme/tools", "default_branch": "main"},
    )
    assert create_resp.status_code == 201
    repo_id = create_resp.json()["id"]

    conflict_resp = client.post(
        "/api/repos",
        json={"repo_url": "https://github.com/acme/tools", "default_branch": "main"},
    )
    assert conflict_resp.status_code == 409

    invalid_delete = client.delete("/api/repos/not-a-uuid")
    assert invalid_delete.status_code == 404

    other_repo = Repository(
        user_id=uuid.uuid4(),
        repo_url="https://github.com/other/repo",
        repo_full_name="other/repo",
        default_branch="main",
    )
    seed_db = db_sessionmaker()
    seed_db.add(other_repo)
    seed_db.commit()
    seed_db.refresh(other_repo)
    seed_db.close()

    wrong_owner = client.delete(f"/api/repos/{other_repo.id}")
    assert wrong_owner.status_code == 404

    delete_resp = client.delete(f"/api/repos/{repo_id}")
    assert delete_resp.status_code == 204

    app.dependency_overrides.clear()
