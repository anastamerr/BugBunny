import hashlib
import hmac
import json
import uuid

from fastapi.testclient import TestClient

from src.api.deps import get_db
from src.main import app
from src.models import Repository, Scan


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


def test_github_push_webhook_triggers_scan(db_sessionmaker, monkeypatch):
    import os

    os.environ["GITHUB_WEBHOOK_SECRET"] = "test-secret"
    os.environ["GITHUB_REPOS"] = "acme/tools"

    from src.config import get_settings

    get_settings.cache_clear()

    from src.api.routes import webhooks as webhooks_routes

    async def fake_run_scan_pipeline(  # noqa: ANN001
        scan_id, repo_url, branch, scan_type="sast", target_url=None
    ):
        return None

    monkeypatch.setattr(webhooks_routes, "run_scan_pipeline", fake_run_scan_pipeline)
    monkeypatch.setattr(webhooks_routes, "sio", DummySio())

    app.dependency_overrides[get_db] = _override_db(db_sessionmaker)
    client = TestClient(app)

    test_user_id = uuid.uuid4()
    seed_db = db_sessionmaker()
    seed_db.add(
        Repository(
            user_id=test_user_id,
            repo_url="https://github.com/acme/tools",
            repo_full_name="acme/tools",
            default_branch="main",
        )
    )
    seed_db.commit()
    seed_db.close()

    payload = {
        "ref": "refs/heads/main",
        "after": "a" * 40,
        "repository": {
            "full_name": "acme/tools",
            "html_url": "https://github.com/acme/tools",
        },
    }
    body = json.dumps(payload).encode("utf-8")
    sig = hmac.new(b"test-secret", body, hashlib.sha256).hexdigest()

    resp = client.post(
        "/api/webhooks/github",
        content=body,
        headers={
            "Content-Type": "application/json",
            "X-GitHub-Event": "push",
            "X-Hub-Signature-256": f"sha256={sig}",
        },
    )
    assert resp.status_code == 200
    payload_resp = resp.json()
    assert payload_resp["ok"] is True

    verify_db = db_sessionmaker()
    scan = verify_db.query(Scan).filter(Scan.repo_url == "https://github.com/acme/tools").first()
    assert scan is not None
    assert scan.user_id == test_user_id
    assert scan.trigger == "webhook"
    assert scan.commit_sha == "a" * 40
    assert scan.commit_url == f"https://github.com/acme/tools/commit/{'a' * 40}"
    verify_db.close()

    app.dependency_overrides.clear()


def test_github_pull_request_webhook_triggers_scan(db_sessionmaker, monkeypatch):
    import os

    os.environ["GITHUB_WEBHOOK_SECRET"] = "test-secret"
    os.environ["GITHUB_REPOS"] = "acme/tools"

    from src.config import get_settings

    get_settings.cache_clear()

    from src.api.routes import webhooks as webhooks_routes

    async def fake_run_scan_pipeline(  # noqa: ANN001
        scan_id, repo_url, branch, scan_type="sast", target_url=None
    ):
        return None

    monkeypatch.setattr(webhooks_routes, "run_scan_pipeline", fake_run_scan_pipeline)
    monkeypatch.setattr(webhooks_routes, "sio", DummySio())

    app.dependency_overrides[get_db] = _override_db(db_sessionmaker)
    client = TestClient(app)

    test_user_id = uuid.uuid4()
    seed_db = db_sessionmaker()
    seed_db.add(
        Repository(
            user_id=test_user_id,
            repo_url="https://github.com/acme/tools",
            repo_full_name="acme/tools",
            default_branch="main",
        )
    )
    seed_db.commit()
    seed_db.close()

    payload = {
        "action": "opened",
        "repository": {
            "full_name": "acme/tools",
            "html_url": "https://github.com/acme/tools",
        },
        "pull_request": {
            "number": 42,
            "html_url": "https://github.com/acme/tools/pull/42",
            "head": {"ref": "feature/scan", "sha": "b" * 40},
            "base": {
                "repo": {"html_url": "https://github.com/acme/tools"},
            },
        },
    }
    body = json.dumps(payload).encode("utf-8")
    sig = hmac.new(b"test-secret", body, hashlib.sha256).hexdigest()

    resp = client.post(
        "/api/webhooks/github",
        content=body,
        headers={
            "Content-Type": "application/json",
            "X-GitHub-Event": "pull_request",
            "X-Hub-Signature-256": f"sha256={sig}",
        },
    )
    assert resp.status_code == 200
    payload_resp = resp.json()
    assert payload_resp["ok"] is True

    verify_db = db_sessionmaker()
    scan = verify_db.query(Scan).filter(Scan.pr_number == 42).first()
    assert scan is not None
    assert scan.user_id == test_user_id
    assert scan.trigger == "webhook"
    assert scan.branch == "feature/scan"
    assert scan.pr_url == "https://github.com/acme/tools/pull/42"
    assert scan.commit_sha == "b" * 40
    assert scan.commit_url == f"https://github.com/acme/tools/commit/{'b' * 40}"
    verify_db.close()

    app.dependency_overrides.clear()
