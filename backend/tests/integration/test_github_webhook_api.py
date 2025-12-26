import hashlib
import hmac
import json
import uuid

from fastapi.testclient import TestClient

from src.api.deps import get_db
from src.main import app
from src.models import BugReport, Repository


def test_github_issues_webhook_creates_bug(db_sessionmaker, monkeypatch):
    import os

    os.environ["GITHUB_WEBHOOK_SECRET"] = "test-secret"
    os.environ["GITHUB_REPOS"] = "anastamerr/Quantumflow"

    from src.config import get_settings

    get_settings.cache_clear()

    from src.api.routes import webhooks as webhooks_routes
    from src.integrations.github_ingestor import GitHubIngestor

    class DummyClassifier:
        def classify(self, title, description):
            return {
                "type": "bug",
                "component": "backend",
                "severity": "high",
                "overall_confidence": 0.9,
            }

    class DummyRouter:
        def route_bug(self, classification):
            return {"team": "backend_team"}

    monkeypatch.setattr(
        webhooks_routes,
        "get_ingestor",
        lambda: GitHubIngestor(classifier=DummyClassifier(), auto_router=DummyRouter()),
    )

    def override_get_db():
        db = db_sessionmaker()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)

    seed_db = db_sessionmaker()
    seed_db.add(
        Repository(
            user_id=uuid.uuid4(),
            repo_url="https://github.com/anastamerr/Quantumflow",
            repo_full_name="anastamerr/Quantumflow",
            default_branch="main",
        )
    )
    seed_db.commit()
    seed_db.close()

    payload = {
        "action": "opened",
        "repository": {"full_name": "anastamerr/Quantumflow"},
        "issue": {
            "number": 1,
            "title": "API returns empty response",
            "body": "User API returning null for profile",
            "state": "open",
            "created_at": "2025-01-01T00:00:00Z",
            "html_url": "https://github.com/anastamerr/Quantumflow/issues/1",
            "user": {"login": "tester"},
            "labels": [{"name": "bug"}],
        },
    }
    body = json.dumps(payload).encode("utf-8")
    sig = hmac.new(b"test-secret", body, hashlib.sha256).hexdigest()

    resp = client.post(
        "/api/webhooks/github",
        content=body,
        headers={
            "Content-Type": "application/json",
            "X-GitHub-Event": "issues",
            "X-Hub-Signature-256": f"sha256={sig}",
        },
    )
    assert resp.status_code == 200
    assert resp.json()["ok"] is True

    verify_db = db_sessionmaker()
    bug = verify_db.query(BugReport).filter(BugReport.bug_id == "gh:anastamerr/Quantumflow#1").first()
    assert bug is not None
    assert bug.source == "github"
    assert bug.title == "API returns empty response"
    assert bug.assigned_team == "backend_team"
    verify_db.close()

    app.dependency_overrides.clear()


def test_github_issue_comment_webhook_updates_bug_labels(db_sessionmaker, monkeypatch):
    import os

    os.environ["GITHUB_WEBHOOK_SECRET"] = "test-secret"
    os.environ["GITHUB_REPOS"] = "anastamerr/Quantumflow"

    from src.config import get_settings

    get_settings.cache_clear()

    from src.api.routes import webhooks as webhooks_routes
    from src.integrations.github_ingestor import GitHubIngestor

    class DummyClassifier:
        def classify(self, title, description):
            return {
                "type": "bug",
                "component": "backend",
                "severity": "high",
                "overall_confidence": 0.9,
            }

    class DummyRouter:
        def route_bug(self, classification):
            return {"team": "backend_team"}

    monkeypatch.setattr(
        webhooks_routes,
        "get_ingestor",
        lambda: GitHubIngestor(classifier=DummyClassifier(), auto_router=DummyRouter()),
    )

    def override_get_db():
        db = db_sessionmaker()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)

    seed_db = db_sessionmaker()
    seed_db.add(
        Repository(
            user_id=uuid.uuid4(),
            repo_url="https://github.com/anastamerr/Quantumflow",
            repo_full_name="anastamerr/Quantumflow",
            default_branch="main",
        )
    )
    seed_db.commit()
    seed_db.close()

    payload = {
        "action": "created",
        "repository": {"full_name": "anastamerr/Quantumflow"},
        "issue": {
            "number": 2,
            "title": "Webhook comment test",
            "body": "Initial issue body",
            "state": "open",
            "created_at": "2025-01-01T00:00:00Z",
            "html_url": "https://github.com/anastamerr/Quantumflow/issues/2",
            "user": {"login": "tester"},
            "labels": [{"name": "bug"}],
        },
        "comment": {
            "id": 123,
            "body": "I can reproduce this on v1.2.3",
            "html_url": "https://github.com/anastamerr/Quantumflow/issues/2#issuecomment-123",
            "created_at": "2025-01-01T01:00:00Z",
            "updated_at": "2025-01-01T01:00:00Z",
            "user": {"login": "commenter"},
        },
    }
    body = json.dumps(payload).encode("utf-8")
    sig = hmac.new(b"test-secret", body, hashlib.sha256).hexdigest()

    resp = client.post(
        "/api/webhooks/github",
        content=body,
        headers={
            "Content-Type": "application/json",
            "X-GitHub-Event": "issue_comment",
            "X-Hub-Signature-256": f"sha256={sig}",
        },
    )
    assert resp.status_code == 200
    assert resp.json()["ok"] is True

    verify_db = db_sessionmaker()
    bug = (
        verify_db.query(BugReport)
        .filter(BugReport.bug_id == "gh:anastamerr/Quantumflow#2")
        .first()
    )
    assert bug is not None
    assert isinstance(bug.labels, dict)
    assert "comments" in bug.labels
    assert bug.labels["comments"][0]["body"].startswith("I can reproduce")
    verify_db.close()

    app.dependency_overrides.clear()
