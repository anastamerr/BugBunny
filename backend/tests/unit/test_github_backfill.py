import pytest

from src.integrations import github_backfill


def test_backfill_counts_created_updated(monkeypatch):
    class DummySettings:
        github_repos = "acme/tools"
        repo_list = None
        github_token = "token-123"
        github_backfill_limit = 10

    monkeypatch.setattr(github_backfill, "get_settings", lambda: DummySettings())
    monkeypatch.setattr(github_backfill, "normalize_repo_list", lambda value: ["acme/tools"])

    class FakeClient:
        def __init__(self, token):
            self.token = token
            self.closed = False

        def iter_issues(self, repo_full_name, limit=50):  # noqa: ANN001
            return [{"id": 1}, {"id": 2}]

        def close(self):
            self.closed = True

    fake_client = FakeClient("token-123")
    monkeypatch.setattr(github_backfill, "GitHubClient", lambda token: fake_client)

    class FakeIngestor:
        def __init__(self):
            self.calls = []

        def upsert_issue(self, session, *, repo_full_name, issue, action=None):  # noqa: ANN001
            self.calls.append((repo_full_name, issue))
            created = issue.get("id") == 1
            return object(), created

    fake_ingestor = FakeIngestor()
    monkeypatch.setattr(github_backfill, "GitHubIngestor", lambda: fake_ingestor)

    class FakeSession:
        def __init__(self):
            self.closed = False

        def close(self):
            self.closed = True

    fake_session = FakeSession()
    monkeypatch.setattr(github_backfill, "SessionLocal", lambda: fake_session)

    result = github_backfill.backfill_github_issues()

    assert result == {"created": 1, "updated": 1}
    assert fake_session.closed is True
    assert fake_client.closed is True
    assert len(fake_ingestor.calls) == 2


def test_backfill_requires_token(monkeypatch):
    class DummySettings:
        github_repos = "acme/tools"
        repo_list = None
        github_token = None
        github_backfill_limit = 10

    monkeypatch.setattr(github_backfill, "get_settings", lambda: DummySettings())
    monkeypatch.setattr(github_backfill, "normalize_repo_list", lambda value: ["acme/tools"])

    with pytest.raises(RuntimeError, match="GITHUB_TOKEN"):
        github_backfill.backfill_github_issues()
