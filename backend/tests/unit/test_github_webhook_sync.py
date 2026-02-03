import pytest

from src.integrations import github_webhook_sync


class FakeResponse:
    def __init__(self, payload=None, status_code=200):
        self._payload = payload
        self.status_code = status_code

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError("http error")


class FakeClient:
    def __init__(self, hooks_payload):
        self.hooks_payload = hooks_payload
        self.calls = []
        self.patched = []
        self.created = []
        self.pings = []

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):  # noqa: ANN001
        return False

    def get(self, url, params=None):  # noqa: ANN001
        self.calls.append(("get", url, params))
        return FakeResponse(self.hooks_payload)

    def patch(self, url, json=None):  # noqa: ANN001
        self.patched.append((url, json))
        return FakeResponse({"id": 42})

    def post(self, url, json=None):  # noqa: ANN001
        if url.endswith("/pings"):
            self.pings.append(url)
            return FakeResponse({})
        self.created.append((url, json))
        return FakeResponse({"id": 99})


def test_get_ngrok_public_url_picks_https(monkeypatch):
    def fake_get(url, timeout=5.0):  # noqa: ANN001
        return FakeResponse(
            {
                "tunnels": [
                    {"proto": "http", "public_url": "http://bad"},
                    {"proto": "https", "public_url": "https://good.ngrok-free.app"},
                ]
            }
        )

    monkeypatch.setattr(
        "src.integrations.github_webhook_sync.httpx.get",
        fake_get,
    )

    url = github_webhook_sync._get_ngrok_public_url("http://ngrok")
    assert url == "https://good.ngrok-free.app"


def test_sync_updates_ngrok_hooks(monkeypatch):
    class DummySettings:
        github_repos = "acme/tools"
        repo_list = None
        github_token = "token-123"
        github_webhook_secret = "secret"

    monkeypatch.setattr(github_webhook_sync, "get_settings", lambda: DummySettings())
    monkeypatch.setattr(
        github_webhook_sync, "normalize_repo_list", lambda value: ["acme/tools"]
    )

    hooks_payload = [
        {
            "id": 10,
            "events": ["issues", "issue_comment"],
            "config": {"url": "https://old.ngrok-free.app/api/webhooks/github"},
        }
    ]
    fake_client = FakeClient(hooks_payload)

    def fake_httpx_client(*args, **kwargs):  # noqa: ANN001
        return fake_client

    monkeypatch.setattr(
        "src.integrations.github_webhook_sync.httpx.Client",
        fake_httpx_client,
    )

    result = github_webhook_sync.sync_github_webhooks(
        public_url="https://new.ngrok-free.app",
        dry_run=False,
    )

    assert result["updated"]
    assert result["updated"][0]["repo"] == "acme/tools"
    assert fake_client.patched
    assert fake_client.pings


def test_sync_create_if_missing_dry_run(monkeypatch):
    class DummySettings:
        github_repos = "acme/tools"
        repo_list = None
        github_token = "token-123"
        github_webhook_secret = "secret"

    monkeypatch.setattr(github_webhook_sync, "get_settings", lambda: DummySettings())
    monkeypatch.setattr(
        github_webhook_sync, "normalize_repo_list", lambda value: ["acme/tools"]
    )

    fake_client = FakeClient(hooks_payload=[])

    def fake_httpx_client(*args, **kwargs):  # noqa: ANN001
        return fake_client

    monkeypatch.setattr(
        "src.integrations.github_webhook_sync.httpx.Client",
        fake_httpx_client,
    )

    result = github_webhook_sync.sync_github_webhooks(
        public_url="https://demo.ngrok-free.app",
        create_if_missing=True,
        dry_run=True,
    )

    assert result["created"]
    assert fake_client.created == []
    assert fake_client.pings == []
