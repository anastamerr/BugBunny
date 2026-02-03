from datetime import timezone

import pytest

from src.integrations.github_client import GitHubClient, parse_github_timestamp


class FakeResponse:
    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError("http error")


class FakeClient:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def get(self, url, params=None):
        self.calls.append((url, params))
        return self.responses.pop(0)

    def close(self):
        return None


def test_iter_issues_paginates_and_filters_prs(monkeypatch):
    responses = [
        FakeResponse(
            [
                {"id": 1, "number": 1},
                {"id": 2, "number": 2, "pull_request": {"url": "https://x"}},
            ]
        ),
        FakeResponse([{"id": 3, "number": 3}]),
    ]
    fake_client = FakeClient(responses)

    def fake_httpx_client(*args, **kwargs):  # noqa: ANN001
        return fake_client

    monkeypatch.setattr(
        "src.integrations.github_client.httpx.Client", fake_httpx_client
    )

    client = GitHubClient(token="token-123")
    items = list(client.iter_issues("acme/tools", per_page=2, limit=2))

    assert [item["id"] for item in items] == [1, 3]
    assert fake_client.calls[0][0] == "/repos/acme/tools/issues"
    assert fake_client.calls[0][1]["page"] == 1
    assert fake_client.calls[0][1]["per_page"] == 2
    assert fake_client.calls[1][1]["page"] == 2


def test_iter_issues_stops_on_empty_or_invalid(monkeypatch):
    responses = [FakeResponse([]), FakeResponse({"ok": True})]
    fake_client = FakeClient(responses)

    def fake_httpx_client(*args, **kwargs):  # noqa: ANN001
        return fake_client

    monkeypatch.setattr(
        "src.integrations.github_client.httpx.Client", fake_httpx_client
    )

    client = GitHubClient(token="token-123")
    items = list(client.iter_issues("acme/tools", limit=10))

    assert items == []
    assert len(fake_client.calls) == 1


def test_parse_github_timestamp():
    value = "2025-01-01T12:34:56Z"
    parsed = parse_github_timestamp(value)
    assert parsed is not None
    assert parsed.tzinfo == timezone.utc

    assert parse_github_timestamp("not-a-date") is None
    assert parse_github_timestamp(None) is None


def test_github_client_requires_token():
    with pytest.raises(ValueError, match="GitHub token is required"):
        GitHubClient(token="")
