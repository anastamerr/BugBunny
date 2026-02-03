import pytest

from src.services.scanner.zap_client import ZapDockerSession, ZapError


@pytest.mark.asyncio
async def test_spider_scan_parses_scan_id(monkeypatch):
    session = ZapDockerSession(
        image="ghcr.io/zaproxy/zaproxy:stable",
        api_key=None,
        timeout_seconds=10,
    )

    async def fake_action(component, action, params=None):  # noqa: ANN001
        return {"scan": "3"}

    monkeypatch.setattr(session, "_action", fake_action)

    scan_id = await session.spider_scan("https://example.com")
    assert scan_id == "3"


@pytest.mark.asyncio
async def test_spider_scan_accepts_zero_id(monkeypatch):
    session = ZapDockerSession(
        image="ghcr.io/zaproxy/zaproxy:stable",
        api_key=None,
        timeout_seconds=10,
    )

    async def fake_action(component, action, params=None):  # noqa: ANN001
        return {"scan": "0"}

    monkeypatch.setattr(session, "_action", fake_action)

    scan_id = await session.spider_scan("https://example.com")
    assert scan_id == "0"


@pytest.mark.asyncio
async def test_active_scan_parses_scan_id(monkeypatch):
    session = ZapDockerSession(
        image="ghcr.io/zaproxy/zaproxy:stable",
        api_key=None,
        timeout_seconds=10,
    )

    async def fake_action(component, action, params=None):  # noqa: ANN001
        return {"scan": 7}

    monkeypatch.setattr(session, "_action", fake_action)

    scan_id = await session.active_scan(url="https://example.com")
    assert scan_id == "7"


@pytest.mark.asyncio
async def test_active_scan_accepts_zero_id(monkeypatch):
    session = ZapDockerSession(
        image="ghcr.io/zaproxy/zaproxy:stable",
        api_key=None,
        timeout_seconds=10,
    )

    async def fake_action(component, action, params=None):  # noqa: ANN001
        return {"scan": 0}

    monkeypatch.setattr(session, "_action", fake_action)

    scan_id = await session.active_scan(url="https://example.com")
    assert scan_id == "0"


@pytest.mark.asyncio
async def test_scan_id_key_variants(monkeypatch):
    session = ZapDockerSession(
        image="ghcr.io/zaproxy/zaproxy:stable",
        api_key=None,
        timeout_seconds=10,
    )

    responses = [
        {"scanId": "4"},
        {"scan_id": 5},
        {"scanid": "6"},
    ]

    async def fake_action(component, action, params=None):  # noqa: ANN001
        return responses.pop(0)

    monkeypatch.setattr(session, "_action", fake_action)

    assert await session.spider_scan("https://example.com") == "4"
    assert await session.spider_scan("https://example.com") == "5"
    assert await session.spider_scan("https://example.com") == "6"


@pytest.mark.asyncio
async def test_spider_scan_raises_on_invalid_scan_id(monkeypatch):
    session = ZapDockerSession(
        image="ghcr.io/zaproxy/zaproxy:stable",
        api_key=None,
        timeout_seconds=10,
    )

    async def fake_action(component, action, params=None):  # noqa: ANN001
        return {"scan": ""}

    monkeypatch.setattr(session, "_action", fake_action)

    with pytest.raises(ZapError) as excinfo:
        await session.spider_scan("https://example.com")

    message = str(excinfo.value)
    assert "invalid scan id" in message.lower()
    assert "spider scan" in message.lower()
    assert "response=" in message.lower()


@pytest.mark.asyncio
async def test_spider_scan_rejects_non_numeric_scan_id(monkeypatch):
    session = ZapDockerSession(
        image="ghcr.io/zaproxy/zaproxy:stable",
        api_key=None,
        timeout_seconds=10,
    )

    async def fake_action(component, action, params=None):  # noqa: ANN001
        return {"scan": "abc"}

    monkeypatch.setattr(session, "_action", fake_action)

    with pytest.raises(ZapError):
        await session.spider_scan("https://example.com")


@pytest.mark.asyncio
async def test_spider_scan_rejects_decimal_scan_id(monkeypatch):
    session = ZapDockerSession(
        image="ghcr.io/zaproxy/zaproxy:stable",
        api_key=None,
        timeout_seconds=10,
    )

    async def fake_action(component, action, params=None):  # noqa: ANN001
        return {"scan": "1.2"}

    monkeypatch.setattr(session, "_action", fake_action)

    with pytest.raises(ZapError):
        await session.spider_scan("https://example.com")


@pytest.mark.asyncio
async def test_spider_scan_rejects_zero_decimal_scan_id(monkeypatch):
    session = ZapDockerSession(
        image="ghcr.io/zaproxy/zaproxy:stable",
        api_key=None,
        timeout_seconds=10,
    )

    async def fake_action(component, action, params=None):  # noqa: ANN001
        return {"scan": "0.0"}

    monkeypatch.setattr(session, "_action", fake_action)

    with pytest.raises(ZapError):
        await session.spider_scan("https://example.com")


@pytest.mark.asyncio
async def test_wait_status_uses_scan_id(monkeypatch):
    session = ZapDockerSession(
        image="ghcr.io/zaproxy/zaproxy:stable",
        api_key=None,
        timeout_seconds=10,
    )
    captured = {}

    async def fake_view(component, view, params=None):  # noqa: ANN001
        captured["scan_id"] = params.get("scanId") if params else None
        return {"status": "100"}

    monkeypatch.setattr(session, "_view", fake_view)

    await session._wait_status("spider", "5")
    assert captured["scan_id"] == "5"


@pytest.mark.asyncio
async def test_wait_status_allows_zero_scan_id(monkeypatch):
    session = ZapDockerSession(
        image="ghcr.io/zaproxy/zaproxy:stable",
        api_key=None,
        timeout_seconds=10,
    )

    captured = {}

    async def fake_view(component, view, params=None):  # noqa: ANN001
        captured["scan_id"] = params.get("scanId") if params else None
        return {"status": "100"}

    monkeypatch.setattr(session, "_view", fake_view)

    await session._wait_status("ascan", "0")
    assert captured["scan_id"] == "0"


@pytest.mark.asyncio
async def test_wait_status_rejects_negative_scan_id():
    session = ZapDockerSession(
        image="ghcr.io/zaproxy/zaproxy:stable",
        api_key=None,
        timeout_seconds=10,
    )

    with pytest.raises(ZapError):
        await session._wait_status("ascan", -1)
