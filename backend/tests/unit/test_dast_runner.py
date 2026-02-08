import pytest

from src.services.scanner.dast_runner import DASTRunner
from src.services.scanner.zap_client import ZapError
from src.services.scanner.zap_parser import parse_zap_alert


def test_parse_zap_alert_fills_defaults():
    payload = {
        "alertId": "40012",
        "alert": "Test Alert",
        "risk": "High",
        "confidence": "Medium",
        "url": "https://example.com/a",
        "param": "id",
        "description": "Example description",
    }
    finding = parse_zap_alert(payload, "https://example.com")

    assert finding is not None
    assert finding.template_id == "40012"
    assert finding.matched_at == "https://example.com/a"
    assert finding.endpoint == "https://example.com"
    assert finding.evidence is not None
    assert "zap_alert=" in (finding.evidence or [""])[0]


class DummyZap:
    def __init__(self, alerts):
        self._alerts = alerts

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):  # noqa: ANN001
        return None

    async def spider_scan(self, *args, **kwargs):  # noqa: ANN001
        return "1"

    async def wait_spider(self, scan_id):  # noqa: ANN001
        return None

    async def active_scan(self, *args, **kwargs):  # noqa: ANN001
        return "2"

    async def wait_active(self, scan_id):  # noqa: ANN001
        return None

    async def alerts(self, *args, **kwargs):  # noqa: ANN001
        return self._alerts

    async def add_header_rule(self, *args, **kwargs):  # noqa: ANN001
        return None

    async def remove_header_rule(self, *args, **kwargs):  # noqa: ANN001
        return None


class FlakyZap:
    _attempt = 0

    def __init__(self, alerts):
        self._alerts = alerts

    async def __aenter__(self):
        FlakyZap._attempt += 1
        if FlakyZap._attempt == 1:
            raise ZapError("ZAP API error: ReadError('')")
        return DummyZap(self._alerts)

    async def __aexit__(self, exc_type, exc, tb):  # noqa: ANN001
        return None


@pytest.mark.asyncio
async def test_scan_parses_alerts(monkeypatch):
    alerts = [
        {
            "alertId": "100",
            "alert": "One",
            "risk": "Low",
            "confidence": "Low",
            "url": "https://example.com/a",
            "description": "Example",
        },
        {
            "alertId": "200",
            "alert": "Two",
            "risk": "High",
            "confidence": "High",
            "url": "https://example.com/b",
            "description": "Example",
        },
    ]

    monkeypatch.setattr(
        "src.services.scanner.dast_runner.ZapDockerSession",
        lambda **kwargs: DummyZap(alerts),
    )
    monkeypatch.setattr(
        "src.services.scanner.dast_runner.is_docker_available",
        lambda: True,
    )

    runner = DASTRunner()
    findings = await runner.scan("https://example.com")

    assert len(findings) == 2
    assert {item.template_id for item in findings} == {"100", "200"}


@pytest.mark.asyncio
async def test_scan_handles_zap_error(monkeypatch):
    class BoomZap:
        async def __aenter__(self):
            raise ZapError("boom")

        async def __aexit__(self, exc_type, exc, tb):  # noqa: ANN001
            return None

    monkeypatch.setattr(
        "src.services.scanner.dast_runner.ZapDockerSession",
        lambda **kwargs: BoomZap(),
    )
    monkeypatch.setattr(
        "src.services.scanner.dast_runner.is_docker_available",
        lambda: True,
    )

    runner = DASTRunner()
    findings = await runner.scan("https://example.com")

    assert findings == []
    assert runner.last_error is not None


@pytest.mark.asyncio
async def test_scan_retries_once_on_transient_zap_error(monkeypatch):
    alerts = [
        {
            "alertId": "100",
            "alert": "One",
            "risk": "Low",
            "confidence": "Low",
            "url": "https://example.com/a",
            "description": "Example",
        }
    ]
    FlakyZap._attempt = 0

    monkeypatch.setattr(
        "src.services.scanner.dast_runner.ZapDockerSession",
        lambda **kwargs: FlakyZap(alerts),
    )
    monkeypatch.setattr(
        "src.services.scanner.dast_runner.is_docker_available",
        lambda: True,
    )
    monkeypatch.setattr(
        "src.services.scanner.dast_runner.asyncio.sleep",
        lambda _seconds: DummyAwaitable(),
    )

    runner = DASTRunner()
    findings = await runner.scan("https://example.com")

    assert len(findings) == 1
    assert findings[0].template_id == "100"
    assert runner.last_error is None


class DummyAwaitable:
    def __await__(self):
        if False:
            yield None
        return None
