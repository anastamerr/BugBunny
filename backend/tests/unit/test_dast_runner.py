import json
from types import SimpleNamespace

import pytest

from src.services.scanner.dast_runner import DASTRunner, _parse_nuclei_finding


def test_parse_nuclei_finding_fills_defaults():
    payload = {
        "template-id": "CVE-2024-0001",
        "info": {"name": "Test", "severity": "high"},
    }
    finding = _parse_nuclei_finding(payload, "https://example.com")

    assert finding is not None
    assert finding.template_id == "CVE-2024-0001"
    assert finding.matched_at == "https://example.com"
    assert finding.endpoint == "https://example.com"


@pytest.mark.asyncio
async def test_scan_parses_jsonl_output(monkeypatch):
    output = "\n".join(
        [
            json.dumps(
                {
                    "template-id": "id-1",
                    "info": {"name": "One", "severity": "low"},
                    "matched-at": "https://example.com/a",
                }
            ),
            "not json",
            json.dumps(
                {
                    "template-id": "id-2",
                    "info": {"name": "Two", "severity": "high"},
                    "matched-at": "https://example.com/b",
                }
            ),
        ]
    )
    result = SimpleNamespace(returncode=0, stdout=output, stderr="")

    def fake_run(*args, **kwargs):
        return result

    monkeypatch.setattr(
        "src.services.scanner.dast_runner.subprocess.run",
        fake_run,
    )

    runner = DASTRunner()
    findings = await runner.scan("https://example.com")

    assert len(findings) == 2
    assert {item.template_id for item in findings} == {"id-1", "id-2"}


@pytest.mark.asyncio
async def test_scan_handles_timeout(monkeypatch):
    def fake_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="nuclei", timeout=1)

    import subprocess

    monkeypatch.setattr(
        "src.services.scanner.dast_runner.subprocess.run",
        fake_run,
    )

    runner = DASTRunner()
    findings = await runner.scan("https://example.com")

    assert findings == []
    assert runner.last_error is not None
