from types import SimpleNamespace

import pytest

from src.services.scanner.dependency_scanner import DependencyScanner, _parse_results


def test_parse_results_extracts_vulnerabilities():
    payload = {
        "Results": [
            {
                "Target": "requirements.txt",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2024-0001",
                        "PkgName": "requests",
                        "InstalledVersion": "2.0.0",
                        "FixedVersion": "2.31.0",
                        "Severity": "HIGH",
                        "Description": "Test description",
                        "CVSS": {"nvd": {"V3Score": 9.8}},
                    }
                ],
            }
        ]
    }

    findings = _parse_results(payload)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.cve_id == "CVE-2024-0001"
    assert finding.package_name == "requests"
    assert finding.cvss_score == 9.8
    assert finding.target == "requirements.txt"


@pytest.mark.asyncio
async def test_scan_returns_empty_on_invalid_json(monkeypatch, tmp_path):
    result = SimpleNamespace(returncode=0, stdout="not json", stderr="")

    def fake_run(*args, **kwargs):
        return result

    monkeypatch.setattr(
        "src.services.scanner.dependency_scanner.subprocess.run",
        fake_run,
    )

    scanner = DependencyScanner()
    findings = await scanner.scan(tmp_path)

    assert findings == []
