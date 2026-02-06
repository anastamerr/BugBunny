"""Tests for the TargetedDASTRunner service (ZAP)."""

import pytest

from src.services.scanner.targeted_dast_runner import (
    TargetedDASTRunner,
    _alert_targets_endpoint,
    _prepare_target_request,
)
from src.services.scanner.types import DASTAttackConfig, TriagedFinding
from src.services.scanner.types import DASTAttackResult
from src.services.scanner.zap_parser import classify_vulnerability


def make_triaged_finding(
    rule_id: str = "python.django.security.injection.sql-injection",
    rule_message: str = "SQL injection vulnerability",
    file_path: str = "api/routes/users.py",
    line_start: int = 45,
    code_snippet: str = "cursor.execute(f\"SELECT * FROM users WHERE id={id}\")",
    is_false_positive: bool = False,
) -> TriagedFinding:
    return TriagedFinding(
        rule_id=rule_id,
        rule_message=rule_message,
        semgrep_severity="ERROR",
        file_path=file_path,
        line_start=line_start,
        line_end=line_start + 1,
        code_snippet=code_snippet,
        context_snippet=code_snippet,
        function_name="get_user",
        class_name=None,
        is_test_file=False,
        is_generated=False,
        imports=["flask"],
        is_false_positive=is_false_positive,
        ai_severity="high",
        ai_confidence=0.85,
        ai_reasoning="SQL injection detected",
        exploitability="User input directly concatenated into SQL query",
    )


class DummyZap:
    def __init__(self, alerts):
        self._alerts = alerts

    async def create_context(self, name):  # noqa: ANN001
        return "1"

    async def include_in_context(self, name, regex):  # noqa: ANN001
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

    async def remove_context(self, name):  # noqa: ANN001
        return None


def test_classify_vulnerability():
    assert classify_vulnerability("sql injection") == "sqli"
    assert classify_vulnerability("cross site scripting") == "xss"
    assert classify_vulnerability("command injection") == "command-injection"
    assert classify_vulnerability("server-side request forgery") == "ssrf"
    assert classify_vulnerability("path traversal") == "path-traversal"
    assert (
        classify_vulnerability(
            "noise", rule_id="python.django.security.injection.sql-injection"
        )
        == "sqli"
    )
    assert classify_vulnerability("unknown") is None


def test_attack_findings_callable():
    assert hasattr(TargetedDASTRunner, "_attack_findings_impl") is True
    runner = TargetedDASTRunner()
    assert hasattr(runner, "attack_findings") is True
    assert callable(runner.attack_findings) is True


def test_generate_config_for_sqli():
    runner = TargetedDASTRunner()
    finding = make_triaged_finding(
        rule_id="sql-injection",
        code_snippet="cursor.execute(f\"SELECT * FROM users WHERE id={request.args.get('id')}\")",
    )
    config = runner._generate_attack_config(
        finding, "https://example.com", "/repo"
    )

    assert config is not None
    assert config.vuln_type == "sqli"
    assert "https://example.com" in config.target_endpoint
    assert config.target_parameter == "id"


def test_prepare_target_request_get_param():
    config = DASTAttackConfig(
        finding_id="test:file.py:1",
        vuln_type="sqli",
        vuln_keywords=[],
        target_endpoint="https://example.com/api/users",
        target_parameter="id",
        http_method="GET",
    )
    url, post_data = _prepare_target_request(config)
    assert "id=" in url
    assert post_data is None


def test_alert_targets_endpoint():
    alert = {"url": "https://example.com/api/users?id=1"}
    assert _alert_targets_endpoint(alert, "https://example.com/api/users") is True


@pytest.mark.asyncio
async def test_execute_attack_confirms_when_alert_matches():
    runner = TargetedDASTRunner()
    config = DASTAttackConfig(
        finding_id="test:file.py:1",
        vuln_type="sqli",
        vuln_keywords=[],
        target_endpoint="https://example.com/api/users",
        target_parameter="id",
        http_method="GET",
        endpoint_mapping_confidence=0.9,
    )

    alerts = [
        {
            "alertId": "40012",
            "alert": "SQL Injection",
            "risk": "High",
            "confidence": "High",
            "url": "https://example.com/api/users?id=1",
            "param": "id",
            "description": "SQL injection detected",
        }
    ]
    result = await runner._execute_attack(
        DummyZap(alerts), config, original_netloc=None, docker_netloc=None
    )

    assert result.attack_succeeded is True
    assert result.verification_status == "confirmed_exploitable"
    assert result.proof_of_exploit is not None
    assert "curl" in (result.proof_of_exploit or "")


@pytest.mark.asyncio
async def test_execute_attack_not_confirmed_when_no_alerts():
    runner = TargetedDASTRunner()
    config = DASTAttackConfig(
        finding_id="test:file.py:1",
        vuln_type="sqli",
        vuln_keywords=[],
        target_endpoint="https://example.com/api/users",
        target_parameter="id",
        http_method="GET",
        endpoint_mapping_confidence=0.9,
    )

    result = await runner._execute_attack(
        DummyZap([]), config, original_netloc=None, docker_netloc=None
    )

    assert result.attack_succeeded is False
    assert result.verification_status == "attempted_not_reproduced"
    assert result.matched_at is not None
    assert result.evidence is not None
    assert any("dast_target=" in item for item in result.evidence or [])


@pytest.mark.asyncio
async def test_attack_findings_attacks_false_positives(monkeypatch):
    runner = TargetedDASTRunner()
    findings = [
        make_triaged_finding(is_false_positive=True),
        make_triaged_finding(is_false_positive=True),
    ]

    monkeypatch.setattr(runner, "is_available", lambda: False)

    results = await runner.attack_findings(
        "https://example.com", findings, "/repo"
    )

    assert len(results) == 2
    assert all(result.verification_status == "error_tooling" for result in results)


@pytest.mark.asyncio
async def test_attack_findings_returns_error_when_docker_unavailable(monkeypatch):
    runner = TargetedDASTRunner()
    findings = [make_triaged_finding()]

    monkeypatch.setattr(runner, "is_available", lambda: False)

    results = await runner.attack_findings(
        "https://example.com", findings, "/repo"
    )

    assert len(results) == 1
    assert results[0].verification_status == "error_tooling"


def test_map_results_handles_missing_ai_confidence():
    runner = TargetedDASTRunner()
    finding = make_triaged_finding()
    finding.ai_confidence = None
    finding_id = f"{finding.rule_id}:{finding.file_path}:{finding.line_start}"
    result = DASTAttackResult(
        finding_id=finding_id,
        attack_succeeded=True,
        confidence=0.95,
        verification_status="confirmed_exploitable",
    )

    updated, confirmed = runner.map_results_to_findings(
        [finding],
        [result],
        "/repo",
    )

    assert confirmed == 1
    assert updated[0].ai_confidence == pytest.approx(0.2)
    assert updated[0].confirmed_exploitable is True
