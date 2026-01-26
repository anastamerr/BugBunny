"""Tests for the TargetedDASTRunner service."""

import json
from unittest.mock import AsyncMock, patch

import pytest

from src.services.scanner.targeted_dast_runner import TargetedDASTRunner
from src.services.scanner.types import TriagedFinding


def make_triaged_finding(
    rule_id: str = "python.django.security.injection.sql-injection",
    rule_message: str = "SQL injection vulnerability",
    file_path: str = "api/routes/users.py",
    line_start: int = 45,
    code_snippet: str = "cursor.execute(f\"SELECT * FROM users WHERE id={id}\")",
    is_false_positive: bool = False,
) -> TriagedFinding:
    """Create a test TriagedFinding instance."""
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


class TestVulnerabilityClassification:
    """Tests for vulnerability classification."""

    def test_classifies_sql_injection(self):
        runner = TargetedDASTRunner()
        vuln_type, templates = runner._classify_vulnerability(
            "sql-injection", "SQL injection in query"
        )
        assert vuln_type == "sqli"
        assert templates[:1] == ["-tags"]

    def test_classifies_xss(self):
        runner = TargetedDASTRunner()
        vuln_type, templates = runner._classify_vulnerability(
            "xss-reflected", "Cross-site scripting vulnerability"
        )
        assert vuln_type == "xss"
        assert templates[:1] == ["-tags"]

    def test_classifies_command_injection(self):
        runner = TargetedDASTRunner()
        vuln_type, templates = runner._classify_vulnerability(
            "command-injection", "OS command injection"
        )
        assert vuln_type == "command-injection"
        assert templates[:1] == ["-tags"]

    def test_classifies_ssrf(self):
        runner = TargetedDASTRunner()
        vuln_type, templates = runner._classify_vulnerability(
            "ssrf", "Server-side request forgery"
        )
        assert vuln_type == "ssrf"
        assert templates[:1] == ["-tags"]

    def test_classifies_path_traversal(self):
        runner = TargetedDASTRunner()
        vuln_type, templates = runner._classify_vulnerability(
            "path-traversal", "Directory traversal attack"
        )
        assert vuln_type == "path-traversal"
        assert templates[:1] == ["-tags"]

    def test_returns_none_for_unknown(self):
        runner = TargetedDASTRunner()
        vuln_type, templates = runner._classify_vulnerability(
            "unknown-rule", "Unknown vulnerability"
        )
        assert vuln_type is None
        assert templates == []


class TestFileToEndpointMapping:
    """Tests for file path to endpoint mapping."""

    def test_maps_flask_route(self):
        runner = TargetedDASTRunner()
        endpoint = runner._map_file_to_endpoint(
            "api/routes/users.py", "/repo"
        )
        assert endpoint == "/api/users"

    def test_maps_controller(self):
        runner = TargetedDASTRunner()
        endpoint = runner._map_file_to_endpoint(
            "controllers/AuthController.py", "/repo"
        )
        assert endpoint == "/auth"

    def test_maps_handler(self):
        runner = TargetedDASTRunner()
        endpoint = runner._map_file_to_endpoint(
            "handlers/search_handler.go", "/repo"
        )
        assert endpoint == "/search"

    def test_fallback_to_filename(self):
        runner = TargetedDASTRunner()
        endpoint = runner._map_file_to_endpoint(
            "some/random/file.py", "/repo"
        )
        assert endpoint == "/file"


class TestParameterExtraction:
    """Tests for parameter extraction from code context."""

    def test_extracts_flask_param(self):
        runner = TargetedDASTRunner()
        finding = make_triaged_finding(
            code_snippet="user_id = request.args.get('user_id')"
        )
        param = runner._extract_parameter(finding)
        assert param == "user_id"

    def test_extracts_django_param(self):
        runner = TargetedDASTRunner()
        finding = make_triaged_finding(
            code_snippet="item_id = request.GET.get('item_id')"
        )
        param = runner._extract_parameter(finding)
        assert param == "item_id"

    def test_extracts_express_param(self):
        runner = TargetedDASTRunner()
        finding = make_triaged_finding(
            code_snippet="const id = req.query.id"
        )
        param = runner._extract_parameter(finding)
        assert param == "id"

    def test_defaults_to_id(self):
        runner = TargetedDASTRunner()
        finding = make_triaged_finding(
            code_snippet="some code without parameter patterns"
        )
        param = runner._extract_parameter(finding)
        assert param == "id"


class TestAttackConfigGeneration:
    """Tests for attack configuration generation."""

    def test_generates_config_for_sqli(self):
        runner = TargetedDASTRunner()
        finding = make_triaged_finding(
            rule_id="sql-injection",
            code_snippet="cursor.execute(f\"SELECT * FROM users WHERE id={request.args.get('id')}\")"
        )
        config = runner._generate_attack_config(
            finding, "https://example.com", "/repo"
        )

        assert config is not None
        assert config.vuln_type == "sqli"
        assert "https://example.com" in config.target_endpoint
        assert config.target_parameter == "id"
        assert config.nuclei_templates[:1] == ["-tags"]

    def test_returns_none_for_unknown_vuln(self):
        runner = TargetedDASTRunner()
        finding = make_triaged_finding(
            rule_id="unknown-vulnerability-type",
            rule_message="Some unknown vulnerability"
        )
        config = runner._generate_attack_config(
            finding, "https://example.com", "/repo"
        )

        assert config is None

    def test_skips_false_positives(self):
        runner = TargetedDASTRunner()
        # False positives should not be attacked
        # This is handled in attack_findings, not in _generate_attack_config
        # So we test it doesn't matter here
        finding = make_triaged_finding(
            rule_id="sql-injection",
            is_false_positive=True
        )
        config = runner._generate_attack_config(
            finding, "https://example.com", "/repo"
        )
        # Config is still generated even for false positives
        # The filtering happens at the attack_findings level
        assert config is not None


class TestHttpMethodDetection:
    """Tests for HTTP method detection."""

    def test_detects_post(self):
        runner = TargetedDASTRunner()
        finding = make_triaged_finding(
            code_snippet="def create_user(request): data = request.POST"
        )
        method = runner._detect_http_method(finding)
        assert method == "POST"

    def test_detects_put(self):
        runner = TargetedDASTRunner()
        finding = make_triaged_finding(
            code_snippet="def update_user(request): ..."
        )
        method = runner._detect_http_method(finding)
        assert method == "PUT"

    def test_defaults_to_get(self):
        runner = TargetedDASTRunner()
        finding = make_triaged_finding(
            code_snippet="def get_user(request): ..."
        )
        method = runner._detect_http_method(finding)
        assert method == "GET"


class TestAttackExecution:
    """Tests for DAST attack execution."""

    @pytest.mark.asyncio
    async def test_attack_findings_skips_false_positives(self):
        runner = TargetedDASTRunner()
        findings = [
            make_triaged_finding(is_false_positive=True),
            make_triaged_finding(is_false_positive=True),
        ]

        with patch.object(runner, "is_available", return_value=True):
            results = await runner.attack_findings(
                "https://example.com", findings, "/repo"
            )

        # No attacks should be made for false positives
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_attack_findings_returns_empty_when_nuclei_unavailable(self):
        runner = TargetedDASTRunner()
        findings = [make_triaged_finding()]

        with patch.object(runner, "is_available", return_value=False):
            results = await runner.attack_findings(
                "https://example.com", findings, "/repo"
            )

        assert len(results) == 1
        assert results[0].verification_status == "error_tooling"
        assert runner.last_error is not None

    @pytest.mark.asyncio
    async def test_execute_attack_parses_nuclei_output(self):
        runner = TargetedDASTRunner()

        nuclei_output = json.dumps({
            "template-id": "sqli-test",
            "matched-at": "https://example.com/api/users?id=1",
            "curl-command": "curl -X GET 'https://example.com/api/users?id=1%27'",
            "info": {
                "severity": "high",
                "classification": {
                    "cve-id": ["CVE-2021-12345"],
                    "cwe-id": ["CWE-89"],
                },
            },
        })

        from src.services.scanner.types import DASTAttackConfig

        config = DASTAttackConfig(
            finding_id="test:file.py:1",
            vuln_type="sqli",
            nuclei_templates=["-tags", "sqli"],
            target_endpoint="https://example.com/api/users",
            target_parameter="id",
            endpoint_mapping_confidence=0.9,
        )

        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_process = AsyncMock()
            mock_process.communicate.return_value = (
                nuclei_output.encode(),
                b"",
            )
            mock_exec.return_value = mock_process

            result = await runner._execute_attack(config)

        assert result.attack_succeeded is True
        assert result.confidence == 0.99
        assert result.verification_status == "confirmed_exploitable"
        assert result.proof_of_exploit is not None
        assert "CVE-2021-12345" in (result.cve_ids or [])

    @pytest.mark.asyncio
    async def test_execute_attack_handles_empty_output(self):
        runner = TargetedDASTRunner()

        from src.services.scanner.types import DASTAttackConfig

        config = DASTAttackConfig(
            finding_id="test:file.py:1",
            vuln_type="sqli",
            nuclei_templates=["-tags", "sqli"],
            target_endpoint="https://example.com/api/users",
            target_parameter="id",
            endpoint_mapping_confidence=0.9,
        )

        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_process = AsyncMock()
            mock_process.communicate.return_value = (b"", b"")
            mock_exec.return_value = mock_process

        result = await runner._execute_attack(config)

        assert result.attack_succeeded is False
        assert result.verification_status == "attempted_not_reproduced"
        assert result.confidence == 0.6

    @pytest.mark.asyncio
    async def test_execute_attack_includes_auth_headers(self):
        runner = TargetedDASTRunner(
            auth_headers={"Authorization": "Bearer token"},
            cookies="session=abc123",
        )

        from src.services.scanner.types import DASTAttackConfig

        config = DASTAttackConfig(
            finding_id="test:file.py:1",
            vuln_type="sqli",
            nuclei_templates=["-tags", "sqli"],
            target_endpoint="https://example.com/api/users",
            target_parameter="id",
        )

        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_process = AsyncMock()
            mock_process.communicate.return_value = (b"", b"")
            mock_exec.return_value = mock_process

            await runner._execute_attack(config)

        cmd = list(mock_exec.call_args[0])
        assert "-tags" in cmd
        assert "Authorization: Bearer token" in cmd
        assert "Cookie: session=abc123" in cmd

    @pytest.mark.asyncio
    async def test_execute_attack_marks_inconclusive_for_low_confidence(self):
        runner = TargetedDASTRunner()

        from src.services.scanner.types import DASTAttackConfig

        config = DASTAttackConfig(
            finding_id="test:file.py:1",
            vuln_type="sqli",
            nuclei_templates=["-tags", "sqli"],
            target_endpoint="https://example.com/api/users",
            target_parameter="id",
            endpoint_mapping_confidence=0.2,
        )

        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_process = AsyncMock()
            mock_process.communicate.return_value = (b"", b"")
            mock_exec.return_value = mock_process

        result = await runner._execute_attack(config)

        assert result.attack_succeeded is False
        assert result.verification_status == "inconclusive_mapping"
        assert result.confidence == 0.35


class TestResultMapping:
    """Tests for mapping DAST results back to findings."""

    def test_maps_successful_attack(self):
        runner = TargetedDASTRunner()
        finding = make_triaged_finding()
        findings = [finding]

        from src.services.scanner.types import DASTAttackResult

        results = [
            DASTAttackResult(
                finding_id=f"{finding.rule_id}:{finding.file_path}:{finding.line_start}",
                attack_succeeded=True,
                confidence=0.99,
                verification_status="confirmed_exploitable",
                proof_of_exploit="curl -X GET 'https://...'",
                evidence=["https://example.com/api/users?id=1'"],
                matched_at="https://example.com/api/users?id=1'",
                endpoint="https://example.com/api/users",
            ),
        ]

        updated_findings, confirmed_count = runner.map_results_to_findings(
            findings, results, "/repo"
        )

        assert confirmed_count == 1
        assert updated_findings[0].confirmed_exploitable is True
        assert updated_findings[0].dast_verification_status == "confirmed_exploitable"
        assert updated_findings[0].dast_curl_command is not None
        assert updated_findings[0].dast_endpoint is not None

    def test_skips_false_positives_in_mapping(self):
        runner = TargetedDASTRunner()
        finding = make_triaged_finding(is_false_positive=True)
        findings = [finding]

        from src.services.scanner.types import DASTAttackResult

        results = [
            DASTAttackResult(
                finding_id=f"{finding.rule_id}:{finding.file_path}:{finding.line_start}",
                attack_succeeded=True,
                confidence=0.99,
                verification_status="confirmed_exploitable",
                proof_of_exploit="curl -X GET '...'",
                evidence=[],
            ),
        ]

        updated_findings, confirmed_count = runner.map_results_to_findings(
            findings, results, "/repo"
        )

        # False positives should be skipped
        assert confirmed_count == 0
