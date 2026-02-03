from src.services.scanner.correlation import correlate_findings
from src.services.scanner.types import DynamicFinding, TriagedFinding


def _make_triaged_finding() -> TriagedFinding:
    return TriagedFinding(
        rule_id="semgrep.sql-injection",
        rule_message="Possible SQL injection detected",
        semgrep_severity="ERROR",
        file_path="app/db.py",
        line_start=10,
        line_end=12,
        code_snippet="query = f\"SELECT * FROM users WHERE id={user_id}\"",
        context_snippet="query = f\"SELECT * FROM users WHERE id={user_id}\"",
        function_name="get_user",
        class_name=None,
        is_test_file=False,
        is_generated=False,
        imports=["import sqlite3"],
        is_false_positive=False,
        ai_severity="high",
        ai_confidence=0.6,
        ai_reasoning="User input flows into SQL string.",
        exploitability="Remote attacker can inject SQL via user_id.",
    )


def _make_dast_finding(*, matched_at: str) -> DynamicFinding:
    return DynamicFinding(
        template_id="test-template",
        template_name="SQL Injection",
        severity="high",
        matched_at=matched_at,
        endpoint="https://example.com",
        curl_command="curl -sS https://example.com?id=1",
        evidence=["error-based response"],
        description="SQL injection vulnerability detected.",
        remediation="Use parameterized queries.",
        cve_ids=[],
        cwe_ids=["CWE-89"],
    )


def test_correlation_keeps_distinct_dast_endpoints():
    triaged = [_make_triaged_finding()]
    triaged[0].dast_matched_at = "https://a.example.com/vuln"
    dast_a = _make_dast_finding(matched_at="https://a.example.com/vuln")
    dast_b = _make_dast_finding(matched_at="https://b.example.com/vuln")

    updated, unmatched = correlate_findings(triaged, [dast_a, dast_b])

    assert updated[0].confirmed_exploitable is True
    assert updated[0].dast_matched_at == dast_a.matched_at
    assert len(unmatched) == 1
    assert unmatched[0].matched_at == dast_b.matched_at
