import uuid

from src.scanguard_scan.correlation import correlate_findings
from src.scanguard_scan.models import DastAlertV2, SastFindingV2


def _make_finding(cwe_ids=None, severity="ERROR"):
    return SastFindingV2(
        id=uuid.uuid4(),
        scan_id=uuid.uuid4(),
        rule_id="python.lang.security.sql.injection",
        message="SQL injection",
        severity=severity,
        file_path="app.py",
        line_start=10,
        line_end=12,
        cwe_ids=cwe_ids or [],
        fingerprint="abc",
        raw={},
    )


def _make_alert(cwe_id=None, risk="high", evidence="evidence"):
    return DastAlertV2(
        id=uuid.uuid4(),
        scan_id=uuid.uuid4(),
        plugin_id="40018",
        name="SQL Injection",
        risk=risk,
        confidence="high",
        url="http://example.com/login",
        param="username",
        evidence=evidence,
        cwe_id=cwe_id,
        raw={},
    )


def test_correlation_confirms_on_cwe_overlap():
    finding = _make_finding(cwe_ids=[89])
    alert = _make_alert(cwe_id=89)

    correlations = correlate_findings(
        [finding],
        [alert],
        dast_error_kind=None,
        dast_error_message=None,
    )

    assert correlations[0].status == "CONFIRMED_EXPLOITABLE"


def test_correlation_unverified_no_match():
    finding = _make_finding(cwe_ids=[89])
    alert = _make_alert(cwe_id=79, evidence="")

    correlations = correlate_findings(
        [finding],
        [alert],
        dast_error_kind=None,
        dast_error_message=None,
    )

    assert correlations[0].status == "UNVERIFIED_NO_MATCH"
    assert "No match" in (correlations[0].reason or "")


def test_correlation_auth_required():
    finding = _make_finding(cwe_ids=[79], severity="WARNING")

    correlations = correlate_findings(
        [finding],
        [],
        dast_error_kind="auth_required",
        dast_error_message="Auth missing",
    )

    assert correlations[0].status == "COULD_NOT_TEST_AUTH_REQUIRED"
    assert correlations[0].reason == "Auth missing"
