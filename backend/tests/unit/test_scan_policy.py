"""Unit tests for scan policy evaluation."""

from __future__ import annotations

import uuid
from unittest.mock import MagicMock

import pytest

from src.models import Finding, Scan
from src.services.scanner.scan_policy import (
    PolicyViolation,
    evaluate_scan_policy,
    _normalize_severity,
    _severity_meets_threshold,
)


def test_normalize_severity():
    """Test severity normalization."""
    assert _normalize_severity("critical") == "critical"
    assert _normalize_severity("CRITICAL") == "critical"
    assert _normalize_severity("High") == "high"
    assert _normalize_severity("medium") == "medium"
    assert _normalize_severity("low") == "low"
    assert _normalize_severity("info") == "info"
    assert _normalize_severity("") == "info"
    assert _normalize_severity(None) == "info"
    assert _normalize_severity("unknown") == "info"


def test_severity_meets_threshold():
    """Test severity threshold comparison."""
    # Critical meets all thresholds
    assert _severity_meets_threshold("critical", "info")
    assert _severity_meets_threshold("critical", "low")
    assert _severity_meets_threshold("critical", "medium")
    assert _severity_meets_threshold("critical", "high")
    assert _severity_meets_threshold("critical", "critical")

    # High meets high and below
    assert _severity_meets_threshold("high", "info")
    assert _severity_meets_threshold("high", "low")
    assert _severity_meets_threshold("high", "medium")
    assert _severity_meets_threshold("high", "high")
    assert not _severity_meets_threshold("high", "critical")

    # Medium doesn't meet high
    assert _severity_meets_threshold("medium", "info")
    assert _severity_meets_threshold("medium", "low")
    assert _severity_meets_threshold("medium", "medium")
    assert not _severity_meets_threshold("medium", "high")
    assert not _severity_meets_threshold("medium", "critical")

    # Info only meets info
    assert _severity_meets_threshold("info", "info")
    assert not _severity_meets_threshold("info", "low")
    assert not _severity_meets_threshold("info", "medium")
    assert not _severity_meets_threshold("info", "high")
    assert not _severity_meets_threshold("info", "critical")


def test_evaluate_scan_policy_invalid_fail_on():
    """Test that invalid fail_on raises ValueError."""
    db = MagicMock()
    scan_id = str(uuid.uuid4())

    with pytest.raises(ValueError, match="Invalid fail_on value"):
        evaluate_scan_policy(db, scan_id, fail_on="invalid")


def test_evaluate_scan_policy_scan_not_found():
    """Test that missing scan raises RuntimeError."""
    db = MagicMock()
    db.query().filter().first.return_value = None
    scan_id = str(uuid.uuid4())

    with pytest.raises(RuntimeError, match="Scan not found"):
        evaluate_scan_policy(db, scan_id, fail_on="high")


def test_evaluate_scan_policy_no_violations():
    """Test policy evaluation with no violations."""
    db = MagicMock()
    scan_id = str(uuid.uuid4())

    # Mock scan
    scan = Scan(id=scan_id, status="completed")
    db.query().filter().first.return_value = scan

    # Mock findings query - no findings
    db.query().filter().filter().all.return_value = []

    result = evaluate_scan_policy(db, scan_id, fail_on="high")

    assert result.passed is True
    assert result.exit_code == 0
    assert result.fail_on == "high"
    assert result.violations_count == 0
    assert len(result.violations) == 0


def test_evaluate_scan_policy_with_violations():
    """Test policy evaluation with violations."""
    db = MagicMock()
    scan_id = str(uuid.uuid4())

    # Mock scan
    scan = Scan(id=scan_id, status="completed")
    db.query().filter().first.return_value = scan

    # Mock findings - create critical and high findings
    finding1 = Finding(
        id=uuid.uuid4(),
        scan_id=scan_id,
        ai_severity="critical",
        rule_id="sql-injection",
        rule_message="SQL Injection vulnerability",
        file_path="app.py",
        line_start=42,
        is_false_positive=False,
    )
    finding2 = Finding(
        id=uuid.uuid4(),
        scan_id=scan_id,
        ai_severity="high",
        rule_id="xss",
        rule_message="XSS vulnerability",
        file_path="views.py",
        line_start=100,
        is_false_positive=False,
    )
    finding3 = Finding(
        id=uuid.uuid4(),
        scan_id=scan_id,
        ai_severity="medium",
        rule_id="path-traversal",
        rule_message="Path traversal",
        file_path="utils.py",
        line_start=25,
        is_false_positive=False,
    )

    db.query().filter().filter().all.return_value = [finding1, finding2, finding3]

    # Test with fail_on=high (should fail with 2 violations)
    result = evaluate_scan_policy(db, scan_id, fail_on="high")

    assert result.passed is False
    assert result.exit_code == 1
    assert result.fail_on == "high"
    assert result.violations_count == 2
    assert len(result.violations) == 2

    # Check violations
    assert result.violations[0].severity == "critical"
    assert result.violations[0].rule_id == "sql-injection"
    assert result.violations[1].severity == "high"
    assert result.violations[1].rule_id == "xss"


def test_evaluate_scan_policy_with_false_positives():
    """Test that false positives are excluded by default."""
    db = MagicMock()
    scan_id = str(uuid.uuid4())

    # Mock scan
    scan = Scan(id=scan_id, status="completed")
    db.query().filter().first.return_value = scan

    # Mock findings - one is false positive
    finding1 = Finding(
        id=uuid.uuid4(),
        scan_id=scan_id,
        ai_severity="critical",
        rule_id="sql-injection",
        rule_message="SQL Injection vulnerability",
        file_path="app.py",
        line_start=42,
        is_false_positive=True,  # False positive
    )
    finding2 = Finding(
        id=uuid.uuid4(),
        scan_id=scan_id,
        ai_severity="high",
        rule_id="xss",
        rule_message="XSS vulnerability",
        file_path="views.py",
        line_start=100,
        is_false_positive=False,
    )

    # When include_false_positives=False, only finding2 returned
    db.query().filter().filter().all.return_value = [finding2]

    result = evaluate_scan_policy(db, scan_id, fail_on="high", include_false_positives=False)

    assert result.passed is False
    assert result.violations_count == 1
    assert result.violations[0].rule_id == "xss"


def test_evaluate_scan_policy_include_false_positives():
    """Test that false positives are included when requested."""
    db = MagicMock()
    scan_id = str(uuid.uuid4())

    # Mock scan
    scan = Scan(id=scan_id, status="completed")
    db.query().filter().first.return_value = scan

    # Mock findings - both returned when include_false_positives=True
    finding1 = Finding(
        id=uuid.uuid4(),
        scan_id=scan_id,
        ai_severity="critical",
        rule_id="sql-injection",
        rule_message="SQL Injection vulnerability",
        file_path="app.py",
        line_start=42,
        is_false_positive=True,
    )
    finding2 = Finding(
        id=uuid.uuid4(),
        scan_id=scan_id,
        ai_severity="high",
        rule_id="xss",
        rule_message="XSS vulnerability",
        file_path="views.py",
        line_start=100,
        is_false_positive=False,
    )

    db.query().filter().all.return_value = [finding1, finding2]

    result = evaluate_scan_policy(db, scan_id, fail_on="high", include_false_positives=True)

    assert result.passed is False
    assert result.violations_count == 2


def test_evaluate_scan_policy_different_thresholds():
    """Test policy evaluation with different fail_on thresholds."""
    db = MagicMock()
    scan_id = str(uuid.uuid4())

    # Mock scan
    scan = Scan(id=scan_id, status="completed")
    db.query().filter().first.return_value = scan

    # Mock findings with various severities
    findings = [
        Finding(
            id=uuid.uuid4(),
            scan_id=scan_id,
            ai_severity="critical",
            rule_id="r1",
            rule_message="Critical",
            file_path="f1",
            line_start=1,
            is_false_positive=False,
        ),
        Finding(
            id=uuid.uuid4(),
            scan_id=scan_id,
            ai_severity="high",
            rule_id="r2",
            rule_message="High",
            file_path="f2",
            line_start=2,
            is_false_positive=False,
        ),
        Finding(
            id=uuid.uuid4(),
            scan_id=scan_id,
            ai_severity="medium",
            rule_id="r3",
            rule_message="Medium",
            file_path="f3",
            line_start=3,
            is_false_positive=False,
        ),
        Finding(
            id=uuid.uuid4(),
            scan_id=scan_id,
            ai_severity="low",
            rule_id="r4",
            rule_message="Low",
            file_path="f4",
            line_start=4,
            is_false_positive=False,
        ),
        Finding(
            id=uuid.uuid4(),
            scan_id=scan_id,
            ai_severity="info",
            rule_id="r5",
            rule_message="Info",
            file_path="f5",
            line_start=5,
            is_false_positive=False,
        ),
    ]

    db.query().filter().filter().all.return_value = findings

    # Test critical threshold - only 1 violation
    result = evaluate_scan_policy(db, scan_id, fail_on="critical")
    assert result.violations_count == 1

    # Reset mock
    db.query().filter().filter().all.return_value = findings

    # Test high threshold - 2 violations (critical + high)
    result = evaluate_scan_policy(db, scan_id, fail_on="high")
    assert result.violations_count == 2

    # Reset mock
    db.query().filter().filter().all.return_value = findings

    # Test medium threshold - 3 violations
    result = evaluate_scan_policy(db, scan_id, fail_on="medium")
    assert result.violations_count == 3

    # Reset mock
    db.query().filter().filter().all.return_value = findings

    # Test low threshold - 4 violations
    result = evaluate_scan_policy(db, scan_id, fail_on="low")
    assert result.violations_count == 4

    # Reset mock
    db.query().filter().filter().all.return_value = findings

    # Test info threshold - all 5 violations
    result = evaluate_scan_policy(db, scan_id, fail_on="info")
    assert result.violations_count == 5
