"""Scan policy evaluation for CI/CD integration.

Evaluates scan findings against severity thresholds and returns a policy result
that can be used to fail CI builds when high/critical vulnerabilities are found.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional
import uuid

from sqlalchemy.orm import Session

from ...models import Finding, Scan


@dataclass
class PolicyViolation:
    """A single finding that violates the policy threshold."""

    finding_id: str
    severity: str
    rule_id: str
    rule_message: str
    file_path: str
    line_start: int


@dataclass
class PolicyResult:
    """Result of policy evaluation."""

    passed: bool
    exit_code: int
    fail_on: str
    violations_count: int
    violations: List[PolicyViolation]


# Severity hierarchy (lowest to highest)
SEVERITY_LEVELS = ["info", "low", "medium", "high", "critical"]

VALID_FAIL_ON_VALUES = set(SEVERITY_LEVELS)


def _normalize_severity(ai_severity: Optional[str]) -> str:
    """Normalize AI severity to standard levels."""
    if not ai_severity:
        return "info"
    normalized = ai_severity.lower().strip()
    if normalized in SEVERITY_LEVELS:
        return normalized
    # Fallback
    return "info"


def _severity_meets_threshold(severity: str, threshold: str) -> bool:
    """Check if severity meets or exceeds threshold.

    Args:
        severity: Normalized severity level (info|low|medium|high|critical)
        threshold: Threshold level (info|low|medium|high|critical)

    Returns:
        True if severity >= threshold in the hierarchy
    """
    try:
        severity_idx = SEVERITY_LEVELS.index(severity)
        threshold_idx = SEVERITY_LEVELS.index(threshold)
        return severity_idx >= threshold_idx
    except ValueError:
        # If either is invalid, assume it doesn't meet threshold
        return False


def evaluate_scan_policy(
    db: Session,
    scan_id: str | uuid.UUID,
    fail_on: str = "high",
    include_false_positives: bool = False,
) -> PolicyResult:
    """Evaluate scan findings against policy threshold.

    Args:
        db: Database session
        scan_id: Scan UUID to evaluate
        fail_on: Minimum severity to fail on (info|low|medium|high|critical)
        include_false_positives: Whether to include findings marked as false positives

    Returns:
        PolicyResult with pass/fail status and violations

    Raises:
        ValueError: If fail_on value is invalid
        RuntimeError: If scan not found
    """
    # Validate fail_on
    if fail_on not in VALID_FAIL_ON_VALUES:
        raise ValueError(
            f"Invalid fail_on value: {fail_on}. "
            f"Must be one of: {', '.join(SEVERITY_LEVELS)}"
        )

    # Normalize scan id
    scan_uuid: uuid.UUID
    if isinstance(scan_id, uuid.UUID):
        scan_uuid = scan_id
    else:
        try:
            scan_uuid = uuid.UUID(str(scan_id))
        except ValueError as exc:
            raise RuntimeError(f"Scan not found: {scan_id}") from exc

    # Check scan exists
    scan = db.query(Scan).filter(Scan.id == scan_uuid).first()
    if not scan:
        raise RuntimeError(f"Scan not found: {scan_id}")

    # Query findings
    query = db.query(Finding).filter(Finding.scan_id == scan_uuid)

    # Filter false positives if requested
    if not include_false_positives:
        query = query.filter(Finding.is_false_positive.is_(False))

    findings = query.all()

    # Evaluate violations
    violations: List[PolicyViolation] = []

    for finding in findings:
        # Normalize severity using existing field
        severity = _normalize_severity(finding.ai_severity)

        # Check if this finding meets the threshold
        if _severity_meets_threshold(severity, fail_on):
            violations.append(
                PolicyViolation(
                    finding_id=str(finding.id),
                    severity=severity,
                    rule_id=finding.rule_id or "unknown",
                    rule_message=finding.rule_message or "No message",
                    file_path=finding.file_path or "unknown",
                    line_start=finding.line_start or 0,
                )
            )

    # Determine pass/fail
    passed = len(violations) == 0
    exit_code = 0 if passed else 1

    return PolicyResult(
        passed=passed,
        exit_code=exit_code,
        fail_on=fail_on,
        violations_count=len(violations),
        violations=violations,
    )
