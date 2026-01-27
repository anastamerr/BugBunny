from __future__ import annotations

from typing import Dict, Iterable, List, Optional, Set, Tuple

from .models import CorrelationV2, DastAlertV2, SastFindingV2

VULN_KEYWORDS: Dict[str, List[str]] = {
    "sqli": ["sql injection", "sqli", "sql-injection"],
    "xss": ["xss", "cross-site scripting", "cross site scripting"],
    "command-injection": ["command injection", "cmd injection", "os command", "shell"],
    "rce": ["rce", "remote code execution", "code injection", "eval"],
    "path-traversal": ["path traversal", "directory traversal", "file inclusion", "lfi"],
    "xxe": ["xxe", "xml external entity"],
    "ssrf": ["ssrf", "server-side request", "server side request forgery"],
    "ssti": ["ssti", "template injection", "server-side template"],
    "open-redirect": ["open redirect", "unvalidated redirect"],
    "deserialization": ["deserialization", "deserialize", "unserialize", "pickle"],
}


def correlate_findings(
    sast_findings: Iterable[SastFindingV2],
    dast_alerts: Iterable[DastAlertV2],
    *,
    dast_error_kind: Optional[str],
    dast_error_message: Optional[str],
    threshold: float = 0.75,
) -> List[CorrelationV2]:
    alerts = list(dast_alerts)
    correlations: List[CorrelationV2] = []

    for finding in sast_findings:
        best_match: Optional[DastAlertV2] = None
        best_score = 0.0
        for alert in alerts:
            score = _correlation_score(finding, alert)
            if score > best_score:
                best_score = score
                best_match = alert

        if best_match and best_score >= threshold and _has_evidence(best_match):
            correlations.append(
                CorrelationV2(
                    scan_id=finding.scan_id,
                    sast_finding_id=finding.id,
                    matched_dast_alert_id=best_match.id,
                    status="CONFIRMED_EXPLOITABLE",
                    reason=None,
                    correlation_score=best_score,
                )
            )
            continue

        status, reason = _status_for_unconfirmed(
            dast_error_kind, dast_error_message
        )
        correlations.append(
            CorrelationV2(
                scan_id=finding.scan_id,
                sast_finding_id=finding.id,
                matched_dast_alert_id=best_match.id if best_match else None,
                status=status,
                reason=reason,
                correlation_score=best_score,
            )
        )

    return correlations


def _status_for_unconfirmed(
    dast_error_kind: Optional[str],
    dast_error_message: Optional[str],
) -> Tuple[str, str]:
    if dast_error_kind == "auth_required":
        return (
            "COULD_NOT_TEST_AUTH_REQUIRED",
            dast_error_message or "Authentication likely required for target.",
        )
    if dast_error_kind == "unreachable":
        return (
            "COULD_NOT_TEST_UNREACHABLE",
            dast_error_message or "Target unreachable.",
        )
    if dast_error_kind == "rate_limited":
        return (
            "COULD_NOT_TEST_RATE_LIMITED",
            dast_error_message or "Target rate limited.",
        )
    if dast_error_kind == "insufficient_coverage":
        return (
            "COULD_NOT_TEST_INSUFFICIENT_COVERAGE",
            dast_error_message or "Spider coverage insufficient to validate findings.",
        )
    if dast_error_kind == "timeout":
        return (
            "COULD_NOT_TEST_TIMEOUT",
            dast_error_message or "DAST exceeded configured timeout.",
        )
    if dast_error_kind == "tool_error":
        return (
            "COULD_NOT_TEST_TOOL_ERROR",
            dast_error_message or "DAST tooling error.",
        )

    return (
        "UNVERIFIED_NO_MATCH",
        "No matching DAST evidence found. No match != safe.",
    )


def _correlation_score(finding: SastFindingV2, alert: DastAlertV2) -> float:
    cwe_overlap = _cwe_overlap(finding, alert)
    if cwe_overlap:
        return 1.0

    finding_keywords = _extract_keywords(finding.rule_id, finding.message)
    alert_keywords = _extract_keywords(alert.name, alert.raw.get("description", ""))
    if finding_keywords & alert_keywords:
        return 0.6

    if _risk_overlap(finding.severity, alert.risk):
        return 0.3

    return 0.0


def _cwe_overlap(finding: SastFindingV2, alert: DastAlertV2) -> bool:
    finding_cwe = {int(cwe) for cwe in (finding.cwe_ids or []) if isinstance(cwe, int)}
    alert_cwe = {alert.cwe_id} if alert.cwe_id else set()
    return bool(finding_cwe & alert_cwe)


def _extract_keywords(*values: str) -> Set[str]:
    text = " ".join([value or "" for value in values]).lower()
    matched: Set[str] = set()
    for key, keywords in VULN_KEYWORDS.items():
        if any(keyword in text for keyword in keywords):
            matched.add(key)
    return matched


def _risk_overlap(semgrep_severity: str, zap_risk: str) -> bool:
    severity = (semgrep_severity or "").lower()
    risk = (zap_risk or "").lower()
    if severity in {"error", "critical", "high"}:
        return risk in {"high", "medium"}
    if severity in {"warning", "medium"}:
        return risk in {"medium", "low"}
    if severity in {"info", "low"}:
        return risk in {"low", "info"}
    return False


def _has_evidence(alert: DastAlertV2) -> bool:
    if not alert.url:
        return False
    if alert.evidence and alert.evidence.strip():
        return True
    return False
