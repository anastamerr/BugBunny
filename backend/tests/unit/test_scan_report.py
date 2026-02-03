from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from src.services.reports import scan_report


def _scan(**overrides):
    data = {
        "id": "scan-1",
        "status": "completed",
        "scan_type": "sast",
        "trigger": "manual",
        "repo_url": "https://github.com/acme/tools",
        "target_url": None,
        "branch": "main",
        "created_at": datetime.now(timezone.utc),
        "commit_sha": "a" * 40,
        "pr_url": None,
        "total_findings": 10,
        "filtered_findings": 4,
        "dast_findings": 0,
        "scanned_files": 12,
        "detected_languages": ["python"],
    }
    data.update(overrides)
    return SimpleNamespace(**data)


def _finding(**overrides):
    data = {
        "rule_id": "rule-1",
        "rule_message": "Possible injection",
        "ai_severity": "critical",
        "semgrep_severity": "ERROR",
        "priority_score": 95,
        "file_path": "app.py",
        "line_start": 10,
        "finding_type": "sast",
        "ai_reasoning": "User input flows to sink.",
        "exploitability": "Remote unauthenticated",
        "remediation": "Use parameterized queries.",
        "is_reachable": True,
        "reachability_score": 1.0,
        "reachability_reason": None,
    }
    data.update(overrides)
    return SimpleNamespace(**data)


def test_noise_reduction_pct():
    scan = _scan(total_findings=10, filtered_findings=4)
    assert scan_report._noise_reduction_pct(scan) == 60
    scan_zero = _scan(total_findings=0, filtered_findings=0)
    assert scan_report._noise_reduction_pct(scan_zero) == 0


def test_severity_label_falls_back_to_semgrep():
    finding = _finding(ai_severity=None, semgrep_severity="WARNING")
    assert scan_report._severity_label(finding) == "medium"


def test_reachability_label_variants():
    finding = _finding(is_reachable=False, reachability_reason="dead code")
    assert scan_report._reachability_label(finding) == "dead code"

    finding = _finding(is_reachable=True, reachability_score=0.42)
    assert scan_report._reachability_label(finding) == "reachable (42% confidence)"

    finding = _finding(is_reachable=True, reachability_score=None)
    assert scan_report._reachability_label(finding) == "reachable"


def test_trend_chart_requires_multiple_completed():
    now = datetime.now(timezone.utc)
    scans = [
        _scan(created_at=now - timedelta(days=1)),
        _scan(created_at=now),
    ]
    drawing = scan_report._build_trend_chart(scans)
    assert drawing is not None

    single = scan_report._build_trend_chart([_scan(created_at=now)])
    assert single is None


def test_build_scan_report_pdf_returns_bytes():
    scan = _scan()
    findings = [_finding()]
    trend_scans = [_scan(), _scan(created_at=datetime.now(timezone.utc) - timedelta(days=1))]
    pdf_bytes = scan_report.build_scan_report_pdf(scan, findings, trend_scans, insights=None)

    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 100
