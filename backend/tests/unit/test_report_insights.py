from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from src.services.reports import report_insights


def _scan(**overrides):
    data = {
        "scan_type": "sast",
        "repo_url": "https://github.com/acme/tools",
        "target_url": None,
        "branch": "main",
        "total_findings": 10,
        "filtered_findings": 4,
        "dast_findings": 0,
        "detected_languages": ["python"],
    }
    data.update(overrides)
    return SimpleNamespace(**data)


def _finding(**overrides):
    data = {
        "rule_id": "rule-1",
        "rule_message": "Possible injection",
        "ai_severity": "high",
        "semgrep_severity": "ERROR",
        "priority_score": 80,
        "file_path": "app.py",
        "line_start": 12,
        "exploitability": "Remote unauthenticated",
        "remediation": "Use parameterized queries.",
        "confirmed_exploitable": True,
        "is_reachable": True,
    }
    data.update(overrides)
    return SimpleNamespace(**data)


class DummyLLM:
    async def is_available(self):
        return True

    async def generate(self, prompt, system=None):  # noqa: ANN001
        return (
            '{"executive_summary":"ok","risk_posture":"high","business_impact":"impact",'
            '"key_risks":["r1","r2"],"recommended_actions":["a1","a2"],'
            '"assurance_notes":"notes","confidence":0.9}'
        )


class UnavailableLLM:
    async def is_available(self):
        return False

    async def generate(self, prompt, system=None):  # noqa: ANN001
        return ""


@pytest.mark.asyncio
async def test_generate_report_insights_uses_llm():
    scan = _scan()
    findings = [_finding()]
    trend_scans = []
    insights = await report_insights.generate_report_insights(
        scan, findings, trend_scans, llm_client=DummyLLM()
    )

    assert insights.executive_summary == "ok"
    assert insights.risk_posture == "high"
    assert insights.confidence == 0.9


@pytest.mark.asyncio
async def test_generate_report_insights_fallback_when_unavailable():
    scan = _scan()
    findings = [_finding(ai_severity="critical")]
    trend_scans = []
    insights = await report_insights.generate_report_insights(
        scan, findings, trend_scans, llm_client=UnavailableLLM()
    )

    assert "Scan identified" in insights.executive_summary
    assert insights.confidence == 0.45


def test_parse_json_block_handles_noise():
    data = report_insights._parse_json_block("prefix {\"a\": 1} suffix")
    assert data == {"a": 1}

    assert report_insights._parse_json_block("no json") is None


def test_pick_list_accepts_string_lines():
    value = "- one\n- two\n- three\n- four"
    items = report_insights._pick_list(value, fallback=["fallback"])
    assert items == ["one", "two", "three"]


def test_trend_summary_improves():
    now = datetime.now(timezone.utc)
    scans = [
        _scan(
            status="completed",
            created_at=now.replace(year=now.year - 1),
            total_findings=10,
            filtered_findings=8,
        ),
        _scan(
            status="completed",
            created_at=now,
            total_findings=10,
            filtered_findings=2,
        ),
    ]
    summary = report_insights._trend_summary(scans)
    assert "noise reduction improved" in summary
