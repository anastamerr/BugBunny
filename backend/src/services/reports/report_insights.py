from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from typing import Sequence

from ...config import get_settings
from ...models import Finding, Scan
from ...services.intelligence.llm_service import LLMClient, get_llm_service


@dataclass(frozen=True)
class ReportInsights:
    executive_summary: str
    risk_posture: str
    business_impact: str
    key_risks: list[str]
    recommended_actions: list[str]
    assurance_notes: str
    confidence: float | None = None


def generate_report_insights_sync(
    scan: Scan,
    findings: Sequence[Finding],
    trend_scans: Sequence[Scan],
) -> ReportInsights:
    fallback = _build_fallback_insights(scan, findings, trend_scans)
    try:
        return asyncio.run(generate_report_insights(scan, findings, trend_scans))
    except RuntimeError:
        return fallback
    except Exception:
        return fallback


async def generate_report_insights(
    scan: Scan,
    findings: Sequence[Finding],
    trend_scans: Sequence[Scan],
    llm_client: LLMClient | None = None,
) -> ReportInsights:
    fallback = _build_fallback_insights(scan, findings, trend_scans)
    settings = get_settings()
    client = llm_client or get_llm_service(settings)

    try:
        if not await client.is_available():
            return fallback
    except Exception:
        return fallback

    prompt = _build_prompt(scan, findings, trend_scans)
    try:
        response = await asyncio.wait_for(
            client.generate(prompt, system=_system_prompt()),
            timeout=45.0,
        )
    except Exception:
        return fallback

    data = _parse_json_block(response)
    if not data:
        return fallback

    return ReportInsights(
        executive_summary=_pick_text(
            data.get("executive_summary"), fallback.executive_summary
        ),
        risk_posture=_pick_text(data.get("risk_posture"), fallback.risk_posture),
        business_impact=_pick_text(
            data.get("business_impact"), fallback.business_impact
        ),
        key_risks=_pick_list(data.get("key_risks"), fallback.key_risks),
        recommended_actions=_pick_list(
            data.get("recommended_actions"), fallback.recommended_actions
        ),
        assurance_notes=_pick_text(
            data.get("assurance_notes"), fallback.assurance_notes
        ),
        confidence=_parse_confidence(data.get("confidence"), fallback.confidence),
    )


def _system_prompt() -> str:
    return (
        "You are ScanGuard AI, a security program advisor.\n"
        "Write concise, business-ready security report insights.\n"
        "Prioritize clarity, risk posture, and actionable next steps.\n"
        "Return only valid JSON."
    )


def _build_prompt(
    scan: Scan,
    findings: Sequence[Finding],
    trend_scans: Sequence[Scan],
) -> str:
    total = scan.total_findings or 0
    filtered = scan.filtered_findings or 0
    noise_reduction = _noise_reduction_pct(total, filtered)
    counts = _severity_counts(findings)
    confirmed_exploitable = sum(1 for f in findings if f.confirmed_exploitable)
    reachable = sum(1 for f in findings if f.is_reachable)
    top_findings = _top_finding_snapshots(findings)
    languages = ", ".join(scan.detected_languages or [])
    trend = _trend_summary(trend_scans)

    context = {
        "scan_type": scan.scan_type,
        "repository": scan.repo_url or "n/a",
        "target_url": scan.target_url or "n/a",
        "branch": scan.branch,
        "total_findings": total,
        "filtered_findings": filtered,
        "noise_reduction_pct": noise_reduction,
        "severity_counts": counts,
        "confirmed_exploitable": confirmed_exploitable,
        "reachable_findings": reachable,
        "dast_findings": scan.dast_findings or 0,
        "languages": languages or "n/a",
        "trend": trend,
        "top_findings": top_findings,
    }

    return (
        "## Scan Context\n"
        f"{json.dumps(context, ensure_ascii=True, indent=2)}\n\n"
        "## Task\n"
        "Return JSON only with:\n"
        "{\n"
        '  "executive_summary": "2-4 sentences, executive-ready",\n'
        '  "risk_posture": "critical|high|medium|low with rationale",\n'
        '  "business_impact": "1-2 sentences about impact",\n'
        '  "key_risks": ["risk 1", "risk 2", "risk 3"],\n'
        '  "recommended_actions": ["action 1", "action 2", "action 3"],\n'
        '  "assurance_notes": "coverage and confidence notes",\n'
        '  "confidence": 0.0-1.0\n'
        "}\n\n"
        "Constraints:\n"
        "- Keep language formal and concise.\n"
        "- Reference top findings and severity counts.\n"
        "- Avoid marketing language or vague claims.\n"
        "- Use ASCII only.\n"
    )


def _build_fallback_insights(
    scan: Scan,
    findings: Sequence[Finding],
    trend_scans: Sequence[Scan],
) -> ReportInsights:
    total = scan.total_findings or 0
    filtered = scan.filtered_findings or 0
    noise_reduction = _noise_reduction_pct(total, filtered)
    counts = _severity_counts(findings)
    risk_label, _ = _risk_rating(counts)
    confirmed_exploitable = sum(1 for f in findings if f.confirmed_exploitable)
    top_findings = _top_finding_labels(findings)
    trend = _trend_summary(trend_scans)

    executive = (
        f"Scan identified {filtered} actionable findings out of {total} total signals "
        f"({noise_reduction}% noise reduction). Overall risk posture is {risk_label} "
        f"based on severity distribution and exploitability signals."
    )
    business_impact = _business_impact_text(counts, confirmed_exploitable)

    key_risks = top_findings or [
        "Prioritized findings indicate exposure in critical paths.",
        "Potential abuse of unsafe data flows remains possible without remediation.",
        "Coverage gaps may exist for runtime-only issues.",
    ]

    actions = _recommended_actions(findings, confirmed_exploitable)
    assurance = _assurance_notes(scan, trend)

    return ReportInsights(
        executive_summary=executive,
        risk_posture=f"{risk_label} risk; focus on critical and high severity items.",
        business_impact=business_impact,
        key_risks=key_risks,
        recommended_actions=actions,
        assurance_notes=assurance,
        confidence=0.45,
    )


def _severity_counts(findings: Sequence[Finding]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for finding in findings:
        label = _severity_label(finding)
        counts[label] = counts.get(label, 0) + 1
    return counts


def _severity_label(finding: Finding) -> str:
    if finding.ai_severity:
        return str(finding.ai_severity).lower()
    mapping = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}
    return mapping.get(str(finding.semgrep_severity), "info")


def _risk_rating(counts: dict[str, int]) -> tuple[str, int]:
    score = (
        counts.get("critical", 0) * 25
        + counts.get("high", 0) * 15
        + counts.get("medium", 0) * 6
        + counts.get("low", 0) * 2
    )
    score = min(100, score)
    if score >= 80:
        return "critical", score
    if score >= 60:
        return "high", score
    if score >= 35:
        return "medium", score
    return "low", score


def _business_impact_text(counts: dict[str, int], confirmed_exploitable: int) -> str:
    if counts.get("critical", 0) > 0 or confirmed_exploitable > 0:
        return (
            "Findings include exploit-ready paths that could enable unauthorized access, "
            "data exposure, or service disruption if left unaddressed."
        )
    if counts.get("high", 0) > 0:
        return (
            "High-severity issues present elevated risk and may enable privilege abuse "
            "or data leakage under realistic conditions."
        )
    if counts.get("medium", 0) > 0:
        return (
            "Moderate risk items could degrade security posture and compound with other "
            "control failures if not remediated."
        )
    return "No high-impact issues detected; maintain current controls and monitoring."


def _top_finding_snapshots(findings: Sequence[Finding]) -> list[dict[str, str]]:
    ordered = sorted(findings, key=_priority_sort_key, reverse=True)
    snapshots: list[dict[str, str]] = []
    for finding in ordered[:5]:
        snapshots.append(
            {
                "title": _finding_label(finding),
                "severity": _severity_label(finding),
                "location": _finding_location(finding),
                "exploitability": (finding.exploitability or "")[:160],
                "remediation": (finding.remediation or "")[:160],
                "confirmed_exploitable": str(bool(finding.confirmed_exploitable)),
            }
        )
    return snapshots


def _top_finding_labels(findings: Sequence[Finding]) -> list[str]:
    ordered = sorted(findings, key=_priority_sort_key, reverse=True)
    labels = [_finding_label(f) for f in ordered[:3]]
    return [label for label in labels if label]


def _priority_sort_key(finding: Finding) -> tuple[int, int]:
    priority = finding.priority_score or 0
    severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    severity = _severity_label(finding)
    return (priority, severity_rank.get(severity, 0))


def _finding_label(finding: Finding) -> str:
    rule = finding.rule_id or "finding"
    message = finding.rule_message or ""
    if message:
        return f"{rule}: {message}"
    return rule


def _finding_location(finding: Finding) -> str:
    if finding.line_start and finding.line_start > 0:
        return f"{finding.file_path}:{finding.line_start}"
    return finding.file_path


def _noise_reduction_pct(total: int, filtered: int) -> int:
    if total <= 0:
        return 0
    ratio = 1 - filtered / total
    ratio = max(0.0, min(1.0, ratio))
    return int(round(ratio * 100))


def _trend_summary(trend_scans: Sequence[Scan]) -> str:
    completed = [scan for scan in trend_scans if scan.status == "completed"]
    if len(completed) < 2:
        return "insufficient history"
    latest = completed[-1]
    earliest = completed[0]
    latest_pct = _noise_reduction_pct(
        latest.total_findings or 0, latest.filtered_findings or 0
    )
    earliest_pct = _noise_reduction_pct(
        earliest.total_findings or 0, earliest.filtered_findings or 0
    )
    delta = latest_pct - earliest_pct
    direction = "improved" if delta >= 0 else "declined"
    return f"noise reduction {direction} by {abs(delta)} points"


def _recommended_actions(
    findings: Sequence[Finding],
    confirmed_exploitable: int,
) -> list[str]:
    actions: list[str] = []
    if confirmed_exploitable:
        actions.append("Patch confirmed exploitable findings immediately.")
    critical_or_high = [
        f for f in findings if _severity_label(f) in {"critical", "high"}
    ]
    if critical_or_high:
        actions.append("Remediate critical and high severity issues before release.")
    if any(f.is_reachable for f in findings):
        actions.append("Harden reachable paths with input validation and auth checks.")
    actions.append("Add regression tests for fixed vulnerabilities.")
    return actions[:3]


def _assurance_notes(scan: Scan, trend: str) -> str:
    coverage = []
    if scan.scan_type in {"sast", "both"}:
        coverage.append("static analysis")
    if scan.scan_type in {"dast", "both"}:
        coverage.append("dynamic testing")
    coverage_text = " and ".join(coverage) if coverage else "analysis"
    return f"Coverage based on {coverage_text}; trend: {trend}."


def _parse_json_block(response: str) -> dict | None:
    if not response:
        return None
    text = response.strip()
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return None
    payload = text[start : end + 1]
    try:
        data = json.loads(payload)
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, dict) else None


def _pick_text(value: object, fallback: str) -> str:
    if isinstance(value, str):
        trimmed = value.strip()
        if trimmed:
            return trimmed
    return fallback


def _pick_list(value: object, fallback: list[str]) -> list[str]:
    items: list[str] = []
    if isinstance(value, list):
        for item in value:
            if isinstance(item, str) and item.strip():
                items.append(item.strip())
    elif isinstance(value, str) and value.strip():
        items = [line.strip(" -") for line in value.splitlines() if line.strip()]
    if items:
        return items[:3]
    return fallback


def _parse_confidence(value: object, fallback: float | None) -> float | None:
    try:
        confidence = float(value)
    except (TypeError, ValueError):
        return fallback
    return max(0.0, min(confidence, 1.0))
