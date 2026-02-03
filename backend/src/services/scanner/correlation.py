from __future__ import annotations

from typing import List, Tuple

from .types import DynamicFinding, TriagedFinding
from .zap_parser import classify_vulnerability


def correlate_findings(
    sast_findings: List[TriagedFinding],
    dast_findings: List[DynamicFinding],
) -> Tuple[List[TriagedFinding], List[DynamicFinding]]:
    matched_dast_keys: set[str] = set()

    for finding in sast_findings:
        location = (finding.dast_matched_at or finding.dast_endpoint or "").strip()
        if not location:
            continue
        vuln_type = classify_vulnerability(
            f"{finding.rule_id} {finding.rule_message or ''}",
            rule_id=finding.rule_id,
        )
        match = _find_match_with_location(location, dast_findings, vuln_type)
        if match:
            matched_dast_keys.add(_dast_key(match))
            finding.confirmed_exploitable = True
            finding.dast_verification_status = (
                finding.dast_verification_status or "confirmed_exploitable"
            )
            if match.matched_at:
                finding.dast_matched_at = match.matched_at
            if match.endpoint:
                finding.dast_endpoint = match.endpoint
            if match.evidence:
                finding.dast_evidence = match.evidence
            if match.cve_ids:
                finding.dast_cve_ids = match.cve_ids
            if match.cwe_ids:
                finding.dast_cwe_ids = match.cwe_ids

    unmatched_dast = [
        item for item in dast_findings if _dast_key(item) not in matched_dast_keys
    ]
    return sast_findings, unmatched_dast


def _find_match_with_location(
    location: str,
    dast_findings: List[DynamicFinding],
    vuln_type: str | None = None,
) -> DynamicFinding | None:
    for dast in dast_findings:
        if vuln_type:
            dast_type = classify_vulnerability(
                f"{dast.template_id} {dast.template_name}"
            )
            if dast_type and dast_type != vuln_type:
                continue
        if _location_matches(location, dast):
            return dast
    return None


def _location_matches(location: str, dast: DynamicFinding) -> bool:
    location = location.strip()
    if not location:
        return False
    matched_at = (dast.matched_at or "").strip()
    endpoint = (dast.endpoint or "").strip()
    if matched_at and matched_at.startswith(location):
        return True
    if endpoint and endpoint == location:
        return True
    return False


def _dast_key(finding: DynamicFinding) -> str:
    matched_at = (finding.matched_at or "").strip()
    endpoint = (finding.endpoint or "").strip()
    location = matched_at or endpoint
    return f"{finding.template_id}::{location}"
