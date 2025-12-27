from __future__ import annotations

import re
from typing import List, Tuple

from .types import DynamicFinding, TriagedFinding


def correlate_findings(
    sast_findings: List[TriagedFinding],
    dast_findings: List[DynamicFinding],
) -> Tuple[List[TriagedFinding], List[DynamicFinding]]:
    matched_templates: set[str] = set()

    for finding in sast_findings:
        match = _find_match(finding, dast_findings)
        if not match:
            continue
        matched_templates.add(match.template_id)
        finding.confirmed_exploitable = True
        finding.is_false_positive = False
        finding.ai_confidence = min(1.0, finding.ai_confidence + 0.2)
        finding.dast_matched_at = match.matched_at
        finding.dast_endpoint = match.endpoint
        finding.dast_curl_command = match.curl_command
        finding.dast_evidence = match.evidence
        finding.dast_cve_ids = match.cve_ids
        finding.dast_cwe_ids = match.cwe_ids

    unmatched_dast = [
        item for item in dast_findings if item.template_id not in matched_templates
    ]
    return sast_findings, unmatched_dast


def _find_match(
    sast: TriagedFinding,
    dast_findings: List[DynamicFinding],
) -> DynamicFinding | None:
    sast_cwe = _extract_cwe(sast.rule_id)
    if not sast_cwe:
        sast_cwe = _extract_cwe(sast.rule_message)

    sast_text = f"{sast.rule_id} {sast.rule_message}".lower()

    for dast in dast_findings:
        dast_text = f"{dast.template_id} {dast.template_name} {dast.description}".lower()

        if sast_cwe and any(sast_cwe == cwe.lower() for cwe in dast.cwe_ids):
            return dast

        if _keyword_match(sast_text, dast_text):
            return dast

    return None


def _extract_cwe(value: str | None) -> str | None:
    if not value:
        return None
    match = re.search(r"cwe[-_]?(\d+)", value, re.IGNORECASE)
    if not match:
        return None
    return f"cwe-{match.group(1)}".lower()


def _keyword_match(sast_text: str, dast_text: str) -> bool:
    groups = [
        ["sql", "sqli", "injection"],
        ["xss", "cross-site", "cross site", "scripting"],
        ["rce", "command", "exec", "eval", "code execution", "command injection"],
        ["ssrf", "server-side request", "server side request", "request forgery"],
        ["path traversal", "directory traversal", "zip slip"],
        ["lfi", "rfi", "file inclusion", "local file inclusion"],
        ["xxe", "xml external entity"],
        ["csrf", "cross-site request forgery", "cross site request forgery"],
        ["ssti", "template injection", "server-side template"],
        ["deserialization", "deserialize", "unserialize", "pickle", "yaml load"],
        ["open redirect", "open-redirect", "unvalidated redirect"],
        [
            "auth bypass",
            "authentication bypass",
            "authorization bypass",
            "privilege escalation",
            "broken access control",
        ],
        ["idor", "insecure direct object reference"],
    ]
    for keywords in groups:
        if any(k in sast_text for k in keywords) and any(k in dast_text for k in keywords):
            return True
    return False
