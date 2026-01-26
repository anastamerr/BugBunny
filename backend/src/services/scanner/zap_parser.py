from __future__ import annotations

import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from .types import DynamicFinding

VULN_KEYWORDS: Dict[str, List[str]] = {
    "sqli": ["sql injection", "sqli", "sql-injection"],
    "xss": ["xss", "cross-site scripting", "cross site scripting"],
    "command-injection": ["command injection", "cmd injection", "os command", "shell"],
    "code-injection": ["code injection", "rce", "remote code", "eval"],
    "path-traversal": ["path traversal", "directory traversal", "file inclusion", "lfi"],
    "xxe": ["xxe", "xml external entity"],
    "ssrf": ["ssrf", "server-side request", "server side request forgery"],
    "ssti": ["ssti", "template injection", "server-side template"],
    "open-redirect": ["open redirect", "unvalidated redirect"],
    "deserialization": ["deserialization", "deserialize", "unserialize", "pickle"],
}


def classify_vulnerability(text: str) -> Optional[str]:
    value = text.lower()
    for vuln_type, keywords in VULN_KEYWORDS.items():
        if any(keyword in value for keyword in keywords):
            return vuln_type
    return None


def alert_matches_vuln_type(alert: Dict[str, Any], vuln_type: str) -> bool:
    keywords = VULN_KEYWORDS.get(vuln_type, [])
    if not keywords:
        return False
    text = " ".join(
        [
            str(alert.get("alert") or ""),
            str(alert.get("name") or ""),
            str(alert.get("description") or ""),
            str(alert.get("other") or ""),
        ]
    ).lower()
    return any(keyword in text for keyword in keywords)


def parse_zap_alert(alert: Dict[str, Any], fallback_url: Optional[str] = None) -> DynamicFinding | None:
    alert_id = str(alert.get("alertId") or alert.get("pluginId") or "")
    alert_name = str(alert.get("alert") or alert.get("name") or "")
    if not alert_id and not alert_name:
        return None

    risk = _normalize_risk(alert.get("risk") or alert.get("riskDesc"))
    confidence = str(alert.get("confidence") or alert.get("confidenceDesc") or "")
    url = str(alert.get("url") or alert.get("uri") or fallback_url or "")
    param = str(alert.get("param") or "")
    description = str(alert.get("description") or "")
    solution = str(alert.get("solution") or "")
    reference = str(alert.get("reference") or "")
    other = str(alert.get("other") or "")
    cwe_ids = _extract_cwe_ids(alert.get("cweid") or alert.get("cweId"))

    evidence = _format_evidence(
        alert_id=alert_id or alert_name,
        alert_name=alert_name or alert_id,
        risk=risk,
        confidence=confidence,
        url=url or fallback_url or "",
        param=param,
        description=description,
    )
    if reference:
        evidence.append(f"reference={_compact(reference)}")
    if other:
        evidence.append(f"other={_compact(other)}")

    endpoint = _extract_endpoint(url or fallback_url or "")

    return DynamicFinding(
        template_id=alert_id or alert_name,
        template_name=alert_name or alert_id,
        severity=risk,
        matched_at=url or fallback_url or "",
        endpoint=endpoint or (fallback_url or ""),
        curl_command="",
        evidence=evidence,
        description=description,
        remediation=solution,
        cve_ids=[],
        cwe_ids=cwe_ids,
    )


def _normalize_risk(value: Any) -> str:
    if value is None:
        return "info"
    text = str(value).strip().lower()
    if "high" in text:
        return "high"
    if "medium" in text:
        return "medium"
    if "low" in text:
        return "low"
    if "info" in text:
        return "info"
    return text or "info"


def _extract_cwe_ids(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, list):
        ids = value
    else:
        ids = [value]
    results = []
    for item in ids:
        try:
            num = int(str(item))
        except (TypeError, ValueError):
            match = re.search(r"cwe[-_]?(\d+)", str(item), re.IGNORECASE)
            if not match:
                continue
            num = int(match.group(1))
        results.append(f"CWE-{num}")
    return results


def _extract_endpoint(value: str) -> str:
    try:
        parsed = urlparse(value)
        if parsed.scheme and parsed.netloc:
            return f"{parsed.scheme}://{parsed.netloc}"
    except Exception:
        return ""
    return ""


def _format_evidence(
    *,
    alert_id: str,
    alert_name: str,
    risk: str,
    confidence: str,
    url: str,
    param: str,
    description: str,
) -> List[str]:
    snippet = _compact(description)
    return [
        (
            "zap_alert="
            f"id:{alert_id} "
            f"name:{alert_name} "
            f"risk:{risk} "
            f"confidence:{confidence or 'unknown'} "
            f"url:{url} "
            f"param:{param or 'n/a'} "
            f"description:{snippet}"
        )
    ]


def _compact(text: str, limit: int = 220) -> str:
    trimmed = " ".join(text.split())
    if len(trimmed) <= limit:
        return trimmed
    return trimmed[: limit - 3] + "..."
