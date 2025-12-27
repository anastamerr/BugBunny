from __future__ import annotations

import asyncio
import json
import logging
import shutil
import subprocess
from typing import List
from urllib.parse import urlparse

from ...config import get_settings
from .types import DynamicFinding

logger = logging.getLogger(__name__)


class DASTRunner:
    def __init__(self, nuclei_path: str = "nuclei") -> None:
        self.nuclei_path = nuclei_path
        self.settings = get_settings()
        self.last_error: str | None = None

    def is_available(self) -> bool:
        return shutil.which(self.nuclei_path) is not None

    async def scan(self, target_url: str) -> List[DynamicFinding]:
        self.last_error = None
        cmd = [
            self.nuclei_path,
            "-u",
            target_url,
            "-jsonl",
            "-silent",
        ]
        if self.settings.nuclei_templates_path:
            cmd.extend(["-t", self.settings.nuclei_templates_path])
        if self.settings.nuclei_rate_limit:
            cmd.extend(["-rl", str(self.settings.nuclei_rate_limit)])
        severity_filter = _normalize_severity_filter(self.settings.nuclei_severities)
        if severity_filter:
            cmd.extend(["-severity", severity_filter])
        tag_filter = _normalize_csv(self.settings.nuclei_tags)
        if tag_filter:
            cmd.extend(["-tags", tag_filter])
        exclude_tags = _normalize_csv(self.settings.nuclei_exclude_tags)
        if exclude_tags:
            cmd.extend(["-exclude-tags", exclude_tags])
        protocol_filter = _normalize_csv(self.settings.nuclei_protocols)
        if protocol_filter:
            cmd.extend(["-pt", protocol_filter])
        if (
            self.settings.nuclei_request_timeout_seconds
            and self.settings.nuclei_request_timeout_seconds > 0
        ):
            cmd.extend(["-timeout", str(self.settings.nuclei_request_timeout_seconds)])

        try:
            result = await asyncio.to_thread(
                subprocess.run,
                cmd,
                capture_output=True,
                text=True,
                check=False,
                timeout=self.settings.nuclei_timeout_seconds,
            )
        except subprocess.TimeoutExpired:
            self.last_error = (
                f"Nuclei scan timed out after {self.settings.nuclei_timeout_seconds}s."
            )
            logger.warning(
                "Nuclei scan timed out after %ss for %s",
                self.settings.nuclei_timeout_seconds,
                target_url,
            )
            return []

        if result.returncode != 0:
            stderr = (result.stderr or "").strip()
            self.last_error = (
                f"Nuclei exited with code {result.returncode}."
                f"{' ' + stderr if stderr else ''}"
            )
            logger.error(
                "Nuclei exited with code %s for %s: %s",
                result.returncode,
                target_url,
                (result.stderr or "").strip(),
            )
            return []

        findings: List[DynamicFinding] = []
        parse_errors = 0
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                parse_errors += 1
                continue
            finding = _parse_nuclei_finding(data, target_url)
            if finding:
                findings.append(finding)
        if parse_errors:
            logger.warning(
                "Nuclei output parse errors: %s line(s) skipped for %s",
                parse_errors,
                target_url,
            )
        return findings


def _parse_nuclei_finding(payload: dict, target_url: str) -> DynamicFinding | None:
    template_id = str(payload.get("template-id") or payload.get("templateID") or "")
    info = payload.get("info") or {}
    template_name = str(info.get("name") or payload.get("template") or template_id)
    severity = str(info.get("severity") or "info").lower()
    matched_at = str(payload.get("matched-at") or payload.get("matched_at") or "")
    host = str(payload.get("host") or payload.get("ip") or "")

    if not matched_at:
        matched_at = target_url
    endpoint = host or _extract_endpoint(matched_at) or _extract_endpoint(target_url)

    curl_command = str(payload.get("curl-command") or "")
    evidence = _to_list(payload.get("extracted-results"))
    description = str(info.get("description") or "")
    remediation = str(info.get("remediation") or "")
    classification = info.get("classification") or {}
    cve_ids = _to_list(classification.get("cve-id") or classification.get("cve"))
    cwe_ids = _to_list(classification.get("cwe-id") or classification.get("cwe"))

    if not template_id and not template_name:
        return None

    return DynamicFinding(
        template_id=template_id or template_name,
        template_name=template_name or template_id,
        severity=severity,
        matched_at=matched_at,
        endpoint=endpoint or target_url,
        curl_command=curl_command,
        evidence=evidence,
        description=description,
        remediation=remediation,
        cve_ids=cve_ids,
        cwe_ids=cwe_ids,
    )


def _extract_endpoint(value: str) -> str:
    try:
        parsed = urlparse(value)
        if parsed.scheme and parsed.netloc:
            return f"{parsed.scheme}://{parsed.netloc}"
    except Exception:
        return ""
    return ""


def _to_list(value) -> List[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value if item]
    if isinstance(value, str):
        return [value]
    return [str(value)]


def _normalize_severity_filter(value: str | None) -> str | None:
    return _normalize_csv(value)


def _normalize_csv(value: str | None) -> str | None:
    if not value:
        return None
    if isinstance(value, str):
        parts = [part.strip().lower() for part in value.split(",")]
        cleaned = [part for part in parts if part]
        return ",".join(cleaned) if cleaned else None
    return None
