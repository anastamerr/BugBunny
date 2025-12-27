from __future__ import annotations

import asyncio
import json
import shutil
import subprocess
from pathlib import Path
from typing import List, Optional

from .types import DependencyFinding


class DependencyScanner:
    def __init__(self, trivy_path: str = "trivy", timeout_seconds: int = 300) -> None:
        self.trivy_path = trivy_path
        self.timeout_seconds = timeout_seconds

    def is_available(self) -> bool:
        return shutil.which(self.trivy_path) is not None

    async def scan(self, repo_path: Path) -> List[DependencyFinding]:
        cmd = [
            self.trivy_path,
            "fs",
            str(repo_path),
            "--format",
            "json",
            "--scanners",
            "vuln",
            "--severity",
            "CRITICAL,HIGH,MEDIUM",
        ]

        try:
            result = await asyncio.to_thread(
                subprocess.run,
                cmd,
                capture_output=True,
                text=True,
                check=False,
                timeout=self.timeout_seconds,
            )
        except subprocess.TimeoutExpired:
            return []

        if result.returncode != 0 or not result.stdout.strip():
            return []

        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError:
            return []

        return _parse_results(payload)


def _parse_results(payload: dict) -> List[DependencyFinding]:
    findings: List[DependencyFinding] = []
    for result in payload.get("Results", []) or []:
        target = result.get("Target")
        for vuln in result.get("Vulnerabilities", []) or []:
            cve_id = str(vuln.get("VulnerabilityID") or "").strip()
            if not cve_id:
                continue
            package_name = str(vuln.get("PkgName") or "").strip()
            installed_version = str(vuln.get("InstalledVersion") or "").strip()
            fixed_version = str(
                vuln.get("FixedVersion") or "No fix available"
            ).strip()
            severity = str(vuln.get("Severity") or "UNKNOWN").lower()
            description = str(vuln.get("Description") or "").strip()
            cvss_score = _extract_cvss_score(vuln.get("CVSS"))

            findings.append(
                DependencyFinding(
                    cve_id=cve_id,
                    package_name=package_name or "unknown",
                    installed_version=installed_version or "unknown",
                    fixed_version=fixed_version or "No fix available",
                    severity=severity,
                    description=description,
                    cvss_score=cvss_score,
                    target=str(target) if target else None,
                )
            )

    return findings


def _extract_cvss_score(value) -> Optional[float]:
    if not isinstance(value, dict):
        return None

    for source in ("nvd", "redhat", "ghsa", "ubuntu", "debian"):
        entry = value.get(source)
        score = _score_from_entry(entry)
        if score is not None:
            return score

    for entry in value.values():
        score = _score_from_entry(entry)
        if score is not None:
            return score

    return None


def _score_from_entry(entry) -> Optional[float]:
    if not isinstance(entry, dict):
        return None
    score = entry.get("V3Score") or entry.get("V2Score")
    try:
        return float(score)
    except (TypeError, ValueError):
        return None
