from __future__ import annotations

import ipaddress
import logging
import socket
import uuid
from datetime import datetime
from enum import Enum
from typing import List, Optional
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, model_validator

from ..config import get_settings

logger = logging.getLogger(__name__)

class ScanStatus(str, Enum):
    pending = "pending"
    cloning = "cloning"
    scanning = "scanning"
    analyzing = "analyzing"
    completed = "completed"
    failed = "failed"


class ScanTrigger(str, Enum):
    manual = "manual"
    webhook = "webhook"


class ScanType(str, Enum):
    sast = "sast"
    dast = "dast"
    both = "both"


def _is_private_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def _is_blocked_host(hostname: str) -> bool:
    host = hostname.strip().lower().strip(".")
    if host in {"localhost", "localhost.localdomain"}:
        return True
    try:
        ip = ipaddress.ip_address(host)
        return _is_private_ip(ip)
    except ValueError:
        pass
    try:
        resolved = socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        for family, _, _, _, sockaddr in resolved:
            ip_str = sockaddr[0]
            try:
                ip = ipaddress.ip_address(ip_str)
                if _is_private_ip(ip):
                    logger.warning(
                        "Hostname %s resolves to private IP %s", host, ip_str
                    )
                    return True
            except ValueError:
                continue
    except socket.gaierror:
        pass
    return False


def _is_allowed_host(hostname: str, allowlist: list[str]) -> bool:
    host = hostname.strip().lower().strip(".")
    for allowed in allowlist:
        allowed_host = allowed.strip().lower().strip(".")
        if not allowed_host:
            continue
        if host == allowed_host or host.endswith(f".{allowed_host}"):
            return True
    return False


def _parse_allowlist(value: str | None) -> list[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def _normalize_target_url(value: str) -> str:
    trimmed = value.strip()
    parsed = urlparse(trimmed)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("target_url must start with http:// or https://")
    if not parsed.netloc:
        raise ValueError("target_url must include a host")
    if not parsed.hostname:
        raise ValueError("target_url must include a host")
    if parsed.username or parsed.password:
        raise ValueError("target_url must not include credentials")
    if _is_blocked_host(parsed.hostname):
        raise ValueError("target_url must be a public http(s) address")
    allowlist = _parse_allowlist(get_settings().dast_allowed_hosts)
    if allowlist and not _is_allowed_host(parsed.hostname, allowlist):
        raise ValueError("target_url host is not allowed")
    return trimmed


class ScanCreate(BaseModel):
    repo_url: Optional[str] = None
    repo_id: Optional[uuid.UUID] = None
    branch: Optional[str] = "main"
    commit_sha: Optional[str] = None
    scan_type: ScanType = ScanType.sast
    dependency_health_enabled: bool = True
    target_url: Optional[str] = None
    dast_consent: bool = False
    dast_auth_headers: Optional[dict[str, str]] = None
    dast_cookies: Optional[str] = None

    @model_validator(mode="after")
    def _require_repo(self) -> "ScanCreate":
        settings = get_settings()
        if self.scan_type in {ScanType.sast, ScanType.both}:
            if not self.repo_url and not self.repo_id:
                raise ValueError("repo_url or repo_id is required for SAST scans")
        if self.scan_type == ScanType.both and not settings.dast_deploy_script:
            raise ValueError(
                "DAST verification for 'both' scans requires DAST_DEPLOY_SCRIPT to deploy the SAST commit"
            )
        if self.scan_type in {ScanType.dast, ScanType.both}:
            if not self.target_url:
                if self.scan_type == ScanType.dast:
                    raise ValueError("target_url is required for DAST scans")
            if not self.dast_consent:
                raise ValueError("dast_consent is required for DAST scans")
            if self.target_url:
                self.target_url = _normalize_target_url(self.target_url)
        if self.scan_type == ScanType.dast:
            self.dependency_health_enabled = False
        return self


class ScanUpdate(BaseModel):
    status: Optional[ScanStatus] = None
    scan_type: Optional[ScanType] = None
    dependency_health_enabled: Optional[bool] = None
    is_paused: Optional[bool] = None
    target_url: Optional[str] = None
    trigger: Optional[ScanTrigger] = None
    total_findings: Optional[int] = None
    filtered_findings: Optional[int] = None
    dast_findings: Optional[int] = None
    dast_confirmed_count: Optional[int] = None
    error_message: Optional[str] = None
    pr_number: Optional[int] = None
    pr_url: Optional[str] = None
    commit_sha: Optional[str] = None
    commit_url: Optional[str] = None
    detected_languages: Optional[List[str]] = None
    rulesets: Optional[List[str]] = None
    scanned_files: Optional[int] = None
    semgrep_version: Optional[str] = None


class ScanRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    repo_id: Optional[uuid.UUID] = None
    repo_url: Optional[str] = None
    branch: str
    scan_type: ScanType
    dependency_health_enabled: bool
    target_url: Optional[str] = None
    status: ScanStatus
    is_paused: bool
    trigger: ScanTrigger
    total_findings: int
    filtered_findings: int
    dast_findings: int
    dast_confirmed_count: int = 0
    dast_verification_status: str = "not_applicable"
    error_message: Optional[str] = None
    pr_number: Optional[int] = None
    pr_url: Optional[str] = None
    commit_sha: Optional[str] = None
    commit_url: Optional[str] = None
    detected_languages: Optional[List[str]] = None
    rulesets: Optional[List[str]] = None
    scanned_files: Optional[int] = None
    semgrep_version: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    report_url: Optional[str] = None
    report_generated_at: Optional[datetime] = None
