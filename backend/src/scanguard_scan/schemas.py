from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


class ScanType(str, Enum):
    sast = "sast"
    dast = "dast"
    both = "both"


class ScanStatus(str, Enum):
    queued = "queued"
    running = "running"
    completed = "completed"
    failed = "failed"


class VerificationStatus(str, Enum):
    confirmed = "CONFIRMED_EXPLOITABLE"
    unverified_no_match = "UNVERIFIED_NO_MATCH"
    auth_required = "COULD_NOT_TEST_AUTH_REQUIRED"
    unreachable = "COULD_NOT_TEST_UNREACHABLE"
    rate_limited = "COULD_NOT_TEST_RATE_LIMITED"
    insufficient_coverage = "COULD_NOT_TEST_INSUFFICIENT_COVERAGE"
    timeout = "COULD_NOT_TEST_TIMEOUT"
    tool_error = "COULD_NOT_TEST_TOOL_ERROR"


class SastScanRequest(BaseModel):
    repo_url: str
    branch: str = "main"
    github_token: Optional[str] = None
    semgrep_config: str = "auto"
    timeout_seconds: int = 600


class DastAuthConfig(BaseModel):
    headers: Dict[str, str] = Field(default_factory=dict)
    cookies: str = ""


class DastZapConfig(BaseModel):
    timeout_seconds: int = 1800
    spider_minutes: int = 5
    active_scan_minutes: int = 20


class DastScanRequest(BaseModel):
    target_url: str
    auth: Optional[DastAuthConfig] = None
    zap: Optional[DastZapConfig] = None


class BothScanTimeouts(BaseModel):
    sast_seconds: int = 900
    dast_seconds: int = 1800


class BothScanRequest(BaseModel):
    repo_url: str
    branch: str = "main"
    target_url: str
    github_token: Optional[str] = None
    auth: Optional[DastAuthConfig] = None
    semgrep_config: str = "auto"
    timeouts: BothScanTimeouts = Field(default_factory=BothScanTimeouts)


class ScanCreateResponse(BaseModel):
    scan_id: uuid.UUID
    type: ScanType
    status: ScanStatus


class ScanJobRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    scan_type: ScanType
    status: ScanStatus
    repo_url: Optional[str] = None
    branch: Optional[str] = None
    target_url: Optional[str] = None
    auth_present: bool = False
    error_message: Optional[str] = None
    metrics: Optional[Dict[str, Any]] = None
    created_at: datetime
    updated_at: datetime


class SastFindingRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    scan_id: uuid.UUID
    rule_id: str
    message: Optional[str] = None
    severity: str
    file_path: str
    line_start: int
    line_end: int
    cwe_ids: List[int] = Field(default_factory=list)
    fingerprint: str
    raw: Dict[str, Any]


class DastAlertRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    scan_id: uuid.UUID
    plugin_id: str
    name: str
    risk: str
    confidence: str
    url: str
    param: str
    evidence: Optional[str] = None
    cwe_id: Optional[int] = None
    raw: Dict[str, Any]


class CorrelationRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    scan_id: uuid.UUID
    sast_finding_id: uuid.UUID
    matched_dast_alert_id: Optional[uuid.UUID] = None
    status: VerificationStatus
    reason: Optional[str] = None
    correlation_score: float


class ScanResultsResponse(BaseModel):
    scan: ScanJobRead
    sast_findings: List[SastFindingRead] = Field(default_factory=list)
    dast_alerts: List[DastAlertRead] = Field(default_factory=list)
    correlations: List[CorrelationRead] = Field(default_factory=list)
