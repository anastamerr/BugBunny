from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, ConfigDict


class SemgrepSeverity(str, Enum):
    error = "ERROR"
    warning = "WARNING"
    info = "INFO"


class AISeverity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class FindingType(str, Enum):
    sast = "sast"
    dast = "dast"


class FindingStatus(str, Enum):
    new = "new"
    confirmed = "confirmed"
    dismissed = "dismissed"


class FixStatus(str, Enum):
    generated = "generated"
    pr_opened = "pr_opened"
    failed = "failed"


class FindingBase(BaseModel):
    scan_id: uuid.UUID
    rule_id: str
    rule_message: Optional[str] = None
    semgrep_severity: SemgrepSeverity
    finding_type: FindingType = FindingType.sast
    ai_severity: Optional[AISeverity] = None
    is_false_positive: bool = False
    ai_reasoning: Optional[str] = None
    ai_confidence: Optional[float] = None
    exploitability: Optional[str] = None

    file_path: str
    line_start: int
    line_end: int
    code_snippet: Optional[str] = None
    context_snippet: Optional[str] = None
    function_name: Optional[str] = None
    class_name: Optional[str] = None
    is_test_file: bool = False
    is_generated: bool = False
    imports: Optional[List[str]] = None
    matched_at: Optional[str] = None
    endpoint: Optional[str] = None
    curl_command: Optional[str] = None
    evidence: Optional[List[str]] = None
    description: Optional[str] = None
    remediation: Optional[str] = None
    cve_ids: Optional[List[str]] = None
    cwe_ids: Optional[List[str]] = None
    confirmed_exploitable: bool = False

    # Reachability analysis fields
    is_reachable: bool = True
    reachability_score: Optional[float] = 1.0
    reachability_reason: Optional[str] = None
    entry_points: Optional[List[str]] = None
    call_path: Optional[List[str]] = None

    status: FindingStatus = FindingStatus.new
    priority_score: Optional[int] = None

    fix_status: Optional[FixStatus] = None
    fix_summary: Optional[str] = None
    fix_patch: Optional[str] = None
    fix_pr_url: Optional[str] = None
    fix_branch: Optional[str] = None
    fix_error: Optional[str] = None
    fix_confidence: Optional[float] = None
    fix_generated_at: Optional[datetime] = None


class FindingCreate(FindingBase):
    pass


class FindingUpdate(BaseModel):
    status: Optional[FindingStatus] = None


class FindingRead(FindingBase):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    created_at: datetime
    updated_at: datetime
