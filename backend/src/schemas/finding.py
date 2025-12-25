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


class FindingStatus(str, Enum):
    new = "new"
    confirmed = "confirmed"
    dismissed = "dismissed"


class FindingBase(BaseModel):
    scan_id: uuid.UUID
    rule_id: str
    rule_message: Optional[str] = None
    semgrep_severity: SemgrepSeverity
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

    status: FindingStatus = FindingStatus.new
    priority_score: Optional[int] = None


class FindingCreate(FindingBase):
    pass


class FindingUpdate(BaseModel):
    status: Optional[FindingStatus] = None


class FindingRead(FindingBase):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    created_at: datetime
    updated_at: datetime
