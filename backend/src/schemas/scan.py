from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, ConfigDict


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


class ScanCreate(BaseModel):
    repo_url: str
    branch: Optional[str] = "main"


class ScanUpdate(BaseModel):
    status: Optional[ScanStatus] = None
    trigger: Optional[ScanTrigger] = None
    total_findings: Optional[int] = None
    filtered_findings: Optional[int] = None
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
    repo_url: str
    branch: str
    status: ScanStatus
    trigger: ScanTrigger
    total_findings: int
    filtered_findings: int
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
