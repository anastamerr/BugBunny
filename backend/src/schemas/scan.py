from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, ConfigDict, model_validator


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
    repo_url: Optional[str] = None
    repo_id: Optional[uuid.UUID] = None
    branch: Optional[str] = "main"

    @model_validator(mode="after")
    def _require_repo(self) -> "ScanCreate":
        if not self.repo_url and not self.repo_id:
            raise ValueError("repo_url or repo_id is required")
        return self


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
    repo_id: Optional[uuid.UUID] = None
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
