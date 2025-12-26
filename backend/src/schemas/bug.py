from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict


class BugSource(str, Enum):
    github = "github"
    jira = "jira"
    manual = "manual"


class BugType(str, Enum):
    bug = "bug"
    feature = "feature"
    question = "question"


class BugSeverity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"


class BugStatus(str, Enum):
    new = "new"
    triaged = "triaged"
    assigned = "assigned"
    resolved = "resolved"


class BugReportBase(BaseModel):
    bug_id: str
    source: BugSource
    title: str
    description: Optional[str] = None
    created_at: datetime
    reporter: Optional[str] = None
    labels: Optional[List[str] | Dict[str, Any]] = None
    stack_trace: Optional[str] = None

    classified_type: Optional[BugType] = None
    classified_component: Optional[str] = None
    classified_severity: Optional[BugSeverity] = None
    confidence_score: Optional[float] = None

    is_duplicate: bool = False
    duplicate_of_id: Optional[uuid.UUID] = None
    duplicate_score: Optional[float] = None

    assigned_team: Optional[str] = None
    status: BugStatus = BugStatus.new
    resolution_notes: Optional[str] = None
    embedding_id: Optional[str] = None


class BugReportCreate(BugReportBase):
    pass


class BugReportUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    labels: Optional[List[str] | Dict[str, Any]] = None

    classified_type: Optional[BugType] = None
    classified_component: Optional[str] = None
    classified_severity: Optional[BugSeverity] = None
    confidence_score: Optional[float] = None

    is_duplicate: Optional[bool] = None
    duplicate_of_id: Optional[uuid.UUID] = None
    duplicate_score: Optional[float] = None

    assigned_team: Optional[str] = None
    status: Optional[BugStatus] = None
    resolution_notes: Optional[str] = None
    embedding_id: Optional[str] = None


class BugReportRead(BugReportBase):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
