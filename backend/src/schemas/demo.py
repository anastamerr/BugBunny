from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from .bug import BugReportRead, BugSource
from .scan import ScanRead, ScanType


class DemoInjectBugRequest(BaseModel):
    title: str
    description: Optional[str] = None
    source: BugSource = BugSource.manual

    bug_id: Optional[str] = None
    created_at: Optional[datetime] = None
    reporter: Optional[str] = None
    labels: Optional[List[str] | Dict[str, Any]] = None

class DemoInjectBugResponse(BaseModel):
    bug: BugReportRead


class DemoInjectScanRequest(BaseModel):
    repo_url: Optional[str] = "https://github.com/semgrep/semgrep-pro-tests"
    branch: Optional[str] = "main"
    scan_type: ScanType = ScanType.both
    target_url: Optional[str] = "https://demo.scanguard.local"
    real_findings: int = Field(default=12, ge=0)
    false_positives: int = Field(default=75, ge=0)


class DemoInjectScanResponse(BaseModel):
    scan: ScanRead
    findings_created: int
    real_findings: int
    false_positives: int

