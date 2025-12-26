from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel

from .bug import BugReportRead, BugSource


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

