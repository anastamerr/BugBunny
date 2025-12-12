from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel

from .bug import BugReportRead, BugSource
from .correlation import CorrelationRead
from .incident import DataIncidentRead, IncidentStatus, IncidentType, Severity


class DemoInjectIncidentRequest(BaseModel):
    table_name: str
    incident_type: IncidentType = IncidentType.SCHEMA_DRIFT
    severity: Severity = Severity.CRITICAL
    status: IncidentStatus = IncidentStatus.ACTIVE

    incident_id: Optional[str] = None
    timestamp: Optional[datetime] = None
    details: Optional[Dict[str, Any]] = None
    affected_columns: Optional[List[str]] = None
    anomaly_score: Optional[float] = None
    downstream_systems: Optional[List[str]] = None


class DemoInjectBugRequest(BaseModel):
    title: str
    description: Optional[str] = None
    source: BugSource = BugSource.manual

    bug_id: Optional[str] = None
    created_at: Optional[datetime] = None
    reporter: Optional[str] = None
    labels: Optional[List[str] | Dict[str, Any]] = None

    auto_correlate: bool = True
    generate_explanation: bool = True


class DemoInjectBugResponse(BaseModel):
    bug: BugReportRead
    correlation: Optional[CorrelationRead] = None
    incident: Optional[DataIncidentRead] = None

