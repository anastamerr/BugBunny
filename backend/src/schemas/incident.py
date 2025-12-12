from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict


class IncidentType(str, Enum):
    SCHEMA_DRIFT = "SCHEMA_DRIFT"
    NULL_SPIKE = "NULL_SPIKE"
    VOLUME_ANOMALY = "VOLUME_ANOMALY"
    FRESHNESS = "FRESHNESS"
    DISTRIBUTION_DRIFT = "DISTRIBUTION_DRIFT"
    VALIDATION_FAILURE = "VALIDATION_FAILURE"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class IncidentStatus(str, Enum):
    ACTIVE = "ACTIVE"
    INVESTIGATING = "INVESTIGATING"
    RESOLVED = "RESOLVED"


class DataIncidentBase(BaseModel):
    incident_id: str
    timestamp: datetime
    table_name: str
    incident_type: IncidentType
    severity: Severity
    details: Optional[Dict[str, Any]] = None
    affected_columns: Optional[List[str]] = None
    anomaly_score: Optional[float] = None
    downstream_systems: Optional[List[str]] = None
    status: IncidentStatus = IncidentStatus.ACTIVE
    resolved_at: Optional[datetime] = None
    resolution_notes: Optional[str] = None


class DataIncidentCreate(DataIncidentBase):
    pass


class DataIncidentUpdate(BaseModel):
    incident_type: Optional[IncidentType] = None
    severity: Optional[Severity] = None
    details: Optional[Dict[str, Any]] = None
    affected_columns: Optional[List[str]] = None
    anomaly_score: Optional[float] = None
    downstream_systems: Optional[List[str]] = None
    status: Optional[IncidentStatus] = None
    resolved_at: Optional[datetime] = None
    resolution_notes: Optional[str] = None


class DataIncidentRead(DataIncidentBase):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    created_at: Optional[datetime] = None
