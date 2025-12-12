from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict

from .bug import BugReportRead
from .incident import DataIncidentRead


class CorrelationBase(BaseModel):
    bug_id: uuid.UUID
    incident_id: uuid.UUID
    correlation_score: float
    temporal_score: Optional[float] = None
    component_score: Optional[float] = None
    keyword_score: Optional[float] = None
    explanation: Optional[str] = None


class CorrelationCreate(CorrelationBase):
    pass


class CorrelationRead(CorrelationBase):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    created_at: Optional[datetime] = None


class CorrelationView(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    bug: BugReportRead
    incident: DataIncidentRead
    correlation_score: float
    temporal_score: Optional[float] = None
    component_score: Optional[float] = None
    keyword_score: Optional[float] = None
    explanation: Optional[str] = None
    created_at: Optional[datetime] = None
