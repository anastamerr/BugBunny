from __future__ import annotations

import uuid
from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, ConfigDict


class BugPredictionBase(BaseModel):
    incident_id: uuid.UUID
    predicted_bug_count: int
    predicted_components: Optional[List[str]] = None
    confidence: Optional[float] = None
    prediction_window_hours: Optional[int] = None

    actual_bug_count: Optional[int] = None
    was_accurate: Optional[bool] = None


class BugPredictionCreate(BugPredictionBase):
    pass


class BugPredictionRead(BugPredictionBase):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    created_at: Optional[datetime] = None


class ResolutionPatternRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    incident_type: Optional[str] = None
    affected_table: Optional[str] = None
    symptom_keywords: Optional[List[str]] = None
    resolution_action: Optional[str] = None
    resolution_time_avg: Optional[float] = None
    occurrence_count: Optional[int] = None
    last_seen: Optional[datetime] = None
    embedding_id: Optional[str] = None
