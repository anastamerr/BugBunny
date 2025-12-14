from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, ConfigDict


class IncidentActionStatus(str, Enum):
    todo = "todo"
    doing = "doing"
    done = "done"


class IncidentActionSource(str, Enum):
    generated = "generated"
    manual = "manual"


class IncidentActionBase(BaseModel):
    title: str
    description: Optional[str] = None
    owner_team: Optional[str] = None
    status: IncidentActionStatus = IncidentActionStatus.todo
    source: IncidentActionSource = IncidentActionSource.generated
    sort_order: Optional[int] = None


class IncidentActionCreate(IncidentActionBase):
    source: IncidentActionSource = IncidentActionSource.manual


class IncidentActionUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    owner_team: Optional[str] = None
    status: Optional[IncidentActionStatus] = None
    sort_order: Optional[int] = None


class IncidentActionRead(IncidentActionBase):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    incident_id: uuid.UUID
    created_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None

