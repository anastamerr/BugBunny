from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel


class IncidentPostmortemRead(BaseModel):
    incident_id: uuid.UUID
    markdown: str
    generated_at: datetime

