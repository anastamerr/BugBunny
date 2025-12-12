from __future__ import annotations

import uuid
from typing import Optional

from pydantic import BaseModel


class ChatRequest(BaseModel):
    message: str
    incident_id: Optional[uuid.UUID] = None
    bug_id: Optional[uuid.UUID] = None
    correlation_id: Optional[uuid.UUID] = None


class ChatResponse(BaseModel):
    response: str
    used_llm: bool = False
    model: Optional[str] = None

