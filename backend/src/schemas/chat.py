from __future__ import annotations

import uuid
from typing import Optional

from pydantic import BaseModel


class ChatRequest(BaseModel):
    message: str
    bug_id: Optional[uuid.UUID] = None
    scan_id: Optional[uuid.UUID] = None
    finding_id: Optional[uuid.UUID] = None


class ChatResponse(BaseModel):
    response: str
    used_llm: bool = False
    model: Optional[str] = None

