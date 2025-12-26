from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict


class RepositoryCreate(BaseModel):
    repo_url: str
    default_branch: Optional[str] = "main"


class RepositoryRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    repo_url: str
    repo_full_name: Optional[str] = None
    default_branch: str
    created_at: datetime
    updated_at: datetime
