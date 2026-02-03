from __future__ import annotations

from typing import Optional

from pydantic import BaseModel

from .finding import FixStatus, FindingRead


class AutoFixRequest(BaseModel):
    create_pr: bool = False
    regenerate: bool = False


class AutoFixResponse(BaseModel):
    status: FixStatus
    patch: Optional[str] = None
    summary: Optional[str] = None
    confidence: Optional[float] = None
    pr_url: Optional[str] = None
    branch: Optional[str] = None
    error: Optional[str] = None
    finding: FindingRead
