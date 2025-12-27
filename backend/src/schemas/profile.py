from __future__ import annotations

import uuid
from typing import List, Optional

from pydantic import BaseModel, ConfigDict


class UserSettingsUpdate(BaseModel):
    github_token: Optional[str] = None
    github_webhook_secret: Optional[str] = None
    github_allowlist: Optional[List[str]] = None
    enable_scan_push: Optional[bool] = None
    enable_scan_pr: Optional[bool] = None
    enable_issue_ingest: Optional[bool] = None
    enable_issue_comment_ingest: Optional[bool] = None


class UserSettingsRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    github_token_set: bool
    github_webhook_secret_set: bool
    github_allowlist: List[str]
    enable_scan_push: bool
    enable_scan_pr: bool
    enable_issue_ingest: bool
    enable_issue_comment_ingest: bool


class ProfileRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    user_id: uuid.UUID
    email: Optional[str] = None
    settings: UserSettingsRead
