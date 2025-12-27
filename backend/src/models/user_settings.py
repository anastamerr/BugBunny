from datetime import datetime
import uuid

from sqlalchemy import Boolean, Column, DateTime, JSON, Text
from sqlalchemy.dialects.postgresql import UUID

from .base import Base


class UserSettings(Base):
    __tablename__ = "user_settings"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), nullable=False, unique=True, index=True)
    github_token = Column(Text, nullable=True)
    github_webhook_secret = Column(Text, nullable=True)
    github_allowlist = Column(JSON, nullable=True)
    enable_scan_push = Column(Boolean, nullable=False, default=True)
    enable_scan_pr = Column(Boolean, nullable=False, default=True)
    enable_issue_ingest = Column(Boolean, nullable=False, default=True)
    enable_issue_comment_ingest = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(
        DateTime,
        nullable=False,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
    )
