from datetime import datetime
import uuid

from sqlalchemy import Column, DateTime, Enum, Integer, String, Text
from sqlalchemy.dialects.postgresql import UUID

from .base import Base


class Scan(Base):
    __tablename__ = "scans"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    repo_url = Column(String, nullable=False)
    branch = Column(String, nullable=False, default="main")
    status = Column(
        Enum(
            "pending",
            "cloning",
            "scanning",
            "analyzing",
            "completed",
            "failed",
            name="scan_status",
        ),
        nullable=False,
        default="pending",
    )
    trigger = Column(
        Enum("manual", "webhook", name="scan_trigger"),
        nullable=False,
        default="manual",
    )
    total_findings = Column(Integer, nullable=False, default=0)
    filtered_findings = Column(Integer, nullable=False, default=0)
    error_message = Column(Text, nullable=True)
    pr_number = Column(Integer, nullable=True)
    pr_url = Column(String, nullable=True)
    commit_sha = Column(String, nullable=True)
    commit_url = Column(String, nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(
        DateTime,
        nullable=False,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
    )
