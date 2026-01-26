from datetime import datetime, timezone
import uuid

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import UUID

from .base import Base


class Scan(Base):
    __tablename__ = "scans"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), nullable=False, index=True)
    repo_id = Column(UUID(as_uuid=True), ForeignKey("repositories.id"), nullable=True)
    repo_url = Column(String, nullable=True)
    branch = Column(String, nullable=False, default="main")
    scan_type = Column(
        Enum("sast", "dast", "both", name="scan_type"),
        nullable=False,
        default="sast",
    )
    dependency_health_enabled = Column(Boolean, nullable=False, default=True)
    target_url = Column(String, nullable=True)
    dast_auth_headers = Column(JSON, nullable=True)  # {"Authorization": "Bearer token"}
    dast_cookies = Column(Text, nullable=True)  # "session=abc; token=xyz"
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
    is_paused = Column(Boolean, nullable=False, default=False)
    trigger = Column(
        Enum("manual", "webhook", name="scan_trigger"),
        nullable=False,
        default="manual",
    )
    total_findings = Column(Integer, nullable=False, default=0)
    filtered_findings = Column(Integer, nullable=False, default=0)
    dast_findings = Column(Integer, nullable=False, default=0)
    dast_confirmed_count = Column(Integer, nullable=False, default=0)
    error_message = Column(Text, nullable=True)
    pr_number = Column(Integer, nullable=True)
    pr_url = Column(String, nullable=True)
    commit_sha = Column(String, nullable=True)
    commit_url = Column(String, nullable=True)
    detected_languages = Column(JSON, nullable=True)
    rulesets = Column(JSON, nullable=True)
    scanned_files = Column(Integer, nullable=True)
    semgrep_version = Column(String, nullable=True)
    created_at = Column(
        DateTime, nullable=False, default=lambda: datetime.now(timezone.utc)
    )
    updated_at = Column(
        DateTime,
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )
    report_url = Column(String, nullable=True)
    report_generated_at = Column(DateTime, nullable=True)
