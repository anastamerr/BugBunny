from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, Enum, Float, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.dialects.postgresql import UUID

from ..models.base import Base


SCAN_TYPES = ("sast", "dast", "both")
SCAN_STATUSES = ("queued", "running", "completed", "failed")
VERIFICATION_STATUSES = (
    "CONFIRMED_EXPLOITABLE",
    "UNVERIFIED_NO_MATCH",
    "COULD_NOT_TEST_AUTH_REQUIRED",
    "COULD_NOT_TEST_UNREACHABLE",
    "COULD_NOT_TEST_RATE_LIMITED",
    "COULD_NOT_TEST_INSUFFICIENT_COVERAGE",
    "COULD_NOT_TEST_TIMEOUT",
    "COULD_NOT_TEST_TOOL_ERROR",
)


class ScanJobV2(Base):
    __tablename__ = "scan_jobs_v2"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    created_at = Column(
        DateTime, nullable=False, default=lambda: datetime.now(timezone.utc)
    )
    updated_at = Column(
        DateTime,
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    scan_type = Column(
        Enum(*SCAN_TYPES, name="scan_job_v2_type", native_enum=False),
        nullable=False,
    )
    status = Column(
        Enum(*SCAN_STATUSES, name="scan_job_v2_status", native_enum=False),
        nullable=False,
        default="queued",
    )

    repo_url = Column(String, nullable=True)
    branch = Column(String, nullable=True)
    target_url = Column(String, nullable=True)
    auth_present = Column(Boolean, nullable=False, default=False)

    error_message = Column(Text, nullable=True)
    metrics = Column(JSON, nullable=True)


class SastFindingV2(Base):
    __tablename__ = "sast_findings_v2"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scan_jobs_v2.id"), index=True)

    rule_id = Column(String, nullable=False)
    message = Column(Text, nullable=True)
    severity = Column(String, nullable=False)
    file_path = Column(String, nullable=False)
    line_start = Column(Integer, nullable=False)
    line_end = Column(Integer, nullable=False)
    cwe_ids = Column(JSON, nullable=True)
    fingerprint = Column(String, nullable=False)
    raw = Column(JSON, nullable=False)


class DastAlertV2(Base):
    __tablename__ = "dast_alerts_v2"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scan_jobs_v2.id"), index=True)

    plugin_id = Column(String, nullable=False)
    name = Column(Text, nullable=False)
    risk = Column(String, nullable=False)
    confidence = Column(String, nullable=False)
    url = Column(Text, nullable=False)
    param = Column(Text, nullable=False)
    evidence = Column(Text, nullable=True)
    cwe_id = Column(Integer, nullable=True)
    raw = Column(JSON, nullable=False)


class CorrelationV2(Base):
    __tablename__ = "correlations_v2"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scan_jobs_v2.id"), index=True)
    sast_finding_id = Column(
        UUID(as_uuid=True), ForeignKey("sast_findings_v2.id"), nullable=False
    )
    matched_dast_alert_id = Column(
        UUID(as_uuid=True), ForeignKey("dast_alerts_v2.id"), nullable=True
    )

    status = Column(
        Enum(*VERIFICATION_STATUSES, name="verification_status_v2", native_enum=False),
        nullable=False,
    )
    reason = Column(Text, nullable=True)
    correlation_score = Column(Float, nullable=False, default=0.0)
