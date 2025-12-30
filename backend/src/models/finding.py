from datetime import datetime
import uuid

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Integer,
    JSON,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import UUID

from .base import Base


class Finding(Base):
    __tablename__ = "findings"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(
        UUID(as_uuid=True),
        ForeignKey("scans.id"),
        nullable=False,
        index=True,
    )

    rule_id = Column(String, nullable=False)
    rule_message = Column(Text, nullable=True)
    semgrep_severity = Column(
        Enum("ERROR", "WARNING", "INFO", name="semgrep_severity"),
        nullable=False,
    )
    finding_type = Column(
        Enum("sast", "dast", name="finding_type"),
        nullable=False,
        default="sast",
    )
    ai_severity = Column(
        Enum("critical", "high", "medium", "low", "info", name="ai_severity"),
        nullable=True,
    )
    is_false_positive = Column(Boolean, nullable=False, default=False)
    ai_reasoning = Column(Text, nullable=True)
    ai_confidence = Column(Float, nullable=True)
    exploitability = Column(Text, nullable=True)

    file_path = Column(String, nullable=False)
    line_start = Column(Integer, nullable=False)
    line_end = Column(Integer, nullable=False)
    code_snippet = Column(Text, nullable=True)
    context_snippet = Column(Text, nullable=True)
    function_name = Column(String, nullable=True)
    class_name = Column(String, nullable=True)
    is_test_file = Column(Boolean, nullable=False, default=False)
    is_generated = Column(Boolean, nullable=False, default=False)
    imports = Column(JSON, nullable=True)
    matched_at = Column(String, nullable=True)
    endpoint = Column(String, nullable=True)
    curl_command = Column(Text, nullable=True)
    evidence = Column(JSON, nullable=True)
    description = Column(Text, nullable=True)
    remediation = Column(Text, nullable=True)
    cve_ids = Column(JSON, nullable=True)
    cwe_ids = Column(JSON, nullable=True)
    confirmed_exploitable = Column(Boolean, nullable=False, default=False)

    # Reachability analysis fields
    is_reachable = Column(Boolean, nullable=False, default=True)
    reachability_score = Column(Float, nullable=True, default=1.0)
    reachability_reason = Column(Text, nullable=True)
    entry_points = Column(JSON, nullable=True)
    call_path = Column(JSON, nullable=True)

    status = Column(
        Enum("new", "confirmed", "dismissed", name="finding_status"),
        nullable=False,
        default="new",
    )
    priority_score = Column(Integer, nullable=True)

    fix_status = Column(
        Enum("generated", "pr_opened", "failed", name="fix_status"),
        nullable=True,
    )
    fix_summary = Column(Text, nullable=True)
    fix_patch = Column(Text, nullable=True)
    fix_pr_url = Column(String, nullable=True)
    fix_branch = Column(String, nullable=True)
    fix_error = Column(Text, nullable=True)
    fix_confidence = Column(Float, nullable=True)
    fix_generated_at = Column(DateTime, nullable=True)

    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(
        DateTime,
        nullable=False,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
    )
