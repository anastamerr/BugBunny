from sqlalchemy import Boolean, Column, DateTime, Enum, Float, ForeignKey, JSON, String
from sqlalchemy.dialects.postgresql import UUID
import uuid

from .base import Base


class BugReport(Base):
    __tablename__ = "bug_reports"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    bug_id = Column(String, unique=True, index=True)  # External ID (GitHub, Jira)
    source = Column(Enum("github", "jira", "manual", name="bug_source"))
    title = Column(String, nullable=False)
    description = Column(String)
    created_at = Column(DateTime, nullable=False)
    reporter = Column(String)
    labels = Column(JSON)  # Original labels
    stack_trace = Column(String, nullable=True)

    # Classification results
    classified_type = Column(Enum("bug", "feature", "question", name="bug_type"))
    classified_component = Column(String)
    classified_severity = Column(
        Enum("critical", "high", "medium", "low", name="bug_severity")
    )
    confidence_score = Column(Float)

    # Duplicate detection
    is_duplicate = Column(Boolean, default=False)
    duplicate_of_id = Column(
        UUID(as_uuid=True),
        ForeignKey("bug_reports.id"),
        nullable=True,
    )
    duplicate_score = Column(Float, nullable=True)

    # Routing
    assigned_team = Column(String, nullable=True)
    status = Column(Enum("new", "triaged", "assigned", "resolved", name="bug_status"))
    resolution_notes = Column(String, nullable=True)

    # Embedding reference
    embedding_id = Column(String, nullable=True)  # Pinecone vector ID
