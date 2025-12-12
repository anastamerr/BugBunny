from sqlalchemy import Column, DateTime, Float, ForeignKey, String, func
from sqlalchemy.dialects.postgresql import UUID
import uuid

from .base import Base


class BugIncidentCorrelation(Base):
    __tablename__ = "correlations"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    bug_id = Column(UUID(as_uuid=True), ForeignKey("bug_reports.id"))
    incident_id = Column(UUID(as_uuid=True), ForeignKey("data_incidents.id"))

    correlation_score = Column(Float)
    temporal_score = Column(Float)
    component_score = Column(Float)
    keyword_score = Column(Float)

    explanation = Column(String)  # LLM-generated explanation
    created_at = Column(DateTime, server_default=func.now())

