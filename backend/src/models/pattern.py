from sqlalchemy import Boolean, Column, DateTime, Float, ForeignKey, Integer, JSON, String, func
from sqlalchemy.dialects.postgresql import UUID
import uuid

from .base import Base


class ResolutionPattern(Base):
    __tablename__ = "resolution_patterns"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    incident_type = Column(String)
    affected_table = Column(String)
    symptom_keywords = Column(JSON)  # Keywords from related bugs
    resolution_action = Column(String)
    resolution_time_avg = Column(Float)  # Average time to resolve in hours
    occurrence_count = Column(Integer, default=1)
    last_seen = Column(DateTime)
    embedding_id = Column(String)  # For similarity matching


class BugPrediction(Base):
    __tablename__ = "bug_predictions"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    incident_id = Column(UUID(as_uuid=True), ForeignKey("data_incidents.id"))
    predicted_bug_count = Column(Integer)
    predicted_components = Column(JSON)
    confidence = Column(Float)
    prediction_window_hours = Column(Integer)
    created_at = Column(DateTime, server_default=func.now())

    # Validation
    actual_bug_count = Column(Integer, nullable=True)
    was_accurate = Column(Boolean, nullable=True)

