from sqlalchemy import Column, DateTime, Enum, Float, JSON, String, func
from sqlalchemy.dialects.postgresql import UUID
import uuid

from .base import Base


class DataIncident(Base):
    __tablename__ = "data_incidents"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    incident_id = Column(String, unique=True, index=True)  # DI-2025-01-15-001
    timestamp = Column(DateTime, nullable=False)
    table_name = Column(String, nullable=False, index=True)
    incident_type = Column(
        Enum(
            "SCHEMA_DRIFT",
            "NULL_SPIKE",
            "VOLUME_ANOMALY",
            "FRESHNESS",
            "DISTRIBUTION_DRIFT",
            "VALIDATION_FAILURE",
            name="incident_type",
        )
    )
    severity = Column(
        Enum("CRITICAL", "HIGH", "MEDIUM", "LOW", name="severity")
    )
    details = Column(JSON)  # Flexible storage for incident specifics
    affected_columns = Column(JSON)  # List of column names
    anomaly_score = Column(Float)
    downstream_systems = Column(JSON)  # List of affected systems
    status = Column(Enum("ACTIVE", "INVESTIGATING", "RESOLVED", name="status"))
    resolved_at = Column(DateTime, nullable=True)
    resolution_notes = Column(String, nullable=True)
    created_at = Column(DateTime, server_default=func.now())

