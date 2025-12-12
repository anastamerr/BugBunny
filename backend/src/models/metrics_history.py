from sqlalchemy import Column, DateTime, JSON, String, func
from sqlalchemy.dialects.postgresql import UUID
import uuid

from .base import Base


class MetricsHistory(Base):
    __tablename__ = "metrics_history"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    table_name = Column(String, index=True, nullable=False)
    metrics = Column(JSON, nullable=False)
    recorded_at = Column(DateTime, server_default=func.now())

