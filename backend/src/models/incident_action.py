from __future__ import annotations

import uuid

from sqlalchemy import Column, DateTime, Enum, ForeignKey, Integer, String, func
from sqlalchemy.dialects.postgresql import UUID

from .base import Base


class IncidentAction(Base):
    __tablename__ = "incident_actions"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    incident_id = Column(
        UUID(as_uuid=True),
        ForeignKey("data_incidents.id"),
        nullable=False,
        index=True,
    )

    title = Column(String, nullable=False)
    description = Column(String, nullable=True)
    owner_team = Column(String, nullable=True)

    status = Column(
        Enum("todo", "doing", "done", name="incident_action_status"),
        nullable=False,
        default="todo",
    )
    source = Column(
        Enum("generated", "manual", name="incident_action_source"),
        nullable=False,
        default="generated",
    )
    sort_order = Column(Integer, nullable=True)

    completed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, server_default=func.now())

