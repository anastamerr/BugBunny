from datetime import datetime, timezone
import uuid

from sqlalchemy import Column, DateTime, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID

from .base import Base


class Repository(Base):
    __tablename__ = "repositories"
    __table_args__ = (
        UniqueConstraint("user_id", "repo_url", name="uq_repo_user_url"),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), nullable=False, index=True)
    repo_url = Column(String, nullable=False)
    repo_full_name = Column(String, nullable=True)
    default_branch = Column(String, nullable=False, default="main")
    created_at = Column(
        DateTime, nullable=False, default=lambda: datetime.now(timezone.utc)
    )
    updated_at = Column(
        DateTime,
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )
