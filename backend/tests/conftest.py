import os
import sys
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from unittest.mock import MagicMock

BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

os.environ["GITHUB_BACKFILL_ON_START"] = "false"
try:
    from src.config import get_settings

    get_settings.cache_clear()
except Exception:
    pass


@pytest.fixture
def db_engine():
    """Create a thread-safe in-memory SQLite engine."""
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    from src.models import Base

    Base.metadata.create_all(bind=engine)
    try:
        yield engine
    finally:
        engine.dispose()


@pytest.fixture
def db_sessionmaker(db_engine):
    return sessionmaker(bind=db_engine)


@pytest.fixture
def db_session(db_sessionmaker):
    session = db_sessionmaker()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def mock_pinecone():
    """Mock Pinecone service for unit tests."""
    mock = MagicMock()
    mock.find_similar_bugs.return_value = []
    mock.upsert_bug.return_value = "test-id"
    return mock


@pytest.fixture
def mock_ollama():
    """Mock Ollama service for unit tests."""
    mock = MagicMock()
    mock.generate.return_value = "Test explanation"
    mock.is_available.return_value = True
    return mock


@pytest.fixture
def sample_bug():
    """Sample bug for testing."""
    return {
        "bug_id": "GH-123",
        "title": "Dashboard shows $0 revenue",
        "description": "Revenue dashboard displaying zero values since this morning",
        "classified_component": "analytics_dashboard",
        "classified_severity": "critical",
    }
