from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from src.db import seed
from src.models import Base, BugReport


def test_seed_sample_data_inserts_once(monkeypatch):
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(bind=engine)

    monkeypatch.setattr(seed, "SessionLocal", SessionLocal)

    seed.seed_sample_data()
    seed.seed_sample_data()

    session = SessionLocal()
    try:
        count = session.query(BugReport).count()
    finally:
        session.close()

    assert count == 1
