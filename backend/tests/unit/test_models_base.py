from sqlalchemy import Column, Integer, create_engine, inspect

from src.models.base import Base


class _DummyModel(Base):
    __tablename__ = "dummy_models"

    id = Column(Integer, primary_key=True)


def test_base_metadata_creates_tables():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(bind=engine)

    inspector = inspect(engine)
    assert "dummy_models" in inspector.get_table_names()
