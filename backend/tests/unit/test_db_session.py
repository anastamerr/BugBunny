import importlib

from sqlalchemy import text

from src import config as config_module


def test_session_local_uses_configured_db_url(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "sqlite://")
    config_module.get_settings.cache_clear()

    import src.db.session as session_module

    importlib.reload(session_module)

    session = session_module.SessionLocal()
    try:
        result = session.execute(text("select 1")).scalar()
        assert result == 1
    finally:
        session.close()
