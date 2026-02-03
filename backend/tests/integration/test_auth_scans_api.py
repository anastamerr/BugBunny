from __future__ import annotations

import uuid

from fastapi.testclient import TestClient

from src.api import deps as api_deps
from src.api.deps import get_db
from src.main import app


def _override_db(db_sessionmaker):
    def _get_db():
        db = db_sessionmaker()
        try:
            yield db
        finally:
            db.close()

    return _get_db


def test_scans_requires_auth(db_sessionmaker, monkeypatch):
    class DummySettings:
        dev_auth_bypass = False
        supabase_jwt_secret = "secret"
        supabase_jwt_issuer = None
        dev_auth_user_id = None
        dev_auth_email = None

    monkeypatch.setattr(api_deps, "get_settings", lambda: DummySettings())
    app.dependency_overrides[get_db] = _override_db(db_sessionmaker)
    client = TestClient(app)

    resp = client.get("/api/scans")
    assert resp.status_code == 401
    assert resp.json().get("detail") == "Missing authorization header"

    app.dependency_overrides.clear()


def test_scans_dev_auth_bypass(db_sessionmaker, monkeypatch):
    class DummySettings:
        dev_auth_bypass = True
        supabase_jwt_secret = None
        supabase_jwt_issuer = None
        dev_auth_user_id = str(uuid.uuid4())
        dev_auth_email = "dev@example.com"

    monkeypatch.setattr(api_deps, "get_settings", lambda: DummySettings())
    app.dependency_overrides[get_db] = _override_db(db_sessionmaker)
    client = TestClient(app)

    resp = client.get("/api/scans")
    assert resp.status_code == 200

    app.dependency_overrides.clear()
