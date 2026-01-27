from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.api.deps import get_db
from src.scanguard_scan import api as scans_api
from src.scanguard_scan.schemas import DastZapConfig


def test_both_scan_passes_auth_and_timeouts(db_session, monkeypatch):
    captured = {}

    def fake_run_scan_job(context):
        captured["context"] = context

    monkeypatch.setattr(scans_api, "run_scan_job", fake_run_scan_job)

    app = FastAPI()

    def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    app.include_router(scans_api.router, prefix="/api")

    client = TestClient(app)
    payload = {
        "repo_url": "https://github.com/example/repo",
        "branch": "main",
        "target_url": "http://example.com",
        "auth": {
            "headers": {"Authorization": "Bearer token"},
            "cookies": "session=abc",
        },
        "semgrep_config": "auto",
        "timeouts": {"sast_seconds": 900, "dast_seconds": 1800},
    }

    response = client.post("/api/v2/scans/both", json=payload)

    assert response.status_code == 200
    context = captured["context"]
    assert context.auth_headers == {"Authorization": "Bearer token"}
    assert context.auth_cookies == "session=abc"
    assert context.sast_timeout_seconds == 900
    assert context.dast_timeout_seconds == 1800


def test_dast_defaults():
    zap = DastZapConfig()
    assert zap.timeout_seconds >= 1800
    assert zap.spider_minutes == 5
    assert zap.active_scan_minutes == 20
