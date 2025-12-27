from __future__ import annotations

import uuid
from typing import List, Tuple

from fastapi.testclient import TestClient

from src.api.deps import CurrentUser, get_current_user, get_db
from src.main import app
from src.models import Finding, Scan


class DummySio:
    async def emit(self, *args, **kwargs):  # noqa: ANN001
        return None


def _override_db(db_sessionmaker):
    def _get_db():
        db = db_sessionmaker()
        try:
            yield db
        finally:
            db.close()

    return _get_db


TEST_USER_ID = uuid.uuid4()


def _override_current_user():
    return CurrentUser(id=TEST_USER_ID, email="tester@example.com")


def test_create_scan_creates_record(db_sessionmaker, monkeypatch):
    from src.api.routes import scans as scans_routes

    called: List[Tuple[str, str, str]] = []

    async def fake_run_scan_pipeline(  # noqa: ANN001
        scan_id, repo_url, branch, scan_type="sast", target_url=None
    ):
        called.append((str(scan_id), repo_url, branch))

    monkeypatch.setattr(scans_routes, "run_scan_pipeline", fake_run_scan_pipeline)
    monkeypatch.setattr(scans_routes, "sio", DummySio())

    app.dependency_overrides[get_db] = _override_db(db_sessionmaker)
    app.dependency_overrides[get_current_user] = _override_current_user
    client = TestClient(app)

    resp = client.post(
        "/api/scans",
        json={"repo_url": "https://github.com/example/repo", "branch": "main"},
    )
    assert resp.status_code == 201
    payload = resp.json()
    assert payload["repo_url"] == "https://github.com/example/repo"
    assert payload["branch"] == "main"
    assert payload["status"] == "pending"
    assert payload["trigger"] == "manual"

    verify_db = db_sessionmaker()
    scan_id = uuid.UUID(payload["id"])
    scan = verify_db.query(Scan).filter(Scan.id == scan_id).first()
    assert scan is not None
    verify_db.close()

    assert called
    app.dependency_overrides.clear()


def test_create_dast_scan_validates_target(db_sessionmaker, monkeypatch):
    from src.api.routes import scans as scans_routes
    from src.schemas import scan as scan_schema

    class DummySettings:
        dast_allowed_hosts = None

    async def fake_run_scan_pipeline(  # noqa: ANN001
        scan_id, repo_url, branch, scan_type="sast", target_url=None
    ):
        return None

    monkeypatch.setattr(scans_routes, "run_scan_pipeline", fake_run_scan_pipeline)
    monkeypatch.setattr(scans_routes, "sio", DummySio())
    monkeypatch.setattr(scan_schema, "get_settings", lambda: DummySettings())

    app.dependency_overrides[get_db] = _override_db(db_sessionmaker)
    app.dependency_overrides[get_current_user] = _override_current_user
    client = TestClient(app)

    resp = client.post(
        "/api/scans",
        json={
            "scan_type": "dast",
            "target_url": "scanme.nmap.org",
            "dast_consent": True,
        },
    )
    assert resp.status_code == 422

    resp = client.post(
        "/api/scans",
        json={
            "scan_type": "dast",
            "target_url": "http://localhost:8000",
            "dast_consent": True,
        },
    )
    assert resp.status_code == 422

    resp = client.post(
        "/api/scans",
        json={
            "scan_type": "dast",
            "target_url": "http://scanme.nmap.org",
            "dast_consent": True,
        },
    )
    assert resp.status_code == 201
    payload = resp.json()
    assert payload["target_url"] == "http://scanme.nmap.org"
    assert payload["scan_type"] == "dast"

    app.dependency_overrides.clear()


def test_create_dast_scan_allowlist(db_sessionmaker, monkeypatch):
    from src.api.routes import scans as scans_routes
    from src.schemas import scan as scan_schema

    class AllowlistSettings:
        dast_allowed_hosts = "example.com,trusted.org"
        scan_max_active = None
        scan_min_interval_seconds = None

    async def fake_run_scan_pipeline(  # noqa: ANN001
        scan_id, repo_url, branch, scan_type="sast", target_url=None
    ):
        return None

    monkeypatch.setattr(scans_routes, "run_scan_pipeline", fake_run_scan_pipeline)
    monkeypatch.setattr(scans_routes, "sio", DummySio())
    monkeypatch.setattr(scans_routes, "get_settings", lambda: AllowlistSettings())
    monkeypatch.setattr(scan_schema, "get_settings", lambda: AllowlistSettings())

    app.dependency_overrides[get_db] = _override_db(db_sessionmaker)
    app.dependency_overrides[get_current_user] = _override_current_user
    client = TestClient(app)

    resp = client.post(
        "/api/scans",
        json={
            "scan_type": "dast",
            "target_url": "http://notallowed.com",
            "dast_consent": True,
        },
    )
    assert resp.status_code == 422

    resp = client.post(
        "/api/scans",
        json={
            "scan_type": "dast",
            "target_url": "http://example.com",
            "dast_consent": True,
        },
    )
    assert resp.status_code == 201
    assert resp.json()["target_url"] == "http://example.com"

    resp = client.post(
        "/api/scans",
        json={
            "scan_type": "dast",
            "target_url": "http://sub.trusted.org/path",
            "dast_consent": True,
        },
    )
    assert resp.status_code == 201
    assert resp.json()["target_url"] == "http://sub.trusted.org/path"

    app.dependency_overrides.clear()


def test_scan_limit_blocks_active_scans(db_sessionmaker, monkeypatch):
    from src.api.routes import scans as scans_routes

    class DummySettings:
        scan_max_active = 1
        scan_min_interval_seconds = None

    async def fake_run_scan_pipeline(  # noqa: ANN001
        scan_id, repo_url, branch, scan_type="sast", target_url=None
    ):
        return None

    monkeypatch.setattr(scans_routes, "run_scan_pipeline", fake_run_scan_pipeline)
    monkeypatch.setattr(scans_routes, "sio", DummySio())
    monkeypatch.setattr(scans_routes, "get_settings", lambda: DummySettings())

    app.dependency_overrides[get_db] = _override_db(db_sessionmaker)
    app.dependency_overrides[get_current_user] = _override_current_user
    client = TestClient(app)

    db = db_sessionmaker()
    db.add(
        Scan(
            user_id=TEST_USER_ID,
            repo_url="https://github.com/example/repo",
            branch="main",
            status="scanning",
            trigger="manual",
            total_findings=0,
            filtered_findings=0,
        )
    )
    db.commit()
    db.close()

    resp = client.post(
        "/api/scans",
        json={"repo_url": "https://github.com/example/repo", "branch": "main"},
    )
    assert resp.status_code == 429

    app.dependency_overrides.clear()


def test_scan_findings_filtering(db_sessionmaker, monkeypatch):
    from src.api.routes import scans as scans_routes

    monkeypatch.setattr(scans_routes, "sio", DummySio())
    app.dependency_overrides[get_db] = _override_db(db_sessionmaker)
    app.dependency_overrides[get_current_user] = _override_current_user
    client = TestClient(app)

    db = db_sessionmaker()
    scan = Scan(
        user_id=TEST_USER_ID,
        repo_url="https://github.com/example/repo",
        branch="main",
        status="completed",
        trigger="manual",
        total_findings=2,
        filtered_findings=1,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    scan_id = str(scan.id)

    finding_keep = Finding(
        scan_id=scan.id,
        rule_id="rule-1",
        rule_message="test",
        semgrep_severity="ERROR",
        ai_severity="high",
        is_false_positive=False,
        file_path="app.py",
        line_start=10,
        line_end=10,
    )
    finding_drop = Finding(
        scan_id=scan.id,
        rule_id="rule-2",
        rule_message="test",
        semgrep_severity="WARNING",
        ai_severity="low",
        is_false_positive=True,
        file_path="app.py",
        line_start=20,
        line_end=20,
    )
    db.add(finding_keep)
    db.add(finding_drop)
    db.commit()
    db.close()

    resp = client.get(f"/api/scans/{scan_id}/findings")
    assert resp.status_code == 200
    payload = resp.json()
    assert len(payload) == 1
    assert payload[0]["rule_id"] == "rule-1"

    resp_all = client.get(
        f"/api/scans/{scan_id}/findings",
        params={"include_false_positives": True},
    )
    assert resp_all.status_code == 200
    assert len(resp_all.json()) == 2

    app.dependency_overrides.clear()


def test_update_finding_status(db_sessionmaker, monkeypatch):
    from src.api.routes import scans as scans_routes

    monkeypatch.setattr(scans_routes, "sio", DummySio())
    app.dependency_overrides[get_db] = _override_db(db_sessionmaker)
    app.dependency_overrides[get_current_user] = _override_current_user
    client = TestClient(app)

    db = db_sessionmaker()
    scan = Scan(
        user_id=TEST_USER_ID,
        repo_url="https://github.com/example/repo",
        branch="main",
        status="completed",
        trigger="manual",
        total_findings=1,
        filtered_findings=1,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    finding = Finding(
        scan_id=scan.id,
        rule_id="rule-1",
        rule_message="test",
        semgrep_severity="ERROR",
        ai_severity="high",
        is_false_positive=False,
        file_path="app.py",
        line_start=10,
        line_end=10,
        status="new",
    )
    db.add(finding)
    db.commit()
    db.refresh(finding)
    finding_id = str(finding.id)
    db.close()

    resp = client.patch(
        f"/api/findings/{finding_id}",
        json={"status": "confirmed"},
    )
    assert resp.status_code == 200
    payload = resp.json()
    assert payload["status"] == "confirmed"

    app.dependency_overrides.clear()
