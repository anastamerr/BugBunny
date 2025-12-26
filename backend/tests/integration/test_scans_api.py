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

    async def fake_run_scan_pipeline(scan_id, repo_url, branch):  # noqa: ANN001
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
