"""Integration tests for scan policy API endpoint."""

from __future__ import annotations

import uuid

from fastapi.testclient import TestClient

from src.api import deps as api_deps
from src.api.deps import get_db
from src.main import app
from src.models import Finding, Scan


def _override_db(db_sessionmaker):
    def _get_db():
        db = db_sessionmaker()
        try:
            yield db
        finally:
            db.close()

    return _get_db


def test_scan_policy_api_no_violations(db_sessionmaker, monkeypatch):
    """Test policy API endpoint with no violations."""
    # Setup
    db = db_sessionmaker()
    user_id = uuid.uuid4()

    scan_id = uuid.uuid4()
    scan = Scan(
        id=scan_id,
        user_id=user_id,
        repo_url="https://github.com/test/repo",
        branch="main",
        scan_type="sast",
        status="completed",
    )
    db.add(scan)
    db.commit()

    # Add only low severity findings
    finding = Finding(
        scan_id=scan_id,
        rule_id="test-rule",
        rule_message="Test finding",
        ai_severity="low",
        semgrep_severity="INFO",
        file_path="test.py",
        line_start=1,
        line_end=1,
        is_false_positive=False,
    )
    db.add(finding)
    db.commit()
    db.close()

    # Mock auth
    class DummySettings:
        dev_auth_bypass = True
        dev_auth_user_id = str(user_id)
        dev_auth_email = "test@example.com"
        supabase_jwt_secret = None
        supabase_jwt_issuer = None

    monkeypatch.setattr(api_deps, "get_settings", lambda: DummySettings())
    app.dependency_overrides[get_db] = _override_db(db_sessionmaker)
    client = TestClient(app)

    # Test with fail_on=high (should pass)
    resp = client.get(f"/api/scans/{scan_id}/policy?fail_on=high")
    assert resp.status_code == 200
    data = resp.json()
    assert data["passed"] is True
    assert data["exit_code"] == 0
    assert data["fail_on"] == "high"
    assert data["violations_count"] == 0
    assert len(data["violations"]) == 0

    app.dependency_overrides.clear()


def test_scan_policy_api_with_violations(db_sessionmaker, monkeypatch):
    """Test policy API endpoint with violations."""
    # Setup
    db = db_sessionmaker()
    user_id = uuid.uuid4()
    db.commit()

    scan_id = uuid.uuid4()
    scan = Scan(
        id=scan_id,
        user_id=user_id,
        repo_url="https://github.com/test/repo",
        branch="main",
        scan_type="sast",
        status="completed",
    )
    db.add(scan)
    db.commit()

    # Add critical and high findings
    finding1 = Finding(
        scan_id=scan_id,
        rule_id="sql-injection",
        rule_message="SQL Injection detected",
        ai_severity="critical",
        semgrep_severity="ERROR",
        file_path="app.py",
        line_start=42,
        line_end=42,
        is_false_positive=False,
    )
    finding2 = Finding(
        scan_id=scan_id,
        rule_id="xss",
        rule_message="XSS vulnerability",
        ai_severity="high",
        semgrep_severity="ERROR",
        file_path="views.py",
        line_start=100,
        line_end=100,
        is_false_positive=False,
    )
    finding3 = Finding(
        scan_id=scan_id,
        rule_id="info-disclosure",
        rule_message="Info disclosure",
        ai_severity="medium",
        semgrep_severity="WARNING",
        file_path="utils.py",
        line_start=25,
        line_end=25,
        is_false_positive=False,
    )
    db.add_all([finding1, finding2, finding3])
    db.commit()
    db.close()

    # Mock auth
    class DummySettings:
        dev_auth_bypass = True
        dev_auth_user_id = str(user_id)
        dev_auth_email = "test@example.com"
        supabase_jwt_secret = None
        supabase_jwt_issuer = None

    monkeypatch.setattr(api_deps, "get_settings", lambda: DummySettings())
    app.dependency_overrides[get_db] = _override_db(db_sessionmaker)
    client = TestClient(app)

    # Test with fail_on=high (should fail with 2 violations)
    resp = client.get(f"/api/scans/{scan_id}/policy?fail_on=high")
    assert resp.status_code == 200
    data = resp.json()
    assert data["passed"] is False
    assert data["exit_code"] == 1
    assert data["fail_on"] == "high"
    assert data["violations_count"] == 2
    assert len(data["violations"]) == 2

    # Check violation details
    violations = data["violations"]
    assert violations[0]["severity"] == "critical"
    assert violations[0]["rule_id"] == "sql-injection"
    assert violations[0]["file_path"] == "app.py"
    assert violations[1]["severity"] == "high"
    assert violations[1]["rule_id"] == "xss"

    # Test with fail_on=medium (should fail with 3 violations)
    resp = client.get(f"/api/scans/{scan_id}/policy?fail_on=medium")
    assert resp.status_code == 200
    data = resp.json()
    assert data["passed"] is False
    assert data["violations_count"] == 3

    # Test with fail_on=critical (should fail with 1 violation)
    resp = client.get(f"/api/scans/{scan_id}/policy?fail_on=critical")
    assert resp.status_code == 200
    data = resp.json()
    assert data["passed"] is False
    assert data["violations_count"] == 1

    app.dependency_overrides.clear()


def test_scan_policy_api_false_positives(db_sessionmaker, monkeypatch):
    """Test that false positives are excluded by default."""
    # Setup
    db = db_sessionmaker()
    user_id = uuid.uuid4()
    db.commit()

    scan_id = uuid.uuid4()
    scan = Scan(
        id=scan_id,
        user_id=user_id,
        repo_url="https://github.com/test/repo",
        branch="main",
        scan_type="sast",
        status="completed",
    )
    db.add(scan)
    db.commit()

    # Add critical finding marked as false positive
    finding1 = Finding(
        scan_id=scan_id,
        rule_id="sql-injection",
        rule_message="SQL Injection detected",
        ai_severity="critical",
        semgrep_severity="ERROR",
        file_path="app.py",
        line_start=42,
        line_end=42,
        is_false_positive=True,  # False positive
    )
    # Add real high finding
    finding2 = Finding(
        scan_id=scan_id,
        rule_id="xss",
        rule_message="XSS vulnerability",
        ai_severity="high",
        semgrep_severity="ERROR",
        file_path="views.py",
        line_start=100,
        line_end=100,
        is_false_positive=False,
    )
    db.add_all([finding1, finding2])
    db.commit()
    db.close()

    # Mock auth
    class DummySettings:
        dev_auth_bypass = True
        dev_auth_user_id = str(user_id)
        dev_auth_email = "test@example.com"
        supabase_jwt_secret = None
        supabase_jwt_issuer = None

    monkeypatch.setattr(api_deps, "get_settings", lambda: DummySettings())
    app.dependency_overrides[get_db] = _override_db(db_sessionmaker)
    client = TestClient(app)

    # Test with default (exclude false positives) - should have 1 violation
    resp = client.get(f"/api/scans/{scan_id}/policy?fail_on=high")
    assert resp.status_code == 200
    data = resp.json()
    assert data["violations_count"] == 1
    assert data["violations"][0]["rule_id"] == "xss"

    # Test with include_false_positives=true - should have 2 violations
    resp = client.get(f"/api/scans/{scan_id}/policy?fail_on=high&include_false_positives=true")
    assert resp.status_code == 200
    data = resp.json()
    assert data["violations_count"] == 2

    app.dependency_overrides.clear()


def test_scan_policy_api_invalid_fail_on(db_sessionmaker, monkeypatch):
    """Test policy API with invalid fail_on parameter."""
    # Setup
    db = db_sessionmaker()
    user_id = uuid.uuid4()
    db.commit()

    scan_id = uuid.uuid4()
    scan = Scan(
        id=scan_id,
        user_id=user_id,
        repo_url="https://github.com/test/repo",
        branch="main",
        scan_type="sast",
        status="completed",
    )
    db.add(scan)
    db.commit()
    db.close()

    # Mock auth
    class DummySettings:
        dev_auth_bypass = True
        dev_auth_user_id = str(user_id)
        dev_auth_email = "test@example.com"
        supabase_jwt_secret = None
        supabase_jwt_issuer = None

    monkeypatch.setattr(api_deps, "get_settings", lambda: DummySettings())
    app.dependency_overrides[get_db] = _override_db(db_sessionmaker)
    client = TestClient(app)

    # Test with invalid fail_on - should fail validation
    resp = client.get(f"/api/scans/{scan_id}/policy?fail_on=invalid")
    assert resp.status_code == 422  # Validation error

    app.dependency_overrides.clear()


def test_scan_policy_api_scan_not_found(db_sessionmaker, monkeypatch):
    """Test policy API with non-existent scan."""
    user_id = uuid.uuid4()

    # Mock auth
    class DummySettings:
        dev_auth_bypass = True
        dev_auth_user_id = str(user_id)
        dev_auth_email = "test@example.com"
        supabase_jwt_secret = None
        supabase_jwt_issuer = None

    monkeypatch.setattr(api_deps, "get_settings", lambda: DummySettings())
    app.dependency_overrides[get_db] = _override_db(db_sessionmaker)
    client = TestClient(app)

    fake_scan_id = uuid.uuid4()
    resp = client.get(f"/api/scans/{fake_scan_id}/policy?fail_on=high")
    assert resp.status_code == 404

    app.dependency_overrides.clear()


def test_scan_policy_api_unauthorized(db_sessionmaker, monkeypatch):
    """Test policy API requires authentication."""
    # Setup scan owned by different user
    db = db_sessionmaker()
    user_id = uuid.uuid4()
    db.commit()

    scan_id = uuid.uuid4()
    scan = Scan(
        id=scan_id,
        user_id=user_id,
        repo_url="https://github.com/test/repo",
        branch="main",
        scan_type="sast",
        status="completed",
    )
    db.add(scan)
    db.commit()
    db.close()

    # Mock auth as different user
    different_user_id = uuid.uuid4()

    class DummySettings:
        dev_auth_bypass = True
        dev_auth_user_id = str(different_user_id)
        dev_auth_email = "other@example.com"
        supabase_jwt_secret = None
        supabase_jwt_issuer = None

    monkeypatch.setattr(api_deps, "get_settings", lambda: DummySettings())
    app.dependency_overrides[get_db] = _override_db(db_sessionmaker)
    client = TestClient(app)

    # Should return 404 (not authorized to view this scan)
    resp = client.get(f"/api/scans/{scan_id}/policy?fail_on=high")
    assert resp.status_code == 404

    app.dependency_overrides.clear()
