from datetime import datetime, timezone

from fastapi.testclient import TestClient

from src.api.deps import get_db
from src.main import app


def test_incident_actions_postmortem_and_learning(db_sessionmaker):
    def override_get_db():
        db = db_sessionmaker()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)

    payload = {
        "incident_id": "DI-PLAYBOOK-001",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "table_name": "user_transactions",
        "incident_type": "SCHEMA_DRIFT",
        "severity": "CRITICAL",
        "details": {"foo": "bar"},
        "affected_columns": ["user_id"],
        "anomaly_score": 0.9,
        "downstream_systems": ["analytics_dashboard"],
        "status": "ACTIVE",
    }

    create_resp = client.post("/api/incidents", json=payload)
    assert create_resp.status_code == 201
    incident = create_resp.json()
    incident_id = incident["id"]

    actions_resp = client.get(f"/api/incidents/{incident_id}/actions")
    assert actions_resp.status_code == 200
    actions = actions_resp.json()
    assert len(actions) >= 2
    assert actions[0]["incident_id"] == incident_id

    first_action_id = actions[0]["id"]
    patch_action = client.patch(
        f"/api/incidents/{incident_id}/actions/{first_action_id}",
        json={"status": "done"},
    )
    assert patch_action.status_code == 200
    assert patch_action.json()["status"] == "done"

    resolve_resp = client.patch(
        f"/api/incidents/{incident_id}",
        json={"status": "RESOLVED", "resolution_notes": "Backfilled the pipeline and fixed schema mapping."},
    )
    assert resolve_resp.status_code == 200
    assert resolve_resp.json()["status"] == "RESOLVED"
    assert resolve_resp.json()["resolved_at"] is not None

    postmortem_resp = client.get(f"/api/incidents/{incident_id}/postmortem")
    assert postmortem_resp.status_code == 200
    pm = postmortem_resp.json()
    assert pm["incident_id"] == incident_id
    assert "Backfilled the pipeline" in pm["markdown"]
    assert "Postmortem:" in pm["markdown"]

    # Create another incident with same (type, table) to verify resolution learning shows up.
    payload2 = {
        **payload,
        "incident_id": "DI-PLAYBOOK-002",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "status": "ACTIVE",
    }
    create2 = client.post("/api/incidents", json=payload2)
    assert create2.status_code == 201
    incident2_id = create2.json()["id"]

    actions2_resp = client.get(f"/api/incidents/{incident2_id}/actions")
    assert actions2_resp.status_code == 200
    actions2 = actions2_resp.json()
    assert any(a["title"] == "Apply proven fix" for a in actions2)

    app.dependency_overrides.clear()

