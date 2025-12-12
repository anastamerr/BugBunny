from __future__ import annotations

import os
import time
from typing import Any, Dict

import httpx

API_URL = os.getenv("DATABUG_API_URL", "http://localhost:8000/api")


def post(path: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    with httpx.Client(timeout=30.0) as client:
        resp = client.post(f"{API_URL}{path}", json=payload)
        resp.raise_for_status()
        return resp.json()


def run_demo(delay_s: float = 1.0) -> None:
    incident = post(
        "/demo/inject-incident",
        {
            "table_name": "user_transactions",
            "incident_type": "SCHEMA_DRIFT",
            "severity": "CRITICAL",
            "affected_columns": ["user_id"],
            "downstream_systems": ["analytics_dashboard", "user_api"],
            "details": {"change": "user_id -> userId"},
        },
    )
    print(f"[1/2] Injected incident: {incident['incident_id']} ({incident['id']})")
    time.sleep(delay_s)

    bug = post(
        "/demo/inject-bug",
        {
            "title": "Dashboard shows $0 revenue",
            "description": "Revenue dashboard displaying zero values since this morning",
            "auto_correlate": True,
            "generate_explanation": True,
        },
    )
    print(f"[2/2] Injected bug: {bug['bug']['bug_id']} ({bug['bug']['id']})")
    if bug.get("correlation"):
        print("Created correlation:", bug["correlation"]["id"])


if __name__ == "__main__":
    run_demo()

