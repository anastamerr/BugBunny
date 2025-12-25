from __future__ import annotations

import os
import time
from typing import Any, Dict

import httpx

API_URL = (
    os.getenv("SCANGUARD_API_URL")
    or os.getenv("DATABUG_API_URL")
    or "http://localhost:8000/api"
)


def post(path: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    with httpx.Client(timeout=30.0) as client:
        resp = client.post(f"{API_URL}{path}", json=payload)
        resp.raise_for_status()
        return resp.json()


def run_demo(delay_s: float = 1.0) -> None:
    bug = post(
        "/demo/inject-bug",
        {
            "title": "Dashboard shows $0 revenue",
            "description": "Revenue dashboard displaying zero values since this morning",
        },
    )
    print(f"[1/2] Injected bug: {bug['bug']['bug_id']} ({bug['bug']['id']})")
    time.sleep(delay_s)

    followup = post(
        "/demo/inject-bug",
        {
            "title": "User API returning empty profiles",
            "description": "GET /api/users/{id} returns null for all users",
        },
    )
    print(f"[2/2] Injected bug: {followup['bug']['bug_id']} ({followup['bug']['id']})")


if __name__ == "__main__":
    run_demo()

