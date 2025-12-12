from __future__ import annotations

from functools import lru_cache
from typing import Any, Dict

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from ...api.deps import get_db
from ...config import get_settings
from ...integrations.github_ingestor import GitHubIngestor
from ...integrations.github_webhook import (
    get_repo_full_name,
    is_pull_request,
    normalize_repo_list,
    verify_github_signature,
)
from ...realtime import sio
from ...schemas.bug import BugReportRead
from ...schemas.correlation import CorrelationRead

router = APIRouter(prefix="/webhooks", tags=["webhooks"])


@lru_cache
def get_ingestor() -> GitHubIngestor:
    return GitHubIngestor()


@router.post("/github")
async def github_webhook(
    request: Request,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    settings = get_settings()
    secret = settings.github_webhook_secret or ""
    if not secret:
        raise HTTPException(status_code=500, detail="GITHUB_WEBHOOK_SECRET is not set")

    body = await request.body()
    signature = request.headers.get("X-Hub-Signature-256")
    if not verify_github_signature(secret=secret, body=body, signature_256=signature):
        raise HTTPException(status_code=401, detail="Invalid signature")

    event = (request.headers.get("X-GitHub-Event") or "").lower()
    payload = await request.json()

    if event == "ping":
        return {"ok": True, "event": "ping"}

    repo_full_name = get_repo_full_name(payload)
    allowed = normalize_repo_list(settings.github_repos or settings.repo_list)
    if repo_full_name and allowed:
        allowed_norm = {r.lower() for r in allowed}
        if repo_full_name.lower() not in allowed_norm:
            return {"ok": True, "ignored": True, "reason": "repo_not_allowed"}

    if event == "issues":
        action = payload.get("action")
        issue = payload.get("issue") or {}
        if not isinstance(issue, dict):
            return {"ok": True}
        if is_pull_request(issue):
            return {"ok": True, "ignored": True, "reason": "pull_request"}
        if not repo_full_name:
            return {"ok": True, "ignored": True, "reason": "missing_repo"}

        ingestor = get_ingestor()
        bug, created, corr, _incident = ingestor.upsert_issue(
            db,
            repo_full_name=repo_full_name,
            issue=issue,
            action=action,
            auto_correlate=True,
        )

        bug_event = BugReportRead.model_validate(bug).model_dump(mode="json")
        background_tasks.add_task(
            sio.emit,
            "bug.created" if created else "bug.updated",
            bug_event,
        )
        if corr is not None:
            corr_event = CorrelationRead.model_validate(corr).model_dump(mode="json")
            background_tasks.add_task(sio.emit, "correlation.created", corr_event)

        return {"ok": True}

    return {"ok": True, "ignored": True, "event": event}
