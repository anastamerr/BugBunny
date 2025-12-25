from __future__ import annotations

from datetime import datetime, timedelta
from functools import lru_cache
from typing import Any, Dict, Optional

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
from ...models import Scan
from ...realtime import sio
from ...schemas.bug import BugReportRead
from ...schemas.scan import ScanRead
from ...services.scanner import run_scan_pipeline

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

    if event == "push":
        repo_url = _get_repo_url(payload)
        branch = _get_branch_from_ref(payload.get("ref"))
        commit_sha = payload.get("after")
        commit_url = _build_commit_url(repo_url, commit_sha)

        if not repo_full_name:
            return {"ok": True, "ignored": True, "reason": "missing_repo"}
        if not repo_url:
            return {"ok": True, "ignored": True, "reason": "missing_repo_url"}
        if _is_rate_limited(db, repo_url):
            return {"ok": True, "ignored": True, "reason": "rate_limited"}

        scan = _create_scan(
            db,
            repo_url=repo_url,
            branch=branch,
            trigger="webhook",
            commit_sha=_safe_str(commit_sha),
            commit_url=_safe_str(commit_url),
        )
        background_tasks.add_task(run_scan_pipeline, scan.id, scan.repo_url, scan.branch)
        background_tasks.add_task(
            sio.emit,
            "scan.created",
            ScanRead.model_validate(scan).model_dump(mode="json"),
        )
        return {"ok": True, "scan_id": str(scan.id)}

    if event == "pull_request":
        action = payload.get("action")
        if action not in {"opened", "synchronize"}:
            return {"ok": True, "ignored": True, "reason": "action_not_supported"}

        pull_request = payload.get("pull_request") or {}
        repo_url = _get_repo_url(payload) or _get_pr_repo_url(pull_request)
        branch = _get_branch_from_pr(pull_request)
        pr_number = pull_request.get("number")
        pr_url = pull_request.get("html_url")
        head = pull_request.get("head") or {}
        commit_sha = head.get("sha")
        commit_url = _build_commit_url(repo_url, commit_sha)

        if not repo_full_name:
            return {"ok": True, "ignored": True, "reason": "missing_repo"}
        if not repo_url:
            return {"ok": True, "ignored": True, "reason": "missing_repo_url"}
        if _is_rate_limited(db, repo_url):
            return {"ok": True, "ignored": True, "reason": "rate_limited"}

        scan = _create_scan(
            db,
            repo_url=repo_url,
            branch=branch,
            trigger="webhook",
            pr_number=_safe_int(pr_number),
            pr_url=_safe_str(pr_url),
            commit_sha=_safe_str(commit_sha),
            commit_url=_safe_str(commit_url),
        )
        background_tasks.add_task(run_scan_pipeline, scan.id, scan.repo_url, scan.branch)
        background_tasks.add_task(
            sio.emit,
            "scan.created",
            ScanRead.model_validate(scan).model_dump(mode="json"),
        )
        return {"ok": True, "scan_id": str(scan.id)}

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
        bug, created = ingestor.upsert_issue(
            db,
            repo_full_name=repo_full_name,
            issue=issue,
            action=action,
        )

        bug_event = BugReportRead.model_validate(bug).model_dump(mode="json")
        background_tasks.add_task(
            sio.emit,
            "bug.created" if created else "bug.updated",
            bug_event,
        )
        return {"ok": True}

    if event == "issue_comment":
        action = payload.get("action")
        issue = payload.get("issue") or {}
        comment = payload.get("comment") or {}
        if not isinstance(issue, dict) or not isinstance(comment, dict):
            return {"ok": True}
        if is_pull_request(issue):
            return {"ok": True, "ignored": True, "reason": "pull_request"}
        if not repo_full_name:
            return {"ok": True, "ignored": True, "reason": "missing_repo"}

        ingestor = get_ingestor()
        bug, created = ingestor.upsert_issue_comment(
            db,
            repo_full_name=repo_full_name,
            issue=issue,
            comment=comment,
            action=action,
        )

        bug_event = BugReportRead.model_validate(bug).model_dump(mode="json")
        background_tasks.add_task(
            sio.emit,
            "bug.created" if created else "bug.updated",
            bug_event,
        )
        return {"ok": True}

    return {"ok": True, "ignored": True, "event": event}


def _create_scan(
    db: Session,
    repo_url: str,
    branch: str,
    trigger: str,
    pr_number: Optional[int] = None,
    pr_url: Optional[str] = None,
    commit_sha: Optional[str] = None,
    commit_url: Optional[str] = None,
) -> Scan:
    scan = Scan(
        repo_url=repo_url,
        branch=branch,
        status="pending",
        trigger=trigger,
        total_findings=0,
        filtered_findings=0,
        pr_number=pr_number,
        pr_url=pr_url,
        commit_sha=commit_sha,
        commit_url=commit_url,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


def _is_rate_limited(db: Session, repo_url: str) -> bool:
    cutoff = datetime.utcnow() - timedelta(seconds=60)
    recent = (
        db.query(Scan)
        .filter(Scan.repo_url == repo_url, Scan.created_at >= cutoff)
        .order_by(Scan.created_at.desc())
        .first()
    )
    return recent is not None


def _get_repo_url(payload: Dict[str, Any]) -> Optional[str]:
    repo = payload.get("repository")
    if isinstance(repo, dict):
        url = repo.get("html_url")
        if isinstance(url, str):
            return url
    return None


def _get_pr_repo_url(pull_request: Dict[str, Any]) -> Optional[str]:
    base = pull_request.get("base")
    if isinstance(base, dict):
        repo = base.get("repo")
        if isinstance(repo, dict):
            url = repo.get("html_url")
            if isinstance(url, str):
                return url
    return None


def _get_branch_from_ref(ref: Optional[str]) -> str:
    if not ref:
        return "main"
    if ref.startswith("refs/heads/"):
        return ref.replace("refs/heads/", "") or "main"
    return ref


def _get_branch_from_pr(pull_request: Dict[str, Any]) -> str:
    head = pull_request.get("head")
    if isinstance(head, dict):
        ref = head.get("ref")
        if isinstance(ref, str) and ref:
            return ref
    return "main"


def _build_commit_url(repo_url: Optional[str], commit_sha: Any) -> Optional[str]:
    repo = _safe_str(repo_url)
    sha = _safe_str(commit_sha)
    if not repo or not sha:
        return None
    return f"{repo}/commit/{sha}"


def _safe_str(value: Any) -> Optional[str]:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _safe_int(value: Any) -> Optional[int]:
    try:
        if value is None:
            return None
        return int(value)
    except (TypeError, ValueError):
        return None
