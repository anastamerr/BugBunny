from __future__ import annotations

from datetime import datetime, timedelta
from functools import lru_cache
import json
from typing import Any, Dict, Optional
import uuid

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request
from sqlalchemy import or_
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
from ...models import Repository, Scan, UserSettings
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
    body = await request.body()
    signature = request.headers.get("X-Hub-Signature-256")
    event = (request.headers.get("X-GitHub-Event") or "").lower()

    try:
        payload = json.loads(body.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail="Invalid payload") from exc

    if event == "ping":
        return {"ok": True, "event": "ping"}

    repo_full_name = get_repo_full_name(payload)
    allowed = normalize_repo_list(settings.github_repos or settings.repo_list)
    if repo_full_name and allowed:
        allowed_norm = {r.lower() for r in allowed}
        if repo_full_name.lower() not in allowed_norm:
            return {"ok": True, "ignored": True, "reason": "repo_not_allowed"}

    repo_url_hint = _get_repo_url(payload)
    watched_repos = _find_watched_repos(
        db,
        repo_url=repo_url_hint,
        repo_full_name=repo_full_name,
    )
    if not watched_repos:
        return {"ok": True, "ignored": True, "reason": "repo_not_registered"}

    user_settings = _get_user_settings_map(db, watched_repos)
    if not _has_webhook_secret(
        global_secret=settings.github_webhook_secret,
        user_settings=user_settings,
    ):
        raise HTTPException(
            status_code=500, detail="Webhook secret is not configured"
        )
    if not _verify_signature_any(
        body=body,
        signature=signature,
        global_secret=settings.github_webhook_secret,
        user_settings=user_settings,
    ):
        raise HTTPException(status_code=401, detail="Invalid signature")

    eligible_repos = _filter_repos_for_event(event, watched_repos, user_settings)
    if not eligible_repos:
        return {"ok": True, "ignored": True, "reason": "repo_not_allowed"}

    if event == "push":
        repo_url = repo_url_hint
        branch = _get_branch_from_ref(payload.get("ref"))
        commit_sha = payload.get("after")
        commit_url = _build_commit_url(repo_url, commit_sha)

        if not repo_url:
            return {"ok": True, "ignored": True, "reason": "missing_repo_url"}
        scan_ids: list[str] = []
        for repo in eligible_repos:
            if _is_rate_limited(db, repo.repo_url, repo.user_id):
                continue
            scan = _create_scan(
                db,
                repo_url=repo.repo_url,
                branch=branch,
                trigger="webhook",
                user_id=repo.user_id,
                repo_id=repo.id,
                commit_sha=_safe_str(commit_sha),
                commit_url=_safe_str(commit_url),
            )
            scan_ids.append(str(scan.id))
            background_tasks.add_task(
                run_scan_pipeline,
                scan.id,
                scan.repo_url,
                scan.branch,
                scan.scan_type,
                scan.target_url,
            )
            background_tasks.add_task(
                sio.emit,
                "scan.created",
                ScanRead.model_validate(scan).model_dump(mode="json"),
            )
        return {"ok": True, "scan_ids": scan_ids}

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

        if not repo_url:
            return {"ok": True, "ignored": True, "reason": "missing_repo_url"}
        scan_ids: list[str] = []
        for repo in eligible_repos:
            if _is_rate_limited(db, repo.repo_url, repo.user_id):
                continue
            scan = _create_scan(
                db,
                repo_url=repo.repo_url,
                branch=branch,
                trigger="webhook",
                user_id=repo.user_id,
                repo_id=repo.id,
                pr_number=_safe_int(pr_number),
                pr_url=_safe_str(pr_url),
                commit_sha=_safe_str(commit_sha),
                commit_url=_safe_str(commit_url),
            )
            scan_ids.append(str(scan.id))
            background_tasks.add_task(
                run_scan_pipeline,
                scan.id,
                scan.repo_url,
                scan.branch,
                scan.scan_type,
                scan.target_url,
            )
            background_tasks.add_task(
                sio.emit,
                "scan.created",
                ScanRead.model_validate(scan).model_dump(mode="json"),
            )
        return {"ok": True, "scan_ids": scan_ids}

    if event == "issues":
        action = payload.get("action")
        issue = payload.get("issue") or {}
        if not isinstance(issue, dict):
            return {"ok": True}
        if is_pull_request(issue):
            return {"ok": True, "ignored": True, "reason": "pull_request"}
        if not repo_full_name:
            return {"ok": True, "ignored": True, "reason": "missing_repo"}
        if not eligible_repos:
            return {"ok": True, "ignored": True, "reason": "repo_not_allowed"}

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
        if not eligible_repos:
            return {"ok": True, "ignored": True, "reason": "repo_not_allowed"}

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
    user_id: uuid.UUID,
    repo_id: Optional[uuid.UUID] = None,
    pr_number: Optional[int] = None,
    pr_url: Optional[str] = None,
    commit_sha: Optional[str] = None,
    commit_url: Optional[str] = None,
) -> Scan:
    scan = Scan(
        user_id=user_id,
        repo_id=repo_id,
        repo_url=repo_url,
        branch=branch,
        scan_type="sast",
        target_url=None,
        status="pending",
        trigger=trigger,
        total_findings=0,
        filtered_findings=0,
        dast_findings=0,
        pr_number=pr_number,
        pr_url=pr_url,
        commit_sha=commit_sha,
        commit_url=commit_url,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


def _is_rate_limited(db: Session, repo_url: str, user_id: uuid.UUID) -> bool:
    cutoff = datetime.utcnow() - timedelta(seconds=60)
    recent = (
        db.query(Scan)
        .filter(
            Scan.repo_url == repo_url,
            Scan.user_id == user_id,
            Scan.created_at >= cutoff,
        )
        .order_by(Scan.created_at.desc())
        .first()
    )
    return recent is not None


def _get_user_settings_map(
    db: Session, repos: list[Repository]
) -> dict[uuid.UUID, UserSettings]:
    user_ids = {repo.user_id for repo in repos if repo.user_id}
    if not user_ids:
        return {}
    rows = (
        db.query(UserSettings).filter(UserSettings.user_id.in_(user_ids)).all()
    )
    return {row.user_id: row for row in rows}


def _verify_signature_any(
    *,
    body: bytes,
    signature: Optional[str],
    global_secret: Optional[str],
    user_settings: dict[uuid.UUID, UserSettings],
) -> bool:
    secrets: list[str] = []
    if global_secret:
        secrets.append(global_secret)
    for settings in user_settings.values():
        if settings.github_webhook_secret:
            secrets.append(settings.github_webhook_secret)

    if not secrets:
        return False

    for secret in secrets:
        if verify_github_signature(
            secret=secret,
            body=body,
            signature_256=signature,
        ):
            return True
    return False


def _has_webhook_secret(
    *,
    global_secret: Optional[str],
    user_settings: dict[uuid.UUID, UserSettings],
) -> bool:
    if global_secret:
        return True
    for settings in user_settings.values():
        if settings.github_webhook_secret:
            return True
    return False


def _filter_repos_for_event(
    event: str,
    repos: list[Repository],
    settings_map: dict[uuid.UUID, UserSettings],
) -> list[Repository]:
    filtered: list[Repository] = []
    for repo in repos:
        settings = settings_map.get(repo.user_id)
        if not _is_repo_allowed(repo, settings):
            continue
        if event == "push" and settings is not None and not settings.enable_scan_push:
            continue
        if (
            event == "pull_request"
            and settings is not None
            and not settings.enable_scan_pr
        ):
            continue
        if event == "issues" and settings is not None and not settings.enable_issue_ingest:
            continue
        if (
            event == "issue_comment"
            and settings is not None
            and not settings.enable_issue_comment_ingest
        ):
            continue
        filtered.append(repo)
    return filtered


def _is_repo_allowed(
    repo: Repository,
    settings: Optional[UserSettings],
) -> bool:
    allowlist = settings.github_allowlist if settings else None
    if not allowlist:
        return True
    normalized_allowlist = {str(item).lower() for item in allowlist if item}
    if not normalized_allowlist:
        return True

    repo_url = _normalize_repo_url(repo.repo_url)
    repo_url_norm = repo_url.lower() if repo_url else ""
    repo_name = (repo.repo_full_name or "").lower()
    return repo_url_norm in normalized_allowlist or repo_name in normalized_allowlist


def _find_watched_repos(
    db: Session,
    repo_url: Optional[str],
    repo_full_name: Optional[str],
) -> list[Repository]:
    q = db.query(Repository)
    filters = []
    if repo_url:
        filters.append(Repository.repo_url == repo_url)
    if repo_full_name:
        filters.append(Repository.repo_full_name == repo_full_name)
    if not filters:
        return []
    return q.filter(or_(*filters)).all()


def _get_repo_url(payload: Dict[str, Any]) -> Optional[str]:
    repo = payload.get("repository")
    if isinstance(repo, dict):
        url = repo.get("html_url")
        if isinstance(url, str):
            return _normalize_repo_url(url)
    return None


def _get_pr_repo_url(pull_request: Dict[str, Any]) -> Optional[str]:
    base = pull_request.get("base")
    if isinstance(base, dict):
        repo = base.get("repo")
        if isinstance(repo, dict):
            url = repo.get("html_url")
            if isinstance(url, str):
                return _normalize_repo_url(url)
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


def _normalize_repo_url(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    trimmed = value.strip().rstrip("/")
    if trimmed.endswith(".git"):
        trimmed = trimmed[:-4]
    return trimmed


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
