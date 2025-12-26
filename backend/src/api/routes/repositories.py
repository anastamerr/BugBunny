from __future__ import annotations

import re
import uuid
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ...api.deps import CurrentUser, get_current_user, get_db
from ...models import Repository
from ...schemas.repository import RepositoryCreate, RepositoryRead

router = APIRouter(prefix="/repos", tags=["repos"])


@router.get("", response_model=List[RepositoryRead])
def list_repositories(
    current_user: CurrentUser = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> List[Repository]:
    return (
        db.query(Repository)
        .filter(Repository.user_id == current_user.id)
        .order_by(Repository.created_at.desc())
        .all()
    )


@router.post("", response_model=RepositoryRead, status_code=status.HTTP_201_CREATED)
def create_repository(
    payload: RepositoryCreate,
    current_user: CurrentUser = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Repository:
    repo_url = _normalize_repo_url(payload.repo_url)
    if not repo_url:
        raise HTTPException(status_code=400, detail="Repository URL is required")

    default_branch = (payload.default_branch or "main").strip() or "main"
    repo = Repository(
        user_id=current_user.id,
        repo_url=repo_url,
        repo_full_name=_extract_repo_full_name(repo_url),
        default_branch=default_branch,
    )

    db.add(repo)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(
            status_code=409,
            detail="Repository already exists",
        ) from exc

    db.refresh(repo)
    return repo


@router.delete(
    "/{repo_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_model=None,
)
def delete_repository(
    repo_id: str,
    current_user: CurrentUser = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> None:
    repo_uuid = _parse_uuid(repo_id, "Repository not found")
    repo = (
        db.query(Repository)
        .filter(Repository.id == repo_uuid, Repository.user_id == current_user.id)
        .first()
    )
    if not repo:
        raise HTTPException(status_code=404, detail="Repository not found")

    db.delete(repo)
    db.commit()


def _normalize_repo_url(value: str) -> str:
    if not value:
        return ""
    trimmed = value.strip().rstrip("/")
    return trimmed[:-4] if trimmed.endswith(".git") else trimmed


def _extract_repo_full_name(value: str) -> Optional[str]:
    if not value:
        return None

    # HTTPS URLs (https://github.com/owner/repo)
    if value.startswith("http://") or value.startswith("https://"):
        try:
            _, path = value.split("://", 1)
            parts = path.split("/", 1)
            if len(parts) == 2:
                path_part = parts[1].strip("/")
                segments = [s for s in path_part.split("/") if s]
                if len(segments) >= 2:
                    return f"{segments[0]}/{segments[1]}"
        except ValueError:
            return None

    # SSH URLs (git@github.com:owner/repo)
    match = re.search(r":(?P<owner>[^/]+)/(?P<repo>[^/]+)$", value)
    if match:
        owner = match.group("owner")
        repo = match.group("repo")
        if owner and repo:
            return f"{owner}/{repo}"

    return None


def _parse_uuid(value: str, message: str) -> uuid.UUID:
    try:
        return uuid.UUID(value)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=message) from exc
