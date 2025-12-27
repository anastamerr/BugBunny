from __future__ import annotations

import re
from typing import List

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ...api.deps import CurrentUser, get_current_user, get_db
from ...models import UserSettings
from ...schemas.profile import ProfileRead, UserSettingsRead, UserSettingsUpdate

router = APIRouter(prefix="/profile", tags=["profile"])


@router.get("", response_model=ProfileRead)
def get_profile(
    current_user: CurrentUser = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> ProfileRead:
    settings = _get_or_default_settings(db, current_user.id)
    return ProfileRead(
        user_id=current_user.id,
        email=current_user.email,
        settings=settings,
    )


@router.patch("", response_model=ProfileRead)
def update_profile(
    payload: UserSettingsUpdate,
    current_user: CurrentUser = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> ProfileRead:
    settings = db.query(UserSettings).filter(UserSettings.user_id == current_user.id).first()
    if settings is None:
        settings = UserSettings(user_id=current_user.id)
        db.add(settings)
        db.commit()
        db.refresh(settings)

    updates = payload.model_dump(exclude_unset=True)
    if "github_allowlist" in updates and updates["github_allowlist"] is not None:
        updates["github_allowlist"] = _normalize_allowlist(updates["github_allowlist"])

    for key, value in updates.items():
        if key in {"github_token", "github_webhook_secret"}:
            if value is None:
                continue
            if isinstance(value, str) and value.strip() == "":
                setattr(settings, key, None)
                continue
        setattr(settings, key, value)

    db.add(settings)
    db.commit()
    db.refresh(settings)

    return ProfileRead(
        user_id=current_user.id,
        email=current_user.email,
        settings=_to_settings_read(settings),
    )


def _get_or_default_settings(db: Session, user_id) -> UserSettingsRead:
    settings = db.query(UserSettings).filter(UserSettings.user_id == user_id).first()
    if settings is None:
        return UserSettingsRead(
            github_token_set=False,
            github_webhook_secret_set=False,
            github_allowlist=[],
            enable_scan_push=True,
            enable_scan_pr=True,
            enable_issue_ingest=True,
            enable_issue_comment_ingest=True,
        )
    return _to_settings_read(settings)


def _to_settings_read(settings: UserSettings) -> UserSettingsRead:
    return UserSettingsRead(
        github_token_set=bool(settings.github_token),
        github_webhook_secret_set=bool(settings.github_webhook_secret),
        github_allowlist=settings.github_allowlist or [],
        enable_scan_push=settings.enable_scan_push,
        enable_scan_pr=settings.enable_scan_pr,
        enable_issue_ingest=settings.enable_issue_ingest,
        enable_issue_comment_ingest=settings.enable_issue_comment_ingest,
    )


def _normalize_allowlist(values: List[str]) -> List[str]:
    normalized: list[str] = []
    for raw in values:
        if raw is None:
            continue
        for chunk in re.split(r"[,\n]", str(raw)):
            item = chunk.strip().strip("/")
            if not item:
                continue
            if item.endswith(".git"):
                item = item[:-4]
            normalized.append(item.lower())
    return sorted(set(normalized))
