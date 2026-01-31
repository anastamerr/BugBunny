from __future__ import annotations

from collections.abc import Generator
from dataclasses import dataclass
from typing import Optional
import uuid

import jwt
from fastapi import Header, HTTPException, status

from sqlalchemy.orm import Session

from ..config import get_settings
from ..db.session import SessionLocal


@dataclass(frozen=True)
class CurrentUser:
    id: uuid.UUID
    email: Optional[str] = None
    role: Optional[str] = None


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_current_user(
    authorization: Optional[str] = Header(default=None),
) -> CurrentUser:
    settings = get_settings()
    if settings.dev_auth_bypass:
        fallback_id = "00000000-0000-0000-0000-000000000000"
        raw_id = settings.dev_auth_user_id or fallback_id
        try:
            user_id = uuid.UUID(raw_id)
        except ValueError:
            user_id = uuid.UUID(fallback_id)
        return CurrentUser(
            id=user_id,
            email=settings.dev_auth_email or "dev@local",
            role="developer",
        )
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authorization header",
        )
    if not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authorization header",
        )

    token = authorization.split(" ", 1)[1].strip()
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing bearer token",
        )

    if not settings.supabase_jwt_secret:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="SUPABASE_JWT_SECRET is not configured",
        )

    decode_kwargs = {
        "key": settings.supabase_jwt_secret,
        "algorithms": ["HS256"],
        "options": {"verify_aud": False},
    }
    if settings.supabase_jwt_issuer:
        decode_kwargs["issuer"] = settings.supabase_jwt_issuer

    try:
        payload = jwt.decode(token, **decode_kwargs)
    except jwt.PyJWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        ) from exc

    subject = payload.get("sub") or payload.get("user_id")
    if not isinstance(subject, str) or not subject:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token is missing subject",
        )

    try:
        user_id = uuid.UUID(subject)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token subject is invalid",
        ) from exc

    email = payload.get("email")
    role = payload.get("role")
    return CurrentUser(id=user_id, email=email, role=role)
