from __future__ import annotations

import hmac
import hashlib
from typing import Any, Dict, Optional


def verify_github_signature(
    *,
    secret: str,
    body: bytes,
    signature_256: Optional[str],
) -> bool:
    if not secret:
        return False
    if not signature_256:
        return False
    if not signature_256.startswith("sha256="):
        return False

    expected = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    provided = signature_256.split("sha256=", 1)[1].strip()
    return hmac.compare_digest(expected, provided)


def get_repo_full_name(payload: Dict[str, Any]) -> Optional[str]:
    repo = payload.get("repository") or {}
    full_name = repo.get("full_name")
    if isinstance(full_name, str) and full_name:
        return full_name
    return None


def is_pull_request(issue_payload: Dict[str, Any]) -> bool:
    return bool(issue_payload.get("pull_request"))


def normalize_repo_list(raw: Optional[str]) -> list[str]:
    if not raw:
        return []
    parts: list[str] = []
    for chunk in raw.replace("\n", ",").split(","):
        item = chunk.strip()
        if not item:
            continue
        parts.append(item)
    return parts

