from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Iterator, Optional

import httpx


class GitHubClient:
    def __init__(
        self,
        *,
        token: str,
        api_base: str = "https://api.github.com",
    ):
        if not token:
            raise ValueError("GitHub token is required")
        self.api_base = api_base.rstrip("/")
        self._client = httpx.Client(
            base_url=self.api_base,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "User-Agent": "scanguard-ai",
            },
            timeout=30.0,
        )

    def close(self) -> None:
        self._client.close()

    def iter_issues(
        self,
        repo_full_name: str,
        *,
        state: str = "all",
        per_page: int = 100,
        limit: int = 50,
    ) -> Iterator[Dict[str, Any]]:
        owner, repo = repo_full_name.split("/", 1)
        page = 1
        yielded = 0
        while yielded < limit:
            resp = self._client.get(
                f"/repos/{owner}/{repo}/issues",
                params={
                    "state": state,
                    "sort": "created",
                    "direction": "desc",
                    "per_page": per_page,
                    "page": page,
                },
            )
            resp.raise_for_status()
            items = resp.json()
            if not isinstance(items, list) or not items:
                break

            for item in items:
                if not isinstance(item, dict):
                    continue
                if item.get("pull_request"):
                    continue
                yield item
                yielded += 1
                if yielded >= limit:
                    return

            page += 1


def parse_github_timestamp(value: Optional[str]):
    if not value:
        return None
    # GitHub returns ISO 8601 timestamps, e.g. "2025-01-01T12:34:56Z"
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception:
        return None
