from __future__ import annotations

from datetime import datetime
import re
from typing import Any, Dict, Iterator, Optional, Tuple

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

    def create_pull_request(
        self,
        repo_full_name: str,
        *,
        title: str,
        body: str,
        head: str,
        base: str,
    ) -> Tuple[str, Optional[int]]:
        owner, repo = repo_full_name.split("/", 1)
        resp = self._client.post(
            f"/repos/{owner}/{repo}/pulls",
            json={
                "title": title,
                "body": body,
                "head": head,
                "base": base,
            },
        )
        resp.raise_for_status()
        payload = resp.json()
        html_url = payload.get("html_url")
        if not isinstance(html_url, str) or not html_url.strip():
            raise RuntimeError("GitHub did not return a PR URL.")
        pr_number = payload.get("number")
        if not isinstance(pr_number, int):
            pr_number = None
            match = re.search(r"/pull/(\d+)", html_url)
            if match:
                try:
                    pr_number = int(match.group(1))
                except ValueError:
                    pr_number = None
        return html_url.strip(), pr_number

    def create_issue_comment(
        self,
        repo_full_name: str,
        *,
        issue_number: int,
        body: str,
    ) -> str:
        owner, repo = repo_full_name.split("/", 1)
        resp = self._client.post(
            f"/repos/{owner}/{repo}/issues/{issue_number}/comments",
            json={"body": body},
        )
        resp.raise_for_status()
        payload = resp.json()
        html_url = payload.get("html_url")
        if not isinstance(html_url, str) or not html_url.strip():
            raise RuntimeError("GitHub did not return a comment URL.")
        return html_url.strip()


def parse_github_timestamp(value: Optional[str]):
    if not value:
        return None
    # GitHub returns ISO 8601 timestamps, e.g. "2025-01-01T12:34:56Z"
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception:
        return None
