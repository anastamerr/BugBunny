from __future__ import annotations

from typing import Dict

from ..config import get_settings
from ..db.session import SessionLocal
from .github_client import GitHubClient
from .github_ingestor import GitHubIngestor
from .github_webhook import normalize_repo_list


def backfill_github_issues() -> Dict[str, int]:
    settings = get_settings()
    repos = normalize_repo_list(settings.github_repos or settings.repo_list)
    if not repos:
        raise RuntimeError("GITHUB_REPOS (or REPO_LIST) is not set")

    token = settings.github_token
    if not token:
        raise RuntimeError("GITHUB_TOKEN is not set")

    client = GitHubClient(token=token)
    ingestor = GitHubIngestor()
    session = SessionLocal()
    created = 0
    updated = 0
    try:
        for repo in repos:
            for issue in client.iter_issues(repo, limit=settings.github_backfill_limit):
                _bug, was_created = ingestor.upsert_issue(
                    session,
                    repo_full_name=repo,
                    issue=issue,
                    action=None,
                )
                if was_created:
                    created += 1
                else:
                    updated += 1
    finally:
        session.close()
        client.close()

    return {"created": created, "updated": updated}


if __name__ == "__main__":
    result = backfill_github_issues()
    print(result)
