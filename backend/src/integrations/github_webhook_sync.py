from __future__ import annotations

import argparse
import json
from typing import Any, Dict, List, Optional

import httpx

from ..config import get_settings
from .github_webhook import normalize_repo_list


def _get_ngrok_public_url(api_url: str = "http://127.0.0.1:4040/api/tunnels") -> str:
    resp = httpx.get(api_url, timeout=5.0)
    resp.raise_for_status()
    data = resp.json()
    tunnels = data.get("tunnels") if isinstance(data, dict) else None
    if not isinstance(tunnels, list):
        raise RuntimeError("ngrok API response missing tunnels list")

    for t in tunnels:
        if not isinstance(t, dict):
            continue
        if t.get("proto") != "https":
            continue
        public_url = t.get("public_url")
        if isinstance(public_url, str) and public_url.startswith("https://"):
            return public_url

    raise RuntimeError("No https ngrok tunnel found")


def _build_webhook_url(public_url: str) -> str:
    return public_url.rstrip("/") + "/api/webhooks/github"


def _should_update_hook(current_url: str, desired_url: str) -> bool:
    if current_url.rstrip("/") == desired_url.rstrip("/"):
        return False
    if "ngrok-free.app" in current_url:
        return True
    return False


def sync_github_webhooks(
    *,
    public_url: Optional[str] = None,
    ngrok_api_url: str = "http://127.0.0.1:4040/api/tunnels",
    create_if_missing: bool = False,
    dry_run: bool = False,
) -> Dict[str, Any]:
    settings = get_settings()

    repos = normalize_repo_list(settings.github_repos or settings.repo_list)
    if not repos:
        raise RuntimeError("GITHUB_REPOS (or REPO_LIST) is not set")

    token = settings.github_token
    if not token:
        raise RuntimeError("GITHUB_TOKEN is not set")

    secret = settings.github_webhook_secret
    if not secret:
        raise RuntimeError("GITHUB_WEBHOOK_SECRET is not set")

    if not public_url:
        public_url = _get_ngrok_public_url(ngrok_api_url)

    webhook_url = _build_webhook_url(public_url)

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "scanguard-ai",
    }

    updated: List[Dict[str, Any]] = []
    created: List[Dict[str, Any]] = []
    skipped: List[Dict[str, Any]] = []

    with httpx.Client(timeout=30.0, headers=headers) as client:
        for repo in repos:
            hooks_resp = client.get(f"https://api.github.com/repos/{repo}/hooks")
            hooks_resp.raise_for_status()
            hooks = hooks_resp.json()
            if not isinstance(hooks, list):
                raise RuntimeError(f"Unexpected hooks response for {repo}")

            candidates: List[Dict[str, Any]] = []
            for hook in hooks:
                if not isinstance(hook, dict):
                    continue
                config = hook.get("config") or {}
                if not isinstance(config, dict):
                    continue
                current_url = config.get("url")
                if not isinstance(current_url, str):
                    continue
                if _should_update_hook(current_url, webhook_url):
                    candidates.append(hook)

            if not candidates and create_if_missing:
                if dry_run:
                    created.append({"repo": repo, "hook_id": None, "url": webhook_url, "dry_run": True})
                    continue

                resp = client.post(
                    f"https://api.github.com/repos/{repo}/hooks",
                    json={
                        "name": "web",
                        "active": True,
                        "events": ["issues", "issue_comment"],
                        "config": {
                            "url": webhook_url,
                            "content_type": "json",
                            "secret": secret,
                            "insecure_ssl": "0",
                        },
                    },
                )
                resp.raise_for_status()
                hook = resp.json()
                hook_id = hook.get("id") if isinstance(hook, dict) else None
                created.append({"repo": repo, "hook_id": hook_id, "url": webhook_url})
                try:
                    client.post(f"https://api.github.com/repos/{repo}/hooks/{hook_id}/pings").raise_for_status()
                except Exception:
                    pass
                continue

            if not candidates:
                skipped.append({"repo": repo, "reason": "no_ngrok_webhook_found"})
                continue

            for hook in candidates:
                hook_id = hook.get("id")
                config = hook.get("config") or {}
                current_url = config.get("url")
                if not isinstance(hook_id, int) or not isinstance(current_url, str):
                    continue

                if current_url.rstrip("/") == webhook_url.rstrip("/"):
                    skipped.append({"repo": repo, "hook_id": hook_id, "reason": "already_correct"})
                    continue

                payload = {
                    "active": True,
                    "events": hook.get("events") or ["issues", "issue_comment"],
                    "config": {
                        "url": webhook_url,
                        "content_type": (config.get("content_type") or "json"),
                        "secret": secret,
                        "insecure_ssl": (config.get("insecure_ssl") or "0"),
                    },
                }

                if dry_run:
                    updated.append({"repo": repo, "hook_id": hook_id, "old_url": current_url, "new_url": webhook_url, "dry_run": True})
                    continue

                patch_resp = client.patch(
                    f"https://api.github.com/repos/{repo}/hooks/{hook_id}",
                    json=payload,
                )
                patch_resp.raise_for_status()
                updated.append(
                    {
                        "repo": repo,
                        "hook_id": hook_id,
                        "old_url": current_url,
                        "new_url": webhook_url,
                    }
                )

                try:
                    client.post(
                        f"https://api.github.com/repos/{repo}/hooks/{hook_id}/pings"
                    ).raise_for_status()
                except Exception:
                    pass

    return {
        "ngrok_public_url": public_url,
        "webhook_url": webhook_url,
        "updated": updated,
        "created": created,
        "skipped": skipped,
    }


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Sync GitHub webhooks to the current ngrok URL (dev helper)."
    )
    parser.add_argument(
        "--public-url",
        default=None,
        help="Override ngrok public URL (otherwise uses local ngrok API).",
    )
    parser.add_argument(
        "--ngrok-api-url",
        default="http://127.0.0.1:4040/api/tunnels",
        help="ngrok local API URL (default: http://127.0.0.1:4040/api/tunnels).",
    )
    parser.add_argument(
        "--create-if-missing",
        action="store_true",
        help="Create a webhook if none exists for a repo.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print what would change without updating GitHub.",
    )
    args = parser.parse_args(argv)

    result = sync_github_webhooks(
        public_url=args.public_url,
        ngrok_api_url=args.ngrok_api_url,
        create_if_missing=args.create_if_missing,
        dry_run=args.dry_run,
    )
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

