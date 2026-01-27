from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Optional
from urllib.parse import quote, urlparse, urlunparse


class RepoFetchError(RuntimeError):
    pass


def _inject_token(repo_url: str, token: Optional[str]) -> str:
    if not token:
        return repo_url
    parsed = urlparse(repo_url)
    if parsed.scheme not in {"http", "https"}:
        return repo_url
    if parsed.username or parsed.password:
        return repo_url
    safe_token = quote(token, safe="")
    netloc = f"{safe_token}@{parsed.netloc}"
    return urlunparse(
        (parsed.scheme, netloc, parsed.path, parsed.params, parsed.query, parsed.fragment)
    )


def clone_repo(
    repo_url: str,
    branch: str,
    github_token: Optional[str],
    timeout_seconds: int,
) -> Path:
    if shutil.which("git") is None:
        raise RepoFetchError("git is not installed or not in PATH")

    target_dir = Path(tempfile.mkdtemp(prefix="scanguard_repo_"))
    url = _inject_token(repo_url, github_token)
    cmd = [
        "git",
        "clone",
        "--depth",
        "1",
        "--branch",
        branch,
        url,
        str(target_dir),
    ]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as exc:
        raise RepoFetchError(f"git clone timed out after {timeout_seconds}s") from exc

    if result.returncode != 0:
        stderr = (result.stderr or result.stdout or "").strip()
        raise RepoFetchError(f"git clone failed: {stderr or 'unknown error'}")

    return target_dir


def cleanup_repo(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path, ignore_errors=True)
