from __future__ import annotations

import asyncio
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import List
from urllib.parse import urlparse

from ...config import get_settings


class RepoFetcher:
    def __init__(self, git_path: str = "git") -> None:
        self.git_path = git_path
        self.settings = get_settings()

    async def clone(
        self,
        repo_url: str,
        branch: str = "main",
        github_token: str | None = None,
    ) -> tuple[Path, str]:
        target_dir = Path(tempfile.mkdtemp(prefix="scanguard-"))
        auth_url = self._apply_github_token(repo_url, github_token)
        cmd = [
            self.git_path,
            "clone",
            "--depth",
            "1",
            "--branch",
            branch,
            auth_url,
            str(target_dir),
        ]

        try:
            await asyncio.to_thread(self._run_command, cmd, repo_url, github_token)
            return target_dir, branch
        except RuntimeError as exc:
            if branch and self._is_branch_missing_error(str(exc)):
                default_branch = await asyncio.to_thread(
                    self._get_default_branch, auth_url
                )
                if default_branch and default_branch != branch:
                    shutil.rmtree(target_dir, ignore_errors=True)
                    target_dir = Path(tempfile.mkdtemp(prefix="scanguard-"))
                    cmd = [
                        self.git_path,
                        "clone",
                        "--depth",
                        "1",
                        "--branch",
                        default_branch,
                        auth_url,
                        str(target_dir),
                    ]
                    await asyncio.to_thread(
                        self._run_command, cmd, repo_url, github_token
                    )
                    return target_dir, default_branch
            shutil.rmtree(target_dir, ignore_errors=True)
            raise
        except Exception:
            shutil.rmtree(target_dir, ignore_errors=True)
            raise

    async def cleanup(self, repo_path: Path) -> None:
        await asyncio.to_thread(shutil.rmtree, repo_path, True)

    def detect_languages(self, repo_path: Path) -> List[str]:
        languages, _ = self.analyze_repo(repo_path)
        return languages

    def analyze_repo(self, repo_path: Path) -> tuple[List[str], int]:
        languages: set[str] = set()
        file_count = 0
        extension_map = {
            ".py": "python",
            ".js": "javascript",
            ".jsx": "javascript",
            ".ts": "javascript",
            ".tsx": "javascript",
            ".go": "go",
            ".java": "java",
        }

        for path in repo_path.rglob("*"):
            if not path.is_file():
                continue
            if self._should_skip(path):
                continue

            file_count += 1
            language = extension_map.get(path.suffix.lower())
            if language:
                languages.add(language)

        return sorted(languages), file_count

    def _apply_github_token(self, repo_url: str, github_token: str | None) -> str:
        token = github_token or self.settings.github_token
        if not token:
            return repo_url

        parsed = urlparse(repo_url)
        if parsed.scheme not in {"http", "https"}:
            return repo_url
        if "github.com" not in parsed.netloc:
            return repo_url

        auth_netloc = f"{token}@{parsed.netloc}"
        return parsed._replace(netloc=auth_netloc).geturl()

    def _run_command(
        self, cmd: List[str], repo_url: str, github_token: str | None
    ) -> None:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            message = (result.stderr or result.stdout or "").strip()
            token = github_token or self.settings.github_token or ""
            if token:
                message = message.replace(token, "***")
            detail = message or "Unknown git error"
            raise RuntimeError(f"Failed to clone repo {repo_url}: {detail}")

    def _should_skip(self, path: Path) -> bool:
        skip_dirs = {
            ".git",
            "node_modules",
            "dist",
            "build",
            "vendor",
            ".venv",
            "__pycache__",
        }
        return any(part in skip_dirs for part in path.parts)

    def _get_default_branch(self, repo_url: str) -> str | None:
        cmd = [self.git_path, "ls-remote", "--symref", repo_url, "HEAD"]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            return None

        for line in result.stdout.splitlines():
            if line.startswith("ref:"):
                parts = line.split()
                if len(parts) >= 2 and parts[1].startswith("refs/heads/"):
                    return parts[1].split("/", 2)[-1]
        return None

    def _is_branch_missing_error(self, message: str) -> bool:
        lowered = message.lower()
        return "remote branch" in lowered or "couldn't find remote ref" in lowered
