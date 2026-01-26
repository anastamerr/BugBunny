from __future__ import annotations

import asyncio
import subprocess
from pathlib import Path
from typing import Optional

from ...config import get_settings
from ...schemas.scan import _normalize_target_url


class DeploymentService:
    def __init__(self, deploy_script: Optional[str] = None) -> None:
        self.settings = get_settings()
        self.deploy_script = deploy_script or self.settings.dast_deploy_script
        self.last_error: str | None = None

    def is_configured(self) -> bool:
        return bool(self.deploy_script)

    async def deploy(self, repo_path: Path, commit_sha: str, branch: str) -> str:
        self.last_error = None
        if not self.deploy_script:
            raise RuntimeError("DAST deploy script is not configured.")
        if not commit_sha:
            raise RuntimeError("Commit SHA is required for deployment.")
        if not repo_path.exists():
            raise RuntimeError("Repository path does not exist for deployment.")

        cmd = [self.deploy_script, str(repo_path), commit_sha, branch]
        try:
            result = await asyncio.to_thread(
                subprocess.run,
                cmd,
                capture_output=True,
                text=True,
                check=False,
            )
        except Exception as exc:
            self.last_error = f"Deployment script failed to run: {exc}"
            raise RuntimeError(self.last_error) from exc

        if result.returncode != 0:
            output = (result.stderr or result.stdout or "").strip()
            self.last_error = output or "Deployment script exited with an error."
            raise RuntimeError(self.last_error)

        target_url = (result.stdout or "").strip().splitlines()
        if not target_url:
            self.last_error = "Deployment script did not return a target URL."
            raise RuntimeError(self.last_error)

        return _validate_target_url(target_url[0].strip())


def _validate_target_url(value: str) -> str:
    try:
        return _normalize_target_url(value)
    except ValueError as exc:
        raise RuntimeError(str(exc)) from exc
