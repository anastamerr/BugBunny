from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Optional

try:
    from pydantic_settings import BaseSettings, SettingsConfigDict
except ImportError:  # pragma: no cover
    from pydantic import BaseSettings  # type: ignore

    SettingsConfigDict = None  # type: ignore


class ScanSettings(BaseSettings):
    semgrep_docker_image: str = "returntocorp/semgrep:latest"
    zap_docker_image: str = "ghcr.io/zaproxy/zaproxy:stable"
    zap_api_key: Optional[str] = None

    default_sast_timeout_seconds: int = 900
    default_dast_timeout_seconds: int = 1800
    default_spider_minutes: int = 5
    default_active_scan_minutes: int = 20

    repo_clone_timeout_seconds: int = 300
    dast_min_spider_urls: int = 3

    if SettingsConfigDict is not None:
        _ENV_FILE = Path(__file__).resolve().parents[2] / ".env"
        model_config = SettingsConfigDict(
            env_file=str(_ENV_FILE),
            env_file_encoding="utf-8",
            env_prefix="SCANGUARD_SCAN_",
            extra="ignore",
        )
    else:  # pragma: no cover
        class Config:
            env_file = str(Path(__file__).resolve().parents[2] / ".env")
            env_file_encoding = "utf-8"
            env_prefix = "SCANGUARD_SCAN_"
            extra = "ignore"


@lru_cache
def get_scan_settings() -> ScanSettings:
    return ScanSettings()
