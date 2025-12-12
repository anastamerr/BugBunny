from __future__ import annotations

from functools import lru_cache
from typing import Optional

try:
    from pydantic_settings import BaseSettings, SettingsConfigDict
except ImportError:  # pragma: no cover
    from pydantic import BaseSettings  # type: ignore

    SettingsConfigDict = None  # type: ignore


class Settings(BaseSettings):
    database_url: str = "postgresql://postgres:postgres@db:5432/databug"
    redis_url: str = "redis://redis:6379/0"
    pinecone_api_key: Optional[str] = None
    pinecone_environment: Optional[str] = None
    ollama_host: str = "http://ollama:11434"
    api_prefix: str = "/api"

    github_token: Optional[str] = None
    github_webhook_secret: Optional[str] = None
    github_repos: Optional[str] = None  # comma-separated owner/repo list
    repo_list: Optional[str] = None  # legacy alias for github_repos
    github_backfill_limit: int = 50
    github_backfill_on_start: bool = False

    if SettingsConfigDict is not None:
        model_config = SettingsConfigDict(
            env_file=".env",
            env_file_encoding="utf-8",
            extra="ignore",
        )
    else:  # pragma: no cover
        class Config:
            env_file = ".env"
            env_file_encoding = "utf-8"
            extra = "ignore"


@lru_cache
def get_settings() -> Settings:
    return Settings()
