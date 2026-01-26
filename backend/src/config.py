from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Optional

try:
    from pydantic_settings import BaseSettings, SettingsConfigDict
except ImportError:  # pragma: no cover
    from pydantic import BaseSettings  # type: ignore

    SettingsConfigDict = None  # type: ignore


class Settings(BaseSettings):
    database_url: str = "postgresql://postgres:postgres@db:5432/scanguard"
    # Optional override used only for Alembic migrations (e.g. Supabase Session Pooler).
    alembic_database_url: Optional[str] = None
    redis_url: str = "redis://redis:6379/0"
    pinecone_api_key: Optional[str] = None
    pinecone_environment: Optional[str] = None
    ollama_host: str = "http://ollama:11434"
    ollama_model: str = "llama3:8b"

    llm_provider: str = "auto"  # auto | ollama | openrouter
    open_router_api_key: Optional[str] = None
    open_router_model: str = "google/gemini-2.0-flash-lite-001"
    open_router_base_url: str = "https://openrouter.ai/api/v1"
    open_router_site_url: Optional[str] = None
    open_router_app_name: Optional[str] = None
    api_prefix: str = "/api"

    github_token: Optional[str] = None
    github_webhook_secret: Optional[str] = None
    github_repos: Optional[str] = None  # comma-separated owner/repo list
    repo_list: Optional[str] = None  # legacy alias for github_repos
    github_backfill_limit: int = 50
    github_backfill_on_start: bool = False

    supabase_jwt_secret: Optional[str] = None
    supabase_jwt_issuer: Optional[str] = None
    supabase_url: Optional[str] = None
    supabase_service_key: Optional[str] = None
    zap_docker_image: str = "ghcr.io/zaproxy/zaproxy:stable"
    zap_api_key: Optional[str] = None
    zap_timeout_seconds: int = 300
    zap_request_timeout_seconds: Optional[int] = None
    zap_max_depth: Optional[int] = None
    zap_scan_policy: Optional[str] = None
    dast_allowed_hosts: Optional[str] = None
    dast_deploy_script: Optional[str] = None
    dast_require_verification: bool = False
    dast_verification_timeout: int = 5
    scan_max_active: Optional[int] = None
    scan_min_interval_seconds: Optional[int] = None
    dependency_health_use_llm: bool = True

    if SettingsConfigDict is not None:
        _ENV_FILE = Path(__file__).resolve().parents[1] / ".env"
        model_config = SettingsConfigDict(
            env_file=str(_ENV_FILE),
            env_file_encoding="utf-8",
            extra="ignore",
        )
    else:  # pragma: no cover
        class Config:
            env_file = str(Path(__file__).resolve().parents[1] / ".env")
            env_file_encoding = "utf-8"
            extra = "ignore"


@lru_cache
def get_settings() -> Settings:
    return Settings()
