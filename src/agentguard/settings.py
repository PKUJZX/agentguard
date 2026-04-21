"""Pydantic-settings configuration for AgentGuard.

All values can be overridden via environment variables prefixed with
``AGENTGUARD_``. See ``.env.example`` for an exhaustive list.
"""

from __future__ import annotations

from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

REPO_ROOT = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    """Runtime configuration for the gateway."""

    model_config = SettingsConfigDict(
        env_prefix="AGENTGUARD_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    host: str = "0.0.0.0"
    port: int = 8080

    upstream_url: str = "http://localhost:9000"

    redis_url: str = "redis://localhost:6379/0"
    postgres_dsn: str = "sqlite+aiosqlite:///./agentguard.db"

    hitl_hmac_secret: str = "change-me-hitl-shared-secret"
    hitl_webhook_url: str | None = None

    policies_path: Path = Field(default=REPO_ROOT / "configs" / "policies.yaml")
    dlp_rules_path: Path = Field(default=REPO_ROOT / "configs" / "dlp_rules.yaml")

    idempotency_ttl: int = 3600
    idempotency_secret: str = "change-me-idempotency-secret"

    request_timeout: float = 30.0


_settings: Settings | None = None


def get_settings() -> Settings:
    """Return a process-wide singleton Settings instance."""

    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings


def reset_settings_for_tests() -> None:
    """Clear the cached singleton — tests call this after mutating env vars."""

    global _settings
    _settings = None
