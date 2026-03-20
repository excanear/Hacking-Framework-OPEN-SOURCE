"""
Platform configuration management using Pydantic Settings.

All settings can be overridden via environment variables or a .env file.
Sub-setting classes carry an env_prefix so each logical group is isolated.

SECURITY NOTE: Never commit secrets to version control.
               Use environment variables or a .env file (excluded by .gitignore).
"""

from __future__ import annotations

import secrets
from functools import lru_cache
from typing import List, Optional

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


# ─── Sub-settings ─────────────────────────────────────────────────────────────


class DatabaseSettings(BaseSettings):
    """Database connection parameters.

    Set DATABASE_URL to use a full connection string (overrides individual fields).
    For local dev without PostgreSQL use:
        DATABASE_URL=sqlite+aiosqlite:///./security_platform_dev.db
    """

    model_config = SettingsConfigDict(env_prefix="DB_", env_file=".env", extra="ignore")

    # Full URL override — takes precedence over host/port/name/user/password
    url: Optional[str] = Field(default=None, alias="DATABASE_URL", validation_alias="DATABASE_URL")

    host: str = Field(default="localhost")
    port: int = Field(default=5432)
    name: str = Field(default="security_platform")
    user: str = Field(default="secplatform")
    password: str = Field(default="changeme_in_production")
    pool_size: int = Field(default=10)
    max_overflow: int = Field(default=20)

    @property
    def async_url(self) -> str:
        if self.url:
            return self.url
        return (
            f"postgresql+asyncpg://{self.user}:{self.password}"
            f"@{self.host}:{self.port}/{self.name}"
        )

    @property
    def is_sqlite(self) -> bool:
        return self.async_url.startswith("sqlite")

    @property
    def sync_url(self) -> str:
        if self.url:
            return self.url.replace("+aiosqlite", "").replace("+asyncpg", "+psycopg2")
        return (
            f"postgresql+psycopg2://{self.user}:{self.password}"
            f"@{self.host}:{self.port}/{self.name}"
        )


class RedisSettings(BaseSettings):
    """Redis connection parameters used for caching and Celery broker."""

    model_config = SettingsConfigDict(env_prefix="REDIS_", env_file=".env", extra="ignore")

    host: str = Field(default="localhost")
    port: int = Field(default=6379)
    password: Optional[str] = Field(default=None)
    db: int = Field(default=0)
    celery_db: int = Field(default=1)

    @property
    def url(self) -> str:
        if self.password:
            return f"redis://:{self.password}@{self.host}:{self.port}/{self.db}"
        return f"redis://{self.host}:{self.port}/{self.db}"

    @property
    def celery_broker_url(self) -> str:
        if self.password:
            return f"redis://:{self.password}@{self.host}:{self.port}/{self.celery_db}"
        return f"redis://{self.host}:{self.port}/{self.celery_db}"


class SecuritySettings(BaseSettings):
    """Authentication and access-control configuration."""

    model_config = SettingsConfigDict(env_prefix="SECURITY_", env_file=".env", extra="ignore")

    # In production override SECRET_KEY with a strong random value via env var.
    secret_key: str = Field(default_factory=lambda: secrets.token_hex(32))
    algorithm: str = Field(default="HS256")
    access_token_expire_minutes: int = Field(default=60)
    allowed_hosts: List[str] = Field(default=["localhost", "127.0.0.1"])
    cors_origins: List[str] = Field(
        default=["http://localhost:3000", "http://localhost:8080"]
    )


class ElasticsearchSettings(BaseSettings):
    """Optional Elasticsearch sink for aggregated log/event data."""

    model_config = SettingsConfigDict(env_prefix="ES_", env_file=".env", extra="ignore")

    enabled: bool = Field(default=False)
    host: str = Field(default="localhost")
    port: int = Field(default=9200)
    index_prefix: str = Field(default="security_platform")

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}"


# ─── Main settings ────────────────────────────────────────────────────────────


class PlatformSettings(BaseSettings):
    """Top-level platform configuration."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Application
    app_name: str = Field(default="Security Research Platform")
    app_version: str = Field(default="1.0.0")
    environment: str = Field(default="development")
    debug: bool = Field(default=False)
    log_level: str = Field(default="INFO")

    # API server
    api_host: str = Field(default="0.0.0.0")
    api_port: int = Field(default=8000)
    api_prefix: str = Field(default="/api/v1")

    # Worker / scan limits
    worker_concurrency: int = Field(default=4)
    scan_timeout_seconds: int = Field(default=300)
    max_targets_per_scan: int = Field(default=100)

    # Module discovery path (relative to project root)
    modules_path: str = Field(default="modules")

    # Reports output directory
    reports_dir: str = Field(default="reports/output")

    # Dev mode: run Celery tasks synchronously (no Redis required)
    celery_task_always_eager: bool = Field(default=False)


@lru_cache(maxsize=1)
def get_settings() -> PlatformSettings:
    """Return the cached singleton settings instance."""
    return PlatformSettings()


# ─── Convenience module-level singletons ──────────────────────────────────────

settings = get_settings()
db_settings = DatabaseSettings()
redis_settings = RedisSettings()
security_settings = SecuritySettings()
es_settings = ElasticsearchSettings()
