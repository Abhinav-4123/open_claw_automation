"""
NEXUS QA Configuration Management

Centralized configuration with validation, environment variable support,
and sensible defaults for all environments.
"""

import os
from typing import List, Optional
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    """Application settings with validation and defaults."""

    # ==========================================================================
    # APPLICATION
    # ==========================================================================
    app_name: str = Field(default="NEXUS QA", description="Application name")
    app_version: str = Field(default="2.0.0", description="Application version")
    environment: str = Field(default="development", description="Environment (development, staging, production)")
    debug: bool = Field(default=False, description="Debug mode")
    app_url: str = Field(default="http://localhost:8000", description="Public application URL")

    # ==========================================================================
    # SERVER
    # ==========================================================================
    host: str = Field(default="0.0.0.0", description="Server host")
    port: int = Field(default=8000, description="Server port")
    workers: int = Field(default=4, description="Number of workers")
    reload: bool = Field(default=False, description="Auto-reload on code changes")

    # ==========================================================================
    # DATABASE
    # ==========================================================================
    database_url: str = Field(
        default="sqlite:///./nexus_qa.db",
        description="Database URL (PostgreSQL for production)"
    )
    database_pool_size: int = Field(default=5, description="Connection pool size")
    database_max_overflow: int = Field(default=10, description="Max overflow connections")
    database_pool_timeout: int = Field(default=30, description="Pool timeout in seconds")

    # ==========================================================================
    # REDIS
    # ==========================================================================
    redis_url: str = Field(
        default="redis://localhost:6379/0",
        description="Redis URL for caching and job queue"
    )
    redis_prefix: str = Field(default="nexus:", description="Redis key prefix")
    cache_ttl: int = Field(default=3600, description="Default cache TTL in seconds")

    # ==========================================================================
    # CELERY (Job Queue)
    # ==========================================================================
    celery_broker_url: str = Field(
        default="redis://localhost:6379/1",
        description="Celery broker URL"
    )
    celery_result_backend: str = Field(
        default="redis://localhost:6379/2",
        description="Celery result backend"
    )
    celery_task_timeout: int = Field(default=3600, description="Task timeout in seconds")
    celery_max_retries: int = Field(default=3, description="Max task retries")
    celery_worker_concurrency: int = Field(default=4, description="Number of concurrent workers")
    celery_task_rate_limit: str = Field(default="10/m", description="Default task rate limit")

    # ==========================================================================
    # AUTHENTICATION
    # ==========================================================================
    require_auth: bool = Field(default=False, description="Require API authentication")
    api_keys: str = Field(default="", description="Comma-separated API keys")
    jwt_secret: str = Field(default="change-me-in-production", description="JWT secret key")
    jwt_algorithm: str = Field(default="HS256", description="JWT algorithm")
    jwt_expiration_hours: int = Field(default=24, description="JWT expiration in hours")

    # ==========================================================================
    # RATE LIMITING
    # ==========================================================================
    rate_limit_enabled: bool = Field(default=True, description="Enable rate limiting")
    rate_limit_requests: int = Field(default=100, description="Requests per window")
    rate_limit_window: int = Field(default=3600, description="Window in seconds")

    # ==========================================================================
    # LLM PROVIDERS
    # ==========================================================================
    llm_provider: str = Field(default="auto", description="LLM provider (auto, gemini, openai, anthropic)")
    gemini_api_key: str = Field(default="", description="Google Gemini API key")
    gemini_model: str = Field(default="gemini-2.0-flash", description="Gemini model name")
    openai_api_key: str = Field(default="", description="OpenAI API key")
    openai_model: str = Field(default="gpt-4o", description="OpenAI model name")
    anthropic_api_key: str = Field(default="", description="Anthropic API key")
    anthropic_model: str = Field(default="claude-3-5-sonnet-20241022", description="Anthropic model name")

    # ==========================================================================
    # SCANNING
    # ==========================================================================
    scan_timeout: int = Field(default=3600, description="Scan timeout in seconds (1 hour)")
    scan_max_pages: int = Field(default=100, description="Maximum pages to crawl")
    scan_max_depth: int = Field(default=5, description="Maximum crawl depth")
    scan_screenshot_quality: int = Field(default=80, description="Screenshot JPEG quality")
    browser_headless: bool = Field(default=True, description="Run browser in headless mode")
    browser_pool_size: int = Field(default=5, description="Browser pool size")

    # ==========================================================================
    # STORAGE
    # ==========================================================================
    storage_type: str = Field(default="local", description="Storage type (local, gcs, s3)")
    storage_bucket: str = Field(default="", description="Cloud storage bucket name")
    storage_path: str = Field(default="./storage", description="Local storage path")
    report_retention_days: int = Field(default=90, description="Report retention in days")

    # ==========================================================================
    # NOTIFICATIONS
    # ==========================================================================
    slack_webhook_url: str = Field(default="", description="Slack webhook URL")
    smtp_host: str = Field(default="", description="SMTP host")
    smtp_port: int = Field(default=587, description="SMTP port")
    smtp_user: str = Field(default="", description="SMTP username")
    smtp_password: str = Field(default="", description="SMTP password")
    smtp_from: str = Field(default="", description="Email from address")

    # ==========================================================================
    # BILLING
    # ==========================================================================
    stripe_secret_key: str = Field(default="", description="Stripe secret key")
    stripe_webhook_secret: str = Field(default="", description="Stripe webhook secret")
    stripe_price_starter: str = Field(default="", description="Stripe price ID for starter plan")
    stripe_price_growth: str = Field(default="", description="Stripe price ID for growth plan")

    # ==========================================================================
    # OBSERVABILITY
    # ==========================================================================
    log_level: str = Field(default="INFO", description="Log level")
    log_format: str = Field(default="json", description="Log format (json, text)")
    sentry_dsn: str = Field(default="", description="Sentry DSN for error tracking")
    sentry_traces_sample_rate: float = Field(default=0.1, description="Sentry trace sampling rate")
    metrics_enabled: bool = Field(default=False, description="Enable Prometheus metrics")

    # ==========================================================================
    # CORS
    # ==========================================================================
    cors_origins: str = Field(
        default="http://localhost:3000,http://localhost:8000",
        description="Comma-separated CORS origins"
    )

    # ==========================================================================
    # VALIDATORS
    # ==========================================================================
    @field_validator("environment")
    @classmethod
    def validate_environment(cls, v: str) -> str:
        allowed = ["development", "staging", "production", "test"]
        if v not in allowed:
            raise ValueError(f"environment must be one of {allowed}")
        return v

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        allowed = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        v = v.upper()
        if v not in allowed:
            raise ValueError(f"log_level must be one of {allowed}")
        return v

    # ==========================================================================
    # PROPERTIES
    # ==========================================================================
    @property
    def is_production(self) -> bool:
        return self.environment == "production"

    @property
    def is_development(self) -> bool:
        return self.environment == "development"

    @property
    def api_key_list(self) -> List[str]:
        if not self.api_keys:
            return []
        return [k.strip() for k in self.api_keys.split(",") if k.strip()]

    @property
    def cors_origin_list(self) -> List[str]:
        if not self.cors_origins:
            return ["*"]
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def database_is_postgres(self) -> bool:
        return self.database_url.startswith("postgresql")

    @property
    def scan_timeout_seconds(self) -> int:
        """Scan timeout in seconds (alias for scan_timeout)."""
        return self.scan_timeout

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False


@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()


# Global settings instance
settings = get_settings()
