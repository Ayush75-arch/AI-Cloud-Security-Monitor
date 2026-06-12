"""
CloudGuard-AI — Application Configuration
All settings loaded from environment variables with type validation.
"""
import os
from pathlib import Path
from threading import Lock
from typing import Literal

from dotenv import dotenv_values
from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


APP_DIR = Path(__file__).resolve().parent
BACKEND_DIR = APP_DIR.parent
REPO_ROOT = BACKEND_DIR.parent
ENV_FILES = (
    REPO_ROOT / ".env",
    BACKEND_DIR / ".env",
    Path(".env"),
)
REFRESHABLE_ENV_KEYS = {
    "AI_PROVIDER",
    "GROQ_API_KEY",
    "GROQ_MODEL",
    "LOCAL_LLM_BASE_URL",
    "LOCAL_LLM_MODEL",
}


def _refresh_runtime_env() -> None:
    """Keep long-running dev servers in sync with edited .env values."""
    for env_file in ENV_FILES:
        if not env_file.is_file():
            continue
        for key, value in dotenv_values(env_file).items():
            if key in REFRESHABLE_ENV_KEYS and value is not None:
                os.environ[key] = value


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=ENV_FILES,
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── App ──────────────────────────────────────────────────────────────
    APP_NAME: str = "CloudGuard-AI"
    APP_VERSION: str = "1.0.0"
    ENVIRONMENT: Literal["development", "staging", "production", "test"] = "development"
    DEBUG: bool = False
    LOG_LEVEL: str = "INFO"

    # ── API ──────────────────────────────────────────────────────────────
    API_V1_PREFIX: str = "/api/v1"
    ALLOWED_ORIGINS: list[str] = ["http://localhost:5173", "http://localhost:3000"]

    # ── Database ─────────────────────────────────────────────────────────
    DATABASE_URL: str = "sqlite+aiosqlite:///./cloudguard.db"
    DB_POOL_SIZE: int = 10
    DB_MAX_OVERFLOW: int = 20

    # ── Redis / Celery ────────────────────────────────────────────────────
    REDIS_URL: str = "redis://localhost:6379/0"
    CELERY_BROKER_URL: str = "redis://localhost:6379/0"
    CELERY_RESULT_BACKEND: str = "redis://localhost:6379/1"

    # ── AWS ──────────────────────────────────────────────────────────────
    AWS_ACCESS_KEY_ID: str = ""
    AWS_SECRET_ACCESS_KEY: str = ""
    AWS_DEFAULT_REGION: str = "us-east-1"
    # If empty, uses instance profile / environment credentials
    AWS_SESSION_TOKEN: str = ""

    # ── AI ───────────────────────────────────────────────────────────────
    AI_PROVIDER: Literal["groq", "local"] = "groq"
    GROQ_API_KEY: str = ""
    GROQ_MODEL: str = "llama-3.3-70b-versatile"
    LOCAL_LLM_BASE_URL: str = "http://localhost:11434"
    LOCAL_LLM_MODEL: str = "llama3"

    # ── Security ─────────────────────────────────────────────────────────
    SECRET_KEY: str = "change-me-in-production-use-secrets-manager"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    # ── Notifications ─────────────────────────────────────────────────────
    SLACK_WEBHOOK_URL: str = ""
    CUSTOM_WEBHOOK_URL: str = ""
    CUSTOM_WEBHOOK_HEADERS: dict = {}
    SMTP_SERVER: str = ""
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    EMAIL_FROM: str = "cloudguard@localhost"
    EMAIL_TO: str = ""

    @field_validator("DEBUG", mode="before")
    @classmethod
    def parse_debug(cls, value):
        if isinstance(value, str):
            normalized = value.strip().lower()
            if normalized in {"1", "true", "yes", "on"}:
                return True
            if normalized in {"0", "false", "no", "off", ""}:
                return False
            return False
        return value


def get_settings() -> Settings:
    _refresh_runtime_env()
    s = Settings()
    if s.ENVIRONMENT == "production":
        if s.SECRET_KEY.startswith("change-me"):
            raise RuntimeError(
                "SECRET_KEY must be set to a secure value in production. "
                "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\""
            )
        if "sqlite" in s.DATABASE_URL:
            raise RuntimeError(
                "SQLite is not supported in production. Set DATABASE_URL to a PostgreSQL URL."
            )
    return s


class SettingsProxy:
    """Mutable settings holder so long-lived imports can pick up .env changes."""

    def __init__(self) -> None:
        self._settings = get_settings()
        self._lock = Lock()

    def refresh(self) -> Settings:
        with self._lock:
            self._settings = get_settings()
            return self._settings

    def __getattr__(self, name: str):
        return getattr(self._settings, name)


settings = SettingsProxy()


def refresh_settings() -> Settings:
    return settings.refresh()
