"""
CloudGuard-AI — Application Configuration
All settings loaded from environment variables with type validation.
"""
from functools import lru_cache
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    # ── App ──────────────────────────────────────────────────────────────
    APP_NAME: str = "CloudGuard-AI"
    APP_VERSION: str = "1.0.0"
    ENVIRONMENT: Literal["development", "staging", "production"] = "development"
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
    AI_PROVIDER: Literal["openai", "local"] = "openai"
    OPENAI_API_KEY: str = ""
    OPENAI_MODEL: str = "gpt-4o"
    LOCAL_LLM_BASE_URL: str = "http://localhost:11434"
    LOCAL_LLM_MODEL: str = "llama3"

    # ── Security ─────────────────────────────────────────────────────────
    SECRET_KEY: str = "change-me-in-production-use-secrets-manager"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
