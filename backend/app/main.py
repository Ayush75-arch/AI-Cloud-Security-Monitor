"""
CloudGuard-AI — FastAPI Application Entry Point (Production-grade)
Middleware stack: RequestID → SecurityHeaders → RequestLogging → CORS → GZip
"""
import os

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from app.api.v1.router import router as v1_router
from app.auth.router import router as auth_router
from app.config import settings
from app.database import engine, Base
from app.middleware import (
    RequestIDMiddleware,
    RequestLoggingMiddleware,
    SecurityHeadersMiddleware,
)
from app.utils.exceptions import register_exception_handlers
from app.utils.logger import get_logger, setup_logging
from app.utils.rate_limit import limiter

setup_logging()
logger = get_logger(__name__)


def _apply_migrations(conn) -> None:
    """
    Safe additive migrations for SQLite.
    Adds new columns without dropping data. Idempotent — safe to run every startup.
    """
    from sqlalchemy import text, inspect
    inspector = inspect(conn)

    if not inspector.has_table("findings"):
        return

    existing = {col["name"] for col in inspector.get_columns("findings")}

    new_columns = [
        ("fingerprint", "VARCHAR(16)"),
        ("resolved_at",  "DATETIME"),
    ]
    for column, col_type in new_columns:
        if column not in existing:
            conn.execute(text(f"ALTER TABLE findings ADD COLUMN {column} {col_type}"))
            logger.info("migration_applied", column=column)


async def lifespan(app: FastAPI):
    logger.info(
        "cloudguard_startup",
        version=settings.APP_VERSION,
        env=settings.ENVIRONMENT,
        db=settings.DATABASE_URL.split("://")[0],
        ai=settings.AI_PROVIDER,
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        # Safe migrations: add new columns if they don't exist yet (SQLite doesn't auto-migrate)
        await conn.run_sync(_apply_migrations)
    yield
    await engine.dispose()
    from app.ai.groq_client import close_groq_client
    await close_groq_client()
    logger.info("cloudguard_shutdown")


def create_app() -> FastAPI:
    app = FastAPI(
        title=settings.APP_NAME,
        version=settings.APP_VERSION,
        description=(
            "AI-powered Cloud Security Posture Management platform. "
            "Scans AWS infrastructure, detects misconfigurations, "
            "maps to compliance frameworks, and generates AI remediation guidance."
        ),
        docs_url="/docs" if settings.ENVIRONMENT != "production" else None,
        redoc_url="/redoc" if settings.ENVIRONMENT != "production" else None,
        openapi_url="/openapi.json" if settings.ENVIRONMENT != "production" else None,
        lifespan=lifespan,
    )

    # ── Rate limiter state ────────────────────────────────────────────────
    app.state.limiter = limiter

    # ── Middleware (outermost first) ──────────────────────────────────────
    app.add_middleware(RequestIDMiddleware)
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(RequestLoggingMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.ALLOWED_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["X-Request-ID", "X-Response-Time"],
    )
    app.add_middleware(GZipMiddleware, minimum_size=1000)
    if not os.environ.get("TESTING"):
        app.add_middleware(SlowAPIMiddleware)

    # ── Rate limit exceeded handler ───────────────────────────────────────
    @app.exception_handler(RateLimitExceeded)
    async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
        return JSONResponse(
            status_code=429,
            content={
                "data": None,
                "errors": [{"code": "RATE_LIMIT_EXCEEDED", "message": str(exc.detail)}],
            },
        )

    # ── Domain exception handlers ─────────────────────────────────────────
    register_exception_handlers(app)

    # ── Routers ───────────────────────────────────────────────────────────
    app.include_router(auth_router, prefix=settings.API_V1_PREFIX)
    app.include_router(v1_router, prefix=settings.API_V1_PREFIX)

    # ── Root health probe (unauthenticated, for load balancers) ──────────
    @app.get("/health", include_in_schema=False)
    async def root_health():
        return {"status": "ok", "version": settings.APP_VERSION}

    return app


app = create_app()
