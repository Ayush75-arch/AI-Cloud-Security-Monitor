"""
CloudGuard-AI — Structured Logger
Uses structlog for JSON-formatted, production-ready logging.
"""
import logging
import sys

import structlog
from structlog.types import FilteringBoundLogger

from app.config import settings


def setup_logging() -> None:
    """Configure structlog with JSON output for production, pretty for dev."""
    log_level = getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO)

    shared_processors: list = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
    ]

    if settings.ENVIRONMENT == "development":
        # Human-readable for local dev
        processors = shared_processors + [
            structlog.dev.ConsoleRenderer(colors=True)
        ]
    else:
        # JSON for log aggregators (Datadog, CloudWatch, ELK)
        processors = shared_processors + [
            structlog.processors.dict_tracebacks,
            structlog.processors.JSONRenderer(),
        ]

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(log_level),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(sys.stdout),
        cache_logger_on_first_use=True,
    )

    # Silence noisy third-party loggers
    logging.getLogger("boto3").setLevel(logging.WARNING)
    logging.getLogger("botocore").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)


def get_logger(name: str) -> FilteringBoundLogger:
    return structlog.get_logger(name)
