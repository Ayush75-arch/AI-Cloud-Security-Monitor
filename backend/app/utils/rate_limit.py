"""
CloudGuard-AI — Rate Limiter
Uses slowapi (Starlette-compatible) with in-memory storage for dev,
Redis storage for production.
"""
import os
from typing import Union

from slowapi import Limiter
from slowapi.util import get_remote_address

from app.config import settings


class NoopLimiter:
    """No-op rate limiter for test environments. Accepts all requests."""

    def limit(self, limit_value: str):
        def decorator(func):
            return func
        return decorator

    @property
    def enabled(self) -> bool:
        return False


_is_test = settings.ENVIRONMENT == "test" or os.environ.get("TESTING")

limiter: Union[Limiter, NoopLimiter]

if _is_test:
    limiter = NoopLimiter()
elif settings.ENVIRONMENT == "production" and settings.REDIS_URL:
    limiter = Limiter(
        key_func=get_remote_address,
        storage_uri=settings.REDIS_URL,
        default_limits=["200/minute"],
    )
else:
    limiter = Limiter(
        key_func=get_remote_address,
        default_limits=["200/minute"],
    )
